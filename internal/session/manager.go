package session

import (
	"container/list"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	bifrostcrypto "bifrost/internal/crypto"
	"bifrost/internal/metrics"
	"bifrost/internal/policy"
	"bifrost/internal/protocol"
)

const (
	responseCacheTTL = 10 * time.Minute
	sessionTTL       = 30 * time.Minute
	dialTimeout      = 5 * time.Second
)

type Manager struct {
	secret        string
	policy        *policy.Policy
	metrics       *metrics.Registry
	logger        *log.Logger
	TraceRequests bool

	mu       sync.Mutex
	sessions map[protocol.SessionID]*Session
	cache    map[cacheKey]*cacheEntry
	order    *list.List
}

type Session struct {
	id       protocol.SessionID
	streams  map[protocol.StreamID]*Stream
	lastSeen time.Time
}

type Stream struct {
	id      protocol.StreamID
	session protocol.SessionID
	dest    string
	conn    net.Conn
	pending chan []byte
	done    chan struct{}
	once    sync.Once

	trace         bool
	logger        *log.Logger
	openedAt      time.Time
	requestBytes  atomic.Int64
	responseBytes atomic.Int64
	summaryOnce   sync.Once
}

type cacheKey struct {
	sessionID protocol.SessionID
	querySeq  uint64
}

type cacheEntry struct {
	key     cacheKey
	payload []byte
	at      time.Time
	elem    *list.Element
}

func NewManager(secret string, p *policy.Policy, m *metrics.Registry, logger *log.Logger) *Manager {
	return &Manager{
		secret:   secret,
		policy:   p,
		metrics:  m,
		logger:   logger,
		sessions: make(map[protocol.SessionID]*Session),
		cache:    make(map[cacheKey]*cacheEntry),
		order:    list.New(),
	}
}

func (m *Manager) HandlePacket(in []byte) ([]byte, error) {
	pkt, frame, err := protocol.DecodeSecureFrame(m.secret, bifrostcrypto.ClientToServer, in)
	if err != nil {
		if m.metrics != nil {
			m.metrics.AuthFailures.Add(1)
		}
		return nil, err
	}
	key := cacheKey{sessionID: pkt.SessionID, querySeq: pkt.QuerySeq}
	m.mu.Lock()
	if ent := m.cache[key]; ent != nil && time.Since(ent.at) <= responseCacheTTL {
		out := append([]byte(nil), ent.payload...)
		m.mu.Unlock()
		return out, nil
	}
	s := m.sessions[pkt.SessionID]
	if s == nil {
		s = &Session{id: pkt.SessionID, streams: make(map[protocol.StreamID]*Stream), lastSeen: time.Now()}
		m.sessions[pkt.SessionID] = s
		if m.metrics != nil {
			m.metrics.SessionsActive.Add(1)
		}
	}
	s.lastSeen = time.Now()
	m.cleanupLocked()
	m.mu.Unlock()

	resp := m.handleFrame(s, frame)
	out, err := protocol.EncodeSecureFrame(m.secret, pkt.SessionID, bifrostcrypto.ServerToClient, pkt.QuerySeq, resp)
	if err != nil {
		return nil, err
	}
	m.storeCache(key, out)
	return out, nil
}

func (m *Manager) handleFrame(s *Session, f protocol.Frame) protocol.Frame {
	switch f.Type {
	case protocol.TypeHello, protocol.TypeAuth:
		return ack(f, nil)
	case protocol.TypeOpen:
		dest := string(f.Payload)
		if !m.policy.Allow(dest) {
			if m.logger != nil {
				m.logger.Printf("deny stream=%d dest=%s", f.StreamID, dest)
			}
			return errFrame(f, "destination denied")
		}
		conn, err := net.DialTimeout("tcp", dest, dialTimeout)
		if err != nil {
			return errFrame(f, err.Error())
		}
		st := newStream(s.id, f.StreamID, dest, conn, m.TraceRequests, m.logger)
		m.mu.Lock()
		old := s.streams[f.StreamID]
		if old != nil {
			old.Close()
		}
		s.streams[f.StreamID] = st
		m.mu.Unlock()
		if m.metrics != nil {
			m.metrics.StreamsActive.Add(1)
		}
		if m.TraceRequests && m.logger != nil {
			m.logger.Printf("trace stream event=open session=%x stream=%d dest=%s", s.id, f.StreamID, dest)
		}
		go st.readLoop(m.metrics)
		return ack(f, nil)
	case protocol.TypeData:
		st := m.getStream(s, f.StreamID)
		if st == nil {
			return errFrame(f, "unknown stream")
		}
		n, err := st.conn.Write(f.Payload)
		if n > 0 {
			st.requestBytes.Add(int64(n))
		}
		if err != nil {
			st.Close()
			m.dropStream(s, f.StreamID)
			return errFrame(f, err.Error())
		}
		if m.metrics != nil {
			m.metrics.BytesRX.Add(int64(len(f.Payload)))
		}
		return st.response(f)
	case protocol.TypePing:
		st := m.getStream(s, f.StreamID)
		if st == nil {
			return errFrame(f, "unknown stream")
		}
		return st.response(f)
	case protocol.TypeClose:
		st := m.getStream(s, f.StreamID)
		if st != nil {
			st.Close()
			m.dropStream(s, f.StreamID)
		}
		return closeFrame(f)
	default:
		return errFrame(f, "unsupported frame type "+protocol.TypeName(f.Type))
	}
}

func newStream(sessionID protocol.SessionID, id protocol.StreamID, dest string, conn net.Conn, trace bool, logger *log.Logger) *Stream {
	return &Stream{
		id:       id,
		session:  sessionID,
		dest:     dest,
		conn:     conn,
		pending:  make(chan []byte, 128),
		done:     make(chan struct{}),
		trace:    trace,
		logger:   logger,
		openedAt: time.Now(),
	}
}

func (s *Stream) readLoop(m *metrics.Registry) {
	defer close(s.done)
	defer s.conn.Close()
	defer s.logSummary("closed")
	buf := make([]byte, protocol.MaxResponsePayload)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			s.responseBytes.Add(int64(n))
			if m != nil {
				m.BytesTX.Add(int64(n))
			}
			select {
			case s.pending <- chunk:
			default:
			}
		}
		if err != nil {
			if err != io.EOF {
				select {
				case s.pending <- []byte{}:
				default:
				}
			}
			return
		}
	}
}

func (s *Stream) response(req protocol.Frame) protocol.Frame {
	select {
	case data := <-s.pending:
		if len(data) == 0 {
			return closeFrame(req)
		}
		return protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: req.StreamID, Seq: req.Seq, Payload: data}
	case <-s.done:
		select {
		case data := <-s.pending:
			if len(data) > 0 {
				return protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: req.StreamID, Seq: req.Seq, Payload: data}
			}
		default:
		}
		return closeFrame(req)
	default:
		return protocol.Frame{Version: protocol.Version, Type: protocol.TypePong, StreamID: req.StreamID, Seq: req.Seq}
	}
}

func (s *Stream) Close() {
	s.once.Do(func() {
		_ = s.conn.Close()
	})
}

func (s *Stream) logSummary(reason string) {
	if !s.trace || s.logger == nil {
		return
	}
	s.summaryOnce.Do(func() {
		s.logger.Printf("trace stream event=close session=%x stream=%d dest=%s request_bytes=%d response_bytes=%d duration=%s reason=%s", s.session, s.id, s.dest, s.requestBytes.Load(), s.responseBytes.Load(), time.Since(s.openedAt), reason)
	})
}

func (m *Manager) getStream(s *Session, id protocol.StreamID) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return s.streams[id]
}

func (m *Manager) dropStream(s *Session, id protocol.StreamID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := s.streams[id]; st != nil {
		delete(s.streams, id)
		if m.metrics != nil {
			m.metrics.StreamsActive.Add(-1)
		}
	}
}

func ack(f protocol.Frame, payload []byte) protocol.Frame {
	return protocol.Frame{Version: protocol.Version, Type: protocol.TypeACK, StreamID: f.StreamID, Seq: f.Seq, Payload: payload}
}

func errFrame(f protocol.Frame, msg string) protocol.Frame {
	return protocol.Frame{Version: protocol.Version, Type: protocol.TypeError, StreamID: f.StreamID, Seq: f.Seq, Payload: []byte(msg)}
}

func closeFrame(f protocol.Frame) protocol.Frame {
	return protocol.Frame{Version: protocol.Version, Type: protocol.TypeClose, StreamID: f.StreamID, Seq: f.Seq}
}

func (m *Manager) storeCache(key cacheKey, payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ent := &cacheEntry{key: key, payload: append([]byte(nil), payload...), at: time.Now()}
	ent.elem = m.order.PushBack(ent)
	m.cache[key] = ent
	m.cleanupLocked()
}

func (m *Manager) cleanupLocked() {
	now := time.Now()
	for e := m.order.Front(); e != nil; {
		next := e.Next()
		ent := e.Value.(*cacheEntry)
		if now.Sub(ent.at) > responseCacheTTL {
			delete(m.cache, ent.key)
			m.order.Remove(e)
		}
		e = next
	}
	for id, s := range m.sessions {
		if now.Sub(s.lastSeen) <= sessionTTL {
			continue
		}
		for sid, st := range s.streams {
			st.Close()
			delete(s.streams, sid)
			if m.metrics != nil {
				m.metrics.StreamsActive.Add(-1)
			}
		}
		delete(m.sessions, id)
		if m.metrics != nil {
			m.metrics.SessionsActive.Add(-1)
		}
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		for _, st := range s.streams {
			st.Close()
		}
	}
	return nil
}

func (m *Manager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("sessions=%d cache=%d", len(m.sessions), len(m.cache))
}
