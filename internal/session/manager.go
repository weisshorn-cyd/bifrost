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
	DefaultResponsePayloadSize = protocol.MaxResponsePayload
	MaxResponsePayloadSize     = protocol.MaxFramePayload
	DefaultResponseWaitTimeout = 250 * time.Millisecond

	responseCacheTTL = 10 * time.Minute
	sessionTTL       = 30 * time.Minute
	dialTimeout      = 5 * time.Second
)

type Manager struct {
	secret              string
	policy              *policy.Policy
	metrics             *metrics.Registry
	logger              *log.Logger
	TraceSummary        bool
	TraceRequests       bool
	ResponsePayloadSize int
	ResponseWaitTimeout time.Duration

	mu       sync.Mutex
	sessions map[protocol.SessionID]*Session
	cache    map[cacheKey]*cacheEntry
	inflight map[cacheKey]*inflightQuery
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

	trace               bool
	logger              *log.Logger
	openedAt            time.Time
	responsePayloadSize int
	responseWaitTimeout time.Duration
	requestBytes        atomic.Int64
	responseBytes       atomic.Int64
	summaryOnce         sync.Once
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

type inflightQuery struct {
	done    chan struct{}
	payload []byte
	err     error
}

func NewManager(secret string, p *policy.Policy, m *metrics.Registry, logger *log.Logger) *Manager {
	return &Manager{
		secret:   secret,
		policy:   p,
		metrics:  m,
		logger:   logger,
		sessions: make(map[protocol.SessionID]*Session),
		cache:    make(map[cacheKey]*cacheEntry),
		inflight: make(map[cacheKey]*inflightQuery),
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
	if inFlight := m.inflight[key]; inFlight != nil {
		m.mu.Unlock()
		<-inFlight.done
		if inFlight.err != nil {
			return nil, inFlight.err
		}
		return append([]byte(nil), inFlight.payload...), nil
	}
	inFlight := &inflightQuery{done: make(chan struct{})}
	m.inflight[key] = inFlight
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
		m.finishInflight(key, nil, err)
		return nil, err
	}
	m.storeCache(key, out)
	m.finishInflight(key, out, nil)
	return out, nil
}

func (m *Manager) finishInflight(key cacheKey, payload []byte, err error) {
	m.mu.Lock()
	inFlight := m.inflight[key]
	if inFlight != nil {
		inFlight.payload = append([]byte(nil), payload...)
		inFlight.err = err
		delete(m.inflight, key)
		close(inFlight.done)
	}
	m.mu.Unlock()
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
		st := newStream(s.id, f.StreamID, dest, conn, m.responsePayloadSize(), m.responseWaitTimeout(), m.traceSummary(), m.logger)
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

func newStream(sessionID protocol.SessionID, id protocol.StreamID, dest string, conn net.Conn, responsePayloadSize int, responseWaitTimeout time.Duration, trace bool, logger *log.Logger) *Stream {
	return &Stream{
		id:                  id,
		session:             sessionID,
		dest:                dest,
		conn:                conn,
		pending:             make(chan []byte, 128),
		done:                make(chan struct{}),
		trace:               trace,
		logger:              logger,
		openedAt:            time.Now(),
		responsePayloadSize: responsePayloadSize,
		responseWaitTimeout: responseWaitTimeout,
	}
}

func (s *Stream) readLoop(m *metrics.Registry) {
	defer close(s.done)
	defer s.conn.Close()
	defer s.logSummary("closed")
	buf := make([]byte, s.responsePayloadSize)
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

func (m *Manager) responsePayloadSize() int {
	if m.ResponsePayloadSize > 0 {
		return m.ResponsePayloadSize
	}
	return DefaultResponsePayloadSize
}

func (m *Manager) responseWaitTimeout() time.Duration {
	if m.ResponseWaitTimeout < 0 {
		return 0
	}
	if m.ResponseWaitTimeout > 0 {
		return m.ResponseWaitTimeout
	}
	return DefaultResponseWaitTimeout
}

func (m *Manager) traceSummary() bool {
	return m.TraceSummary || m.TraceRequests
}

func (s *Stream) response(req protocol.Frame) protocol.Frame {
	if resp, ok := s.tryResponse(req); ok {
		return resp
	}
	wait := s.responseWaitTimeout
	if wait <= 0 {
		return protocol.Frame{Version: protocol.Version, Type: protocol.TypePong, StreamID: req.StreamID, Seq: req.Seq}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return protocol.Frame{Version: protocol.Version, Type: protocol.TypePong, StreamID: req.StreamID, Seq: req.Seq}
	case data := <-s.pending:
		return dataFrame(req, data)
	case <-s.done:
		if resp, ok := s.tryResponse(req); ok {
			return resp
		}
		return closeFrame(req)
	}
}

func (s *Stream) tryResponse(req protocol.Frame) (protocol.Frame, bool) {
	select {
	case data := <-s.pending:
		if len(data) == 0 {
			return closeFrame(req), true
		}
		return dataFrame(req, data), true
	case <-s.done:
		select {
		case data := <-s.pending:
			if len(data) > 0 {
				return dataFrame(req, data), true
			}
		default:
		}
		return closeFrame(req), true
	default:
		return protocol.Frame{}, false
	}
}

func dataFrame(req protocol.Frame, data []byte) protocol.Frame {
	if len(data) == 0 {
		return closeFrame(req)
	}
	return protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: req.StreamID, Seq: req.Seq, Payload: data}
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
