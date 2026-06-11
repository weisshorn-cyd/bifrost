package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"bifrost/internal/protocol"
	"bifrost/internal/session"
)

const DefaultPollInterval = time.Second

type Server struct {
	Addr           string
	Client         *session.Client
	Logger         *log.Logger
	PollInterval   time.Duration
	DisablePolling bool

	ln net.Listener
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(parent context.Context, conn net.Conn) {
	defer conn.Close()
	dest, err := handshake(conn)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("socks handshake: %v", err)
		}
		return
	}
	streamID := s.Client.NextStreamID()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	resp, err := s.Client.Send(ctx, protocol.Frame{Version: protocol.Version, Type: protocol.TypeOpen, StreamID: streamID, Payload: []byte(dest)})
	if err != nil || resp.Type != protocol.TypeACK {
		_ = sendReply(conn, 0x05)
		return
	}
	if err := sendReply(conn, 0x00); err != nil {
		return
	}
	s.proxy(ctx, cancel, conn, streamID)
}

func (s *Server) proxy(ctx context.Context, cancel context.CancelFunc, conn net.Conn, streamID protocol.StreamID) {
	respCh := make(chan protocol.Frame, 64)
	pollNow := make(chan struct{}, 1)
	var wg sync.WaitGroup
	var sendMu sync.Mutex
	send := func(ctx context.Context, f protocol.Frame) (protocol.Frame, error) {
		sendMu.Lock()
		defer sendMu.Unlock()
		return s.Client.Send(ctx, f)
	}
	sendResp := func(f protocol.Frame) {
		select {
		case respCh <- f:
		case <-ctx.Done():
		}
	}
	requestPoll := func() {
		select {
		case pollNow <- struct{}{}:
		default:
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, protocol.MaxQueryPayload)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				resp, qerr := send(ctx, protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: streamID, Payload: payload})
				if qerr == nil {
					sendResp(resp)
				}
				if qerr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				_, _ = send(context.Background(), protocol.Frame{Version: protocol.Version, Type: protocol.TypeClose, StreamID: streamID})
				cancel()
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var tick <-chan time.Time
		var ticker *time.Ticker
		if !s.DisablePolling {
			ticker = time.NewTicker(s.pollInterval())
			defer ticker.Stop()
			tick = ticker.C
		}
		poll := func() bool {
			resp, err := send(ctx, protocol.Frame{Version: protocol.Version, Type: protocol.TypePing, StreamID: streamID})
			if err != nil {
				cancel()
				return false
			}
			sendResp(resp)
			return true
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-pollNow:
				if !poll() {
					return
				}
			case <-tick:
				if !poll() {
					return
				}
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			wg.Wait()
			return
		case f := <-respCh:
			switch f.Type {
			case protocol.TypeData:
				if len(f.Payload) > 0 {
					if _, err := conn.Write(f.Payload); err != nil {
						cancel()
					} else {
						requestPoll()
					}
				}
			case protocol.TypeClose, protocol.TypeError:
				cancel()
			}
		}
	}
}

func (s *Server) pollInterval() time.Duration {
	if s.PollInterval > 0 {
		return s.PollInterval
	}
	return DefaultPollInterval
}

func handshake(rw net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", errors.New("unsupported socks version")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return "", err
	}
	if _, err := rw.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(rw, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 {
		return "", errors.New("unsupported request version")
	}
	if req[1] != 1 {
		_ = sendReply(rw, 0x07)
		return "", errors.New("only CONNECT is supported")
	}
	var host string
	switch req[3] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(rw, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(rw, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(rw, name); err != nil {
			return "", err
		}
		host = string(name)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(rw, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		_ = sendReply(rw, 0x08)
		return "", errors.New("unsupported address type")
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(rw, portBytes[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func sendReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func UnsupportedCommandError(cmd byte) error {
	return fmt.Errorf("unsupported SOCKS command %d", cmd)
}
