package session_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bifrostcrypto "bifrost/internal/crypto"
	"bifrost/internal/metrics"
	"bifrost/internal/policy"
	"bifrost/internal/protocol"
	"bifrost/internal/session"
)

func TestManagerCachesDuplicateQueryResponse(t *testing.T) {
	p, err := policy.New("")
	if err != nil {
		t.Fatal(err)
	}
	m := session.NewManager("test-secret", p, &metrics.Registry{}, log.Default())
	var sid protocol.SessionID
	copy(sid[:], []byte("1234567890abcdef"))
	req, err := protocol.EncodeSecureFrame("test-secret", sid, bifrostcrypto.ClientToServer, 7, protocol.Frame{Version: protocol.Version, Type: protocol.TypeHello})
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.HandlePacket(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.HandlePacket(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("duplicate query did not return cached response")
	}
}

func TestManagerDuplicateInflightQueryHasSingleSideEffect(t *testing.T) {
	p, err := policy.New("127.0.0.1:*")
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	upstream := newTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		writes.Add(1)
		time.Sleep(200 * time.Millisecond)
	})
	m := session.NewManager("test-secret", p, &metrics.Registry{}, log.Default())
	m.ResponseWaitTimeout = 250 * time.Millisecond
	var sid protocol.SessionID
	copy(sid[:], []byte("1234567890abcdef"))

	open := sendFrame(t, m, sid, 1, protocol.Frame{Version: protocol.Version, Type: protocol.TypeOpen, StreamID: 1, Payload: []byte(upstream)})
	if open.Type != protocol.TypeACK {
		t.Fatalf("open response type = %s, want ACK", protocol.TypeName(open.Type))
	}
	req, err := protocol.EncodeSecureFrame("test-secret", sid, bifrostcrypto.ClientToServer, 2, protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: 1, Payload: []byte("ping")})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.HandlePacket(req)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("upstream writes = %d, want 1", got)
	}
}

func TestManagerResponsePayloadSize(t *testing.T) {
	p, err := policy.New("127.0.0.1:*")
	if err != nil {
		t.Fatal(err)
	}
	upstream := newTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(bytes.Repeat([]byte{'x'}, 128))
	})
	m := session.NewManager("test-secret", p, &metrics.Registry{}, log.Default())
	m.ResponsePayloadSize = 37
	var sid protocol.SessionID
	copy(sid[:], []byte("1234567890abcdef"))

	open := sendFrame(t, m, sid, 1, protocol.Frame{Version: protocol.Version, Type: protocol.TypeOpen, StreamID: 1, Payload: []byte(upstream)})
	if open.Type != protocol.TypeACK {
		t.Fatalf("open response type = %s, want ACK", protocol.TypeName(open.Type))
	}
	data := sendFrame(t, m, sid, 2, protocol.Frame{Version: protocol.Version, Type: protocol.TypeData, StreamID: 1, Payload: bytes.Repeat([]byte{'q'}, 64)})
	for qseq := uint64(3); data.Type == protocol.TypePong && qseq < 20; qseq++ {
		time.Sleep(10 * time.Millisecond)
		data = sendFrame(t, m, sid, qseq, protocol.Frame{Version: protocol.Version, Type: protocol.TypePing, StreamID: 1})
	}
	if data.Type != protocol.TypeData {
		t.Fatalf("data response type = %s, want DATA", protocol.TypeName(data.Type))
	}
	if len(data.Payload) > 37 {
		t.Fatalf("payload length = %d, want <= 37", len(data.Payload))
	}
}

func sendFrame(t *testing.T, m *session.Manager, sid protocol.SessionID, qseq uint64, f protocol.Frame) protocol.Frame {
	t.Helper()
	req, err := protocol.EncodeSecureFrame("test-secret", sid, bifrostcrypto.ClientToServer, qseq, f)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := m.HandlePacket(req)
	if err != nil {
		t.Fatal(err)
	}
	_, frame, err := protocol.DecodeSecureFrame("test-secret", bifrostcrypto.ServerToClient, resp)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newTCPServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	waitTCP(t, ln.Addr().String())
	return ln.Addr().String()
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for tcp %s", addr)
}
