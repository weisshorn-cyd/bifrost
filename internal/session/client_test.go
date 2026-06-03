package session_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	bifrostcrypto "bifrost/internal/crypto"
	"bifrost/internal/metrics"
	"bifrost/internal/protocol"
	"bifrost/internal/session"
)

func TestClientRetransmitsSamePacket(t *testing.T) {
	reg := &metrics.Registry{}
	rt := &flakyRT{secret: "test-secret"}
	c, err := session.NewClient("test-secret", rt, reg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Send(context.Background(), protocol.Frame{Version: protocol.Version, Type: protocol.TypeHello})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != protocol.TypeACK {
		t.Fatalf("response type = %s, want ACK", protocol.TypeName(resp.Type))
	}
	if rt.calls != 2 {
		t.Fatalf("calls = %d, want 2", rt.calls)
	}
	if !bytes.Equal(rt.firstPayload, rt.secondPayload) {
		t.Fatal("retransmission changed packet bytes")
	}
	if got := reg.QueriesRetransmitted.Load(); got != 1 {
		t.Fatalf("retransmitted metric = %d, want 1", got)
	}
}

type flakyRT struct {
	secret        string
	calls         int
	firstPayload  []byte
	secondPayload []byte
}

func (f *flakyRT) RoundTrip(_ context.Context, payload []byte) ([]byte, error) {
	f.calls++
	if f.calls == 1 {
		f.firstPayload = append([]byte(nil), payload...)
		return nil, errors.New("simulated loss")
	}
	f.secondPayload = append([]byte(nil), payload...)
	p, frame, err := protocol.DecodeSecureFrame(f.secret, bifrostcrypto.ClientToServer, payload)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeSecureFrame(f.secret, p.SessionID, bifrostcrypto.ServerToClient, p.QuerySeq, protocol.Frame{
		Version:  protocol.Version,
		Type:     protocol.TypeACK,
		StreamID: frame.StreamID,
		Seq:      frame.Seq,
	})
}
