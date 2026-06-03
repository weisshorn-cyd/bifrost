package session_test

import (
	"bytes"
	"log"
	"testing"

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
