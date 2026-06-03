package dns

import (
	"testing"

	"bifrost/internal/protocol"
)

func TestTXTResponseFitsClassicUDPWithMaxPayloads(t *testing.T) {
	queryPayload := make([]byte, protocol.PacketHeaderLen+16+protocol.FrameHeaderLen+protocol.MaxQueryPayload)
	respPayload := make([]byte, protocol.PacketHeaderLen+16+protocol.FrameHeaderLen+protocol.MaxResponsePayload)
	query, err := BuildQuery(1, queryPayload, "cdn.c12y.ch")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildTXTResponse(query, respPayload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > 512 {
		t.Fatalf("response is %d bytes, want <= 512", len(resp))
	}
}
