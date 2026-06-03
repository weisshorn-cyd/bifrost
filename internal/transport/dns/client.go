package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"bifrost/internal/metrics"
)

type Client struct {
	Addr    string
	Domain  string
	Timeout time.Duration
	Metrics *metrics.Registry

	id atomic.Uint32
}

func (c *Client) RoundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 1500 * time.Millisecond
	}
	id := uint16(c.id.Add(1))
	req, err := BuildQuery(id, payload, c.Domain)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", c.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	start := time.Now()
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	if c.Metrics != nil {
		c.Metrics.QueriesSent.Add(1)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if c.Metrics != nil {
		c.Metrics.ObserveDNSRTT(time.Since(start))
	}
	if binary.BigEndian.Uint16(buf[:2]) != id {
		return nil, fmt.Errorf("dns response id mismatch")
	}
	resp, err := ParseTXTResponse(buf[:n])
	if err != nil {
		return nil, err
	}
	if resp.RCode != 0 {
		return nil, fmt.Errorf("dns rcode %d", resp.RCode)
	}
	return resp.Payload, nil
}
