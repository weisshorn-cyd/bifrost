package doh

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"bifrost/internal/metrics"
	dnswire "bifrost/internal/transport/dns"
)

type Client struct {
	URL     string
	Domain  string
	Timeout time.Duration
	Client  *http.Client
	Metrics *metrics.Registry

	id atomic.Uint32
}

func (c *Client) RoundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	id := uint16(c.id.Add(1))
	msg, err := dnswire.BuildQuery(id, payload, c.Domain)
	if err != nil {
		return nil, err
	}
	httpClient := c.Client
	if httpClient == nil {
		timeout := c.Timeout
		if timeout == 0 {
			timeout = 1500 * time.Millisecond
		}
		httpClient = &http.Client{Timeout: timeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if c.Metrics != nil {
		c.Metrics.QueriesSent.Add(1)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	if c.Metrics != nil {
		c.Metrics.ObserveDNSRTT(time.Since(start))
	}
	if len(body) < 2 || binary.BigEndian.Uint16(body[:2]) != id {
		return nil, fmt.Errorf("dns response id mismatch")
	}
	parsed, err := dnswire.ParseTXTResponse(body)
	if err != nil {
		return nil, err
	}
	if parsed.RCode != 0 {
		return nil, fmt.Errorf("dns rcode %d", parsed.RCode)
	}
	return parsed.Payload, nil
}
