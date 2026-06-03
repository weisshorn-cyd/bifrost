package session

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	bifrostcrypto "bifrost/internal/crypto"
	"bifrost/internal/metrics"
	"bifrost/internal/protocol"
)

type RoundTripper interface {
	RoundTrip(context.Context, []byte) ([]byte, error)
}

type Client struct {
	secret     string
	sessionID  protocol.SessionID
	rt         RoundTripper
	metrics    *metrics.Registry
	ackTimeout time.Duration
	maxRetries int

	querySeq atomic.Uint64
	streamID atomic.Uint32
}

func NewClient(secret string, rt RoundTripper, m *metrics.Registry) (*Client, error) {
	id, err := bifrostcrypto.RandomSessionID()
	if err != nil {
		return nil, err
	}
	return &Client{
		secret:     secret,
		sessionID:  protocol.SessionID(id),
		rt:         rt,
		metrics:    m,
		ackTimeout: 1500 * time.Millisecond,
		maxRetries: 3,
	}, nil
}

func (c *Client) NextStreamID() protocol.StreamID {
	return protocol.StreamID(c.streamID.Add(1))
}

func (c *Client) Send(ctx context.Context, f protocol.Frame) (protocol.Frame, error) {
	qseq := c.querySeq.Add(1)
	f.Seq = qseq
	packet, err := protocol.EncodeSecureFrame(c.secret, c.sessionID, bifrostcrypto.ClientToServer, qseq, f)
	if err != nil {
		return protocol.Frame{}, err
	}
	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 && c.metrics != nil {
			c.metrics.QueriesRetransmitted.Add(1)
		}
		reqCtx := ctx
		cancel := func() {}
		if _, ok := ctx.Deadline(); !ok {
			reqCtx, cancel = context.WithTimeout(ctx, c.ackTimeout)
		}
		respBytes, err := c.rt.RoundTrip(reqCtx, packet)
		cancel()
		if err != nil {
			last = err
			continue
		}
		p, resp, err := protocol.DecodeSecureFrame(c.secret, bifrostcrypto.ServerToClient, respBytes)
		if err != nil {
			last = err
			continue
		}
		if p.SessionID != c.sessionID || p.QuerySeq != qseq {
			last = errors.New("response does not match query")
			continue
		}
		return resp, nil
	}
	return protocol.Frame{}, fmt.Errorf("query failed after retries: %w", last)
}
