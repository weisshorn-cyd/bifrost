package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"bifrost/internal/metrics"
)

type ResolverClient struct {
	Domain   string
	Timeout  time.Duration
	Resolver *net.Resolver
	Metrics  *metrics.Registry
}

func (c *ResolverClient) RoundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	qname, err := PayloadToQName(payload, c.Domain)
	if err != nil {
		return nil, err
	}
	qname += "."
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 1500 * time.Millisecond
	}
	reqCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		reqCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	start := time.Now()
	txts, err := resolver.LookupTXT(reqCtx, qname)
	if err != nil {
		return nil, err
	}
	if c.Metrics != nil {
		c.Metrics.QueriesSent.Add(1)
		c.Metrics.ObserveDNSRTT(time.Since(start))
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no txt answer")
	}
	var out []byte
	for _, txt := range txts {
		out = append(out, txt...)
	}
	return out, nil
}
