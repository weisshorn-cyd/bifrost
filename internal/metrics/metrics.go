package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

type Registry struct {
	SessionsActive       atomic.Int64
	StreamsActive        atomic.Int64
	QueriesSent          atomic.Int64
	QueriesRetransmitted atomic.Int64
	BytesTX              atomic.Int64
	BytesRX              atomic.Int64
	AuthFailures         atomic.Int64
	DNSRTTCount          atomic.Int64
	DNSRTTSumMicros      atomic.Int64
}

func (r *Registry) ObserveDNSRTT(d time.Duration) {
	r.DNSRTTCount.Add(1)
	r.DNSRTTSumMicros.Add(d.Microseconds())
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE bifrost_sessions_active gauge\nbifrost_sessions_active %d\n", r.SessionsActive.Load())
		fmt.Fprintf(w, "# TYPE bifrost_streams_active gauge\nbifrost_streams_active %d\n", r.StreamsActive.Load())
		fmt.Fprintf(w, "# TYPE bifrost_queries_sent counter\nbifrost_queries_sent %d\n", r.QueriesSent.Load())
		fmt.Fprintf(w, "# TYPE bifrost_queries_retransmitted counter\nbifrost_queries_retransmitted %d\n", r.QueriesRetransmitted.Load())
		fmt.Fprintf(w, "# TYPE bifrost_bytes_tx counter\nbifrost_bytes_tx %d\n", r.BytesTX.Load())
		fmt.Fprintf(w, "# TYPE bifrost_bytes_rx counter\nbifrost_bytes_rx %d\n", r.BytesRX.Load())
		fmt.Fprintf(w, "# TYPE bifrost_auth_failures counter\nbifrost_auth_failures %d\n", r.AuthFailures.Load())
		count := r.DNSRTTCount.Load()
		sum := float64(r.DNSRTTSumMicros.Load()) / 1_000_000
		fmt.Fprintf(w, "# TYPE bifrost_dns_rtt_seconds summary\nbifrost_dns_rtt_seconds_sum %.6f\nbifrost_dns_rtt_seconds_count %d\n", sum, count)
	})
}
