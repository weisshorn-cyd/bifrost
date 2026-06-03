package doh

import (
	"io"
	"log"
	"net/http"
	"time"

	dnswire "bifrost/internal/transport/dns"
)

type DNSHandler interface {
	HandleDNSMessage([]byte) []byte
}

type HandlerOptions struct {
	Logger        *log.Logger
	TraceRequests bool
}

func Handler(h DNSHandler) http.Handler {
	return HandlerWithOptions(h, HandlerOptions{})
}

func HandlerWithOptions(h DNSHandler, opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqBytes := r.ContentLength
		if reqBytes < 0 {
			reqBytes = 0
		}
		tw := &traceResponseWriter{ResponseWriter: w}
		defer func() {
			if !opts.TraceRequests || opts.Logger == nil {
				return
			}
			status := tw.status
			if status == 0 {
				status = http.StatusOK
			}
			opts.Logger.Printf("trace request transport=doh remote=%s method=%s path=%s status=%d request_bytes=%d response_bytes=%d duration=%s", r.RemoteAddr, r.Method, r.URL.RequestURI(), status, reqBytes, tw.bytes, time.Since(start))
		}()
		if r.Method != http.MethodPost {
			http.Error(tw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/dns-message" {
			http.Error(tw, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		reqBytes = int64(len(body))
		if err != nil {
			http.Error(tw, "bad request", http.StatusBadRequest)
			return
		}
		resp := h.HandleDNSMessage(body)
		if resp == nil {
			http.Error(tw, "server failure", http.StatusInternalServerError)
			return
		}
		tw.Header().Set("Content-Type", "application/dns-message")
		_, _ = tw.Write(resp)
	})
}

type traceResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *traceResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *traceResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

var _ DNSHandler = (*dnswire.Server)(nil)
