package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"bifrost/internal/metrics"
	"bifrost/internal/policy"
	"bifrost/internal/session"
	dnsserver "bifrost/internal/transport/dns"
	"bifrost/internal/transport/doh"
)

func main() {
	var (
		secret        = flag.String("secret", env("BIFROST_SECRET", "dev-secret-change-me"), "shared client/server secret")
		domain        = flag.String("domain", env("BIFROST_DOMAIN", "t.example.com"), "authoritative tunnel domain")
		nsName        = flag.String("ns-name", env("BIFROST_NS_NAME", ""), "authoritative nameserver name for NS/SOA records")
		dnsAddr       = flag.String("dns-addr", env("BIFROST_DNS_ADDR", "127.0.0.1:5353"), "UDP DNS listen address")
		httpAddr      = flag.String("http-addr", env("BIFROST_HTTP_ADDR", "127.0.0.1:8053"), "HTTP DoH and metrics listen address")
		allow         = flag.String("allow", env("BIFROST_ALLOW", ""), "comma-separated destination allow-list, for example 127.0.0.1:*,example.com:443")
		respPayload   = flag.Int("response-payload-size", envInt("BIFROST_RESPONSE_PAYLOAD_SIZE", session.DefaultResponsePayloadSize), "maximum server-to-client payload bytes per DNS response")
		respWait      = flag.Duration("response-wait", envDuration("BIFROST_RESPONSE_WAIT", session.DefaultResponseWaitTimeout), "time to wait for upstream bytes before returning an empty response; set 0 to disable")
		traceLevel    = flag.String("trace-level", env("BIFROST_TRACE_LEVEL", ""), "trace level: off, summary, or verbose")
		traceRequests = flag.Bool("trace-requests", envBool("BIFROST_TRACE_REQUESTS", false), "deprecated alias for -trace-level verbose")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "bifrost-server ", log.LstdFlags|log.Lmicroseconds)
	if *respPayload < 1 || *respPayload > session.MaxResponsePayloadSize {
		logger.Fatalf("-response-payload-size must be between 1 and %d", session.MaxResponsePayloadSize)
	}
	if *respWait < 0 {
		logger.Fatal("-response-wait must be greater than or equal to 0")
	}
	traceSummary, traceVerbose, err := parseTraceLevel(*traceLevel, *traceRequests)
	if err != nil {
		logger.Fatal(err)
	}
	p, err := policy.New(*allow)
	if err != nil {
		logger.Fatal(err)
	}
	reg := &metrics.Registry{}
	mgr := session.NewManager(*secret, p, reg, logger)
	mgr.TraceSummary = traceSummary
	mgr.TraceRequests = traceVerbose
	mgr.ResponsePayloadSize = *respPayload
	if *respWait == 0 {
		mgr.ResponseWaitTimeout = -1
	} else {
		mgr.ResponseWaitTimeout = *respWait
	}
	dnsSrv := &dnsserver.Server{Addr: *dnsAddr, Domain: *domain, NSName: *nsName, Manager: mgr, Logger: logger, TraceRequests: traceVerbose}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)
	go func() {
		logger.Printf("dns udp listening on %s for %s", *dnsAddr, *domain)
		errCh <- dnsSrv.ListenAndServe(ctx)
	}()
	mux := http.NewServeMux()
	mux.Handle("/dns-query", doh.HandlerWithOptions(dnsSrv, doh.HandlerOptions{Logger: logger, TraceRequests: traceVerbose}))
	mux.Handle("/metrics", reg.Handler())
	httpSrv := &http.Server{Addr: *httpAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Shutdown(context.Background())
	}()
	go func() {
		logger.Printf("http listening on %s", *httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	if err := <-errCh; err != nil {
		logger.Fatal(err)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseTraceLevel(level string, legacyVerbose bool) (summary, verbose bool, err error) {
	if legacyVerbose && level == "" {
		level = "verbose"
	}
	switch level {
	case "", "off":
		return false, false, nil
	case "summary":
		return true, false, nil
	case "verbose":
		return true, true, nil
	default:
		return false, false, fmt.Errorf("-trace-level must be off, summary, or verbose")
	}
}
