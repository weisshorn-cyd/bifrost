package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

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
		traceRequests = flag.Bool("trace-requests", envBool("BIFROST_TRACE_REQUESTS", false), "log each server request with response byte counts")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "bifrost-server ", log.LstdFlags|log.Lmicroseconds)
	p, err := policy.New(*allow)
	if err != nil {
		logger.Fatal(err)
	}
	reg := &metrics.Registry{}
	mgr := session.NewManager(*secret, p, reg, logger)
	mgr.TraceRequests = *traceRequests
	dnsSrv := &dnsserver.Server{Addr: *dnsAddr, Domain: *domain, NSName: *nsName, Manager: mgr, Logger: logger, TraceRequests: *traceRequests}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)
	go func() {
		logger.Printf("dns udp listening on %s for %s", *dnsAddr, *domain)
		errCh <- dnsSrv.ListenAndServe(ctx)
	}()
	mux := http.NewServeMux()
	mux.Handle("/dns-query", doh.HandlerWithOptions(dnsSrv, doh.HandlerOptions{Logger: logger, TraceRequests: *traceRequests}))
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
