package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bifrost/internal/metrics"
	"bifrost/internal/session"
	"bifrost/internal/socks"
	dnsclient "bifrost/internal/transport/dns"
	"bifrost/internal/transport/doh"
)

func main() {
	var (
		secret  = flag.String("secret", env("BIFROST_SECRET", "dev-secret-change-me"), "shared client/server secret")
		domain  = flag.String("domain", env("BIFROST_DOMAIN", "t.example.com"), "tunnel domain")
		listen  = flag.String("listen", env("BIFROST_SOCKS_ADDR", "127.0.0.1:1080"), "SOCKS5 listen address")
		dohURL  = flag.String("doh-url", env("BIFROST_DOH_URL", ""), "DoH endpoint URL; selects DoH when set")
		dnsAddr = flag.String("dns-addr", env("BIFROST_DNS_ADDR", ""), "UDP DNS server address; selects DNS-over-UDP when set")
	)
	flag.Parse()

	reg := &metrics.Registry{}
	rt, transport, err := newRoundTripper(*dnsAddr, *dohURL, *domain, reg)
	if err != nil {
		log.Fatal(err)
	}
	client, err := session.NewClient(*secret, rt, reg)
	if err != nil {
		log.Fatal(err)
	}
	logger := log.New(os.Stdout, "bifrost-client ", log.LstdFlags|log.Lmicroseconds)
	srv := &socks.Server{Addr: *listen, Client: client, Logger: logger}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Printf("socks5 listening on %s via %s", *listen, transport)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatal(err)
	}
}

func newRoundTripper(dnsAddr, dohURL, domain string, reg *metrics.Registry) (session.RoundTripper, string, error) {
	if dnsAddr != "" && dohURL != "" {
		return nil, "", fmt.Errorf("only one of -dns-addr or -doh-url may be set")
	}
	if dnsAddr != "" {
		return &dnsclient.Client{Addr: dnsAddr, Domain: domain, Timeout: 1500 * time.Millisecond, Metrics: reg}, "dns-udp", nil
	}
	if dohURL != "" {
		return &doh.Client{URL: dohURL, Domain: domain, Timeout: 1500 * time.Millisecond, Metrics: reg}, "doh", nil
	}
	return &dnsclient.ResolverClient{Domain: domain, Timeout: 1500 * time.Millisecond, Metrics: reg}, "dns-udp(system-resolver)", nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
