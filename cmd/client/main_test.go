package main

import (
	"testing"

	"bifrost/internal/metrics"
	dnsclient "bifrost/internal/transport/dns"
	"bifrost/internal/transport/doh"
)

func TestNewRoundTripperSelectsDNSAddr(t *testing.T) {
	rt, name, err := newRoundTripper("127.0.0.1:5353", "", "t.example.com", &metrics.Registry{})
	if err != nil {
		t.Fatal(err)
	}
	if name != "dns-udp" {
		t.Fatalf("name = %q, want dns-udp", name)
	}
	if _, ok := rt.(*dnsclient.Client); !ok {
		t.Fatalf("rt = %T, want *dns.Client", rt)
	}
}

func TestNewRoundTripperSelectsDoHURL(t *testing.T) {
	rt, name, err := newRoundTripper("", "http://127.0.0.1:8053/dns-query", "t.example.com", &metrics.Registry{})
	if err != nil {
		t.Fatal(err)
	}
	if name != "doh" {
		t.Fatalf("name = %q, want doh", name)
	}
	if _, ok := rt.(*doh.Client); !ok {
		t.Fatalf("rt = %T, want *doh.Client", rt)
	}
}

func TestNewRoundTripperDefaultsToResolver(t *testing.T) {
	rt, name, err := newRoundTripper("", "", "t.example.com", &metrics.Registry{})
	if err != nil {
		t.Fatal(err)
	}
	if name != "dns-udp(system-resolver)" {
		t.Fatalf("name = %q, want dns-udp(system-resolver)", name)
	}
	if _, ok := rt.(*dnsclient.ResolverClient); !ok {
		t.Fatalf("rt = %T, want *dns.ResolverClient", rt)
	}
}

func TestNewRoundTripperRejectsDNSAddrAndDoHURL(t *testing.T) {
	_, _, err := newRoundTripper("127.0.0.1:5353", "http://127.0.0.1:8053/dns-query", "t.example.com", &metrics.Registry{})
	if err == nil {
		t.Fatal("expected error")
	}
}
