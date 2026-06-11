package e2e_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"bifrost/internal/metrics"
	"bifrost/internal/policy"
	"bifrost/internal/session"
	"bifrost/internal/socks"
	dnstunnel "bifrost/internal/transport/dns"
	"bifrost/internal/transport/doh"
)

const testSecret = "test-secret"

func TestSOCKSOverDoHConcurrentStreams(t *testing.T) {
	upstream := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "doh:%s", r.URL.Path)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	dnsSrv := newDNSServer(t, u.Host)
	dohSrv := newHTTPServer(t, doh.Handler(dnsSrv))
	defer dohSrv.Close()
	socksAddr := startSocks(t, &doh.Client{URL: dohSrv.URL, Domain: "t.example.com", Timeout: time.Second})

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := fetchViaSocks(t, socksAddr, upstream.URL+fmt.Sprintf("/stream-%d", i))
			want := fmt.Sprintf("doh:/stream-%d", i)
			if body != want {
				t.Errorf("body = %q, want %q", body, want)
			}
		}()
	}
	wg.Wait()
}

func TestSOCKSOverDNSUDP(t *testing.T) {
	upstream := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "dns:%s", r.URL.Path)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	dnsSrv := newDNSServer(t, u.Host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsAddr := freeUDPAddr(t)
	dnsSrv.Addr = dnsAddr
	go func() {
		if err := dnsSrv.ListenAndServe(ctx); err != nil {
			t.Errorf("dns server: %v", err)
		}
	}()
	waitUDP(t, dnsAddr)
	socksAddr := startSocks(t, &dnstunnel.Client{Addr: dnsAddr, Domain: "t.example.com", Timeout: time.Second})

	body := fetchViaSocks(t, socksAddr, upstream.URL+"/udp")
	if body != "dns:/udp" {
		t.Fatalf("body = %q, want dns:/udp", body)
	}
}

func TestSOCKSOverDNSUDPLargeResponse(t *testing.T) {
	body := strings.Repeat("x", 4096)
	upstream := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	dnsSrv := newDNSServer(t, u.Host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsAddr := freeUDPAddr(t)
	dnsSrv.Addr = dnsAddr
	go func() {
		if err := dnsSrv.ListenAndServe(ctx); err != nil {
			t.Errorf("dns server: %v", err)
		}
	}()
	waitUDP(t, dnsAddr)
	socksAddr := startSocks(t, &dnstunnel.Client{Addr: dnsAddr, Domain: "t.example.com", Timeout: time.Second})

	got := fetchViaSocks(t, socksAddr, upstream.URL+"/large")
	if got != body {
		t.Fatalf("body length = %d, want %d", len(got), len(body))
	}
}

func TestSOCKSOverDNSUDPWithPollingDisabled(t *testing.T) {
	want := "no-poll:" + strings.Repeat("z", 2048)
	upstream := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, want)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	dnsSrv := newDNSServer(t, u.Host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsAddr := freeUDPAddr(t)
	dnsSrv.Addr = dnsAddr
	go func() {
		if err := dnsSrv.ListenAndServe(ctx); err != nil {
			t.Errorf("dns server: %v", err)
		}
	}()
	waitUDP(t, dnsAddr)
	socksAddr := startSocksWithOptions(t, &dnstunnel.Client{Addr: dnsAddr, Domain: "t.example.com", Timeout: time.Second}, socksOptions{disablePolling: true})

	body := fetchViaSocks(t, socksAddr, upstream.URL+"/disabled")
	if body != want {
		t.Fatalf("body length = %d, want %d", len(body), len(want))
	}
}

func TestSOCKSOverMachineResolver(t *testing.T) {
	upstream := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "resolver:%s", r.URL.Path)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	dnsSrv := newDNSServer(t, u.Host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsAddr := freeUDPAddr(t)
	dnsSrv.Addr = dnsAddr
	go func() {
		if err := dnsSrv.ListenAndServe(ctx); err != nil {
			t.Errorf("dns server: %v", err)
		}
	}()
	waitUDP(t, dnsAddr)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	socksAddr := startSocks(t, &dnstunnel.ResolverClient{Resolver: resolver, Domain: "t.example.com", Timeout: time.Second})

	body := fetchViaSocks(t, socksAddr, upstream.URL+"/resolver")
	if body != "resolver:/resolver" {
		t.Fatalf("body = %q, want resolver:/resolver", body)
	}
}

func newDNSServer(t *testing.T, allowHostPort string) *dnstunnel.Server {
	t.Helper()
	p, err := policy.New(allowHostPort)
	if err != nil {
		t.Fatal(err)
	}
	return &dnstunnel.Server{
		Domain:  "t.example.com",
		Manager: session.NewManager(testSecret, p, &metrics.Registry{}, log.Default()),
		Logger:  log.Default(),
	}
}

func startSocks(t *testing.T, rt session.RoundTripper) string {
	t.Helper()
	return startSocksWithOptions(t, rt, socksOptions{})
}

type socksOptions struct {
	disablePolling bool
}

func startSocksWithOptions(t *testing.T, rt session.RoundTripper, opts socksOptions) string {
	t.Helper()
	c, err := session.NewClient(testSecret, rt, &metrics.Registry{})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := (&socks.Server{Addr: addr, Client: c, Logger: log.Default(), DisablePolling: opts.disablePolling}).ListenAndServe(ctx); err != nil {
			t.Errorf("socks server: %v", err)
		}
	}()
	waitTCP(t, addr)
	return addr
}

func fetchViaSocks(t *testing.T, socksAddr, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	conn, err := net.DialTimeout("tcp", socksAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		t.Fatal(err)
	}
	if method != [2]byte{0x05, 0x00} {
		t.Fatalf("method response = %v", method)
	}
	portNum, _ := strconv.Atoi(port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("socks connect reply = %d", reply[1])
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(body))
}

func newHTTPServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	return srv
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for tcp %s", addr)
}

func waitUDP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("udp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for udp %s", addr)
}
