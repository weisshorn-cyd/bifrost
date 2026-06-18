![Bifrost logo](assets/logo.png)

# Bifrost

This repository contains a compact Go implementation of the `SPEC.md` draft:

- SOCKS5 client with CONNECT support.
- Server with UDP DNS TXT and DoH `/dns-query` transports.
- PSK-authenticated HKDF-SHA256 session keys, ChaCha20-Poly1305 AEAD packets, per-session stream IDs, retry/retransmission, duplicate response cache, destination allow-list, audit logging, and Prometheus-style `/metrics`.

Run a local server:

```sh
go run ./cmd/server -secret test-secret -allow '127.0.0.1:*' -dns-addr 127.0.0.1:5353 -http-addr 127.0.0.1:8053
```

For public recursive DNS use, delegate the tunnel domain to the server and expose UDP `:53`.
For `cdn.example.com`, a parent zone can delegate to `ns1.example.com`, and Bifrost will
answer authoritative `NS`/`SOA` records for `cdn.example.com`. Override the advertised
nameserver with `-ns-name` or `BIFROST_NS_NAME` when needed.
The server defaults to `-response-payload-size 160`, which is conservative for recursive
DNS over UDP; increase it only when your DNS path supports larger responses.
Use `-trace-level summary` for per-stream close summaries, or `-trace-level verbose` for
per-request DNS/DoH traces plus stream events.

Run a local SOCKS client over DoH:

```sh
go run ./cmd/client -secret test-secret -listen 127.0.0.1:1080 -doh-url http://127.0.0.1:8053/dns-query
```

Use `-dns-addr` for direct UDP DNS, `-doh-url` for DoH, or neither to use the machine resolver.
The client defaults to `-poll-interval 1s`; lowering it reduces latency but increases DNS
query volume and server CPU. Set `-poll-interval 0` to disable periodic idle polling while
keeping active response draining.

Proxy curl through it:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8080/
```

The server defaults to deny-all egress. Use `-allow` or `BIFROST_ALLOW` to permit destinations.

Run the black-box end-to-end suite (requires `curl` and public network access):

```sh
make e2e
```

It downloads `https://www.google.com/robots.txt` directly and through both the DNS and
DoH SOCKS tunnels, compares the bodies byte-for-byte, and repeats the tunneled request
concurrently. Override the defaults with `E2E_URL`, `E2E_ALLOW`, `E2E_CONCURRENCY`, or
the `E2E_*_PORT` environment variables documented in `e2e/run.sh`.
