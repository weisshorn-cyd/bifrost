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

Run a local SOCKS client over DoH:

```sh
go run ./cmd/client -secret test-secret -listen 127.0.0.1:1080 -doh-url http://127.0.0.1:8053/dns-query
```

Use `-dns-addr` for direct UDP DNS, `-doh-url` for DoH, or neither to use the machine resolver.

Proxy curl through it:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8080/
```

The server defaults to deny-all egress. Use `-allow` or `BIFROST_ALLOW` to permit destinations.
