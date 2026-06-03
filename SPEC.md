# SPEC.md

# Bifrost

Version: 1.0

Status: Draft

Language: Go 1.25+

## Overview

Bifrost is an authenticated and encrypted transport protocol that carries multiplexed TCP streams through DNS and DNS-over-HTTPS (DoH).

Primary goals:
- High throughput
- High reliability
- Bidirectional streams
- Internet-facing security
- Cross-platform client
- Containerized server

## Components

### Client
- SOCKS5 listener
- Session management
- Stream multiplexing
- Encryption
- Retransmission
- Flow control
- DNS transport
- DoH transport

Default bind: 127.0.0.1:1080

### Server
- DNS authoritative server
- DoH endpoint
- Session management
- Stream demultiplexing
- Egress TCP connections
- Policy enforcement
- Auditing
- Metrics

## Transport Priority

1. DoH
2. DNS TCP
3. DNS UDP
4. Recursive-authoritative path

## Security

Required:
- AEAD encryption
- Client authentication
- Replay protection
- Session expiration
- Rate limiting
- Destination allow-list
- Audit logging
- Metrics

Server MUST NOT operate as an open proxy.

## Cryptography

Default:
- X25519
- ChaCha20-Poly1305
- HKDF-SHA256

Session keys:
- client_to_server_key
- server_to_client_key

Replay protection:
- Nonce uint64
- Replay cache window: 10 minutes

## Session Model

A session contains multiple streams.

Session ID:
```go
[16]byte
```

## Stream Model

Each SOCKS connection becomes a stream.

```go
type StreamID uint32
```

States:
- OPENING
- OPEN
- HALF_CLOSED
- CLOSED

## Frame Format

```go
type Frame struct {
    Version    uint8
    Type       uint8
    Flags      uint8
    StreamID   uint32
    Seq        uint64
    PayloadLen uint16
    Payload    []byte
}
```

Frame types:
- HELLO
- AUTH
- OPEN
- DATA
- WINDOW
- ACK
- PING
- PONG
- CLOSE
- ERROR

## Reliability

Client owns retransmission.

Defaults:
```yaml
ack_timeout: 1500ms
max_retries: 3
```

Dedup key:
```text
client_id + session_id + query_seq
```

Server should maintain a response cache keyed by:
```text
(session_id, query_seq)
```

## Flow Control

```yaml
query_window: 8
query_window_max: 32
stream_window: 262144
```

## DNS Transport

Query encoding:
```text
v1.<payload1>.<payload2>.<payload3>.t.example.com
```

Constraints:
- Label <= 63 bytes
- FQDN <= 255 bytes

Encoding:
- Base32Hex

Response carrier:
- TXT records only (v1)

## DoH

Endpoint:
```text
POST /dns-query
```

Content-Type:
```text
application/dns-message
```

## SOCKS5

Supported:
- CONNECT

Unsupported:
- BIND
- UDP ASSOCIATE

## Egress Policy

Default:
```yaml
deny_all: true
```

## Metrics

- bifrost_sessions_active
- bifrost_streams_active
- bifrost_queries_sent
- bifrost_queries_retransmitted
- bifrost_bytes_tx
- bifrost_bytes_rx
- bifrost_dns_rtt_seconds
- bifrost_auth_failures

## Project Layout

```text
cmd/
  client/
  server/

internal/
  auth/
  crypto/
  protocol/
  session/
  stream/
  transport/
    dns/
    doh/
  socks/
  policy/
  metrics/

pkg/
  api/
```

## Acceptance Criteria

- SOCKS5 browsing through DoH
- SOCKS5 browsing through DNS UDP
- Session resumption after packet loss
- Query retransmission
- Duplicate query handling
- Multiple concurrent streams
- Prometheus metrics
- Dockerized server
- Static client binaries
