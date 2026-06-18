#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER_BIN=${BIFROST_SERVER_BIN:-"$ROOT_DIR/bin/bifrost-server"}
CLIENT_BIN=${BIFROST_CLIENT_BIN:-"$ROOT_DIR/bin/bifrost-client"}
TEST_URL=${E2E_URL:-https://www.google.com/robots.txt}
CONCURRENCY=${E2E_CONCURRENCY:-4}
SECRET=${E2E_SECRET:-bifrost-e2e-secret}
DOMAIN=${E2E_DOMAIN:-t.e2e.invalid}
DNS_HOST=${E2E_DNS_HOST:-127.0.0.1}
DNS_PORT=${E2E_DNS_PORT:-15353}
HTTP_HOST=${E2E_HTTP_HOST:-127.0.0.1}
HTTP_PORT=${E2E_HTTP_PORT:-18053}
SOCKS_HOST=${E2E_SOCKS_HOST:-127.0.0.1}
SOCKS_PORT=${E2E_SOCKS_PORT:-11080}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-e2e.XXXXXX")
SERVER_PID=
CLIENT_PID=

case "$TEST_URL" in
  https://*) ;;
  *) echo "E2E_URL must be an https:// URL" >&2; exit 2 ;;
esac

if ! [[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]]; then
  echo "E2E_CONCURRENCY must be a positive integer" >&2
  exit 2
fi

URL_AUTHORITY=${TEST_URL#https://}
URL_AUTHORITY=${URL_AUTHORITY%%/*}
URL_HOST=${URL_AUTHORITY%%:*}
URL_PORT=443
if [[ "$URL_AUTHORITY" == *:* ]]; then
  URL_PORT=${URL_AUTHORITY##*:}
fi
ALLOW=${E2E_ALLOW:-"$URL_HOST:$URL_PORT"}

cleanup_client() {
  if [[ -n "$CLIENT_PID" ]]; then
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
    CLIENT_PID=
  fi
}

cleanup() {
  local status=$?
  cleanup_client
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    echo "e2e failed; logs are in $WORK_DIR" >&2
  else
    rm -rf "$WORK_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 2
  fi
}

wait_for_http() {
  local url=$1
  local pid=$2
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    if curl --silent --fail --max-time 1 --proxy "" "$url" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_tcp() {
  local host=$1
  local port=$2
  local pid=$3
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

download_direct() {
  curl \
    --silent --show-error --fail --location --http1.1 \
    --connect-timeout 10 --max-time 60 \
    --proxy "" \
    --output "$1" \
    "$TEST_URL"
}

download_proxied() {
  curl \
    --silent --show-error --fail --location --http1.1 \
    --connect-timeout 20 --max-time 180 \
    --proxy "socks5h://$SOCKS_HOST:$SOCKS_PORT" \
    --output "$1" \
    "$TEST_URL"
}

start_client() {
  local mode=$1
  local log="$WORK_DIR/client-$mode.log"
  local transport_args=()
  case "$mode" in
    dns) transport_args=(-dns-addr "$DNS_HOST:$DNS_PORT") ;;
    doh) transport_args=(-doh-url "http://$HTTP_HOST:$HTTP_PORT/dns-query") ;;
    *) echo "unknown transport: $mode" >&2; return 2 ;;
  esac
  "$CLIENT_BIN" \
    -secret "$SECRET" \
    -domain "$DOMAIN" \
    -listen "$SOCKS_HOST:$SOCKS_PORT" \
    -poll-interval 20ms \
    "${transport_args[@]}" >"$log" 2>&1 &
  CLIENT_PID=$!
  if ! wait_for_tcp "$SOCKS_HOST" "$SOCKS_PORT" "$CLIENT_PID"; then
    echo "$mode client did not become ready" >&2
    tail -n 100 "$log" >&2 || true
    return 1
  fi
}

test_transport() {
  local mode=$1
  local single="$WORK_DIR/$mode-single.body"
  echo "testing $mode: one proxied request"
  start_client "$mode"
  download_proxied "$single"
  cmp "$WORK_DIR/direct.body" "$single"

  echo "testing $mode: $CONCURRENCY concurrent proxied requests"
  local pids=()
  local i
  for ((i = 1; i <= CONCURRENCY; i++)); do
    download_proxied "$WORK_DIR/$mode-concurrent-$i.body" &
    pids+=("$!")
  done
  local failed=0
  local pid
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done
  if (( failed != 0 )); then
    return 1
  fi
  for ((i = 1; i <= CONCURRENCY; i++)); do
    cmp "$WORK_DIR/direct.body" "$WORK_DIR/$mode-concurrent-$i.body"
  done
  cleanup_client
}

require_command curl
require_command cmp
if [[ ! -x "$SERVER_BIN" || ! -x "$CLIENT_BIN" ]]; then
  echo "binaries not found; run 'make build' first" >&2
  exit 2
fi

echo "fetching direct baseline: $TEST_URL"
download_direct "$WORK_DIR/direct.body"

"$SERVER_BIN" \
  -secret "$SECRET" \
  -domain "$DOMAIN" \
  -dns-addr "$DNS_HOST:$DNS_PORT" \
  -http-addr "$HTTP_HOST:$HTTP_PORT" \
  -allow "$ALLOW" >"$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!
if ! wait_for_http "http://$HTTP_HOST:$HTTP_PORT/metrics" "$SERVER_PID"; then
  echo "server did not become ready" >&2
  tail -n 100 "$WORK_DIR/server.log" >&2 || true
  exit 1
fi

test_transport dns
test_transport doh

echo "e2e passed: direct, DNS tunnel, DoH tunnel, and concurrent responses match"
