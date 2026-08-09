#!/usr/bin/env bash
# PHA-1850 (PHA-1844c M5) canary: streaming /v1/messages Content-Length alignment.
#
# Real Claude Code 2.1.x sends a Content-Length header on streaming SSE
# /v1/messages replies (matching the fully-flushed final frame). Before this
# fix, the proxy deleted both content-length and transfer-encoding on the SSE
# passthrough path, leaving chunked transfer implicit — a fingerprint tell and
# a framing inconsistency vs. genuine Anthropic-side traffic.
#
# This canary runs the proxy against a mocked https.request (no real Anthropic
# network / no live OAuth token required — see scripts/pha-1850-mock-https.js)
# in BOTH regular and billing mode, fires a streaming /v1/messages request,
# and asserts:
#   - the response carries a Content-Length header (not chunked/implicit)
#   - transfer-encoding is absent
#   - Content-Length exactly equals the byte count of the body actually
#     received (curl -w '%{size_download}')
#
# Usage: bash scripts/pha-1850-content-length-canary.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOG_DIR="${PAPERCLIP_RUN_SCRATCH_DIR:-/tmp}"

run_case() {
  local mode="$1" port="$2"
  local log_file="$LOG_DIR/pha-1850-canary-${mode}.log"
  local headers_file="$LOG_DIR/pha-1850-canary-${mode}-headers.txt"
  local body_file="$LOG_DIR/pha-1850-canary-${mode}-body.txt"

  echo "[canary] starting proxy on :$port (mode=$mode, mocked upstream)"
  local envs=(PROXY_PORT="$port" PROXY_MODE="$mode")
  if [ "$mode" = "billing" ]; then
    envs+=(OAUTH_TOKEN="sk-ant-oat-fake-stored-token-for-canary")
  fi
  env "${envs[@]}" node --require ./scripts/pha-1850-mock-https.js anthropic-proxy.js > "$log_file" 2>&1 &
  local pid=$!
  trap "kill $pid 2>/dev/null || true" RETURN

  for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf "http://127.0.0.1:$port/health" > /dev/null 2>&1 && break
    sleep 0.3
  done

  local downloaded
  downloaded=$(curl -sS -D "$headers_file" -o "$body_file" \
    -w '%{size_download}' \
    -X POST "http://127.0.0.1:$port/v1/messages" \
    -H 'content-type: application/json' \
    -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
    -d '{"model":"claude-test","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}')

  kill "$pid" 2>/dev/null || true
  trap - RETURN

  echo "[canary][$mode] response headers:"
  cat "$headers_file"

  local content_length
  content_length=$(grep -i '^content-length:' "$headers_file" | tr -d '\r' | cut -d' ' -f2)
  if [ -z "$content_length" ]; then
    echo "[canary][$mode][FAIL] no content-length header on streaming response"
    cat "$log_file"
    exit 1
  fi

  if grep -qi '^transfer-encoding:' "$headers_file"; then
    echo "[canary][$mode][FAIL] transfer-encoding header present alongside content-length (framing must be unambiguous)"
    exit 1
  fi

  local actual_bytes
  actual_bytes=$(wc -c < "$body_file" | tr -d ' ')

  echo "[canary][$mode] content-length header: $content_length, curl size_download: $downloaded, wc -c body: $actual_bytes"

  if [ "$content_length" != "$downloaded" ] || [ "$content_length" != "$actual_bytes" ]; then
    echo "[canary][$mode][FAIL] Content-Length ($content_length) does not match delivered byte count (curl=$downloaded, wc=$actual_bytes)"
    exit 1
  fi

  echo "[canary][$mode][OK] Content-Length ($content_length) matches full streamed body byte-for-byte"
}

run_case regular 4193
run_case billing 4194

echo "[canary] all PHA-1850 content-length checks passed"
