#!/usr/bin/env bash
# PHA-1391 canary test for SSE reverse-map buffering on top of v1.4.4 + PR #10.
#
# Goal: prove the buffered createSSETransformer still produces correct text
# when terms from REVERSE_MAP are split across Anthropic SSE deltas, AND
# that mid-response upstream errors are surfaced (PR #10) instead of silently
# cutting streams (the v1.4.3 regression).
#
# This script is meant to run against a local node instance of the proxy on a
# side port (no real Anthropic network needed). It feeds pre-recorded SSE
# delta sequences through the proxy's billing-mode createSSETransformer and
# checks the rendered text.
#
# Usage: PROXY_PORT=4015 bash scripts/pha-1391-canary.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PROXY_PORT:-4015}"
PROXY_VERSION="${PROXY_VERSION:-v1.4.5-canary}"
LOG_DIR="${PAPERCLIP_RUN_SCRATCH_DIR:-/tmp}"
LOG_FILE="$LOG_DIR/pha-1391-canary-proxy.log"

echo "[canary] starting proxy on :$PORT (PROXY_VERSION=$PROXY_VERSION)"
PROXY_VERSION="$PROXY_VERSION" PORT="$PORT" node anthropic-proxy.js > "$LOG_FILE" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true' EXIT

# wait for ready
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[canary] /health check:"
curl -sS "http://127.0.0.1:$PORT/health" | tee "$LOG_DIR/pha-1391-health.json"
echo

VERSION_REPORTED=$(curl -sS "http://127.0.0.1:$PORT/health" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
if [ "$VERSION_REPORTED" != "$PROXY_VERSION" ]; then
  echo "[canary][FAIL] version plumb mismatch: expected $PROXY_VERSION, got $VERSION_REPORTED"
  exit 1
fi
echo "[canary][OK] version plumb reports $VERSION_REPORTED"

echo "[canary] running node-level buffer regression check (no network)"
PROXY_VERSION="$PROXY_VERSION" node scripts/pha-1391-buffer-unit.js
echo "[canary][OK] buffer unit test passed"

echo "[canary] all checks passed; proxy log: $LOG_FILE"
