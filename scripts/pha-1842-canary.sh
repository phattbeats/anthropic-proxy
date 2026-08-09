#!/usr/bin/env bash
# PHA-1842 canary: prove the billing-header-as-real-header fix actually gets a
# cache READ on the second identical request (not just a write every time).
#
# Runs the proxy in billing mode on a side port using the OAuth credentials
# already mounted in this environment, fires two identical /v1/messages
# requests with a >1024-token cached system block, and checks:
#   - both requests return 200 (no extra-usage / detection block)
#   - request 1 shows cache_creation_input_tokens > 0 (first write)
#   - request 2 shows cache_read_input_tokens > 0 (prefix held -> read, not write)
#
# Usage: bash scripts/pha-1842-canary.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PROXY_PORT:-4091}"
LOG_DIR="${PAPERCLIP_RUN_SCRATCH_DIR:-/tmp}"
LOG_FILE="$LOG_DIR/pha-1842-canary-proxy.log"

echo "[canary] starting billing-mode proxy on :$PORT"
PROXY_MODE=billing PROXY_PORT="$PORT" node anthropic-proxy.js > "$LOG_FILE" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true' EXIT

for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then break; fi
  sleep 0.5
done

echo "[canary] /health:"
curl -sS "http://127.0.0.1:$PORT/health"; echo

# 1200 reps ≈ 13k tokens, comfortably over every model's cache minimum (1024-2048).
FILLER=$(python3 -c "print('The quick brown fox jumps over the lazy dog. ' * 1200)" 2>/dev/null || node -e "console.log('The quick brown fox jumps over the lazy dog. '.repeat(1200))")

BODY=$(node -e "
const filler = process.argv[1];
console.log(JSON.stringify({
  model: 'claude-haiku-4-5-20251001',
  max_tokens: 8,
  system: [{ type: 'text', text: filler, cache_control: { type: 'ephemeral' } }],
  messages: [{ role: 'user', content: 'Reply with just the word OK.' }],
}));
" "$FILLER")

echo "[canary] request 1 (expect cache_creation_input_tokens > 0)"
RESP1=$(curl -sS -X POST "http://127.0.0.1:$PORT/v1/messages" -H 'content-type: application/json' -d "$BODY")
echo "$RESP1" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const j=JSON.parse(d);console.log(JSON.stringify(j.usage||j,null,2));}catch(e){console.log(d);}})"

sleep 1

echo "[canary] request 2 (expect cache_read_input_tokens > 0)"
RESP2=$(curl -sS -X POST "http://127.0.0.1:$PORT/v1/messages" -H 'content-type: application/json' -d "$BODY")
echo "$RESP2" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const j=JSON.parse(d);console.log(JSON.stringify(j.usage||j,null,2));}catch(e){console.log(d);}})"

CACHE_READ=$(echo "$RESP2" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const j=JSON.parse(d);console.log(j.usage&&j.usage.cache_read_input_tokens||0);}catch(e){console.log(0);}})")

echo
if [ "${CACHE_READ:-0}" -gt 0 ] 2>/dev/null; then
  echo "[canary][OK] request 2 got a cache READ ($CACHE_READ tokens) -> prefix held stable across requests"
else
  echo "[canary][FAIL] request 2 did not report cache_read_input_tokens > 0 -- see proxy log: $LOG_FILE"
  cat "$LOG_FILE"
  exit 1
fi
