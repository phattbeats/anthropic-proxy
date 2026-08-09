#!/usr/bin/env bash
# PHA-1857 canary: structured access log carries an errorType field for
# upstream 4xx/5xx, and successful requests don't emit errorType. Without
# this, a flood of 0-token /v1/messages entries (e.g. during an Anthropic
# rate-limit incident) looks like a logging bug when it's actually the
# upstream not returning a usage field — the two cases should be
# self-explanatory from the log line alone.
#
# Runs the proxy against a mocked https.request (no live Anthropic network /
# no live OAuth token needed — see /tmp/pha-1857-mock-fixed.js):
#   - req 1: /v1/messages streaming success  → tokensIn > 0, no errorType
#   - req 2: /v1/messages streaming 429      → tokensIn = 0, errorType=rate_limit_error
#   - req 3: /v1/messages non-stream success → tokensIn > 0, no errorType
#   - req 4: /v1/messages non-stream 429      → tokensIn = 0, errorType=rate_limit_error
#   - req 5: chat/completions stream success → tokensIn > 0, no errorType
#   - req 6: chat/completions stream 429      → tokensIn = 0, errorType=rate_limit_error
#
# Usage: bash scripts/pha-1857-error-type-canary.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PROXY_PORT:-4304}"
LOG_DIR="${PAPERCLIP_RUN_SCRATCH_DIR:-/tmp}"
LOG_FILE="$LOG_DIR/pha-1857-canary-proxy.log"

# Use the bundled mock; if missing, the canary fails fast (the mock is part
# of this PR's review surface and must be reviewed together with the code).
MOCK="./scripts/pha-1857-mock-https.js"
if [ ! -f "$MOCK" ]; then
  echo "[canary][FAIL] mock harness not found at $MOCK"
  exit 1
fi

echo "[canary] starting proxy on :$PORT (mocked upstream)"
PROXY_PORT="$PORT" PROXY_MODE=regular \
  node --require "$MOCK" anthropic-proxy.js > "$LOG_FILE" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true' EXIT

for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then break; fi
  sleep 0.3
done

curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}'
curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}'
curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":false,"messages":[{"role":"user","content":"hi"}]}'
curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":false,"messages":[{"role":"user","content":"hi"}]}'
curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}'
curl -sS -o /dev/null -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ant-oat-test-fake-oauth-token' \
  -d '{"model":"claude-test","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}'

sleep 0.5
kill "$PROXY_PID" 2>/dev/null || true
trap - EXIT

ENTRIES=$(grep -E '"route":"/v1/(messages|chat/completions)"' "$LOG_FILE" || true)
if [ -z "$ENTRIES" ]; then
  echo "[canary][FAIL] no access log entries for /v1/messages or /v1/chat/completions"
  cat "$LOG_FILE"
  exit 1
fi
echo "$ENTRIES" > "$LOG_DIR/pha-1857-canary-entries.jsonl"

# Validate each entry via node so we don't have to wrestle grep/awk JSON extraction.
node -e '
  const fs = require("fs");
  const lines = fs.readFileSync(process.argv[1], "utf8").trim().split("\n").filter(Boolean);
  const entries = lines.map(l => JSON.parse(l));
  let failures = 0;
  // Reconstruct what we expect from each request in order.
  // (The mock alternates success/429 globally, not per-route, so we track
  // what response the proxy actually saw and validate against that.)
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const ok = e.status >= 200 && e.status < 300;
    const hasErrType = Object.prototype.hasOwnProperty.call(e, "errorType");
    if (ok && hasErrType) {
      console.error(`[FAIL] entry ${i} (status=${e.status}) should not carry errorType; got ${e.errorType}`);
      failures++;
      continue;
    }
    if (!ok && !hasErrType) {
      console.error(`[FAIL] entry ${i} (status=${e.status}) is missing errorType field`);
      failures++;
      continue;
    }
    if (ok && e.tokensIn <= 0 && e.tokensOut <= 0) {
      console.error(`[FAIL] entry ${i} (status=${e.status}, route=${e.route}) reported 0 tokens for a successful response — usage extraction regressed`);
      failures++;
      continue;
    }
    if (!ok && e.tokensIn !== 0) {
      console.error(`[FAIL] entry ${i} (status=${e.status}) should have tokensIn=0 on upstream error, got ${e.tokensIn}`);
      failures++;
      continue;
    }
    if (!ok && e.errorType !== "rate_limit_error") {
      console.error(`[FAIL] entry ${i} (status=${e.status}) errorType=${e.errorType}, expected rate_limit_error`);
      failures++;
      continue;
    }
    console.log(`[OK] entry ${i}: status=${e.status} tokensIn=${e.tokensIn} tokensOut=${e.tokensOut}${hasErrType ? " errorType=" + e.errorType : ""}`);
  }
  if (failures > 0) { console.error(`${failures} validation failure(s)`); process.exit(1); }
  console.log("\n[canary] all 6 access-log entries validate: success logs usage, errors log errorType=rate_limit_error");
' "$LOG_DIR/pha-1857-canary-entries.jsonl"

echo "[canary] all PHA-1857 error-type checks passed"