#!/usr/bin/env bash
# PHA-1596 follow-up live check #2: does a stable/dynamic system prompt split
# survive translation?
#
# Clients split the system prompt into a large stable prefix (cache-marked) and a
# small per-request dynamic suffix (unmarked) — OpenClaw does this at its
# OPENCLAW_CACHE_BOUNDARY. Up to v1.4.10 the proxy joined the parts into one block
# and moved the marker past the volatile half, so the biggest block in the request
# missed cache on every turn.
#
# Sends the same stable prefix twice with a DIFFERENT dynamic suffix each time.
# Fixed proxy: call 2 reads the stable prefix from cache. Broken: it re-creates it.
#
# Usage: scripts/pha1596c-system-split-canary.sh <proxy-host:port> <salt>
set -euo pipefail

HOST="${1:?proxy host:port}"
SALT="${2:?unique salt so each proxy gets its own cache prefix}"
MODEL="${MODEL:-claude-sonnet-4-5}"

STABLE=$(python3 -c "print(('$SALT standing brief: the analyst tracks roster moves, map veto trends and qualifier results. ' * 320))")

call() {
  python3 - "$STABLE" "$MODEL" "$1" > /tmp/pha1596c-req.json <<'PY'
import json, sys
stable, model, dyn = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
  "model": model,
  "max_tokens": 16,
  "stream": True,
  "stream_options": {"include_usage": True},
  "messages": [
    {"role": "system", "content": [
      {"type": "text", "text": stable, "cache_control": {"type": "ephemeral"}},
      {"type": "text", "text": f"<env>current time: {dyn}</env>"},
    ]},
    {"role": "user", "content": "Reply with the single word: ok."},
  ],
}))
PY
  curl -s -X POST "http://$HOST/v1/chat/completions" \
    -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-canary' -H 'Expect:' \
    --data-binary @/tmp/pha1596c-req.json \
  | grep -o '"usage":{[^}]*}[^}]*}[^}]*}' | tail -1
}

echo "== proxy $HOST  (version $(curl -s "http://$HOST/health" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'))"
echo "-- call 1, dynamic suffix A (expect cache WRITE)"; call "2026-07-28T03:00:00Z"
echo "-- call 2, dynamic suffix B (expect cache READ of the stable prefix)"; call "2026-07-28T04:44:44Z"
