#!/usr/bin/env bash
# PHA-1596 follow-up live check: does a cache breakpoint on an assistant message
# that carries BOTH content and tool_calls survive translation to Anthropic?
#
# Sends the OpenClaw-shaped conversation twice through one proxy and reports the
# cache counters. Expected on a fixed proxy: call 1 writes cache, call 2 reads it.
# On v1.4.9 (marker dropped) both calls report zero.
#
# Usage: scripts/pha1596b-canary.sh <proxy-host:port> <salt>
#   e.g. scripts/pha1596b-canary.sh anthropic-proxy-pha1596b:4010 NEW
set -euo pipefail

HOST="${1:?proxy host:port}"
SALT="${2:?unique salt so each proxy gets its own cache prefix}"
MODEL="${MODEL:-claude-sonnet-4-5}"

# ~6k tokens of deterministic filler, so the prefix clears the 1024-token
# minimum for Sonnet with room to spare.
FILLER=$(python3 -c "print(('$SALT scouting report: the roster moved through the qualifier without dropping a map. ' * 320))")

req() {
  python3 - "$FILLER" "$MODEL" "$1" <<'PY'
import json, sys
filler, model, tail = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
  "model": model,
  "max_tokens": 16,
  "stream": True,
  "stream_options": {"include_usage": True},
  "messages": [
    {"role": "user", "content": "Summarize the report."},
    {"role": "assistant",
     "content": filler,
     "tool_calls": [{"id": "call_1", "type": "function",
                     "function": {"name": "lookup", "arguments": "{\"team\":\"navi\"}"}}],
     "cache_control": {"type": "ephemeral"}},
    {"role": "tool", "tool_call_id": "call_1", "content": "lookup returned: ok"},
    {"role": "user", "content": tail},
  ],
}))
PY
}

health() { curl -s "http://$HOST/health"; }

snap() {
  health | python3 -c "import json,sys; u=json.load(sys.stdin)['usage']; print(u['totalCacheCreate'], u['totalCacheRead'])"
}

call() {
  local tail="$1"
  req "$tail" > /tmp/pha1596b-req.json
  curl -s -X POST "http://$HOST/v1/chat/completions" \
    -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-canary' -H 'Expect:' \
    --data-binary @/tmp/pha1596b-req.json \
  | grep -o '"usage":{[^}]*}[^}]*}[^}]*}' | tail -1
}

echo "== proxy $HOST  (version $(health | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'))"
before=$(snap)
echo "-- call 1 (expect cache WRITE)"; call "Reply with the single word: one."
mid=$(snap)
echo "-- call 2 (expect cache READ)";  call "Reply with the single word: two."
after=$(snap)

echo "totalCacheCreate/totalCacheRead: before[$before] after-call-1[$mid] after-call-2[$after]"
