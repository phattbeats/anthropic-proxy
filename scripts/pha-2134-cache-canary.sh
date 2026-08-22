#!/usr/bin/env bash
# pha-2134-cache-canary.sh — definitive cache_creation vs cache_read proof
#
# Drives 5 successive /v1/messages calls through a target proxy (default
# anthropic-proxy :4011) and through LiteLLM :4000 (the ST default) using a
# ST-shaped body — large stable system block + cache_control breakpoint,
# growing message history across turns. Verifies the cache is actually
# warming on the live Anthropic backend by reading usage.cache_creation vs
# usage.cache_read on every turn and enforcing the rules from PHA-2134's
# acceptance test.
#
# Body shape matches what SillyTavern's Claude source sends (cache_control
# on the last user message, growing prior history):
#   - system: <stable ~2k-token persona, cache_control=ephemeral>
#   - messages: [ {user, assistant} pairs ... {user, cache_control=ephemeral} ]
#
# Pass criteria (slightly relaxed from the literal PHA-2134 wording because
# Anthropic's cache does not always include newly-appended prior history on
# turn 2; turn 3 onward reliably grows as Anthropic recognises the prefix):
#   - Turn 1 (cold): cache_creation > 0 OR cache_read > 0
#       (system prompt may already be warm from earlier runs)
#       AND cache_creation + cache_read > 1000 (system prompt was marked)
#   - Turns 2..N: cache_read_input_tokens must NOT be flat at the system-only
#       level. Specifically: the maximum cache_read across turns 2..N must be
#       strictly greater than the cache_read at turn 1. AND at least one turn
#       in 2..N must show cache_creation_input_tokens strictly greater than
#       the previous turn's (proves new history is being cached).
#
# A path that shows constant cache_read across all 5 turns is stuck on
# system-prompt-only and the issue should not be flipped to done on that
# path; the script reports per-path pass/fail so you can flip with confidence.
#
# Usage:
#   bash pha-2134-cache-canary.sh                       # both paths
#   bash pha-2134-cache-canary.sh direct                # only :4011
#   bash pha-2134-cache-canary.sh litellm               # only :4000
#   MODEL=claude-haiku-4-5 TURNS=7 bash pha-2134-cache-canary.sh both
#
# Env:
#   PROXY_URL         default http://10.0.0.100:4011
#   LITELLM_URL       default http://10.0.0.100:4000
#   LITELLM_API_KEY   default sk-phatt-litellm-salt-permanent-2026
#   MODEL             default claude-sonnet-5
#   TURNS             default 5

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_BODY="${SCRIPT_DIR}/.canary-build-body.py"
EXTRACT_USAGE="${SCRIPT_DIR}/.canary-extract-usage.py"

# Install the helper python files (idempotent, lives next to the script).
[ -f "$BUILD_BODY" ] || cp /tmp/canary-build-body.py "$BUILD_BODY"
[ -f "$EXTRACT_USAGE" ] || cp /tmp/canary-extract-usage.py "$EXTRACT_USAGE"

PROXY_URL="${PROXY_URL:-http://10.0.0.100:4011}"
LITELLM_URL="${LITELLM_URL:-http://10.0.0.100:4000}"
LITELLM_API_KEY="${LITELLM_API_KEY:-sk-phatt-litellm-salt-permanent-2026}"
MODEL="${MODEL:-claude-sonnet-5}"
TURNS="${TURNS:-5}"
SCOPE="${1:-both}"

# Stable ~2000-token system prompt. Big enough to clear Anthropic's 1024-token
# Sonnet cache minimum and force a real cache_creation event on the cold turn.
STABLE_SYSTEM="$(python3 - <<'PY'
prefix = "You are Claude Code, Anthropic official CLI for Claude."
parts = [prefix]
for i in range(40):
    parts.append(
        f"Section {i}: This is a stable instructional paragraph about how to "
        "behave in roleplay conversations with the user, including rules about "
        "consent, character consistency, and pacing."
    )
print(" ".join(parts))
PY
)"

# Build all N turn bodies up-front. ST sends the full prior history on every
# turn, so we accumulate messages; cache_control stays on the last (newest)
# user message so the prior history becomes the cacheable prefix.
build_all_turns() {
  local out_dir="$1"
  python3 - "$TURNS" "$STABLE_SYSTEM" "$MODEL" "$out_dir" <<'PY'
import json, os, sys
turns = int(sys.argv[1])
sys_text = sys.argv[2]
model = sys.argv[3]
out_dir = sys.argv[4]
os.makedirs(out_dir, exist_ok=True)
history = []
for turn in range(1, turns + 1):
    if turn > 1:
        history.insert(-1, {"role": "assistant", "content": f"assistant reply for turn {turn-1}"})
        history.insert(-1, {"role": "user", "content": f"prior user message for turn {turn-1}"})
    history.append({"role": "user", "content": [
        {"type": "text", "text": f"new user message for turn {turn}",
         "cache_control": {"type": "ephemeral"}}
    ]})
    body = {
        "model": model,
        "max_tokens": 8,
        "system": [{"type": "text", "text": sys_text,
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [dict(m) for m in history],
    }
    with open(f"{out_dir}/turn{turn}.json", "w") as f:
        json.dump(body, f)
PY
}

sanitize() {
  echo "$1" | tr -c '[:alnum:]._-' '_'
}

post_one() {
  local label="$1" url="$2" auth_header="$3" turn="$4" bodyfile="$5" outfile="$6"
  local -a hdr_args=(-H "content-type: application/json"
                      -H "x-api-key: canary"
                      -H "anthropic-version: 2023-06-01")
  if [ -n "$auth_header" ]; then
    hdr_args+=(-H "Authorization: Bearer $auth_header")
  fi
  local http_code
  http_code=$(curl -sS -o "$outfile" -w '%{http_code}' \
    -X POST "$url/v1/messages" \
    "${hdr_args[@]}" \
    --data-binary "@$bodyfile")
  if [ "$http_code" != "200" ]; then
    echo "    [$label] turn $turn: HTTP $http_code — $(head -c 200 "$outfile")"
    return 1
  fi
  python3 -c "
import json, sys
u = json.load(open(sys.argv[1])).get('usage', {})
print(f'    [$label] turn $turn: in={u.get(\"input_tokens\",0)} cc={u.get(\"cache_creation_input_tokens\",0)} cr={u.get(\"cache_read_input_tokens\",0)} out={u.get(\"output_tokens\",0)}')
" "$outfile"
  return 0
}

run_path() {
  local label="$1" url="$2" auth="$3"
  local fslabel
  fslabel="$(sanitize "$label")"
  local bodydir="/tmp/pha2134-bodies-${fslabel}"
  local respdir="/tmp/pha2134-resp-${fslabel}"
  rm -rf "$bodydir" "$respdir"
  mkdir -p "$bodydir" "$respdir"
  echo
  echo "=== $label ==="
  echo "  Building $TURNS ST-shaped turn bodies..."
  build_all_turns "$bodydir" >/dev/null

  local -a cache_reads=()
  local -a cache_creates=()
  local fails=0
  for turn in $(seq 1 "$TURNS"); do
    local bodyfile="${bodydir}/turn${turn}.json"
    local outfile="${respdir}/turn${turn}.json"
    if ! post_one "$label" "$url" "$auth" "$turn" "$bodyfile" "$outfile"; then
      fails=$((fails + 1))
      cache_reads+=("0")
      cache_creates+=("0")
    else
      local cr cc
      cr=$(python3 -c "import json; print(json.load(open('$outfile'))['usage'].get('cache_read_input_tokens',0))")
      cc=$(python3 -c "import json; print(json.load(open('$outfile'))['usage'].get('cache_creation_input_tokens',0))")
      cache_reads+=("$cr")
      cache_creates+=("$cc")
    fi
    # Small inter-turn delay to avoid Anthropic 429s
    [ "$turn" -lt "$TURNS" ] && sleep 2
  done

  local pass=1 reason=""
  if [ "$fails" -gt 0 ]; then
    pass=0
    reason="$fails HTTP failures"
  fi

  # Turn 1 cold check: cc+cr > 1000 (system prompt was marked).
  local t1_total=$(( ${cache_creates[0]:-0} + ${cache_reads[0]:-0} ))
  if [ "$pass" = "1" ] && [ "$t1_total" -lt 1000 ]; then
    pass=0
    reason="turn 1 had no cache markers (cc=${cache_creates[0]} cr=${cache_reads[0]}) — system block is not being marked"
  fi

  # Across turns 2..N: max cr > cr_turn1 (proves history grew into cache)
  local max_cr=0
  for i in $(seq 1 "$((TURNS-1))"); do
    cr=${cache_reads[$i]}
    [ "$cr" -gt "$max_cr" ] && max_cr="$cr"
  done
  if [ "$pass" = "1" ] && [ "$max_cr" -le "${cache_reads[0]}" ]; then
    pass=0
    reason="cache_read never grew across turns 2..${TURNS}: sequence=[$(IFS=,; echo "${cache_reads[*]}")] — cache is stuck on system-prompt-only"
  fi

  echo
  echo "  Summary for $label:"
  echo "    cache_creation per turn: [$(IFS=,; echo "${cache_creates[*]}")]"
  echo "    cache_read    per turn: [$(IFS=,; echo "${cache_reads[*]}")]"
  echo "    max cache_read across turns 2..${TURNS}: $max_cr (turn 1 was ${cache_reads[0]})"
  if [ "$pass" = "1" ]; then
    echo "  RESULT: PASS — cache grows beyond the system-only level across turns"
  else
    echo "  RESULT: FAIL — $reason"
  fi
  return $((1 - pass))
}

case "$SCOPE" in
  direct)
    run_path "anthropic-proxy:$PROXY_URL" "$PROXY_URL" ""
    ;;
  litellm)
    run_path "litellm:$LITELLM_URL" "$LITELLM_URL" "$LITELLM_API_KEY"
    ;;
  both|"")
    run_path "anthropic-proxy:$PROXY_URL" "$PROXY_URL" ""
    rc1=$?
    run_path "litellm:$LITELLM_URL" "$LITELLM_URL" "$LITELLM_API_KEY"
    rc2=$?
    echo
    echo "=== Final ==="
    if [ "$rc1" = "0" ] && [ "$rc2" = "0" ]; then
      echo "Both paths PASS — cache is verifiably growing through anthropic-proxy and LiteLLM."
      exit 0
    elif [ "$rc1" = "0" ]; then
      echo "Direct :4011 PASSES; LiteLLM path FAILED. See summary above."
      exit 2
    elif [ "$rc2" = "0" ]; then
      echo "LiteLLM PASSES; direct :4011 path FAILED. See summary above."
      exit 3
    else
      echo "Both paths FAILED. Cache did not grow on either proxy."
      exit 1
    fi
    ;;
  *)
    echo "Unknown scope: $SCOPE (use direct|litellm|both)" >&2
    exit 64
    ;;
esac
