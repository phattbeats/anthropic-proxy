#!/usr/bin/env bash
# PHA-1887 sidecar A/B: runs the v1.5.5 baseline and the pha-1887-body-first
# patch side by side against a local fake Anthropic recogniser that returns
# 200 only when the request body has the x-anthropic-billing-header text block
# at system[0]. The first /v1/messages request is what failed in production;
# the canary should mirror that without touching the real upstream.
#
# Usage:
#   bash scripts/pha-1887-sidecar-ab.sh [PORT_BASE]
#
# PORT_BASE defaults to 4700. The baseline binds PORT_BASE+0, the patch binds
# PORT_BASE+1. Each proxy is started with NODE_OPTIONS=--require pointing at
# the in-process mock, PROXY_MODE=billing, OAUTH_TOKEN=dummy. The script prints
# a side-by-side result table and exits non-zero if the patch fails the sidecar.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT_BASE="${1:-4700}"
BASELINE_PORT="$PORT_BASE"
PATCH_PORT="$((PORT_BASE+1))"
MOCK="${ROOT}/scripts/pha-1887-sidecar-mock.js"
REQUEST='{"model":"claude-sonnet-5","max_tokens":8,"system":[{"type":"text","text":"You are Claude Code, Anthropic'"'"'s official CLI for Claude.","cache_control":{"type":"ephemeral"}},{"type":"text","text":"STABLE-PREFIX","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Reply with just the word OK."}]}'

baseline_branch=v1.5.5
patch_branch=pha-1887-body-first
baseline_worktree="${BASELINE_WORKTREE:-/tmp/pha1887-sidecar-baseline}"
patch_worktree="${PATCH_WORKTREE:-/tmp/pha1887-body-first}"

ensure_worktree() {
  local ref="$1" dest="$2"
  if [ ! -d "$dest" ]; then
    git -C "$ROOT" worktree add --detach "$dest" "$ref" >/dev/null
  fi
}

run_proxy() {
  local label="$1" dir="$2" port="$3" logfile="$4" pidfile="$5"
  (cd "$dir" && NODE_OPTIONS=--require="$MOCK" PROXY_MODE=billing OAUTH_TOKEN=dummy CC_VERSION=2.1.205 DEVICE_ID=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef INSTANCE_SESSION_ID=0123456789abcdef0123456789abcdef PROXY_PORT="$port" node anthropic-proxy.js >"$logfile" 2>&1 & echo $! >"$pidfile")
  local pid
  pid=$(cat "$pidfile")
  for _ in $(seq 1 50); do
    if curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo "[$label] proxy failed to come up on :$port" >&2
  return 1
}

shoot_first_request() {
  local label="$1" port="$2" outfile="$3"
  curl -sS -o "$outfile" -w '%{http_code}' -X POST "http://127.0.0.1:$port/v1/messages" -H 'content-type: application/json' --data "$REQUEST"
}

ensure_worktree "$baseline_branch" "$baseline_worktree"
ensure_worktree "$patch_branch" "$patch_worktree"

run_proxy baseline "$baseline_worktree" "$BASELINE_PORT" /tmp/pha-1887-baseline.log /tmp/pha-1887-baseline.pid
base_status=$(shoot_first_request baseline "$BASELINE_PORT" /tmp/pha-1887-baseline-resp.json)
base_body=$(head -c 400 /tmp/pha-1887-baseline-resp.json)
kill "$(cat /tmp/pha-1887-baseline.pid)" 2>/dev/null || true
wait "$(cat /tmp/pha-1887-baseline.pid)" 2>/dev/null || true

run_proxy patch "$patch_worktree" "$PATCH_PORT" /tmp/pha-1887-patch.log /tmp/pha-1887-patch.pid
patch_status=$(shoot_first_request patch "$PATCH_PORT" /tmp/pha-1887-patch-resp.json)
patch_body=$(head -c 400 /tmp/pha-1887-patch-resp.json)
kill "$(cat /tmp/pha-1887-patch.pid)" 2>/dev/null || true
wait "$(cat /tmp/pha-1887-patch.pid)" 2>/dev/null || true

echo
echo "PHA-1887 sidecar A/B (recognition mock)"
printf "%-10s %-6s %s\n" "branch" "status" "first 80 chars of body"
printf "%-10s %-6s %s\n" "v1.5.5" "$base_status" "${base_body:0:120}"
printf "%-10s %-6s %s\n" "patch"  "$patch_status" "${patch_body:0:120}"
echo
if [ "$base_status" = "429" ] && [ "$patch_status" = "200" ]; then
  echo "[OK] patch passes the sidecar; v1.5.5 baseline still fails (matches the production report)."
  exit 0
else
  echo "[FAIL] unexpected sidecar result. Investigate logs /tmp/pha-1887-baseline.log and /tmp/pha-1887-patch.log."
  exit 1
fi
