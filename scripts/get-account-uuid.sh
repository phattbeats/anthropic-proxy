#!/usr/bin/env bash
# Fetch the OAuth account_uuid that genuine Claude Code sends in metadata.user_id.
# Source of truth: Anthropic's OAuth profile endpoint (NOT ~/.claude/.credentials.json,
# and NOT the access token — that token is opaque, not a decodable JWT).
#
# Usage: scripts/get-account-uuid.sh [path-to-credentials.json]
set -euo pipefail

CREDS="${1:-$HOME/.claude/.credentials.json}"
if [[ ! -r "$CREDS" ]]; then
  echo "error: cannot read credentials file: $CREDS" >&2
  exit 1
fi

TOK="$(jq -r '.claudeAiOauth.accessToken // .accessToken // empty' "$CREDS")"
if [[ -z "$TOK" ]]; then
  echo "error: no access token found in $CREDS" >&2
  exit 1
fi

curl -sf -m 20 \
  -H "Authorization: Bearer $TOK" \
  -H "anthropic-beta: oauth-2025-04-20" \
  "https://api.anthropic.com/api/oauth/profile" \
| jq -r '.account.uuid'
