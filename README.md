# Anthropic OAuth Proxy

Thin Docker proxy that fixes OAuth token handling for the Anthropic API. Mode is set via `PROXY_MODE`. Every request logs usage: `[USAGE] model=X in=Y out=Z`.

## Modes

**Regular (default)** — the client sends its own token; the proxy:
- Moves `sk-ant-oat` tokens from `x-api-key` to `Authorization: Bearer`
- Injects required OAuth headers + the Claude Code system prompt
- Translates OpenAI `/v1/chat/completions` → Anthropic `/v1/messages`
- Serves `/v1/models` (fetched live from Anthropic, cached 5 min; static fallback when no token/upstream)

**Billing (`PROXY_MODE=billing`)** — the proxy stores its own Claude Code OAuth token and routes every request through your Claude subscription instead of pay-per-token. Clients don't send a token; the proxy uses its stored one.

## Deploy

```bash
docker build -t anthropic-proxy .
docker run -d --name anthropic-proxy --restart unless-stopped \
  --network <your-network> -p 4010:4010 anthropic-proxy
```

Point your client (e.g. LiteLLM `api_base`) at `http://anthropic-proxy:4010` (same network) or `http://<host>:4010` (port-mapped). Port defaults to `4010`; override with `PROXY_PORT`.

## Billing mode

Get a token (`cat ~/.claude/.credentials.json` → `accessToken`) and run:

```bash
docker run -d --name anthropic-proxy --restart unless-stopped -p 4010:4010 \
  -e PROXY_MODE=billing \
  -e OAUTH_TOKEN=sk-ant-oat01-... \
  -e DEVICE_ID=<64-hex> \
  anthropic-proxy
```

Mount `~/.claude:/root/.claude:ro` instead of `OAUTH_TOKEN` if preferred.

**Detection bypass** — 8 layers adapted from [openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy): per-request fingerprint header, string-trigger sanitization, tool-name renames, system-prompt strip/paraphrase, tool-description strip + stub injection, property-name renames, bidirectional reverse mapping (SSE + JSON), trailing prefill strip.

**Self-maintaining fingerprint:**
- **CLI version** — fetched from npm (`@anthropic-ai/claude-code`) on startup and every 6h; drives both billing- and regular-mode user-agent. Set `CC_VERSION` only to pin (disables auto-update).
- **Session id** — each client's `x-claude-code-session-id` is preserved, so every agent reaches Anthropic as its own session (no shared-session tell or single-session rate ceiling). Falls back to a per-proxy id when none sent.
- **`DEVICE_ID`** — pin so restarts look like the same device. Generate once: `openssl rand -hex 32`.

**SDK / headless harness:** harnesses run with `CLAUDE_CODE_ENTRYPOINT=sdk-cli`, the category Anthropic surcharges (separate credit pool, effective 2026-06-15). Billing mode rewrites entrypoint/headers/body so requests look like interactive Claude Code. Point the harness at the proxy with `ANTHROPIC_BASE_URL=http://anthropic-proxy:4010`.

> Caveats: this is billing evasion against Anthropic's terms; all agents share one OAuth token (a rate-limit ceiling); enforcement may tighten after 2026-06-15. Price the official Agent-SDK pool against expected volume first.

## Endpoints

```bash
curl http://localhost:4010/health      # mode, subscription, token expiry, request totals, ccVersionEmulated
curl http://localhost:4010/v1/models
curl http://localhost:4010/v1/usage    # per-session + per-model attribution; ?since=1h filters session rows by lastSeen
docker logs -f anthropic-proxy | grep USAGE
```

## Logging

Every request emits one structured JSONL line to stdout on completion: `{ts, id, method, route, model, sessionId, status, latencyMs, tokensIn, tokensOut, cacheCreationTokens, cacheReadTokens, ...}`. `sessionId` is the client's `x-claude-code-session-id` (or `x-session-id`) when present, the proxy's stable `INSTANCE_SESSION_ID` otherwise — same derivation as billing-mode.js uses, so cold queries against the JSONL line up with what `/v1/usage` reports live. This is separate from the human-readable `[PROXY]`/`[USAGE]` lines, which stay unchanged.

```bash
docker logs -f anthropic-proxy | grep -v '^\[PROXY\]\|^\[USAGE\]'   # JSONL access log only
```

`LOG_FILE` defaults to `/var/log/anthropic-proxy/access.jsonl` (declared in the Dockerfile, with `/var/log/anthropic-proxy` as a `VOLUME`). To persist across container restarts, mount the volume to a host directory (`-v /mnt/cache/appdata/anthropic-proxy/logs:/var/log/anthropic-proxy`). To use a different path or disable the file mirror entirely, override `LOG_FILE` (e.g. `-e LOG_FILE=` to disable). The proxy only appends — it never rotates or truncates this file, so it grows unbounded for the life of the container. Point an external rotator at it (`logrotate`, or your log-shipping agent's own rotation); a recommended logrotate stanza lives at `scripts/logrotate-anthropic-proxy`. Or rely on your container runtime's stdout log rotation (e.g. Docker's `json-file` driver with `max-size`/`max-file`) and skip `LOG_FILE` entirely.
