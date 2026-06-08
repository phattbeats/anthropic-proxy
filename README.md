# Anthropic OAuth Proxy — Docker Container

Thin proxy that fixes OAuth token handling for Anthropic API. Two modes via `PROXY_MODE` env var.

**Regular mode (default):** client provides its own token; proxy fixes OAuth headers and translates OpenAI→Anthropic.
- Moves `sk-ant-oat` tokens from `x-api-key` to `Authorization: Bearer`
- Injects required OAuth headers + Claude Code system prompt
- Translates OpenAI `/v1/chat/completions` → Anthropic `/v1/messages`
- Serves `/v1/models` for SillyTavern model discovery — fetched **live** from Anthropic (cached 5 min) so newly released models appear automatically; falls back to a built-in static list when no token is available or upstream is unreachable

**Billing mode (`PROXY_MODE=billing`):** proxy stores its own Claude Code OAuth token and routes every request through your Claude subscription (instead of pay-per-token). Includes 8 layers of detection bypass adapted from [zacdcook/openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy):
- Billing fingerprint header injection (per-request SHA256)
- String trigger sanitization (OpenClaw, sessions_*, etc.)
- Tool name renames (29 OpenClaw tools → CC PascalCase)
- System-prompt template strip + paraphrase
- Tool description strip + CC tool-stub injection
- Property-name renames (session_id, agent_id, etc.)
- Bidirectional reverse mapping (SSE + JSON)
- Trailing assistant-prefill strip

Token usage is logged for every request: `[USAGE] model=X in=Y out=Z`.

## Deploy

### Option A: Build locally
```bash
cd /path/to/this/directory
docker build -t anthropic-proxy .
docker run -d \
  --name anthropic-proxy \
  --restart unless-stopped \
  --network <your-docker-network> \
  -p 4010:4010 \
  anthropic-proxy
```

### Option B: Container UI (manual)
1. Add a new container
2. **Name:** `anthropic-proxy`
3. **Repository:** (use the built image or point to a registry)
4. **Network:** your Docker network
5. **Port:** `4010:4010`
6. **Restart Policy:** `unless-stopped`

## Switching to Billing Mode

To route all traffic through your Claude subscription instead of API billing:

1. Get your Claude Code OAuth token: `cat ~/.claude/.credentials.json` (look for `accessToken`)
2. Add env vars to the container:
   - `PROXY_MODE=billing`
   - `OAUTH_TOKEN=sk-ant-oat01-...` (or mount `~/.claude` as volume `/root/.claude:ro`)
3. Restart the container

Clients connecting to the proxy in billing mode do **not** need to send a token — the proxy uses its stored one for everything.

### Billing-mode fingerprint env (recommended before going live)

Billing mode forges an interactive Claude Code fingerprint. Two extra env vars make that fingerprint convincing and stable. They are **only read in billing mode** (`billing-mode.js` is loaded solely when `PROXY_MODE=billing`), so setting them has **zero effect on regular mode**:

- `CC_VERSION` — the emulated CLI version. Must track the real interactive CLI version (a stale value is a weak fingerprint). Default ships current (`2.1.168`); bump via this env when the CLI updates, no code change needed.
- `DEVICE_ID` / `INSTANCE_SESSION_ID` — pin these so the proxy looks like the *same* device/session across container restarts. If unset, each restart looks like a brand-new device, which hurts fingerprint continuity. Generate once (`openssl rand -hex 32` and `uuidgen`) and keep them stable.

```bash
docker run -d --name anthropic-proxy --restart unless-stopped -p 4010:4010 \
  -e PROXY_MODE=billing \
  -e OAUTH_TOKEN=sk-ant-oat01-... \
  -e CC_VERSION=2.1.168 \
  -e DEVICE_ID=<64-hex-chars> \
  -e INSTANCE_SESSION_ID=<uuid> \
  anthropic-proxy
```

### Routing the Paperclip claude-code harness through billing mode

The harness runs agents with `CLAUDE_CODE_ENTRYPOINT=sdk-cli` — the headless category that Anthropic surcharges (separate credit pool, effective 2026-06-15). Billing mode rewrites the entrypoint/headers/body so the request reaches Anthropic looking like interactive Claude Code, neutralizing the surcharge. To cut the harness over once billing mode is live, set on the harness environment:

```bash
ANTHROPIC_BASE_URL=http://anthropic-proxy:4010
```

Caveats before flipping: this is billing evasion against Anthropic's terms; all agents share one OAuth token + session id (rate-limit ceiling and a behavioral tell — consider per-agent session ids); enforcement may tighten after 2026-06-15. Price the official Max Agent-SDK pool against expected volume first.

```bash
docker run -d \
  --name anthropic-proxy \
  --restart unless-stopped \
  -p 4010:4010 \
  -e PROXY_MODE=billing \
  -e OAUTH_TOKEN=sk-ant-oat01-... \
  anthropic-proxy
```

## After Deploy

Update LiteLLM config to point Anthropic models at the container:
- **API Base:** `http://anthropic-proxy:4010` (if on same Docker network)
- Or `http://YOURIP:4010` (if using host port mapping)

## Health Check
```bash
curl http://localhost:4010/health
curl http://localhost:4010/v1/models
```
`/health` shows mode, subscription type (in billing mode), token expiry, and request totals.

## Token Usage Logs

Every request logs to stdout:
```
[USAGE] model=claude-sonnet-4-6 in=1234 out=567 | totals: req=42 in=51200 out=23400
```
Tail with `docker logs -f anthropic-proxy | grep USAGE` for billing visibility.
