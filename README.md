# Anthropic OAuth Proxy — Docker Container

Thin proxy that fixes OAuth token handling for Anthropic API. Two modes via `PROXY_MODE` env var.

**Regular mode (default):** client provides its own token; proxy fixes OAuth headers and translates OpenAI→Anthropic.
- Moves `sk-ant-oat` tokens from `x-api-key` to `Authorization: Bearer`
- Injects required OAuth headers + Claude Code system prompt
- Translates OpenAI `/v1/chat/completions` → Anthropic `/v1/messages`
- Serves `/v1/models` for SillyTavern model discovery

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

## Deploy on Unraid

### Option A: Build locally
```bash
cd /path/to/this/directory
docker build -t anthropic-proxy .
docker run -d \
  --name anthropic-proxy \
  --restart unless-stopped \
  --network custom \
  -p 4010:4010 \
  anthropic-proxy
```

### Option B: Unraid Community Apps (manual)
1. Go to Docker tab → Add Container
2. **Name:** `anthropic-proxy`
3. **Repository:** (use the built image or point to a registry)
4. **Network:** `custom`
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
