# Anthropic OAuth Proxy — Docker Container

Thin proxy that fixes OAuth token handling for Anthropic API.
- Moves `sk-ant-oat` tokens from `x-api-key` to `Authorization: Bearer`
- Injects required OAuth headers + Claude Code system prompt
- Translates OpenAI `/v1/chat/completions` → Anthropic `/v1/messages`
- Serves `/v1/models` for SillyTavern model discovery

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

## After Deploy

Update LiteLLM config to point Anthropic models at the container:
- **API Base:** `http://anthropic-proxy:4010` (if on same Docker network)
- Or `http://YOURIP:4010` (if using host port mapping)

## Health Check
```bash
curl http://localhost:4010/v1/models
```
Should return a JSON list of Claude models.
