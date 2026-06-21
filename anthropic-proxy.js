#!/usr/bin/env node
// Thin proxy: fixes OAuth token handling for Anthropic API
//
// Modes (set via PROXY_MODE env var):
//   regular (default) — Client passes its own token; proxy fixes OAuth headers,
//                       injects Claude Code system prompt, and handles
//                       OpenAI ↔ Anthropic translation.
//   billing           — Proxy stores its own Claude Code OAuth token (via
//                       OAUTH_TOKEN env or ~/.claude/.credentials.json) and
//                       runs full subscription-billing evasion (8 layers of
//                       request transformation + reverse mapping). Client
//                       does not need to send a token.
//
// Both modes log token usage per request.
//
// Usage: node anthropic-proxy.js [port]

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PROXY_DIR = __dirname;
const USE_HTTPS = fs.existsSync(path.join(PROXY_DIR, 'proxy-key.pem'));

const PROXY_MODE = (process.env.PROXY_MODE || 'regular').toLowerCase();
const BILLING_MODE = PROXY_MODE === 'billing';
const billing = BILLING_MODE ? require('./billing-mode') : null;
// Stored OAuth token is optional in billing mode — if the client passes one in
// the Authorization header / x-api-key, we use that instead. Only fall back to
// stored creds when the client did not send a token.
let billingOAuthFallback = null;
if (BILLING_MODE) {
  try {
    billingOAuthFallback = billing.loadOAuthToken();
    console.log(`[PROXY] Billing mode enabled. Stored token subscription: ${billingOAuthFallback.subscriptionType}`);
  } catch (e) {
    console.log(`[PROXY] Billing mode enabled. No stored token (${e.message}); will use client-provided OAuth tokens.`);
  }
}

// Billing-mode stored-token accessor. The token loaded at boot expires in hours;
// this re-reads the credentials file when it nears expiry so the stored-token
// path survives a token rollover without a proxy restart, and writes the refresh
// back to the cache. Billing-only: billingOAuthFallback is null in regular mode,
// so this is a no-op there. Returns null when no stored token is available.
function currentStoredToken() {
  if (!billingOAuthFallback) return null;
  billingOAuthFallback = billing.refreshTokenIfStale(billingOAuthFallback);
  return billingOAuthFallback ? billingOAuthFallback.accessToken : null;
}

const PORT = parseInt(process.argv[2] || process.env.PROXY_PORT || '4010');
const TARGET = 'api.anthropic.com';
const OAUTH_PREFIX = 'sk-ant-oat';
const CLAUDE_CODE_SYSTEM = "You are Claude Code, Anthropic's official CLI for Claude.";

// --- Live Claude Code version ------------------------------------------------
// The CLI version we declare to Anthropic should track the real published Claude
// Code release rather than a hand-bumped constant that silently goes stale.
// We read the latest version from the npm registry — the same source the CLI
// itself ships from — and refresh periodically. This feeds BOTH the regular-mode
// OAuth user-agent and (via billing.setCCVersion) the billing-mode fingerprint,
// so there is one self-updating source of truth.
//
// Resolution: CC_VERSION env pins the value and disables auto-update (explicit
// ops override); otherwise the live npm version is used; otherwise the fallback.
const CC_VERSION_FALLBACK = '2.1.168';
const CC_VERSION_PINNED = !!process.env.CC_VERSION;
const CC_VERSION_LATEST_URL = 'https://registry.npmjs.org/@anthropic-ai/claude-code/latest';
const CC_VERSION_REFRESH_MS = 6 * 60 * 60 * 1000;
let liveCCVersion = process.env.CC_VERSION || CC_VERSION_FALLBACK;

function applyCCVersion(v) {
  if (!/^\d+\.\d+\.\d+$/.test(v || '') || v === liveCCVersion) return;
  liveCCVersion = v;
  if (BILLING_MODE && billing) billing.setCCVersion(v);
  console.log(`[PROXY] Claude Code version → ${v} (self-updated from npm)`);
}

function refreshCCVersion() {
  if (CC_VERSION_PINNED) return; // explicit env pin: never auto-update
  https.get(CC_VERSION_LATEST_URL, { headers: { accept: 'application/json' } }, r => {
    if (r.statusCode !== 200) { r.resume(); console.error(`[PROXY] CC version fetch: HTTP ${r.statusCode}`); return; }
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => {
      try { applyCCVersion(JSON.parse(d).version); }
      catch (e) { console.error(`[PROXY] CC version parse failed: ${e.message}`); }
    });
  }).on('error', e => console.error(`[PROXY] CC version fetch failed: ${e.message}`));
}

// Regular-mode OAuth headers. Built per-call so the user-agent tracks the live
// Claude Code version instead of a frozen string.
function oauthHeaders() {
  return {
    'anthropic-beta': 'claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14,interleaved-thinking-2025-05-14',
    'anthropic-dangerous-direct-browser-access': 'true',
    'user-agent': `claude-cli/${liveCCVersion}`,
    'x-app': 'cli',
  };
}

// Static fallback list — only used when the live Anthropic /v1/models endpoint
// can't be reached (no token available, or upstream error). The proxy prefers
// the live list so newly-released models appear automatically with no code edit.
const MODELS = [
  // Current shipping models (as of 2026-05)
  { id: 'claude-opus-4-8', name: 'Claude Opus 4.8' },
  { id: 'claude-opus-4-7', name: 'Claude Opus 4.7' },
  { id: 'claude-opus-4-6', name: 'Claude Opus 4.6' },
  { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6' },
  { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5' },
  { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet (2024-10-22)' },
  { id: 'claude-3-5-haiku-20241022', name: 'Claude 3.5 Haiku (2024-10-22)' },
  // Legacy aliases for compatibility
  { id: 'claude-opus-4-5', name: 'Claude Opus 4.5 (legacy)' },
  { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5 (legacy)' },
  { id: 'claude-haiku-3', name: 'Claude Haiku 3 (legacy)' },
];

function staticModelsList() {
  return {
    object: 'list',
    data: MODELS.map(m => ({
      id: m.id,
      object: 'model',
      created: 1700000000,
      owned_by: 'anthropic',
      display_name: m.name,
    }))
  };
}

// Cache the live model list so we don't hit Anthropic on every GET /v1/models
// (SillyTavern/LiteLLM poll this frequently). TTL is short so a freshly-released
// model shows up within a few minutes without a restart.
let modelCache = { data: null, fetchedAt: 0 };
const MODEL_CACHE_TTL_MS = 5 * 60 * 1000;

// Build the auth headers needed to call Anthropic's GET /v1/models on behalf of
// the request. Returns null when no usable token is available (the caller then
// falls back to the cached or static list).
function buildModelFetchHeaders(reqHeaders) {
  const apiKey = getApiKey(reqHeaders);
  const clientHasOAuth = apiKey.startsWith(OAUTH_PREFIX);
  if (BILLING_MODE) {
    const token = clientHasOAuth ? apiKey : currentStoredToken();
    if (!token) return null;
    const headers = billing.buildBillingHeaders(token, reqHeaders);
    delete headers['content-type'];
    return headers;
  }
  const headers = { 'anthropic-version': '2023-06-01' };
  if (clientHasOAuth) {
    headers['authorization'] = `Bearer ${apiKey}`;
    Object.assign(headers, oauthHeaders());
  } else if (apiKey) {
    headers['x-api-key'] = apiKey;
  } else {
    return null;
  }
  return headers;
}

// Fetch the live model list from Anthropic and normalize it to OpenAI shape.
// cb(err, listObject). Anthropic returns { data: [{ type, id, display_name,
// created_at }], has_more, ... } — we map id/display_name straight through so
// whatever Anthropic ships is what clients see.
function fetchUpstreamModels(authHeaders, cb) {
  const upReq = https.request({
    hostname: TARGET, port: 443, path: '/v1/models?limit=1000', method: 'GET', headers: authHeaders,
  }, upRes => {
    let chunks = [];
    upRes.on('data', c => chunks.push(c));
    upRes.on('end', () => {
      if (upRes.statusCode !== 200) {
        return cb(new Error(`upstream /v1/models returned ${upRes.statusCode}`));
      }
      try {
        const r = JSON.parse(Buffer.concat(chunks).toString());
        if (!Array.isArray(r.data)) return cb(new Error('unexpected upstream /v1/models body'));
        cb(null, {
          object: 'list',
          data: r.data.map(m => ({
            id: m.id,
            object: 'model',
            created: m.created_at ? Math.floor(new Date(m.created_at).getTime() / 1000) : 1700000000,
            owned_by: 'anthropic',
            display_name: m.display_name || m.id,
          })),
        });
      } catch (e) { cb(e); }
    });
  });
  upReq.on('error', cb);
  upReq.end();
}

// Parameters SillyTavern sends that Anthropic doesn't support — strip them
const STRIP_PARAMS = ['presence_penalty', 'frequency_penalty', 'logit_bias', 'seed', 'response_format', 'function_call', 'functions'];

// Convert OpenAI chat/completions format to Anthropic messages format
function openAIToAnthropic(body, isOAuth) {
  const payload = JSON.parse(body);

  // Strip ALL OpenAI-specific params that don't exist in Anthropic /v1/messages
  // OpenAI supports many params Anthropic doesn't: temperature, top_p, etc.
  for (const p of STRIP_PARAMS) delete payload[p];
  delete payload.temperature;    // Not supported by Anthropic messages endpoint
  delete payload.top_p;             // Not supported by Anthropic messages endpoint

  const result = {
    model: payload.model,
    max_tokens: payload.max_tokens || 4096,
    stream: payload.stream || false,
  };

  // Extract system messages
  const systemMessages = (payload.messages || []).filter(m => m.role === 'system');
  const chatMessages = (payload.messages || []).filter(m => m.role !== 'system');

  // Build system array
  const systemBlocks = [];
  if (isOAuth) {
    systemBlocks.push({ type: 'text', text: CLAUDE_CODE_SYSTEM });
  }
  for (const s of systemMessages) {
    const text = typeof s.content === 'string' ? s.content : s.content.map(c => c.text || '').join('');
    systemBlocks.push({ type: 'text', text });
  }
  if (systemBlocks.length > 0) result.system = systemBlocks;

  // Convert messages
  result.messages = chatMessages.map(m => ({
    role: m.role === 'assistant' ? 'assistant' : 'user',
    content: typeof m.content === 'string' ? m.content : m.content,
  }));

  // NOTE: temperature, top_p, presence_penalty, frequency_penalty were already stripped
  // above. Do NOT add them back — Anthropic messages endpoint rejects them.
  // stop → stop_sequences is the only valid mapping
  if (payload.stop !== undefined) result.stop_sequences = Array.isArray(payload.stop) ? payload.stop : [payload.stop];

  return JSON.stringify(result);
}

// Convert Anthropic response to OpenAI format
function anthropicToOpenAI(data, model, stream) {
  if (stream) return data; // passthrough SSE for now

  try {
    const r = JSON.parse(data);
    if (r.type === 'error') return data;

    const text = r.content?.find(b => b.type === 'text')?.text || '';
    return JSON.stringify({
      id: r.id || 'chatcmpl-proxy',
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: r.model || model,
      choices: [{
        index: 0,
        message: { role: 'assistant', content: text },
        finish_reason: r.stop_reason === 'end_turn' ? 'stop' : r.stop_reason,
      }],
      usage: {
        prompt_tokens: r.usage?.input_tokens || 0,
        completion_tokens: r.usage?.output_tokens || 0,
        total_tokens: (r.usage?.input_tokens || 0) + (r.usage?.output_tokens || 0),
      }
    });
  } catch (e) {
    return data;
  }
}

function getApiKey(headers) {
  const auth = headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return headers['x-api-key'] || '';
}

let totalReq = 0;
let totalIn = 0;
let totalOut = 0;
function logUsage(model, input, output) {
  totalReq++;
  totalIn += input || 0;
  totalOut += output || 0;
  console.log(`[USAGE] model=${model} in=${input || 0} out=${output || 0} | totals: req=${totalReq} in=${totalIn} out=${totalOut}`);
}
function logUsageFromAnthropic(raw, model) {
  try {
    const r = JSON.parse(raw);
    if (r.usage) logUsage(r.model || model, r.usage.input_tokens, r.usage.output_tokens);
  } catch (e) {}
}
// Track usage from SSE message_delta events.
function makeSSEUsageWatcher(model) {
  let buffer = '';
  let inputTokens = 0;
  let outputTokens = 0;
  let logged = false;
  return {
    feed(chunk) {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const ev = JSON.parse(line.slice(6).trim());
          if (ev.type === 'message_start' && ev.message?.usage?.input_tokens) {
            inputTokens = ev.message.usage.input_tokens;
          } else if (ev.type === 'message_delta' && ev.usage?.output_tokens) {
            outputTokens = ev.usage.output_tokens;
          }
        } catch (e) {}
      }
    },
    flush() {
      if (!logged && (inputTokens || outputTokens)) {
        logUsage(model, inputTokens, outputTokens);
        logged = true;
      }
    },
  };
}

function forwardToAnthropic(targetPath, method, headers, body, res, stream) {
  const options = {
    hostname: TARGET,
    port: 443,
    path: targetPath,
    method,
    headers,
  };

  const proxyReq = https.request(options, proxyRes => {
    if (stream) {
      // Pipe SSE directly — no buffering
      res.writeHead(proxyRes.statusCode, {
        'Content-Type': proxyRes.headers['content-type'] || 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      // Guard against upstream connection drops mid-stream — without this the
      // proxyRes 'error' event is uncaught and crashes the process.
      proxyRes.on('error', e => {
        console.error(`[PROXY] upstream SSE error: ${e.message}`);
        if (!res.headersSent) { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); }
        else if (res.writable) res.end();
      });
      proxyRes.pipe(res);
    } else {
      let chunks = [];
      proxyRes.on('data', c => chunks.push(c));
      proxyRes.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
        res.end(raw);
      });
    }
  });

  proxyReq.on('error', e => {
    console.error(`[PROXY] Error: ${e.message}`);
    if (!res.headersSent) {
      res.writeHead(502);
      res.end(JSON.stringify({ error: e.message }));
    } else if (res.writable) {
      res.end();
    }
  });

  if (body && body.length > 0) proxyReq.write(body);
  proxyReq.end();
}

const handler = (req, res) => {
  let chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks);

    // Model list endpoint — serve the LIVE Anthropic model list so newly
    // released models appear automatically. Cache briefly; fall back to the
    // static list when no token is available or upstream fails.
    if (req.url === '/v1/models' || req.url === '/v1/models/') {
      const sendList = (list, source) => {
        console.log(`[PROXY] GET /v1/models (${source}, ${list.data.length} models)`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(list));
      };

      if (modelCache.data && (Date.now() - modelCache.fetchedAt) < MODEL_CACHE_TTL_MS) {
        return sendList(modelCache.data, 'cache');
      }
      const fetchHeaders = buildModelFetchHeaders(req.headers);
      if (!fetchHeaders) {
        return sendList(modelCache.data || staticModelsList(), modelCache.data ? 'cache' : 'static-no-token');
      }
      fetchUpstreamModels(fetchHeaders, (err, list) => {
        if (err || !list) {
          console.error(`[PROXY] live model fetch failed: ${err ? err.message : 'no data'}; serving ${modelCache.data ? 'stale cache' : 'static list'}`);
          return sendList(modelCache.data || staticModelsList(), modelCache.data ? 'stale-cache' : 'static-fallback');
        }
        modelCache = { data: list, fetchedAt: Date.now() };
        sendList(list, 'live');
      });
      return;
    }

    // Health check endpoint (must be before auth so it works without a token)
    if (req.url === '/health' || req.url === '/v1/health') {
      const health = {
        status: 'ok',
        proxy: 'anthropic-oauth-proxy',
        version: '2.1',
        mode: BILLING_MODE ? 'billing' : 'regular',
        timestamp: new Date().toISOString(),
        usage: { totalReq, totalIn, totalOut },
      };
      if (BILLING_MODE) {
        health.ccVersionEmulated = billing.CC_VERSION;
        health.tokenSource = billingOAuthFallback ? 'stored+client' : 'client-only';
        if (billingOAuthFallback) {
          const expiresIn = (billingOAuthFallback.expiresAt - Date.now()) / 3600000;
          health.storedSubscription = billingOAuthFallback.subscriptionType;
          health.storedTokenExpiresInHours = isFinite(expiresIn) ? expiresIn.toFixed(1) : 'env-var';
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(health));
    }

    const apiKey = getApiKey(req.headers);
    const clientHasOAuth = apiKey.startsWith(OAUTH_PREFIX);
    const isOAuth = clientHasOAuth || BILLING_MODE;

    // Pick the OAuth token to use in billing mode: prefer client-provided,
    // fall back to proxy-stored. Returns null if neither is available.
    const billingTokenSource = BILLING_MODE
      ? (clientHasOAuth ? { accessToken: apiKey, source: 'client' }
        : (() => { const t = currentStoredToken(); return t ? { accessToken: t, source: 'stored' } : null; })())
      : null;

    // Per-agent session id (billing mode): prefer the client's own so each agent
    // is a distinct Claude Code session rather than all sharing one. Computed once
    // here and reused for the billing headers and the body metadata.
    const billingSessionId = BILLING_MODE ? billing.deriveSessionId(req.headers) : null;

    // Build outbound headers
    const headers = { 'content-type': 'application/json', 'anthropic-version': '2023-06-01' };
    if (BILLING_MODE) {
      if (!billingTokenSource) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'billing mode requires an OAuth token: send sk-ant-oat... via Authorization header, or set OAUTH_TOKEN env on the proxy' }));
      }
      Object.assign(headers, billing.buildBillingHeaders(billingTokenSource.accessToken, req.headers, billingSessionId));
    } else if (isOAuth) {
      headers['authorization'] = `Bearer ${apiKey}`;
      Object.assign(headers, oauthHeaders());
    } else {
      headers['x-api-key'] = apiKey;
    }

    // OpenAI chat completions → Anthropic messages
    if (req.url === '/v1/chat/completions') {
      console.log(`[PROXY] chat/completions → /v1/messages (mode: ${BILLING_MODE ? 'billing' : 'regular'}, OAuth: ${isOAuth})`);
      let bodyStr;
      try {
        bodyStr = openAIToAnthropic(rawBody.toString(), isOAuth);
      } catch (e) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Bad request body: ' + e.message }));
      }
      // In billing mode, run the body through the 8-layer transformer
      if (BILLING_MODE) bodyStr = billing.processBody(bodyStr, billingSessionId);
      const bodyBuf = Buffer.from(bodyStr);
      headers['content-length'] = String(bodyBuf.length);

      const reqPayload = JSON.parse(rawBody.toString());
      const model = reqPayload.model;
      const isStreaming = !!reqPayload.stream;
      const options = {
        hostname: TARGET, port: 443, path: '/v1/messages', method: 'POST', headers,
      };
      const proxyReq = https.request(options, proxyRes => {
        if (isStreaming) {
          // Stream SSE: translate Anthropic SSE → OpenAI SSE on the fly
          res.writeHead(proxyRes.statusCode, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
          });
          let buffer = '';
          let inputTokens = 0;
          let outputTokens = 0;
          // In billing mode, reverse-map each SSE event before re-parsing.
          const xform = BILLING_MODE ? billing.createSSETransformer() : null;
          const handleLines = (text) => {
            buffer += text;
            const lines = buffer.split('\n');
            buffer = lines.pop();
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6).trim();
                if (data === '[DONE]') { res.write('data: [DONE]\n\n'); continue; }
                try {
                  const ev = JSON.parse(data);
                  if (ev.type === 'message_start' && ev.message?.usage?.input_tokens) inputTokens = ev.message.usage.input_tokens;
                  if (ev.type === 'message_delta' && ev.usage?.output_tokens) outputTokens = ev.usage.output_tokens;
                  if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
                    res.write(`data: ${JSON.stringify({
                      id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: { content: ev.delta.text }, finish_reason: null }],
                    })}\n\n`);
                  } else if (ev.type === 'message_delta' && ev.delta?.stop_reason) {
                    res.write(`data: ${JSON.stringify({
                      id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: {}, finish_reason: ev.delta.stop_reason === 'end_turn' ? 'stop' : ev.delta.stop_reason }],
                    })}\n\n`);
                    res.write('data: [DONE]\n\n');
                  }
                } catch(e) {}
              } else if (line.trim()) {
                res.write(line + '\n');
              }
            }
          };
          proxyRes.on('data', chunk => {
            const text = xform ? xform.onData(chunk) : chunk.toString();
            if (text) handleLines(text);
          });
          proxyRes.on('end', () => {
            if (xform) {
              const tail = xform.onEnd();
              if (tail) handleLines(tail);
            }
            if (inputTokens || outputTokens) logUsage(model, inputTokens, outputTokens);
            res.end();
          });
          // Guard against upstream connection drops mid-stream.
          proxyRes.on('error', e => {
            console.error(`[PROXY] SSE upstream error: ${e.message}`);
            try { res.end(); } catch (_) {}
          });
        } else {
          let respChunks = [];
          proxyRes.on('data', c => respChunks.push(c));
          proxyRes.on('end', () => {
            let buf = Buffer.concat(respChunks);
            if (BILLING_MODE) buf = billing.reverseMapBuffer(buf);
            const raw = buf.toString();
            logUsageFromAnthropic(raw, model);
            const converted = anthropicToOpenAI(raw, model, false);
            res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
            res.end(converted);
          });
          proxyRes.on('error', e => {
            console.error(`[PROXY] chat/completions upstream error: ${e.message}`);
            if (!res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: e.message }));
            } else if (res.writable) res.end();
          });
        }
      });
      proxyReq.on('error', e => {
        console.error(`[PROXY] chat/completions request error: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        } else if (res.writable) res.end();
      });
      proxyReq.write(bodyBuf);
      proxyReq.end();
      return;
    }

    // Native /v1/messages passthrough with OAuth fix
    if (req.url.startsWith('/v1/messages')) {
      console.log(`[PROXY] /v1/messages passthrough (mode: ${BILLING_MODE ? 'billing' : 'regular'}, OAuth: ${isOAuth})`);
      let bodyBuf = rawBody;
      let parsed = null;
      let model = 'unknown';
      let isStream = false;

      try {
        parsed = JSON.parse(rawBody.toString());
        model = parsed?.model || model;
        isStream = !!parsed?.stream;
        // Strip params Anthropic /v1/messages doesn't accept (LiteLLM/SillyTavern often send these)
        if (parsed) {
          for (const p of STRIP_PARAMS) delete parsed[p];
          delete parsed.temperature;
          delete parsed.top_p;
        }
      } catch (e) {}

      // Cap cache_control breakpoints to Anthropic's hard max of 4, across
      // system + tools + message content (document order, keeping the first 4 —
      // the stable prefix that benefits most from caching). Mode-agnostic and
      // done BEFORE the mode split so billing mode's transform downstream also
      // operates on already-capped content. Clients like LiteLLM/openclaw can
      // emit more than 4 breakpoints, which Anthropic rejects with
      // "A maximum of 4 blocks with cache_control may be provided."
      if (parsed) {
        let cacheCount = 0;
        const stripExcessCache = (blocks) => {
          if (!Array.isArray(blocks)) return blocks;
          return blocks.map(b => {
            if (b && b.cache_control) {
              cacheCount++;
              if (cacheCount > 4) { const { cache_control, ...rest } = b; return rest; }
            }
            return b;
          });
        };
        if (Array.isArray(parsed.system)) parsed.system = stripExcessCache(parsed.system);
        if (Array.isArray(parsed.tools)) parsed.tools = stripExcessCache(parsed.tools);
        if (Array.isArray(parsed.messages)) {
          parsed.messages = parsed.messages.map(m => {
            if (Array.isArray(m.content)) m.content = stripExcessCache(m.content);
            return m;
          });
        }
        if (cacheCount > 4) console.log(`[PROXY] Capped cache_control: stripped ${cacheCount - 4} excess block(s) (max 4)`);
      }

      // Source-of-truth body string for either mode (after param strip + cache cap)
      const sourceBodyStr = parsed ? JSON.stringify(parsed) : rawBody.toString();

      if (BILLING_MODE) {
        // Billing mode: run full request transformation pipeline (8 layers)
        bodyBuf = Buffer.from(billing.processBody(sourceBodyStr, billingSessionId));
      } else if (parsed) {
        // Regular mode: inject Claude Code system prompt for OAuth + cap cache_control
        if (isOAuth) {
          if (!parsed.system || (Array.isArray(parsed.system) && parsed.system.length === 0)) {
            parsed.system = [{ type: 'text', text: CLAUDE_CODE_SYSTEM }];
          } else if (Array.isArray(parsed.system)) {
            const hasCC = parsed.system.some(b => b.text === CLAUDE_CODE_SYSTEM);
            if (!hasCC) parsed.system.unshift({ type: 'text', text: CLAUDE_CODE_SYSTEM });
          } else if (typeof parsed.system === 'string') {
            parsed.system = [{ type: 'text', text: CLAUDE_CODE_SYSTEM }, { type: 'text', text: parsed.system }];
          }
        }
        // cache_control already capped above (mode-agnostic); just serialize.
        bodyBuf = Buffer.from(JSON.stringify(parsed));
      }

      if (!isStream) headers['content-length'] = String(bodyBuf.length);

      // In billing mode we need to apply reverseMap to the response body / SSE stream.
      // In regular mode we passthrough and just log usage.
      const upstreamReq = https.request({
        hostname: TARGET, port: 443, path: '/v1/messages', method: 'POST', headers,
      }, upRes => {
        if (isStream) {
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];
          delete sseHeaders['transfer-encoding'];
          res.writeHead(upRes.statusCode, sseHeaders);
          const usageWatcher = makeSSEUsageWatcher(model);
          if (BILLING_MODE) {
            const xform = billing.createSSETransformer();
            upRes.on('data', chunk => {
              usageWatcher.feed(chunk);
              const out = xform.onData(chunk);
              if (out) res.write(out);
            });
            upRes.on('end', () => {
              const tail = xform.onEnd();
              if (tail) res.write(tail);
              usageWatcher.flush();
              res.end();
            });
          } else {
            upRes.on('data', chunk => { usageWatcher.feed(chunk); res.write(chunk); });
            upRes.on('end', () => { usageWatcher.flush(); res.end(); });
          }
          upRes.on('error', e => {
            console.error(`[PROXY] /v1/messages SSE upstream error: ${e.message}`);
            if (res.writable) res.end();
          });
        } else {
          let respChunks = [];
          upRes.on('data', c => respChunks.push(c));
          upRes.on('end', () => {
            let buf = Buffer.concat(respChunks);
            if (BILLING_MODE) buf = billing.reverseMapBuffer(buf);
            const raw = buf.toString();
            logUsageFromAnthropic(raw, model);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding'];
            nh['content-length'] = Buffer.byteLength(buf);
            res.writeHead(upRes.statusCode, nh);
            res.end(buf);
          });
          upRes.on('error', e => {
            console.error(`[PROXY] /v1/messages upstream error: ${e.message}`);
            if (!res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: e.message }));
            } else if (res.writable) res.end();
          });
        }
      });
      upstreamReq.on('error', e => {
        console.error(`[PROXY] /v1/messages request error: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        } else if (res.writable) res.end();
      });
      upstreamReq.write(bodyBuf);
      upstreamReq.end();
      return;
    }

    // Anything else — passthrough
    console.log(`[PROXY] Passthrough ${req.method} ${req.url}`);
    headers['content-length'] = String(rawBody.length);
    forwardToAnthropic(req.url, req.method, headers, rawBody, res);
  });
};

let server;
if (USE_HTTPS) {
  const sslOpts = {
    key: fs.readFileSync(path.join(PROXY_DIR, 'proxy-key.pem')),
    cert: fs.readFileSync(path.join(PROXY_DIR, 'proxy-cert.pem')),
  };
  server = require('https').createServer(sslOpts, handler);
} else {
  server = http.createServer(handler);
}

server.listen(PORT, '0.0.0.0', () => {
  const proto = USE_HTTPS ? 'https' : 'http';
  console.log(`[PROXY] Anthropic OAuth proxy v2.1 listening on :${PORT} (${proto.toUpperCase()})`);
  console.log(`[PROXY] Mode: ${BILLING_MODE ? 'BILLING (subscription routing, full evasion)' : 'REGULAR (client-provided OAuth)'}`);
  if (BILLING_MODE) {
    const src = billingOAuthFallback
      ? `stored fallback (${billingOAuthFallback.subscriptionType}) + client-provided`
      : 'client-provided only';
    console.log(`[PROXY] Token source: ${src}, emulating CC v${billing.CC_VERSION}`);
  }
  console.log(`[PROXY] Endpoints: /health, /v1/models, /v1/chat/completions, /v1/messages`);
  console.log(`[PROXY] Point SillyTavern/LiteLLM at: ${proto}://<host>:${PORT}`);
  if (CC_VERSION_PINNED) {
    console.log(`[PROXY] CC version pinned via env: ${liveCCVersion} (auto-update disabled)`);
  } else {
    console.log(`[PROXY] CC version auto-update on (npm latest, every ${CC_VERSION_REFRESH_MS / 3600000}h); starting at ${liveCCVersion}`);
    refreshCCVersion();
    setInterval(refreshCCVersion, CC_VERSION_REFRESH_MS).unref();
  }
});
