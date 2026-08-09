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
const crypto = require('crypto');
// Decoding SSE chunks with chunk.toString() corrupts any multi-byte character
// that straddles a TCP chunk boundary. StringDecoder holds the partial bytes
// until the rest arrives (PHA-1860).
const { StringDecoder } = require('string_decoder');

const PROXY_DIR = __dirname;
const USE_HTTPS = fs.existsSync(path.join(PROXY_DIR, 'proxy-key.pem'));

const PROXY_MODE = (process.env.PROXY_MODE || 'regular').toLowerCase();
const BILLING_MODE = PROXY_MODE === 'billing';
const billing = BILLING_MODE ? require('./billing-mode') : null;
// Proxy version (PHA-1387 side quest: was hardcoded '2.1'; now plumbed from release tag).
// Set PROXY_VERSION at build time (Dockerfile ENV from CI tag) or runtime.
const PROXY_VERSION = process.env.PROXY_VERSION || 'unknown';
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

// PROXY_PORT env wins over argv[2] so container/process supervisors can override
// the CLI arg without rebuilding the command line. parseInt radix is explicit
// to avoid octal/hex surprises on leading-zero ports (PHA-1844 audit, M1).
const PORT = parseInt(process.env.PROXY_PORT || process.argv[2] || '4010', 10);
const TARGET = 'api.anthropic.com';
// Idle-socket timeout for upstream Anthropic requests. Without this, a stalled
// upstream connection leaks the socket and hangs the client indefinitely.
// Generous enough for long thinking/streaming turns; override via env.
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || '600000');
// Attach an idle timeout that destroys the request on stall. The existing
// 'error' handlers turn the resulting destroy into a 502 (or clean stream end).
function attachUpstreamTimeout(req, label) {
  req.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    console.error(`[PROXY] upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms (${label})`);
    req.destroy(new Error(`upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`));
  });
}
// Per-stream idle timeout for the downstream SSE response. The upstream side
// has attachUpstreamTimeout; this is the sibling. If no chunk reaches the
// client for SSE_IDLE_TIMEOUT_MS, end the stream with an OpenAI-style error
// chunk + a single log line. Reuses the same wrap-originals pattern as the
// upstream attach*Timeout so the timeout handler can write the error chunk
// without re-arming the timer (PHA-1844 audit, H3).
// PHA-1860: default raised 60s → 180s. Extended-thinking turns can go well past
// a minute between visible deltas; a 60s ceiling turned a slow-but-healthy stream
// into a mid-generation cutoff. Anthropic's own `ping` events keep a live stream
// under this well before it fires.
const SSE_IDLE_TIMEOUT_MS = parseInt(process.env.SSE_IDLE_TIMEOUT_MS || '180000');
// `flavor` picks the shape of the terminating error frame: 'openai' (chat
// completions chunk) or 'anthropic' (native /v1/messages `event: error`). A
// client that can't parse the frame just sees a silent cutoff.
function attachStreamIdleTimeout(res, label, flavor = 'openai') {
  if (!res || res.__sseIdleAttached) return;
  res.__sseIdleAttached = true;
  let timer = null;
  const arm = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      console.error(`[PROXY] SSE stream idle for ${SSE_IDLE_TIMEOUT_MS}ms (${label}); ending with stream error chunk`);
      try {
        const msg = `stream idle timeout after ${SSE_IDLE_TIMEOUT_MS}ms`;
        const errChunk = flavor === 'anthropic'
          ? `event: error\ndata: ${JSON.stringify({
              type: 'error',
              error: { type: 'api_error', message: msg },
            })}\n\n`
          : `data: ${JSON.stringify({
              id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000), model: 'unknown',
              choices: [{ index: 0, delta: {}, finish_reason: 'error' }],
              error: { message: msg, type: 'idle_timeout', code: 'idle_timeout', param: null },
            })}\n\n`;
        // Use the saved originals so the wrapped write/end isn't re-armed by
        // this final write. The subsequent end() also clears the timer.
        try { res.__origWrite(errChunk); } catch (_) {}
        try { res.__origEnd(); } catch (_) {}
      } catch (_) {}
    }, SSE_IDLE_TIMEOUT_MS);
    if (timer.unref) timer.unref();
  };
  const origWrite = res.write.bind(res);
  const origEnd = res.end.bind(res);
  res.__origWrite = origWrite;
  res.__origEnd = origEnd;
  res.write = function(chunk, encoding, cb) {
    arm();
    return origWrite(chunk, encoding, cb);
  };
  res.end = function(chunk, encoding, cb) {
    if (timer) { clearTimeout(timer); timer = null; }
    return origEnd(chunk, encoding, cb);
  };
  res.on('close', () => { if (timer) { clearTimeout(timer); timer = null; } });
  arm();
}
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

// Hard caps on the npm-registry version fetch: a stalled or hostile response
// must not block the proxy startup or grow unbounded in memory (PHA-1844 audit, M7).
const CC_VERSION_FETCH_TIMEOUT_MS = 15000;
const CC_VERSION_FETCH_MAX_BYTES = 5 * 1024 * 1024; // 5MB — npm latest is ~1KB; 5MB is generous headroom.

function refreshCCVersion() {
  if (CC_VERSION_PINNED) return; // explicit env pin: never auto-update
  let settled = false;
  const done = (err) => { if (settled) return; settled = true; if (err) console.error(`[PROXY] CC version fetch ${err}`); };
  const req = https.get(CC_VERSION_LATEST_URL, { headers: { accept: 'application/json' } }, r => {
    if (r.statusCode !== 200) { r.resume(); done(`HTTP ${r.statusCode}`); return; }
    let total = 0;
    let d = '';
    r.on('data', c => {
      total += c.length;
      if (total > CC_VERSION_FETCH_MAX_BYTES) { req.destroy(new Error('payload too large')); done(`exceeded ${CC_VERSION_FETCH_MAX_BYTES}B`); return; }
      d += c;
    });
    r.on('end', () => {
      try { applyCCVersion(JSON.parse(d).version); }
      catch (e) { done(`parse failed: ${e.message}`); }
    });
  });
  req.setTimeout(CC_VERSION_FETCH_TIMEOUT_MS, () => { req.destroy(new Error('timeout')); done(`timeout after ${CC_VERSION_FETCH_TIMEOUT_MS}ms`); });
  req.on('error', e => done(`failed: ${e.message}`));
}

// Beta flags that EVERY outbound request to Anthropic must carry, regardless of
// PROXY_MODE. The 1h prompt-cache TTL depends on `extended-cache-ttl-2025-04-11`
// being present — without it, every cache write silently falls back to 5m and
// nothing errors. Keep this list in sync with billing-mode.js REQUIRED_BETAS
// (billing overwrites the header wholesale, so we set it explicitly here for
// the regular path).
const OAUTH_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'fine-grained-tool-streaming-2025-05-14',
  'interleaved-thinking-2025-05-14',
  'extended-cache-ttl-2025-04-11',
];
const TTL_BETA = 'extended-cache-ttl-2025-04-11';

// Regular-mode OAuth headers. Built per-call so the user-agent tracks the live
// Claude Code version instead of a frozen string.
function oauthHeaders() {
  return {
    'anthropic-beta': OAUTH_BETAS.join(','),
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
  attachUpstreamTimeout(upReq, 'GET /v1/models');
  upReq.end();
}

// Parameters SillyTavern sends that Anthropic doesn't support — strip them
const STRIP_PARAMS = ['presence_penalty', 'frequency_penalty', 'logit_bias', 'seed', 'response_format', 'function_call', 'functions'];

// Default max_tokens when the client omits it entirely. Most OpenAI-shaped
// clients (SillyTavern, etc.) don't send max_tokens, and Anthropic's own
// default of 4096 leaves long completions truncated. Anthropic rejects
// requests whose max_tokens exceeds a model's output ceiling, so any value
// used here (default or client-supplied) is clamped per-model below.
const DEFAULT_MAX_TOKENS = 32768;
const MODEL_MAX_OUTPUT_TOKENS = [
  { pattern: /^claude-opus-4/, limit: 32000 },
  { pattern: /^claude-sonnet-4/, limit: 64000 },
  { pattern: /^claude-haiku-4/, limit: 64000 },
  { pattern: /^claude-3-5-sonnet/, limit: 8192 },
  { pattern: /^claude-3-5-haiku/, limit: 8192 },
  { pattern: /^claude-haiku-3/, limit: 4096 },
];

function maxOutputTokensFor(model) {
  const entry = MODEL_MAX_OUTPUT_TOKENS.find(e => e.pattern.test(model || ''));
  return entry ? entry.limit : DEFAULT_MAX_TOKENS;
}

// OpenAI `tools: [{type:'function', function:{name, description, parameters}}]`
// → Anthropic `tools: [{name, description, input_schema}]`.
function mapOpenAITools(tools) {
  if (!Array.isArray(tools)) return undefined;
  return tools.map(t => {
    const fn = t.function || t;
    const out = {
      name: fn.name,
      description: fn.description,
      input_schema: fn.parameters || { type: 'object', properties: {} },
    };
    // Prompt caching: a client that marked the tool block for caching (either on
    // the OpenAI wrapper or on the inner function object) must keep that marker,
    // or the whole tools prefix is re-billed as fresh input on every turn.
    const cc = t.cache_control || fn.cache_control;
    if (cc) out.cache_control = cc;
    return out;
  });
}

// OpenAI `tool_choice: 'auto'|'none'|'required'|{type:'function',function:{name}}`
// → Anthropic `tool_choice: {type:'auto'|'any'|'tool', name?}`.
// Returns { tool_choice, dropTools } — 'none' has no direct Anthropic equivalent
// on older API versions, so we drop the tools array entirely to guarantee the
// model can't call one, rather than risk an unsupported tool_choice.type.
function mapOpenAIToolChoice(tool_choice) {
  if (tool_choice === undefined || tool_choice === null) return { tool_choice: undefined, dropTools: false };
  if (tool_choice === 'none') return { tool_choice: undefined, dropTools: true };
  if (tool_choice === 'auto') return { tool_choice: { type: 'auto' }, dropTools: false };
  if (tool_choice === 'required') return { tool_choice: { type: 'any' }, dropTools: false };
  if (typeof tool_choice === 'object' && tool_choice.type === 'function' && tool_choice.function?.name) {
    return { tool_choice: { type: 'tool', name: tool_choice.function.name }, dropTools: false };
  }
  return { tool_choice: undefined, dropTools: false };
}

// OpenAI message content (string or array of {type:'text'|'image_url', ...})
// → Anthropic content blocks. text → text, image_url → image (base64 / URL
// source). Anything else: log once per type and skip so a noisy client with
// many unsupported parts doesn't drown the log.
const _warnedUnsupportedContentTypes = new Set();
function mapOpenAIContentParts(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const out = [];
  for (const part of content) {
    if (!part || typeof part !== 'object') continue;
    if (part.type === 'text') {
      const block = { type: 'text', text: part.text };
      // Preserve a client-supplied cache breakpoint — rebuilding the block from
      // scratch silently dropped it, which is why nothing cached on this path.
      if (part.cache_control) block.cache_control = part.cache_control;
      out.push(block);
      continue;
    }
    if (part.type === 'image_url' && part.image_url && typeof part.image_url.url === 'string') {
      const url = part.image_url.url;
      if (url.startsWith('data:')) {
        // data:[<media_type>][;base64],<data> — the header end is the first
        // comma (the data separator); the media_type is the header before the
        // first ';' (drops ;base64, ;charset=, etc.).
        const comma = url.indexOf(',', 5);
        if (comma >= 0) {
          const header = url.slice(5, comma);
          const data = url.slice(comma + 1);
          const semi = header.indexOf(';');
          const media_type = semi >= 0 ? header.slice(0, semi) : header;
          out.push({ type: 'image', source: { type: 'base64', media_type, data } });
          continue;
        }
        // Malformed data: URL (no comma) — fall through to the unsupported-skip below.
      } else if (url.startsWith('http://') || url.startsWith('https://')) {
        // Anthropic requires the URL to be reachable from Anthropic's servers
        // (their infra fetches it). Arbitrary web URLs may time out or 403, so
        // warn — but still pass through so the client controls the request.
        console.log(`[PROXY] passing through image URL source (must be reachable from Anthropic's servers): ${url}`);
        out.push({ type: 'image', source: { type: 'url', url } });
        continue;
      }
      // image_url with unknown scheme or malformed data URL — fall through.
    }
    // Unsupported part type (or unsupported image_url variant). Log once per type.
    const t = part.type || 'unknown';
    if (!_warnedUnsupportedContentTypes.has(t)) {
      console.log(`[PROXY] ignoring unsupported OpenAI content part: ${t}`);
      _warnedUnsupportedContentTypes.add(t);
    }
  }
  return out;
}

// Find the cache breakpoint a client attached to one message. OpenAI's wire
// format has no cache_control, so clients bolt it on in one of two places: on
// the message object itself, or on one of its content parts (Anthropic's own
// convention). Accept either; the part-level marker wins as the more specific
// signal. Returns undefined when the message carries no breakpoint.
function messageCacheControl(m) {
  if (Array.isArray(m.content)) {
    const marked = m.content.find(c => c && c.cache_control);
    if (marked) return marked.cache_control;
  }
  return m.cache_control;
}

// Convert one OpenAI message into zero-or-more Anthropic messages (role +
// content blocks). `tool` role and assistant `tool_calls` need translation
// into Anthropic's tool_result / tool_use content blocks.
//
// Every branch here rebuilds blocks from scratch, so each one has to re-apply
// the client's cache breakpoint or the prefix is re-billed as fresh input.
// A message-level marker lands on the message's LAST block: cache_control
// caches everything up to and including its own block, so marking the last one
// is what "cache through the end of this turn" actually means.
function convertOpenAIMessage(m) {
  const cc = messageCacheControl(m);

  if (m.role === 'tool') {
    let inner = typeof m.content === 'string' ? m.content : mapOpenAIContentParts(m.content);
    // A marker nested inside tool_result content is invisible to capCacheControl
    // (which only walks top-level blocks) and could push the request past
    // Anthropic's max of 4. It was already hoisted onto `cc` above, so drop it
    // from the nested block and carry it on the tool_result itself.
    if (Array.isArray(inner)) {
      inner = inner.map(b => {
        if (b && b.cache_control) { const { cache_control, ...rest } = b; return rest; }
        return b;
      });
    }
    const block = { type: 'tool_result', tool_use_id: m.tool_call_id, content: inner };
    if (cc) block.cache_control = cc;
    return { role: 'user', content: [block] };
  }

  if (m.role === 'assistant' && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) {
    const blocks = [];
    if (m.content) {
      const text = typeof m.content === 'string' ? m.content : m.content.map(c => c.text || '').join('');
      if (text) blocks.push({ type: 'text', text });
    }
    for (const tc of m.tool_calls) {
      let input = {};
      try { input = tc.function?.arguments ? JSON.parse(tc.function.arguments) : {}; } catch (e) { input = {}; }
      blocks.push({ type: 'tool_use', id: tc.id, name: tc.function?.name, input });
    }
    // Anthropic accepts cache_control on a tool_use block, which is what the
    // last block is whenever the assistant turn ended in a tool call.
    if (cc && blocks.length > 0) blocks[blocks.length - 1].cache_control = cc;
    return { role: 'assistant', content: blocks };
  }

  const role = m.role === 'assistant' ? 'assistant' : 'user';
  const content = mapOpenAIContentParts(m.content);
  if (cc) {
    if (Array.isArray(content)) {
      // mapOpenAIContentParts already carried part-level markers across. Only
      // place a message-level one when none survived — a second breakpoint for
      // the same message would burn one of Anthropic's four for nothing.
      if (content.length > 0 && !content.some(b => b && b.cache_control)) {
        content[content.length - 1] = { ...content[content.length - 1], cache_control: cc };
      }
    } else if (typeof content === 'string' && content) {
      // A bare string can't hold a marker; promote it to a single text block.
      return { role, content: [{ type: 'text', text: content, cache_control: cc }] };
    }
  }
  return { role, content };
}

// Anthropic requires alternating user/assistant turns — merge consecutive
// same-role messages (e.g. several tool results in a row) into one, combining
// their content into a single content-block array.
function mergeConsecutiveRoles(messages) {
  const merged = [];
  for (const m of messages) {
    const prev = merged[merged.length - 1];
    if (prev && prev.role === m.role) {
      const prevBlocks = Array.isArray(prev.content) ? prev.content : [{ type: 'text', text: prev.content }];
      const curBlocks = Array.isArray(m.content) ? m.content : [{ type: 'text', text: m.content }];
      prev.content = prevBlocks.concat(curBlocks);
    } else {
      merged.push({ role: m.role, content: m.content });
    }
  }
  return merged;
}

// Convert OpenAI chat/completions format to Anthropic messages format
function openAIToAnthropic(body, isOAuth) {
  const payload = JSON.parse(body);

  // Strip OpenAI-only params that don't exist in Anthropic /v1/messages
  for (const p of STRIP_PARAMS) delete payload[p];

  const result = {
    model: payload.model,
    max_tokens: Math.min(payload.max_tokens || DEFAULT_MAX_TOKENS, maxOutputTokensFor(payload.model)),
    stream: payload.stream || false,
  };
  // temperature and top_p ARE supported by Anthropic /v1/messages — pass through.
  if (payload.temperature !== undefined) result.temperature = payload.temperature;
  if (payload.top_p !== undefined) result.top_p = payload.top_p;

  // Extract system messages
  const systemMessages = (payload.messages || []).filter(m => m.role === 'system');
  const chatMessages = (payload.messages || []).filter(m => m.role !== 'system');

  // Build system array
  const systemBlocks = [];
  if (isOAuth) {
    systemBlocks.push({ type: 'text', text: CLAUDE_CODE_SYSTEM });
  }
  // The system prompt is the single highest-value cache breakpoint, so keep the
  // client's part boundaries instead of joining them. Clients deliberately split
  // it into a stable prefix (marked) and a per-request dynamic suffix (unmarked)
  // — OpenClaw does exactly this at its OPENCLAW_CACHE_BOUNDARY. Joining them put
  // the breakpoint *after* the volatile half, so the largest block in the request
  // changed every turn and never hit cache.
  for (const s of systemMessages) {
    const parts = typeof s.content === 'string'
      ? [{ text: s.content }]
      : (Array.isArray(s.content) ? s.content.filter(c => c && typeof c.text === 'string') : []);
    const blocks = [];
    for (const p of parts) {
      if (!p.text) continue; // an empty text block is rejected by Anthropic
      const block = { type: 'text', text: p.text };
      if (p.cache_control) block.cache_control = p.cache_control;
      blocks.push(block);
    }
    if (blocks.length === 0) continue;
    // A marker on the message itself covers the whole message, so it lands on the
    // last block — but only when no part carried its own, more specific one.
    if (s.cache_control && !blocks.some(b => b.cache_control)) {
      blocks[blocks.length - 1].cache_control = s.cache_control;
    }
    systemBlocks.push(...blocks);
  }
  if (systemBlocks.length > 0) result.system = systemBlocks;

  // Convert messages (tool calls/results → tool_use/tool_result blocks),
  // then merge consecutive same-role turns since Anthropic requires alternation.
  result.messages = mergeConsecutiveRoles(chatMessages.map(convertOpenAIMessage));

  // tools/tool_choice
  const { tool_choice, dropTools } = mapOpenAIToolChoice(payload.tool_choice);
  if (Array.isArray(payload.tools) && payload.tools.length > 0 && !dropTools) {
    result.tools = mapOpenAITools(payload.tools);
    if (tool_choice) result.tool_choice = tool_choice;
  }

  // NOTE: presence_penalty, frequency_penalty, etc. were already stripped above —
  // those have no Anthropic equivalent. stop → stop_sequences is the only mapping left.
  if (payload.stop !== undefined) result.stop_sequences = Array.isArray(payload.stop) ? payload.stop : [payload.stop];

  return JSON.stringify(result);
}

// Cap cache_control breakpoints to Anthropic's hard max of 4, across
// system + tools + message content (document order, keeping the first 4 —
// the stable prefix that benefits most from caching). Clients like LiteLLM/
// openclaw can emit more than 4 breakpoints, which Anthropic rejects with
// "A maximum of 4 blocks with cache_control may be provided."
// Mutates and returns `parsed` (an Anthropic /v1/messages body); null-safe.
function capCacheControl(parsed) {
  if (!parsed) return parsed;
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
  return parsed;
}

// Anthropic stop_reason → OpenAI finish_reason
function mapStopReason(stop_reason) {
  if (stop_reason === 'end_turn' || stop_reason === 'stop_sequence') return 'stop';
  if (stop_reason === 'tool_use') return 'tool_calls';
  if (stop_reason === 'max_tokens') return 'length';
  return stop_reason;
}

// Anthropic error → OpenAI error shape. OpenAI clients (LiteLLM, openclaw)
// parse {"error":{message,type,code}}; passing Anthropic's
// {"type":"error","error":{...}} through verbatim makes them misclassify
// upstream overload/5xx as billing/auth failures. Keep the original
// Anthropic type in `code` for debuggability.
const ANTHROPIC_TO_OPENAI_ERROR_TYPE = {
  invalid_request_error: 'invalid_request_error',
  authentication_error: 'authentication_error',
  permission_error: 'permission_error',
  not_found_error: 'invalid_request_error',
  request_too_large: 'invalid_request_error',
  rate_limit_error: 'rate_limit_error',
  api_error: 'server_error',
  overloaded_error: 'server_error',
};
function anthropicErrorToOpenAI(r) {
  const at = r.error?.type || 'api_error';
  return JSON.stringify({
    error: {
      message: r.error?.message || 'upstream error',
      type: ANTHROPIC_TO_OPENAI_ERROR_TYPE[at] || 'server_error',
      code: at,
      param: null,
    },
  });
}

// Convert Anthropic response to OpenAI format
function anthropicToOpenAI(data, model, stream) {
  if (stream) return data; // passthrough SSE for now

  try {
    const r = JSON.parse(data);
    if (r.type === 'error') return anthropicErrorToOpenAI(r);

    const blocks = r.content || [];
    const text = blocks.filter(b => b.type === 'text').map(b => b.text).join('');
    const toolUseBlocks = blocks.filter(b => b.type === 'tool_use');
    const message = { role: 'assistant', content: text || null };
    if (toolUseBlocks.length > 0) {
      message.tool_calls = toolUseBlocks.map(b => ({
        id: b.id,
        type: 'function',
        function: { name: b.name, arguments: JSON.stringify(b.input || {}) },
      }));
    }

    return JSON.stringify({
      id: r.id || 'chatcmpl-proxy',
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: r.model || model,
      choices: [{
        index: 0,
        message,
        finish_reason: mapStopReason(r.stop_reason),
      }],
      usage: openAIUsage(extractUsage(r.usage)),
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

// --- Usage extraction --------------------------------------------------------
// Anthropic's input_tokens EXCLUDES cache_creation_input_tokens and
// cache_read_input_tokens. Normalizing here is the only way the console log, the
// JSONL access log and the OpenAI usage surface can agree on real prompt size.
const EMPTY_USAGE = { input: 0, output: 0, cacheCreate: 0, cacheRead: 0, cache5m: 0, cache1h: 0 };
function extractUsage(u) {
  if (!u || typeof u !== 'object') return { ...EMPTY_USAGE };
  const c = u.cache_creation || {};
  return {
    input: u.input_tokens || 0,
    output: u.output_tokens || 0,
    cacheCreate: u.cache_creation_input_tokens || 0,
    cacheRead: u.cache_read_input_tokens || 0,
    cache5m: c.ephemeral_5m_input_tokens || 0,
    cache1h: c.ephemeral_1h_input_tokens || 0,
  };
}
// Merge a later usage object over an earlier one (message_start -> message_delta).
// A field only wins if the newer event reports it: message_delta omits the cache
// fields, and must not zero out what message_start gave us.
function mergeUsage(a, b) {
  const out = { ...a };
  for (const k of Object.keys(EMPTY_USAGE)) if (b[k]) out[k] = b[k];
  return out;
}
// OpenAI semantics: cached tokens are a SUBSET of prompt_tokens.
function openAIUsage(u) {
  const prompt = u.input + u.cacheRead + u.cacheCreate;
  return {
    prompt_tokens: prompt,
    completion_tokens: u.output,
    total_tokens: prompt + u.output,
    prompt_tokens_details: { cached_tokens: u.cacheRead },
    cache_creation_input_tokens: u.cacheCreate,
    cache_read_input_tokens: u.cacheRead,
  };
}

let totalReq = 0;
let totalIn = 0;
let totalOut = 0;
let totalCacheCreate = 0;
let totalCacheRead = 0;
function logUsage(model, u) {
  const usage = u || EMPTY_USAGE;
  totalReq++;
  totalIn += usage.input || 0;
  totalOut += usage.output || 0;
  totalCacheCreate += usage.cacheCreate || 0;
  totalCacheRead += usage.cacheRead || 0;
  // Only spell out the 5m/1h split when upstream actually reported one — most
  // responses report neither, and a permanent "(5m=0 1h=0)" is pure noise.
  const ttl = [];
  if (usage.cache5m) ttl.push(`5m=${usage.cache5m}`);
  if (usage.cache1h) ttl.push(`1h=${usage.cache1h}`);
  const ttlStr = ttl.length ? ` (${ttl.join(' ')})` : '';
  console.log(`[USAGE] model=${model} in=${usage.input || 0} out=${usage.output || 0} cache_write=${usage.cacheCreate || 0}${ttlStr} cache_read=${usage.cacheRead || 0} | totals: req=${totalReq} in=${totalIn} out=${totalOut} cache_write=${totalCacheCreate} cache_read=${totalCacheRead}`);
}
// Pull the Anthropic error type out of a JSON error body so the structured
// access log can record WHY a request returned 0 tokens (e.g. rate_limit_error
// has no usage field — that's normal, not a logging bug). Tolerant of
// malformed bodies and billing-mode reverse-mapped output.
function extractAnthropicErrorType(raw) {
  if (!raw || typeof raw !== 'string') return null;
  // Trim a possible SSE prefix in case the body leaked through the streaming path.
  const trimmed = raw.replace(/^data:\s*/, '').trim();
  if (!trimmed.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed.error === 'object' && typeof parsed.error.type === 'string') {
      return parsed.error.type;
    }
  } catch (_) {}
  return null;
}

// Returns a normalized usage object when usage was present, else null — callers
// use this to feed the per-request structured access log without re-parsing.
function logUsageFromAnthropic(raw, model) {
  try {
    const r = JSON.parse(raw);
    if (r.usage) {
      const u = extractUsage(r.usage);
      logUsage(r.model || model, u);
      return u;
    }
  } catch (e) {}
  return null;
}
// Track usage from SSE message_start / message_delta events. The cache counters
// only ever arrive on message_start, so the two events must be merged, not
// replaced, or the cache numbers are lost by the time the stream ends.
function makeSSEUsageWatcher(model) {
  let buffer = '';
  let usage = { ...EMPTY_USAGE };
  let logged = false;
  const decoder = new StringDecoder('utf8');
  return {
    feed(chunk) {
      buffer += decoder.write(chunk);
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const ev = JSON.parse(line.slice(6).trim());
          if (ev.type === 'message_start' && ev.message?.usage) {
            usage = mergeUsage(usage, extractUsage(ev.message.usage));
          } else if (ev.type === 'message_delta' && ev.usage) {
            usage = mergeUsage(usage, extractUsage(ev.usage));
          }
        } catch (e) {}
      }
    },
    flush() {
      if (!logged && (usage.input || usage.output || usage.cacheCreate || usage.cacheRead)) {
        logUsage(model, usage);
        logged = true;
      }
    },
    get() { return usage; },
  };
}

// --- Structured per-request JSONL access log ---------------------------------
// One JSON line per completed request: request id, route, model, status,
// latency, tokens. Always written to stdout; optionally mirrored to LOG_FILE
// for log shipping / offline analysis. This is separate from the human-
// readable [PROXY]/[USAGE] console lines above, which stay as-is.
const LOG_FILE = process.env.LOG_FILE || null;
let logFileStream = null;
if (LOG_FILE) {
  logFileStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });
  logFileStream.on('error', e => console.error(`[PROXY] LOG_FILE write error: ${e.message}`));
  // Node never rotates this file itself — it grows unbounded for as long as
  // the process runs. Point an external rotator (logrotate, Docker's own
  // json-file/local log-driver rotation, etc.) at LOG_FILE, or pipe stdout
  // instead of setting LOG_FILE if the platform already rotates stdout.
  console.log(`[PROXY] Structured JSONL access log mirrored to LOG_FILE=${LOG_FILE} (grows unbounded — set up external rotation, e.g. logrotate)`);
}

function logAccess(entry) {
  const line = JSON.stringify(entry);
  console.log(line);
  if (logFileStream) logFileStream.write(line + '\n');
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
      attachStreamIdleTimeout(res, `${method} ${targetPath}`);
      // Guard against upstream connection drops mid-stream — without this the
      // proxyRes 'error' event is uncaught and crashes the process.
      proxyRes.on('error', e => {
        console.error(`[PROXY] upstream SSE error: ${e.message}`);
        if (!res.headersSent) { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); }
        else if (res.writable) res.end();
      });
      // Node's pipe() handles backpressure correctly (pauses source when the
      // sink's write() returns false, resumes on 'drain') so we don't need to
      // wire pause/resume by hand here — only the idle timeout.
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

  attachUpstreamTimeout(proxyReq, `${method} ${targetPath}`);
  if (body && body.length > 0) proxyReq.write(body);
  proxyReq.end();
}

const handler = (req, res) => {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const routePath = (req.url || '').split('?')[0];
  // Populated as each route learns the model / token usage; read at 'finish'
  // so every route (including early returns, errors, passthrough) logs.
  let logModel = null;
  let logUsageAcc = { ...EMPTY_USAGE };
  // Set when the upstream returned a non-2xx and the JSON body carried an
  // Anthropic error.type — distinguishes "0 tokens because upstream 429" (no
  // usage field on rate-limit errors) from "0 tokens because logging bug".
  let logErrorType = null;
  res.on('finish', () => {
    const entry = {
      ts: new Date().toISOString(),
      id: requestId,
      method: req.method,
      route: routePath,
      model: logModel,
      status: res.statusCode,
      latencyMs: Date.now() - startTime,
      tokensIn: logUsageAcc.input,
      tokensOut: logUsageAcc.output,
      cacheCreationTokens: logUsageAcc.cacheCreate,
      cacheReadTokens: logUsageAcc.cacheRead,
      cacheCreation5m: logUsageAcc.cache5m,
      cacheCreation1h: logUsageAcc.cache1h,
    };
    if (logErrorType) entry.errorType = logErrorType;
    logAccess(entry);
  });

  // Hard cap on inbound request body. Without this a single client can POST
  // unbounded data and exhaust proxy memory before any per-route logic runs
  // (PHA-1844 audit, H2). 64MB is well above any realistic Claude request and
  // comfortably accommodates multi-megapixel image attachments.
  const MAX_BODY_BYTES = 64 * 1024 * 1024;
  let bodyBytes = 0;
  let bodyTooLarge = false;
  let chunks = [];
  req.on('data', c => {
    if (bodyTooLarge) { c; return; }
    bodyBytes += c.length;
    if (bodyBytes > MAX_BODY_BYTES) {
      bodyTooLarge = true;
      chunks = []; // drop what we already buffered; nothing valid to parse
      if (!res.headersSent) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Request body exceeds ${MAX_BODY_BYTES} bytes (MAX_BODY_BYTES)` }));
      }
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (bodyTooLarge) return; // already responded 413 above
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
        version: PROXY_VERSION,
        mode: BILLING_MODE ? 'billing' : 'regular',
        timestamp: new Date().toISOString(),
        usage: { totalReq, totalIn, totalOut, totalCacheCreate, totalCacheRead },
      };
      if (BILLING_MODE) {
        health.ccVersionEmulated = billing.CC_VERSION;
        health.accountUuidConfigured = billing.accountUuidConfigured;
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

    // Readiness endpoint — actively probes upstream Anthropic so an orchestrator
    // can keep a half-broken pod out of the LB rotation. Returns 503 when the
    // upstream is unreachable, with the failure reason in the body. Bounded by
    // READINESS_TIMEOUT_MS (default 3s) so this never blocks longer than the
    // healthcheck period (PHA-1844 audit, L2).
    if (req.url === '/ready' || req.url === '/v1/ready') {
      const readyTimeoutMs = parseInt(process.env.READINESS_TIMEOUT_MS || '3000', 10);
      const startedAt = Date.now();
      let settled = false;
      const finish = (status, payload) => {
        if (settled) return; settled = true;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      const timer = setTimeout(() => finish(503, {
        ready: false, reason: 'upstream-probe-timeout',
        elapsedMs: Date.now() - startedAt, timeoutMs: readyTimeoutMs,
      }), readyTimeoutMs);
      timer.unref && timer.unref();
      const readyReq = https.request({
        hostname: TARGET, port: 443, path: '/v1/models', method: 'GET',
        headers: { 'anthropic-version': '2023-06-01', accept: 'application/json' },
      }, r => {
        // Any 2xx/3xx/4xx response means the upstream is reachable; only a
        // network failure (handled below) or our timeout counts as not-ready.
        r.resume();
        finish(200, { ready: true, upstreamStatus: r.statusCode, elapsedMs: Date.now() - startedAt });
      });
      readyReq.on('error', e => finish(503, { ready: false, reason: e.message, elapsedMs: Date.now() - startedAt }));
      readyReq.end();
      return;
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
        // Now that translation preserves client cache_control, this path can also
        // exceed Anthropic's 4-breakpoint max — cap it exactly like /v1/messages.
        bodyStr = JSON.stringify(capCacheControl(JSON.parse(bodyStr)));
      } catch (e) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Bad request body: ' + e.message }));
      }
      // In billing mode, run the body through the transformer, then derive the
      // billing header from the processed body (PHA-1842: this used to be injected
      // as system[0] in the body, which broke prompt-cache prefix matching on every
      // request — it now goes out as a real header, leaving the body byte-stable).
      if (BILLING_MODE) {
        bodyStr = billing.processBody(bodyStr, billingSessionId);
        headers['x-anthropic-billing-header'] = billing.buildBillingHeaderValue(bodyStr, billingSessionId);
      }
      const bodyBuf = Buffer.from(bodyStr);
      headers['content-length'] = String(bodyBuf.length);

      const reqPayload = JSON.parse(rawBody.toString());
      const model = reqPayload.model;
      logModel = model;
      const isStreaming = !!reqPayload.stream;
      const options = {
        // Genuine CC 2.1.205 posts to /v1/messages?beta=true (openclaw PR #61).
        hostname: TARGET, port: 443,
        path: BILLING_MODE ? '/v1/messages?beta=true' : '/v1/messages',
        method: 'POST', headers,
      };
      const proxyReq = https.request(options, proxyRes => {
        // Track upstream request-id to chain the next request's cc_prev_req header.
        if (BILLING_MODE) billing.setLastRequestId(proxyRes.headers['request-id'] || proxyRes.headers['anthropic-request-id'], billingSessionId);
        // Upstream rejected the request (overloaded/rate-limit/auth) — the body
        // is a JSON error, not SSE, even when the client asked for streaming.
        // Relay it as an OpenAI-shape JSON error with the real status so
        // clients classify it correctly instead of seeing a garbled stream.
        if (proxyRes.statusCode !== 200) {
          let errChunks = [];
          proxyRes.on('data', c => errChunks.push(c));
          proxyRes.on('end', () => {
            let buf = Buffer.concat(errChunks);
            if (BILLING_MODE) buf = billing.reverseMapBuffer(buf);
            const raw = buf.toString();
            logErrorType = extractAnthropicErrorType(raw) || `upstream_${proxyRes.statusCode}`;
            let body;
            try { body = anthropicErrorToOpenAI(JSON.parse(raw)); }
            catch (e) { body = JSON.stringify({ error: { message: raw || `upstream returned ${proxyRes.statusCode}`, type: 'server_error', code: null, param: null } }); }
            console.error(`[PROXY] chat/completions upstream ${proxyRes.statusCode}: ${body}`);
            const eh = { 'Content-Type': 'application/json' };
            if (proxyRes.headers['retry-after']) eh['Retry-After'] = proxyRes.headers['retry-after'];
            res.writeHead(proxyRes.statusCode, eh);
            res.end(body);
          });
          proxyRes.on('error', () => { try { res.end(); } catch (_) {} });
          return;
        }
        if (isStreaming) {
          // Stream SSE: translate Anthropic SSE → OpenAI SSE on the fly
          res.writeHead(proxyRes.statusCode, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
          });
          attachStreamIdleTimeout(res, 'POST /v1/messages (chat/completions) SSE');
          // H3 (PHA-1844): honor backpressure. Every res.write() below is routed
          // through `sseWrite`; when the kernel buffer is saturated it returns
          // false and we pause proxyRes until the downstream emits 'drain'.
          // Without this, a slow client caused unbounded proxy-side buffering
          // (and memory growth) per connection.
          let upstreamPaused = false;
          const sseWrite = (chunk) => {
            const ok = res.write(chunk);
            if (ok === false && !upstreamPaused) {
              upstreamPaused = true;
              proxyRes.pause();
            }
            return ok;
          };
          res.on('drain', () => {
            if (upstreamPaused) { upstreamPaused = false; proxyRes.resume(); }
          });
          let buffer = '';
          let usage = { ...EMPTY_USAGE };
          let chatId = 'chatcmpl-proxy';
          let sentRole = false;
          const includeUsage = !!reqPayload.stream_options?.include_usage;
          // Anthropic content-block index → OpenAI tool_calls array index, so
          // interleaved tool_use blocks map to stable, incrementing tool_calls[].index.
          const toolCallIndexByBlock = {};
          let nextToolCallIndex = 0;
          // In billing mode, reverse-map each SSE event before re-parsing.
          const xform = BILLING_MODE ? billing.createSSETransformer() : null;
          const rawDecoder = xform ? null : new StringDecoder('utf8');
          const handleLines = (text) => {
            buffer += text;
            const lines = buffer.split('\n');
            buffer = lines.pop();
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6).trim();
                if (data === '[DONE]') { sseWrite('data: [DONE]\n\n'); continue; }
                try {
                  const ev = JSON.parse(data);
                  if (ev.type === 'error') {
                    // Mid-stream upstream error (e.g. overloaded_error during an
                    // incident). Dropping it makes the reply look like a silent
                    // cutoff; surface it as an OpenAI-style stream error chunk.
                    console.error(`[PROXY] chat/completions mid-stream error: ${data}`);
                    sseWrite(`data: ${anthropicErrorToOpenAI(ev)}\n\n`);
                    sseWrite('data: [DONE]\n\n');
                    continue;
                  }
                  if (ev.type === 'message_start') {
                    if (ev.message?.id) chatId = ev.message.id;
                    if (ev.message?.usage) usage = mergeUsage(usage, extractUsage(ev.message.usage));
                    if (!sentRole) {
                      sentRole = true;
                      // OpenAI emits an initial chunk carrying only the role delta before any content.
                      sseWrite(`data: ${JSON.stringify({
                        id: chatId, object: 'chat.completion.chunk',
                        created: Math.floor(Date.now()/1000), model,
                        choices: [{ index: 0, delta: { role: 'assistant', content: '' }, finish_reason: null }],
                      })}\n\n`);
                    }
                  }
                  if (ev.type === 'message_delta' && ev.usage) usage = mergeUsage(usage, extractUsage(ev.usage));
                  if (ev.type === 'content_block_start' && ev.content_block?.type === 'tool_use') {
                    const idx = nextToolCallIndex++;
                    toolCallIndexByBlock[ev.index] = idx;
                    sseWrite(`data: ${JSON.stringify({
                      id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: { tool_calls: [{ index: idx, id: ev.content_block.id, type: 'function', function: { name: ev.content_block.name, arguments: '' } }] }, finish_reason: null }],
                    })}\n\n`);
                  } else if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
                    sseWrite(`data: ${JSON.stringify({
                      id: chatId, object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: { content: ev.delta.text }, finish_reason: null }],
                    })}\n\n`);
                  } else if (ev.type === 'content_block_delta' && ev.delta?.type === 'input_json_delta') {
                    const idx = toolCallIndexByBlock[ev.index];
                    if (idx !== undefined) {
                      sseWrite(`data: ${JSON.stringify({
                        id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                        created: Math.floor(Date.now()/1000), model,
                        choices: [{ index: 0, delta: { tool_calls: [{ index: idx, function: { arguments: ev.delta.partial_json || '' } }] }, finish_reason: null }],
                      })}\n\n`);
                    }
                  } else if (ev.type === 'message_delta' && ev.delta?.stop_reason) {
                    sseWrite(`data: ${JSON.stringify({
                      id: chatId, object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: {}, finish_reason: mapStopReason(ev.delta.stop_reason) }],
                    })}\n\n`);
                    // OpenAI's stream_options.include_usage sends one extra chunk with
                    // an empty choices array carrying final token usage before [DONE].
                    if (includeUsage) {
                      sseWrite(`data: ${JSON.stringify({
                        id: chatId, object: 'chat.completion.chunk',
                        created: Math.floor(Date.now()/1000), model,
                        choices: [],
                        usage: openAIUsage(usage),
                      })}\n\n`);
                    }
                    sseWrite('data: [DONE]\n\n');
                  }
                } catch(e) {}
              } else if (line.trim()) {
                sseWrite(line + '\n');
              }
            }
          };
          proxyRes.on('data', chunk => {
            const text = xform ? xform.onData(chunk) : rawDecoder.write(chunk);
            if (text) handleLines(text);
          });
          proxyRes.on('end', () => {
            const tail = xform ? xform.onEnd() : rawDecoder.end();
            if (tail) handleLines(tail);
            if (usage.input || usage.output || usage.cacheCreate || usage.cacheRead) logUsage(model, usage);
            logUsageAcc = usage;
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
            const u = logUsageFromAnthropic(raw, model);
            if (u) logUsageAcc = u;
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
      attachUpstreamTimeout(proxyReq, 'POST /v1/messages (chat/completions)');
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
        logModel = model;
        isStream = !!parsed?.stream;
        // Strip OpenAI-only params Anthropic /v1/messages doesn't accept (LiteLLM/
        // SillyTavern often send these even on the native endpoint). temperature and
        // top_p ARE valid /v1/messages params, so they're left untouched — pass through.
        if (parsed) {
          for (const p of STRIP_PARAMS) delete parsed[p];
        }
      } catch (e) {}

      // Mode-agnostic and done BEFORE the mode split so billing mode's transform
      // downstream also operates on already-capped content.
      capCacheControl(parsed);

      // Source-of-truth body string for either mode (after param strip + cache cap)
      const sourceBodyStr = parsed ? JSON.stringify(parsed) : rawBody.toString();

      if (BILLING_MODE) {
        // Billing mode: run full request transformation pipeline, then derive the
        // billing header from the processed body (PHA-1842: as a real header, not
        // body block, so system/message cache_control prefixes stay byte-stable).
        const billingProcessedStr = billing.processBody(sourceBodyStr, billingSessionId);
        headers['x-anthropic-billing-header'] = billing.buildBillingHeaderValue(billingProcessedStr, billingSessionId);
        bodyBuf = Buffer.from(billingProcessedStr);
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
        // Genuine CC 2.1.205 posts to /v1/messages?beta=true (openclaw PR #61).
        hostname: TARGET, port: 443,
        path: BILLING_MODE ? '/v1/messages?beta=true' : '/v1/messages',
        method: 'POST', headers,
      }, upRes => {
        if (BILLING_MODE) billing.setLastRequestId(upRes.headers['request-id'] || upRes.headers['anthropic-request-id'], billingSessionId);
        if (isStream) {
          // PHA-1860: REVERTS PHA-1850 (M5) on this path. M5 buffered the entire
          // upstream SSE reply so it could send a real Content-Length instead of
          // implicit chunked. That framing is client-facing only — Anthropic never
          // sees our RESPONSE framing, so it carried no anti-fingerprint value —
          // while it did destroy incremental delivery: clients (LiteLLM, Claude
          // Code) got zero bytes until the turn completed. Long turns tripped
          // client-side stream timeouts, which put the deployment into LiteLLM
          // cooldown and surfaced as immediate 429s, and killed streams mid-reply.
          // Relay incrementally again, with backpressure + the per-stream idle
          // timeout (H3, PHA-1844a) that M5 had also dropped here.
          const usageWatcher = makeSSEUsageWatcher(model);
          // Non-2xx upstream replies to a stream request are a single JSON error
          // body, not SSE. Buffer those so the error type reaches the access log
          // and the client gets a well-framed JSON error (same shape as the
          // chat/completions path).
          if (upRes.statusCode >= 400) {
            const errChunks = [];
            upRes.on('data', c => errChunks.push(c));
            upRes.on('end', () => {
              let buf = Buffer.concat(errChunks);
              if (BILLING_MODE) buf = billing.reverseMapBuffer(buf);
              logErrorType = extractAnthropicErrorType(buf.toString()) || `upstream_${upRes.statusCode}`;
              const eh = { ...upRes.headers };
              delete eh['transfer-encoding'];
              eh['content-length'] = String(buf.length);
              res.writeHead(upRes.statusCode, eh);
              res.end(buf);
            });
            upRes.on('error', e => {
              console.error(`[PROXY] /v1/messages SSE upstream error: ${e.message}`);
              if (!res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: e.message }));
              } else if (res.writable) res.end();
            });
            return;
          }
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];
          delete sseHeaders['transfer-encoding'];
          res.writeHead(upRes.statusCode, sseHeaders);
          attachStreamIdleTimeout(res, 'POST /v1/messages SSE', 'anthropic');
          // Honor downstream backpressure: pause upstream when the kernel buffer
          // saturates, resume on 'drain'. Bounds per-connection memory on slow
          // clients without reintroducing full-reply buffering.
          let upstreamPaused = false;
          const sseWrite = (chunk) => {
            const ok = res.write(chunk);
            if (ok === false && !upstreamPaused) { upstreamPaused = true; upRes.pause(); }
            return ok;
          };
          res.on('drain', () => {
            if (upstreamPaused) { upstreamPaused = false; upRes.resume(); }
          });
          const finishStream = () => {
            usageWatcher.flush();
            logUsageAcc = usageWatcher.get();
            try { res.end(); } catch (_) {}
          };
          if (BILLING_MODE) {
            // Guard against createSSETransformer returning a bad value (a botched
            // build once shipped a body-less wrapper that returned undefined and
            // crash-looped the whole proxy — see PHA-1391). If the transformer is
            // unusable, degrade to raw passthrough rather than taking the process down.
            let xform = billing.createSSETransformer();
            if (!xform || typeof xform.onData !== 'function') {
              console.error('[PROXY] createSSETransformer returned invalid transformer; passing SSE through unmapped');
              xform = null;
            }
            const rawDecoder = xform ? null : new StringDecoder('utf8');
            upRes.on('data', chunk => {
              usageWatcher.feed(chunk);
              const out = xform ? xform.onData(chunk) : rawDecoder.write(chunk);
              if (out) sseWrite(out);
            });
            upRes.on('end', () => {
              const tail = xform ? xform.onEnd() : rawDecoder.end();
              if (tail) sseWrite(tail);
              finishStream();
            });
          } else {
            upRes.on('data', chunk => { usageWatcher.feed(chunk); sseWrite(chunk); });
            upRes.on('end', () => { finishStream(); });
          }
          upRes.on('error', e => {
            console.error(`[PROXY] /v1/messages SSE upstream error: ${e.message}`);
            if (!res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: e.message }));
            } else if (res.writable) res.end();
          });
        } else {
          let respChunks = [];
          upRes.on('data', c => respChunks.push(c));
          upRes.on('end', () => {
            let buf = Buffer.concat(respChunks);
            if (BILLING_MODE) buf = billing.reverseMapBuffer(buf);
            const raw = buf.toString();
            const u = logUsageFromAnthropic(raw, model);
            if (u) logUsageAcc = u;
            if (upRes.statusCode >= 400) {
              logErrorType = extractAnthropicErrorType(raw) || `upstream_${upRes.statusCode}`;
            }
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
      attachUpstreamTimeout(upstreamReq, 'POST /v1/messages');
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

// Last-resort crash guard. A throw inside a stream 'data'/'end' callback is not
// caught by any per-request try/catch and, without this handler, exits the
// process — turning one malformed response into a crash-loop that takes the
// proxy down for every client (PHA-1391). Log and keep serving instead; a
// broken single stream is far better than a dead proxy.
process.on('uncaughtException', (e) => {
  console.error(`[PROXY] uncaughtException (kept alive): ${e && e.stack ? e.stack : e}`);
});
process.on('unhandledRejection', (e) => {
  console.error(`[PROXY] unhandledRejection (kept alive): ${e && e.stack ? e.stack : e}`);
});

// Graceful shutdown. SIGTERM (Docker / k8s) and SIGINT (Ctrl-C) get the same
// treatment: stop accepting new connections, drain in-flight ones, flush the
// structured JSONL log stream, then exit. Without this, the last few access
// log lines and any in-flight response chunks get truncated mid-write
// (PHA-1844 audit, M2).
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[PROXY] ${signal} received — draining connections and flushing logs`);
  // Force-exit after 15s if drain stalls (e.g. a hung client that never reads).
  const forceExit = setTimeout(() => {
    console.error('[PROXY] graceful shutdown timed out after 15s — forcing exit');
    process.exit(1);
  }, 15000);
  forceExit.unref();
  server.close(() => {
    if (logFileStream) {
      logFileStream.end(() => {
        console.log('[PROXY] LOG_FILE flushed');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });
  // close() waits for connections to end on their own; nudge sockets so
  // idle-keepalive clients release promptly.
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(PORT, '0.0.0.0', () => {
  const proto = USE_HTTPS ? 'https' : 'http';
  console.log(`[PROXY] Anthropic OAuth proxy v2.1 (build ${PROXY_VERSION}) listening on :${PORT} (${proto.toUpperCase()})`);
  console.log(`[PROXY] Mode: ${BILLING_MODE ? 'BILLING (subscription routing, full evasion)' : 'REGULAR (client-provided OAuth)'}`);
  // Pin the 1h prompt-cache TTL beta to PROXY_MODE so this state is visible in
  // `docker logs` instead of buried in an array. The assertion below trips if
  // either path drops the TTL beta — that's the silent-5m-fallback failure mode
  // PHA-1611 was filed against.
  const activeBetas = BILLING_MODE ? billing.REQUIRED_BETAS : OAUTH_BETAS;
  const ttlOk = activeBetas.includes(TTL_BETA);
  console.log(`[PROXY] Cache TTL beta: ${TTL_BETA} (${ttlOk ? 'present' : 'MISSING'}) in ${BILLING_MODE ? 'billing' : 'oauth'} beta list (${activeBetas.length} entries)`);
  if (!ttlOk) {
    console.error(`[PROXY] FATAL: ${TTL_BETA} not in active beta list — every cache write will silently fall back to 5m. Fix OAUTH_BETAS / REQUIRED_BETAS.`);
  }
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

// Test seam only. When the proxy is started normally (`node anthropic-proxy.js`)
// require.main === module, so this is a no-op and nothing above it changes.
// scripts/pha1596-usage-unit.js requires the file to unit-test the pure helpers.
if (require.main !== module) module.exports = { extractUsage, mergeUsage, openAIUsage, makeSSEUsageWatcher, openAIToAnthropic, mapOpenAIContentParts, capCacheControl, attachStreamIdleTimeout, SSE_IDLE_TIMEOUT_MS, extractAnthropicErrorType };
