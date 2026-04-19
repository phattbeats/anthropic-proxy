#!/usr/bin/env node
// Thin proxy: fixes OAuth token handling for Anthropic API
// - Serves /v1/models for SillyTavern model discovery
// - Translates /v1/chat/completions (OpenAI) → /v1/messages (Anthropic)
// - Moves sk-ant-oat tokens from x-api-key to Authorization: Bearer
// - Injects required OAuth headers + Claude Code system prompt
// Usage: node anthropic-proxy.js [port]

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PROXY_DIR = path.dirname(process.argv[1]);
const USE_HTTPS = fs.existsSync(path.join(PROXY_DIR, 'proxy-key.pem'));

const PORT = parseInt(process.argv[2] || '4010');
const TARGET = 'api.anthropic.com';
const OAUTH_PREFIX = 'sk-ant-oat';
const CLAUDE_CODE_SYSTEM = "You are Claude Code, Anthropic's official CLI for Claude.";

const OAUTH_HEADERS = {
  'anthropic-beta': 'claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14,interleaved-thinking-2025-05-14',
  'anthropic-dangerous-direct-browser-access': 'true',
  'user-agent': 'claude-cli/2.1.75',
  'x-app': 'cli',
};

const MODELS = [
  // Current shipping models (as of 2026-04)
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

function modelsResponse() {
  return JSON.stringify({
    object: 'list',
    data: MODELS.map(m => ({
      id: m.id,
      object: 'model',
      created: 1700000000,
      owned_by: 'anthropic',
      display_name: m.name,
    }))
  });
}

// Parameters SillyTavern sends that Anthropic doesn't support — strip them
const STRIP_PARAMS = ['presence_penalty', 'frequency_penalty', 'logit_bias', 'seed', 'response_format', 'function_call', 'functions'];

// Convert OpenAI chat/completions format to Anthropic messages format
function openAIToAnthropic(body, isOAuth) {
  const payload = JSON.parse(body);

  // Strip unsupported OpenAI parameters before conversion
  for (const p of STRIP_PARAMS) delete payload[p];

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

  if (payload.temperature !== undefined) result.temperature = payload.temperature;
  if (payload.top_p !== undefined) result.top_p = payload.top_p;
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
    res.writeHead(502);
    res.end(JSON.stringify({ error: e.message }));
  });

  if (body && body.length > 0) proxyReq.write(body);
  proxyReq.end();
}

const handler = (req, res) => {
  let chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks);

    // Model list endpoint
    if (req.url === '/v1/models' || req.url === '/v1/models/') {
      console.log(`[PROXY] GET /v1/models`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(modelsResponse());
    }

    const apiKey = getApiKey(req.headers);
    const isOAuth = apiKey.startsWith(OAUTH_PREFIX);

    // Build outbound headers
    const headers = { 'content-type': 'application/json', 'anthropic-version': '2023-06-01' };
    if (isOAuth) {
      headers['authorization'] = `Bearer ${apiKey}`;
      Object.assign(headers, OAUTH_HEADERS);
    } else {
      headers['x-api-key'] = apiKey;
    }

    // OpenAI chat completions → Anthropic messages
    if (req.url === '/v1/chat/completions') {
      console.log(`[PROXY] chat/completions → /v1/messages (OAuth: ${isOAuth})`);
      let bodyStr;
      try {
        bodyStr = openAIToAnthropic(rawBody.toString(), isOAuth);
      } catch (e) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Bad request body: ' + e.message }));
      }
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
          proxyRes.on('data', chunk => {
            buffer += chunk.toString();
            const lines = buffer.split('\n');
            buffer = lines.pop(); // keep incomplete line
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const data = line.slice(6).trim();
                if (data === '[DONE]') { res.write('data: [DONE]\n\n'); continue; }
                try {
                  const ev = JSON.parse(data);
                  // Anthropic → OpenAI SSE chunk
                  if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
                    const chunk = {
                      id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: { content: ev.delta.text }, finish_reason: null }]
                    };
                    res.write(`data: ${JSON.stringify(chunk)}\n\n`);
                  } else if (ev.type === 'message_delta' && ev.delta?.stop_reason) {
                    const chunk = {
                      id: 'chatcmpl-proxy', object: 'chat.completion.chunk',
                      created: Math.floor(Date.now()/1000), model,
                      choices: [{ index: 0, delta: {}, finish_reason: ev.delta.stop_reason === 'end_turn' ? 'stop' : ev.delta.stop_reason }]
                    };
                    res.write(`data: ${JSON.stringify(chunk)}\n\n`);
                    res.write('data: [DONE]\n\n');
                  }
                } catch(e) {}
              } else if (line.trim()) {
                res.write(line + '\n');
              }
            }
          });
          proxyRes.on('end', () => res.end());
        } else {
          let respChunks = [];
          proxyRes.on('data', c => respChunks.push(c));
          proxyRes.on('end', () => {
            const raw = Buffer.concat(respChunks).toString();
            const converted = anthropicToOpenAI(raw, model, false);
            res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
            res.end(converted);
          });
        }
      });
      proxyReq.on('error', e => { res.writeHead(502); res.end(JSON.stringify({ error: e.message })); });
      proxyReq.write(bodyBuf);
      proxyReq.end();
      return;
    }

    // Native /v1/messages passthrough with OAuth fix
    if (req.url.startsWith('/v1/messages')) {
      console.log(`[PROXY] /v1/messages passthrough (OAuth: ${isOAuth})`);
      let bodyBuf = rawBody;
      let parsed = null;
      try {
        parsed = JSON.parse(rawBody.toString());

        // Always ensure Claude Code system prompt is first for OAuth tokens
        if (isOAuth) {
          if (!parsed.system || (Array.isArray(parsed.system) && parsed.system.length === 0)) {
            parsed.system = [{ type: 'text', text: CLAUDE_CODE_SYSTEM }];
          } else if (Array.isArray(parsed.system)) {
            const hasCC = parsed.system.some(b => b.text === CLAUDE_CODE_SYSTEM);
            if (!hasCC) parsed.system.unshift({ type: 'text', text: CLAUDE_CODE_SYSTEM });
          } else if (typeof parsed.system === 'string') {
            // Convert string system to array with CC prompt first
            parsed.system = [{ type: 'text', text: CLAUDE_CODE_SYSTEM }, { type: 'text', text: parsed.system }];
          }
        }

        // Cap cache_control blocks to 4 max (Anthropic hard limit)
        let cacheCount = 0;
        const stripExcessCache = (blocks) => {
          if (!Array.isArray(blocks)) return blocks;
          return blocks.map(b => {
            if (b.cache_control) {
              cacheCount++;
              if (cacheCount > 4) {
                const { cache_control, ...rest } = b;
                return rest;
              }
            }
            return b;
          });
        };

        if (Array.isArray(parsed.system)) parsed.system = stripExcessCache(parsed.system);
        if (Array.isArray(parsed.messages)) {
          parsed.messages = parsed.messages.map(m => {
            if (Array.isArray(m.content)) m.content = stripExcessCache(m.content);
            return m;
          });
        }

        if (cacheCount > 4) console.log(`[PROXY] Stripped ${cacheCount - 4} excess cache_control blocks`);
        bodyBuf = Buffer.from(JSON.stringify(parsed));
      } catch (e) {}

      const isStream = !!(parsed && parsed.stream);
      if (!isStream) headers['content-length'] = String(bodyBuf.length);
      forwardToAnthropic('/v1/messages', 'POST', headers, bodyBuf, res, isStream);
      return;
    }

    // Health check endpoint
    if (req.url === '/health' || req.url === '/v1/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'ok',
        proxy: 'anthropic-oauth-proxy',
        version: '2.0',
        timestamp: new Date().toISOString(),
      }));
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
  console.log(`[PROXY] Anthropic OAuth proxy v2 listening on :${PORT} (${proto.toUpperCase()})`);
  console.log(`[PROXY] Endpoints: /health, /v1/models, /v1/chat/completions, /v1/messages`);
  console.log(`[PROXY] Point SillyTavern/LiteLLM at: ${proto}://172.18.0.27:${PORT}`);
});
