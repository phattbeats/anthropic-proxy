'use strict';
// PHA-1857 diagnostic harness: monkey-patch https.request so the proxy under
// test never touches the real Anthropic network. Returns BOTH a successful
// SSE stream (with usage data) AND a 429 rate-limit error, alternating per
// request, so the test can verify both:
//   - successful streaming requests log real token usage (no errorType field)
//   - 429 upstream errors log 0 tokens + errorType:rate_limit_error
//   - non-streaming responses parse usage from JSON and don't emit errorType
// Set the success/fail pattern via the PATH_INDICATOR env: odd requests get
// success, even requests get 429. statusCode is set BEFORE invoking the
// callback so the proxy's status-code branching sees the right value.

const https = require('https');
const { EventEmitter } = require('events');

const REAL_REQUEST = https.request.bind(https);
let requestCount = 0;

function buildCannedSSEEvents() {
  return [
    'event: message_start\ndata: ' + JSON.stringify({
      type: 'message_start',
      message: { id: 'msg_pha1857test', type: 'message', role: 'assistant', model: 'claude-test', content: [], usage: { input_tokens: 12, output_tokens: 1 } },
    }) + '\n\n',
    'event: content_block_delta\ndata: ' + JSON.stringify({
      type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hi' },
    }) + '\n\n',
    'event: message_delta\ndata: ' + JSON.stringify({
      type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 24 },
    }) + '\n\n',
    'event: message_stop\ndata: ' + JSON.stringify({ type: 'message_stop' }) + '\n\n',
  ];
}

function buildCannedJSONResponse() {
  return JSON.stringify({
    id: 'msg_pha1857test',
    type: 'message',
    role: 'assistant',
    model: 'claude-test',
    content: [{ type: 'text', text: 'hi' }],
    stop_reason: 'end_turn',
    usage: { input_tokens: 12, output_tokens: 7, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
  });
}

https.request = function patchedRequest(options, callback) {
  const host = (options && (options.hostname || options.host)) || '';
  if (host !== 'api.anthropic.com') {
    return REAL_REQUEST(options, callback);
  }
  const n = ++requestCount;
  const req = new EventEmitter();
  req.write = () => true;
  req.setTimeout = () => req;
  req.destroy = () => {};
  req.end = () => {
    process.nextTick(() => {
      const upRes = new EventEmitter();
      upRes.pause = () => {};
      upRes.resume = () => {};
      // statusCode + headers MUST be set BEFORE invoking the callback so the
      // proxy's `if (proxyRes.statusCode !== 200)` check sees the real value.
      if (n % 2 === 1) {
        upRes.statusCode = 200;
        const isStream = (options.path || '').includes('stream=true') ||
          (typeof options.headers === 'object' && options.headers && options.headers.accept === 'text/event-stream');
        upRes.headers = { 'content-type': isStream ? 'text/event-stream; charset=utf-8' : 'application/json' };
      } else {
        upRes.statusCode = 429;
        upRes.headers = { 'content-type': 'application/json', 'retry-after': '30' };
      }
      if (typeof callback === 'function') callback(upRes);
      if (n % 2 === 1) {
        const isStream = (options.path || '').includes('stream=true');
        // Headers don't reliably carry the hint; use the request body if present.
        // Simplest: emit SSE events for streaming-style responses.
        const wantsStream = n % 4 < 2; // alternate between stream and non-stream successes
        if (wantsStream) {
          const events = buildCannedSSEEvents();
          let idx = 0;
          const feed = () => {
            if (idx >= events.length) { upRes.emit('end'); return; }
            upRes.emit('data', Buffer.from(events[idx++]));
            setImmediate(feed);
          };
          feed();
        } else {
          upRes.emit('data', Buffer.from(buildCannedJSONResponse()));
          upRes.emit('end');
        }
      } else {
        upRes.emit('data', Buffer.from(JSON.stringify({
          type: 'error',
          error: { type: 'rate_limit_error', message: 'Number of request tokens has exceeded your daily rate limit' },
        })));
        upRes.emit('end');
      }
    });
  };
  return req;
};

console.error('[pha-1857-mock] https.request patched for api.anthropic.com: odd=success, even=429');