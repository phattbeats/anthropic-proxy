'use strict';
// PHA-1850 (M5) test harness support: monkey-patch https.request so the proxy
// under test never touches the real Anthropic network. Requests to
// api.anthropic.com are answered with a canned, deliberately chunk-split SSE
// /v1/messages reply (mirrors a real Claude Code streaming response shape);
// anything else falls through to the real https.request.
//
// Load via `node --require ./scripts/pha-1850-mock-https.js anthropic-proxy.js <port>`
// so the patch is installed before anthropic-proxy.js does `require('https')`
// (module caching means the proxy gets the same, now-patched, https object).

const https = require('https');
const { EventEmitter } = require('events');

const REAL_REQUEST = https.request.bind(https);

function buildCannedSSEEvents() {
  return [
    'event: message_start\ndata: ' + JSON.stringify({
      type: 'message_start',
      message: { id: 'msg_pha1850test', type: 'message', role: 'assistant', model: 'claude-test', content: [], usage: { input_tokens: 12, output_tokens: 1 } },
    }) + '\n\n',
    'event: content_block_start\ndata: ' + JSON.stringify({
      type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' },
    }) + '\n\n',
    'event: content_block_delta\ndata: ' + JSON.stringify({
      type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hello, ' },
    }) + '\n\n',
    'event: content_block_delta\ndata: ' + JSON.stringify({
      type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'PHA-1850 world! This chunk is intentionally a bit longer so it has to be split across multiple TCP-level writes by the mock, exercising the same accumulation path a real slow upstream would.' },
    }) + '\n\n',
    'event: content_block_stop\ndata: ' + JSON.stringify({ type: 'content_block_stop', index: 0 }) + '\n\n',
    'event: message_delta\ndata: ' + JSON.stringify({
      type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 24 },
    }) + '\n\n',
    'event: message_stop\ndata: ' + JSON.stringify({ type: 'message_stop' }) + '\n\n',
  ];
}

https.request = function patchedRequest(options, callback) {
  const host = (options && (options.hostname || options.host)) || '';
  if (host !== 'api.anthropic.com') {
    return REAL_REQUEST(options, callback);
  }

  const req = new EventEmitter();
  req.write = () => true;
  req.setTimeout = () => req;
  req.destroy = () => {};
  req.end = () => {
    process.nextTick(() => {
      const upRes = new EventEmitter();
      upRes.statusCode = 200;
      upRes.headers = {
        'content-type': 'text/event-stream; charset=utf-8',
        'transfer-encoding': 'chunked',
        'anthropic-request-id': 'req_pha1850_mock',
        'request-id': 'req_pha1850_mock',
      };
      upRes.pause = () => {};
      upRes.resume = () => {};
      if (typeof callback === 'function') callback(upRes);

      const events = buildCannedSSEEvents();
      let idx = 0;
      const feed = () => {
        if (idx >= events.length) { upRes.emit('end'); return; }
        const ev = events[idx++];
        // Split every event roughly in half to simulate a real upstream that
        // does not deliver whole SSE events in a single TCP chunk.
        const mid = Math.max(1, Math.floor(ev.length / 2));
        upRes.emit('data', Buffer.from(ev.slice(0, mid)));
        setImmediate(() => {
          upRes.emit('data', Buffer.from(ev.slice(mid)));
          setImmediate(feed);
        });
      };
      feed();
    });
  };
  return req;
};

console.error('[pha-1850-mock-https] https.request patched for api.anthropic.com -> canned SSE');
