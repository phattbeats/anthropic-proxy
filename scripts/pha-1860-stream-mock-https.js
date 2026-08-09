'use strict';
// PHA-1860 test harness support: same idea as pha-1850-mock-https.js, but the
// canned SSE reply is fed SLOWLY (a deliberate gap before the tail events) so a
// test can tell incremental relay apart from full-reply buffering. With M5's
// buffering, the client sees nothing until the upstream ends; with incremental
// relay, the first delta lands during the gap.
//
// Load via `node --require ./scripts/pha-1860-stream-mock-https.js anthropic-proxy.js <port>`.

const https = require('https');
const { EventEmitter } = require('events');

const REAL_REQUEST = https.request.bind(https);
const GAP_MS = parseInt(process.env.PHA1860_GAP_MS || '600', 10);

// The delta text ends in an emoji so the same fixture also exercises the
// surrogate-pair carry boundary fixed earlier on this branch.
const EVENTS = [
  'event: message_start\ndata: ' + JSON.stringify({
    type: 'message_start',
    message: { id: 'msg_pha1860', type: 'message', role: 'assistant', model: 'claude-test', content: [], usage: { input_tokens: 12, output_tokens: 1 } },
  }) + '\n\n',
  'event: content_block_start\ndata: ' + JSON.stringify({
    type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' },
  }) + '\n\n',
  'event: content_block_delta\ndata: ' + JSON.stringify({
    type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'first-chunk-marker ' },
  }) + '\n\n',
  // --- GAP_MS pause happens here ---
  'event: content_block_delta\ndata: ' + JSON.stringify({
    type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'tail after the gap 🎉' },
  }) + '\n\n',
  'event: content_block_stop\ndata: ' + JSON.stringify({ type: 'content_block_stop', index: 0 }) + '\n\n',
  'event: message_delta\ndata: ' + JSON.stringify({
    type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 24 },
  }) + '\n\n',
  'event: message_stop\ndata: ' + JSON.stringify({ type: 'message_stop' }) + '\n\n',
];
const GAP_AFTER_INDEX = 2; // pause once the first text delta has been emitted

https.request = function patchedRequest(options, callback) {
  const host = (options && (options.hostname || options.host)) || '';
  if (host !== 'api.anthropic.com') return REAL_REQUEST(options, callback);

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
        'anthropic-request-id': 'req_pha1860_mock',
        'request-id': 'req_pha1860_mock',
      };
      upRes.pause = () => {};
      upRes.resume = () => {};
      if (typeof callback === 'function') callback(upRes);

      let idx = 0;
      const feed = () => {
        if (idx >= EVENTS.length) { upRes.emit('end'); return; }
        const ev = EVENTS[idx++];
        const mid = Math.max(1, Math.floor(ev.length / 2));
        upRes.emit('data', Buffer.from(ev.slice(0, mid)));
        setImmediate(() => {
          upRes.emit('data', Buffer.from(ev.slice(mid)));
          if (idx === GAP_AFTER_INDEX + 1) setTimeout(feed, GAP_MS);
          else setImmediate(feed);
        });
      };
      feed();
    });
  };
  return req;
};

console.error('[pha-1860-stream-mock-https] https.request patched (gap ' + GAP_MS + 'ms)');
