'use strict';
const https = require('https');
const http = require('http');
const { EventEmitter } = require('events');

// In-process fake Anthropic recogniser. Returns 200 only when system[0].text
// starts with 'x-anthropic-billing-header:' (the recognition signal). Otherwise
// 429 with the same shape Anthropic returns on the production path. The first
// /v1/messages request is what fails on the real proxy; /v1/models stays 200
// (matches the readiness probe so it doesn't poison the box).
let reqCount = 0;
function fakeRequest(args, cb) {
  const method = (args && args.method) || 'GET';
  const path = args && args.path || '';
  const chunks = [];
  const req = new EventEmitter();
  req.write = (c) => { chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(String(c))); return true; };
  req.end = (c) => {
    if (c) req.write(c);
    const headers = (args && args.headers) || {};
    const lower = Object.fromEntries(Object.entries(headers).map(([k,v]) => [String(k).toLowerCase(), v]));
    const body = Buffer.concat(chunks).toString();
    setImmediate(() => {
      let status = 200, payload, ct = 'application/json';
      if (path.startsWith('/v1/models')) {
        payload = JSON.stringify({ data: [{ id: 'claude-sonnet-5', name: 'mock' }] });
      } else if (path.startsWith('/v1/messages')) {
        reqCount++;
        try {
          const parsed = JSON.parse(body);
          const sys = parsed.system;
          let firstText = null;
          if (Array.isArray(sys) && sys.length > 0 && typeof sys[0].text === 'string') firstText = sys[0].text;
          if (typeof sys === 'string') firstText = sys;
          if (firstText && firstText.startsWith('x-anthropic-billing-header:')) {
            payload = JSON.stringify({
              id: 'msg_mock', type: 'message', role: 'assistant', model: parsed.model || 'claude-sonnet-5',
              content: [{ type: 'text', text: 'OK' }], stop_reason: 'end_turn',
              usage: { input_tokens: 1, output_tokens: 1 },
            });
          } else {
            status = 429;
            payload = JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'first-message classifier did not recognise the system[0] signal (sidecar mock)' }, request_id: 'req_sidecar_' + reqCount });
          }
        } catch (e) {
          status = 400;
          payload = JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: e.message } });
        }
      } else {
        payload = JSON.stringify({ ok: true });
      }
      const r = new EventEmitter();
      r.statusCode = status;
      const buf = Buffer.from(payload);
      r.headers = { 'content-type': ct, 'content-length': buf.length, 'request-id': 'req_sidecar_' + reqCount };
      r.resume = () => r;
      setImmediate(() => { r.emit('data', buf); r.emit('end'); });
      if (typeof cb === 'function') cb(r); else req.emit('response', r);
    });
  };
  req.destroy = () => req;
  req.setTimeout = () => req;
  return req;
}
https.request = function (args, cb) { return fakeRequest(args, cb); };
https.get = function (args, cb) { return fakeRequest(Object.assign({}, args, { method: 'GET' }), cb); };
process.on('uncaughtException', e => { console.error('SIDECAR-MOCK ERROR', e.stack); process.exit(2); });
