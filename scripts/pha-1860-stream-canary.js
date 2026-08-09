'use strict';
// PHA-1860 regression canary: streaming POST /v1/messages must be relayed
// INCREMENTALLY, not buffered until the upstream ends (the PHA-1850/M5
// behavior this branch reverts). Buffering starved clients of bytes for the
// whole turn, which tripped client-side stream timeouts -> LiteLLM deployment
// cooldown -> immediate 429s, and read as a mid-generation cutoff.
//
// Boots the proxy against scripts/pha-1860-stream-mock-https.js (a canned SSE
// reply with a deliberate mid-stream gap) and asserts:
//   1. the first text delta reaches the client BEFORE the upstream finishes
//   2. no content-length is set on the SSE response
//   3. the full reply still arrives intact, emoji included
//
// Run: node scripts/pha-1860-stream-canary.js

const assert = require('assert');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PHA1860_PORT || '4099', 10);
const GAP_MS = 600;
const ROOT = path.resolve(__dirname, '..');

function ok(msg) { console.log(`  ok - ${msg}`); }

const proxy = spawn(process.execPath, [
  '--require', path.join(__dirname, 'pha-1860-stream-mock-https.js'),
  path.join(ROOT, 'anthropic-proxy.js'), String(PORT),
], {
  cwd: ROOT,
  env: { ...process.env, PHA1860_GAP_MS: String(GAP_MS), BILLING_MODE: 'false' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let proxyLog = '';
proxy.stdout.on('data', d => { proxyLog += d; });
proxy.stderr.on('data', d => { proxyLog += d; });

const cleanup = (code) => { try { proxy.kill('SIGKILL'); } catch (_) {} process.exit(code); };
proxy.on('exit', c => { if (c !== null && c !== 0) { console.error(proxyLog); } });

const waitForListen = () => new Promise((resolve, reject) => {
  const deadline = Date.now() + 8000;
  const tryOnce = () => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/health', method: 'GET' }, res => {
      res.resume(); resolve();
    });
    r.on('error', () => (Date.now() > deadline ? reject(new Error('proxy never listened:\n' + proxyLog)) : setTimeout(tryOnce, 100)));
    r.end();
  };
  tryOnce();
});

(async () => {
  await waitForListen();

  const body = JSON.stringify({
    model: 'claude-test', max_tokens: 64, stream: true,
    messages: [{ role: 'user', content: 'hi' }],
  });

  const result = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: PORT, path: '/v1/messages', method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'authorization': 'Bearer sk-ant-test-not-a-real-key',
        'accept': 'text/event-stream',
      },
    }, res => {
      const t0 = Date.now();
      let firstDeltaAt = null, endAt = null, text = '';
      res.setEncoding('utf8');
      res.on('data', c => {
        text += c;
        if (firstDeltaAt === null && text.includes('first-chunk-marker')) firstDeltaAt = Date.now() - t0;
      });
      res.on('end', () => {
        endAt = Date.now() - t0;
        resolve({ headers: res.headers, status: res.statusCode, firstDeltaAt, endAt, text });
      });
    });
    req.on('error', reject);
    req.end(body);
  });

  assert.strictEqual(result.status, 200, 'proxy returned 200');
  ok('streaming /v1/messages returns 200');

  assert.strictEqual(result.headers['content-length'], undefined,
    `SSE response must not carry content-length (got ${result.headers['content-length']})`);
  ok('no content-length on the SSE response (chunked relay restored)');

  assert.ok(result.firstDeltaAt !== null, 'client never saw the first text delta');
  assert.ok(result.firstDeltaAt < GAP_MS,
    `first delta must arrive before the ${GAP_MS}ms upstream gap ends; got ${result.firstDeltaAt}ms (buffered?)`);
  assert.ok(result.endAt >= GAP_MS,
    `sanity: stream should not finish before the upstream gap (${result.endAt}ms)`);
  ok(`first delta at ${result.firstDeltaAt}ms, stream end at ${result.endAt}ms — incremental, not buffered`);

  assert.ok(result.text.includes('tail after the gap'), 'tail delta missing from client stream');
  assert.ok(result.text.includes('🎉'), 'trailing emoji lost or split');
  assert.ok(result.text.includes('message_stop'), 'message_stop missing');
  ok('full reply delivered intact (tail + emoji + message_stop)');

  console.log('\nPHA-1860 stream canary: PASS');
  cleanup(0);
})().catch(e => {
  console.error('\nPHA-1860 stream canary: FAIL\n' + (e && e.stack || e));
  console.error('--- proxy log ---\n' + proxyLog);
  cleanup(1);
});
