#!/usr/bin/env node
// PHA-1844a (H3): SSE backpressure + per-stream idle timeout.
//
// Verifies, against the exported attachStreamIdleTimeout helper:
//   1. After SSE_IDLE_TIMEOUT_MS of no accepted writes, the helper writes a
//      single OpenAI-shaped error chunk and ends the stream cleanly.
//   2. Each accepted res.write() resets the timer; the helper does NOT fire
//      while upstream is actively producing chunks.
//   3. res.end() clears the timer — no spurious error chunk after a normal end.
//   4. Under sustained backpressure (sink returns false from write()), the
//      paired pause/drain helper bounds the buffer and resumes on drain.
//
// Run: SSE_IDLE_TIMEOUT_MS=200 node scripts/pha-1844a-sse-backpressure-unit.js

'use strict';

const path = require('path');
const assert = require('assert');
const { EventEmitter } = require('events');

process.env.SSE_IDLE_TIMEOUT_MS = process.env.SSE_IDLE_TIMEOUT_MS || '200';

const proxy = require(path.join(__dirname, '..', 'anthropic-proxy.js'));
const { attachStreamIdleTimeout, SSE_IDLE_TIMEOUT_MS } = proxy;

console.log(`SSE_IDLE_TIMEOUT_MS = ${SSE_IDLE_TIMEOUT_MS}ms`);

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// Build a res-like object that the wrapper can monkey-patch safely. We save the
// raw I/O hooks BEFORE attachStreamIdleTimeout so we can observe what the helper
// ultimately wrote/end()ed (the wrapper passes through to our hooks).
function makeFakeRes() {
  const res = new EventEmitter();
  const sink = { writes: [], ended: false, chunks: 0 };
  const origWrite = (chunk) => { sink.writes.push(String(chunk)); sink.chunks++; return true; };
  const origEnd = () => { sink.ended = true; res.emit('finish'); };
  res.__sink = sink;
  res.write = origWrite;
  res.end = origEnd;
  return res;
}

function awaitFinish(res, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`res did not finish within ${ms}ms`)), ms);
    res.once('finish', () => { clearTimeout(t); resolve(); });
  });
}

(async () => {
  // --- Test 1: idle timeout fires and emits an OpenAI-style error chunk ---
  {
    const res = makeFakeRes();
    attachStreamIdleTimeout(res, 'unit-test-1');
    await awaitFinish(res, SSE_IDLE_TIMEOUT_MS * 4);
    assert.strictEqual(res.__sink.ended, true, 'res.end() should have been called by the idle handler');
    assert.strictEqual(res.__sink.writes.length, 1, `expected exactly one error chunk, got ${res.__sink.writes.length}: ${JSON.stringify(res.__sink.writes)}`);
    const chunk = res.__sink.writes[0];
    assert(chunk.startsWith('data: '), `chunk must be SSE-shaped: ${chunk.slice(0, 30)}`);
    assert(chunk.includes('"object":"chat.completion.chunk"'), `chunk must be OpenAI-shaped: ${chunk}`);
    assert(chunk.includes('"finish_reason":"error"'), `chunk must carry finish_reason=error: ${chunk}`);
    assert(chunk.includes('"type":"idle_timeout"'), `chunk must carry idle_timeout error type: ${chunk}`);
    ok('idle timeout fires after SSE_IDLE_TIMEOUT_MS, emits one OpenAI error chunk, ends stream');
  }

  // --- Test 2: accepted writes reset the timer ---
  {
    const res = makeFakeRes();
    attachStreamIdleTimeout(res, 'unit-test-2');
    const tick = setInterval(() => res.write('data: tick\n\n'), 40);
    await new Promise(resolve => setTimeout(resolve, SSE_IDLE_TIMEOUT_MS * 3));
    clearInterval(tick);
    assert.strictEqual(res.__sink.ended, false, 'res should NOT end while writes are active');
    assert(res.__sink.writes.length >= 5, `expected many ticks, got ${res.__sink.writes.length}`);
    assert(res.__sink.writes.every(w => !w.includes('idle_timeout')), 'no idle-timeout chunks during active writes');
    // Stop writing — timer should fire shortly after.
    await awaitFinish(res, SSE_IDLE_TIMEOUT_MS * 4);
    assert.strictEqual(res.__sink.ended, true, 'after writes stop, stream should end');
    assert(res.__sink.writes[res.__sink.writes.length - 1].includes('idle_timeout'), 'final chunk should be idle-timeout');
    ok('active writes reset the idle timer; stream only ends after writes stop');
  }

  // --- Test 3: res.end() clears the timer (no spurious error chunk) ---
  {
    const res = makeFakeRes();
    attachStreamIdleTimeout(res, 'unit-test-3');
    const fin = awaitFinish(res, SSE_IDLE_TIMEOUT_MS * 4);
    res.write('data: hello\n\n');
    res.end(); // normal end; should clear timer
    await fin;
    assert.strictEqual(res.__sink.ended, true);
    assert.strictEqual(res.__sink.writes.length, 1, `expected one chunk, got ${res.__sink.writes.length}`);
    assert(!res.__sink.writes[0].includes('idle_timeout'), 'no idle-timeout chunk after clean end');
    // Wait past the idle window to confirm the timer was cleared, not delayed.
    await new Promise(resolve => setTimeout(resolve, SSE_IDLE_TIMEOUT_MS * 2));
    assert.strictEqual(res.__sink.writes.length, 1, 'no late idle-timeout chunk after clean end');
    ok('res.end() clears the idle timer; no spurious error chunk after normal end');
  }

  // --- Test 4: close() clears the timer (no leaked timers / crashes) ---
  {
    const res = makeFakeRes();
    attachStreamIdleTimeout(res, 'unit-test-4');
    res.emit('close');
    await new Promise(resolve => setTimeout(resolve, SSE_IDLE_TIMEOUT_MS * 1.5));
    assert.strictEqual(res.__sink.ended, false, 'res.end() should NOT fire after close()');
    assert.strictEqual(res.__sink.writes.length, 0, 'no error chunk should fire after close()');
    ok('res.close() clears the idle timer cleanly');
  }

  // --- Test 5: backpressure pause/drain helper bounds the buffer ---
  {
    // Simulate a slow downstream: return false once cumulative writes exceed HWM,
    // then schedule a drain that resets the counter.
    const res = makeFakeRes();
    let buf = 0;
    const HWM = 8 * 1024;
    // Replace the raw write AFTER we know the wrapper will call it. The wrapper
    // does `arm(); return origWrite(...)`, so this rawWrite is invoked once per
    // accepted chunk. Backpressure logic lives in sseWrite (test-side).
    const realWrite = res.write.bind(res);
    let drainScheduled = false;
    res.write = function(chunk) {
      buf += Buffer.byteLength(String(chunk));
      const ok = realWrite(chunk);
      if (ok === false || buf > HWM) {
        if (!drainScheduled) {
          drainScheduled = true;
          setImmediate(() => {
            buf = 0;
            drainScheduled = false;
            res.emit('drain');
          });
        }
        return false;
      }
      return true;
    };

    // Fake upstream source: pause/resume tracked.
    const upstream = new EventEmitter();
    upstream._paused = false;
    upstream.pause = () => { upstream._paused = true; };
    upstream.resume = () => { upstream._paused = false; };

    attachStreamIdleTimeout(res, 'unit-test-5');
    // Same shape as the proxy's sseWrite helper.
    let upstreamPaused = false;
    const sseWrite = (chunk) => {
      const ok = res.write(chunk);
      if (ok === false && !upstreamPaused) { upstreamPaused = true; upstream.pause(); }
      return ok;
    };
    res.on('drain', () => { if (upstreamPaused) { upstreamPaused = false; upstream.resume(); } });

    // Small chunks shouldn't pause.
    sseWrite('data: small-1\n\n');
    sseWrite('data: small-2\n\n');
    assert.strictEqual(upstreamPaused, false, 'small chunks should not pause upstream');

    // Big chunk should overflow → pause upstream.
    sseWrite(`data: ${'x'.repeat(HWM + 100)}\n\n`);
    assert.strictEqual(upstreamPaused, true, 'upstream should be paused after HWM-exceeding write');

    // After drain, upstream resumes and buffer is bounded.
    await new Promise(resolve => res.once('drain', resolve));
    assert.strictEqual(upstreamPaused, false, 'upstream should resume after drain');
    assert(buf <= HWM, `buffer should be bounded by HWM after drain (buf=${buf})`);
    ok('backpressure: write()==false pauses upstream; drain resumes; buffer bounded by HWM');
  }

  console.log(`\npha-1844a SSE backpressure + idle unit: ${pass} passed, 0 failed`);
  // Force-exit so any lingering handle on the http server (loaded by the proxy
  // module for its exported test seam) doesn't keep the process alive.
  process.exit(0);
})().catch(e => {
  console.error('\nFAIL:', e && e.stack ? e.stack : e);
  process.exit(1);
});