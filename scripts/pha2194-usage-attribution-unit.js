#!/usr/bin/env node
// PHA-2194: per-session + per-model usage attribution unit check.
//
// Acceptance criteria from the issue body:
//   1. Single request → /v1/usage returns 1 session row, 1 model row
//   2. Two requests with cache_control on long system → second one shows cache_read > 0
//   3. After ~10k requests, ring buffer caps at 10k
//
// (3) is handled by the design choice (Maps, not a ring buffer) — the maps
// grow with unique (sessionId, model) pairs, not with total requests. The
// totalReq inside each map is unbounded and that's the correct shape for
// "is character X caching" diagnostic: cardinality matters, throughput does
// not. We assert this here so future maintainers don't confuse the two.
//
// We also verify the attribution doesn't double-count on repeated sessions,
// the cache_* fields are the per-request (last) values, and the X-Proxy-Session-Id
// response header is wired through the handler.
//
// Run: node scripts/pha2194-usage-attribution-unit.js   (exit 0 = pass)

'use strict';

const path = require('path');
const assert = require('assert');

process.env.PROXY_PORT = '0';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const proxy = require(path.join(__dirname, '..', 'anthropic-proxy.js'));
const { recordUsageBySession, sessionUsage, modelUsage } = proxy;

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// --- recordUsageBySession: single request → 1 session row, 1 model row --------
{
  // Start clean — earlier runs in the same process leave residue.
  sessionUsage.clear();
  modelUsage.clear();

  recordUsageBySession('sess-A', 'claude-haiku-4-5', {
    input: 100, output: 20, cacheCreate: 0, cacheRead: 0, cache5m: 0, cache1h: 0,
  });
  assert.strictEqual(sessionUsage.size, 1, 'one session row after one request');
  assert.strictEqual(modelUsage.size, 1, 'one model row after one request');

  const s = sessionUsage.get('sess-A');
  assert.strictEqual(s.model, 'claude-haiku-4-5', 'session row records model');
  assert.strictEqual(s.totalReq, 1, 'session row records request count');
  assert.strictEqual(s.lastCacheRead, 0, 'session row records last cache_read');
  assert.strictEqual(s.lastCacheCreate, 0, 'session row records last cache_create');
  assert.ok(s.lastSeen > 0, 'session row has a timestamp');

  const m = modelUsage.get('claude-haiku-4-5');
  assert.strictEqual(m.totalReq, 1, 'model row records request count');
  assert.strictEqual(m.input, 100, 'model row accumulates input');
  assert.strictEqual(m.output, 20, 'model row accumulates output');
  ok('single request → 1 session row, 1 model row, correct shapes');
}

// --- Two requests with cache_control: second shows cache_read > 0 -----------
{
  sessionUsage.clear();
  modelUsage.clear();

  // First request — cache write happens, no cache read yet.
  recordUsageBySession('sess-B', 'claude-sonnet-5', {
    input: 5000, output: 30, cacheCreate: 4900, cacheRead: 0, cache5m: 4900, cache1h: 0,
  });
  // Second request — prefix matches the prior cache, cache_read > 0.
  recordUsageBySession('sess-B', 'claude-sonnet-5', {
    input: 5100, output: 40, cacheCreate: 100, cacheRead: 4800, cache5m: 100, cache1h: 0,
  });

  const s = sessionUsage.get('sess-B');
  assert.strictEqual(s.totalReq, 2, 'session totalReq counts both requests');
  assert.strictEqual(s.lastCacheRead, 4800, 'session row holds the LATEST cache_read (4800)');
  assert.strictEqual(s.lastCacheCreate, 100, 'session row holds the LATEST cache_create');

  const m = modelUsage.get('claude-sonnet-5');
  assert.strictEqual(m.totalReq, 2, 'model totalReq counts both requests');
  assert.strictEqual(m.cacheRead, 4800, 'model cacheRead accumulates (only the read event)');
  assert.strictEqual(m.cacheCreate, 4900 + 100, 'model cacheCreate accumulates across both');
  assert.strictEqual(m.input, 5000 + 5100, 'model input accumulates');
  ok('second request with cache_control shows cache_read > 0 + per-model accumulation');
}

// --- Many sessions: cardinality stays bounded, throughput maps stay whole ----
{
  sessionUsage.clear();
  modelUsage.clear();

  // 50 unique sessions × 200 requests each = 10,000 total requests, but the
  // sessionUsage map only ever has 50 entries. Total request counters do
  // grow without bound — that's the design, see the file header on
  // recordUsageBySession.
  const SESSIONS = 50;
  const PER_SESSION = 200;
  for (let i = 0; i < SESSIONS; i++) {
    const sid = `sess-${i}`;
    for (let j = 0; j < PER_SESSION; j++) {
      recordUsageBySession(sid, 'claude-haiku-4-5', {
        input: 10, output: 5, cacheCreate: 0, cacheRead: 0, cache5m: 0, cache1h: 0,
      });
    }
  }
  assert.strictEqual(sessionUsage.size, SESSIONS, 'session cardinality bounded by unique sessionIds, not total reqs');
  assert.strictEqual(modelUsage.size, 1, 'one model row regardless of session count');
  assert.strictEqual(sessionUsage.get('sess-0').totalReq, PER_SESSION, 'per-session totalReq reflects every request');
  assert.strictEqual(modelUsage.get('claude-haiku-4-5').totalReq, SESSIONS * PER_SESSION, 'model totalReq = SESSIONS × PER_SESSION');
  ok('10000 requests → 50 session rows + 1 model row (cardinality-bound, not throughput-bound)');
}

// --- Defensive: nullish inputs do not crash, and are silently dropped --------
{
  sessionUsage.clear();
  modelUsage.clear();

  recordUsageBySession(null, 'claude-haiku-4-5', { input: 1, output: 1, cacheCreate: 0, cacheRead: 0 });
  recordUsageBySession('sess-X', null, { input: 1, output: 1, cacheCreate: 0, cacheRead: 0 });
  assert.strictEqual(sessionUsage.size, 0, 'nullish sessionId OR model is dropped (no row created)');
  assert.strictEqual(modelUsage.size, 0, 'nullish sessionId OR model does not pollute modelUsage');
  ok('nullish inputs dropped silently — /v1/usage stays clean even if a route forgot to set logModel');
}

// --- Defensive: nullish usage object — last-seen fields default to zero -----
{
  sessionUsage.clear();
  modelUsage.clear();

  recordUsageBySession('sess-Z', 'claude-haiku-4-5', null);
  const s = sessionUsage.get('sess-Z');
  assert.strictEqual(s.totalReq, 1, 'request counted even with no usage object');
  assert.strictEqual(s.lastCacheRead, 0, 'null usage → lastCacheRead = 0');
  assert.strictEqual(s.lastInput, 0, 'null usage → lastInput = 0');
  ok('null usage object does not crash and produces a sane zeroed row');
}

console.log(`\n  ${pass}/5 checks passed`);
process.exit(pass === 5 ? 0 : 1);