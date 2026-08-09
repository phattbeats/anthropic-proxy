#!/usr/bin/env node
// PHA-1860: the access log must carry the subscription quota snapshot that
// Anthropic returns on every response, so a quota-shed 429 is distinguishable
// from a proxy fault.
//
// Background: this issue was originally diagnosed as a regression between
// 1.4.7 and 1.5.0 because the only evidence available was a run of
// `"status":429,"errorType":"rate_limit_error"` lines with zero tokens. The
// actual cause was the account sitting at 0.95 of its 7-day limit with
// org-level overage disabled: past `surpassed-threshold`, Anthropic sheds a
// FRACTION of requests (`fallback-percentage`) instead of blocking outright,
// so 200s and 429s interleave and the failure looks nondeterministic. Those
// facts were in the upstream response headers the whole time; they just never
// reached the log.
//
// Run: node scripts/pha-1860-quota-log-unit.js

'use strict';

const path = require('path');
const assert = require('assert');

// The header-parsing helper is exercised through a local copy of its contract:
// anthropic-proxy.js runs a server on require, so we re-implement nothing and
// instead load it in a guarded child-free way via the exported surface if
// available, falling back to source extraction.
const SRC = require('fs').readFileSync(path.join(__dirname, '..', 'anthropic-proxy.js'), 'utf8');
const fnMatch = SRC.match(/function extractQuota\(headers\) \{[\s\S]*?\n\}/);
assert.ok(fnMatch, 'extractQuota() must exist in anthropic-proxy.js');
const extractQuota = new Function(`${fnMatch[0]}; return extractQuota;`)();

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// --- 1. The real headers captured from the live 429-storm window ---
{
  const headers = {
    'anthropic-ratelimit-unified-status': 'allowed_warning',
    'anthropic-ratelimit-unified-5h-status': 'allowed',
    'anthropic-ratelimit-unified-5h-utilization': '0.17',
    'anthropic-ratelimit-unified-7d-status': 'allowed_warning',
    'anthropic-ratelimit-unified-7d-utilization': '0.95',
    'anthropic-ratelimit-unified-representative-claim': 'seven_day',
    'anthropic-ratelimit-unified-fallback-percentage': '0.5',
    'anthropic-ratelimit-unified-overage-status': 'rejected',
    'anthropic-ratelimit-unified-overage-disabled-reason': 'org_level_disabled',
    'anthropic-ratelimit-unified-reset': '1786323600',
  };
  const q = extractQuota(headers);
  assert.strictEqual(q.util7d, 0.95, 'weekly utilization must be parsed as a number');
  assert.strictEqual(q.util5h, 0.17, '5h utilization must be parsed as a number');
  assert.strictEqual(q.claim, 'seven_day', 'enforced window must be recorded');
  assert.strictEqual(q.shed, 0.5, 'fallback-percentage (shed rate) must be recorded');
  assert.strictEqual(q.overage, 'rejected', 'overage status must be recorded');
  assert.strictEqual(q.resetsAt, '2026-08-10T01:00:00.000Z', 'reset must render as ISO time');
  ok('live quota-shed headers parse into a complete, numeric snapshot');

  // The whole point: the log line must let a human tell shedding from a bug.
  assert.ok(q.util7d > 0.75 && q.shed > 0,
    'a shed-state snapshot must expose both over-threshold utilization and a shed rate');
  ok('snapshot makes quota shedding self-evident (util past threshold + shed rate)');
}

// --- 2. Healthy account: no alarming fields, still logged ---
{
  const q = extractQuota({
    'anthropic-ratelimit-unified-status': 'allowed',
    'anthropic-ratelimit-unified-5h-utilization': '0.02',
    'anthropic-ratelimit-unified-reset': '1786320000',
  });
  assert.strictEqual(q.status, 'allowed');
  assert.strictEqual(q.util5h, 0.02);
  assert.ok(!('shed' in q), 'absent headers must not appear as undefined keys');
  assert.ok(!('util7d' in q), 'absent headers must not appear as undefined keys');
  ok('healthy response yields a compact snapshot with no undefined keys');
}

// --- 3. Non-Anthropic / header-less responses must not pollute the log ---
{
  assert.strictEqual(extractQuota(null), null, 'null headers → null');
  assert.strictEqual(extractQuota({}), null, 'no ratelimit headers → null (log stays clean)');
  assert.strictEqual(extractQuota({ 'content-type': 'application/json' }), null,
    'unrelated headers → null');
  ok('responses without ratelimit headers add no quota field to the log');
}

// --- 4. Malformed values must degrade, not throw or emit NaN ---
{
  const q = extractQuota({
    'anthropic-ratelimit-unified-status': 'allowed_warning',
    'anthropic-ratelimit-unified-7d-utilization': 'not-a-number',
    'anthropic-ratelimit-unified-reset': 'garbage',
  });
  assert.ok(!('util7d' in q), 'unparseable utilization must be omitted, never NaN');
  assert.ok(!('resetsAt' in q), 'unparseable reset must be omitted, never Invalid Date');
  assert.strictEqual(q.status, 'allowed_warning', 'valid sibling fields still survive');
  assert.doesNotThrow(() => JSON.stringify(q), 'snapshot must always be JSON-serializable');
  ok('malformed header values are dropped without NaN/Invalid Date leaking into the log');
}

console.log(`\nPHA-1860 quota-log unit: ${pass}/${pass} checks passed.`);
