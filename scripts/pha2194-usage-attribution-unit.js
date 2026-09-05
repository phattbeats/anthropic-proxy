#!/usr/bin/env node
// PHA-2194 per-session usage attribution unit check.
//
// Covers the /v1/usage deliverable without needing a live upstream call:
// logUsage() must fan usage out into the sessionUsage/modelUsage Maps that
// the /v1/usage handler in anthropic-proxy.js serializes verbatim, and
// deriveGenericSessionId() must accept the same header shape billing-mode's
// deriveSessionId does (so a client's session lines up across both modes)
// while falling back safely when no header is present.
//
// Run: node scripts/pha2194-usage-attribution-unit.js   (exit 0 = pass)

'use strict';

const path = require('path');
const assert = require('assert');

process.env.PROXY_PORT = '0';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const proxy = require(path.join(__dirname, '..', 'anthropic-proxy.js'));
const { logUsage, deriveGenericSessionId, sessionUsage, modelUsage } = proxy;

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// --- deriveGenericSessionId --------------------------------------------------
{
  assert.strictEqual(
    deriveGenericSessionId({ 'x-claude-code-session-id': 'abc123-def456-0000' }),
    'abc123-def456-0000',
    'well-formed x-claude-code-session-id must pass through'
  );
  assert.strictEqual(
    deriveGenericSessionId({ 'x-session-id': 'ABCDEF01-2345-6789' }),
    'ABCDEF01-2345-6789',
    'x-session-id is an accepted fallback header'
  );
  assert.strictEqual(deriveGenericSessionId({}), 'unknown', 'no headers -> unknown, never throws');
  assert.strictEqual(deriveGenericSessionId(null), 'unknown', 'null headers -> unknown, never throws');
  assert.strictEqual(
    deriveGenericSessionId({ 'x-session-id': 'short' }),
    'unknown',
    'malformed/too-short session id is rejected, not passed through raw'
  );
  ok('deriveGenericSessionId: header contract matches billing-mode.deriveSessionId');
}

// --- logUsage fans out into sessionUsage / modelUsage ------------------------
{
  const sid = 'pha2194-test-session-aaaa';
  sessionUsage.delete(sid);
  modelUsage.delete('claude-opus-4-6');

  logUsage('claude-opus-4-6', { input: 10, output: 5, cacheCreate: 0, cacheRead: 0 }, sid);
  let row = sessionUsage.get(sid);
  assert.ok(row, 'first logUsage call must create a session row');
  assert.strictEqual(row.totalReq, 1, 'first call -> totalReq 1');
  assert.strictEqual(row.model, 'claude-opus-4-6', 'session row records the model');
  assert.strictEqual(row.lastCacheRead, 0, 'no cache hit yet on probe 1');

  // Second request on the same session reports a cache hit.
  logUsage('claude-opus-4-6', { input: 10, output: 5, cacheCreate: 0, cacheRead: 8000 }, sid);
  row = sessionUsage.get(sid);
  assert.strictEqual(row.totalReq, 2, 'second call increments totalReq on the same session');
  assert.strictEqual(row.lastCacheRead, 8000, 'lastCacheRead reflects the most recent request, not a running sum');

  const modelRow = modelUsage.get('claude-opus-4-6');
  assert.ok(modelRow, 'logUsage must also roll up a byModel row');
  assert.strictEqual(modelRow.totalReq, 2, 'byModel totalReq sums across sessions on that model');
  assert.strictEqual(modelRow.cacheRead, 8000, 'byModel cacheRead sums across requests');
  ok('logUsage: session row updates in place, byModel accumulates');
}

// --- distinct sessions stay distinct ------------------------------------------
{
  sessionUsage.delete('sid-a');
  sessionUsage.delete('sid-b');
  logUsage('claude-haiku-4-5', { input: 1, output: 1, cacheCreate: 0, cacheRead: 0 }, 'sid-a');
  logUsage('claude-haiku-4-5', { input: 1, output: 1, cacheCreate: 0, cacheRead: 0 }, 'sid-b');
  assert.strictEqual(sessionUsage.get('sid-a').totalReq, 1, 'sid-a unaffected by sid-b traffic');
  assert.strictEqual(sessionUsage.get('sid-b').totalReq, 1, 'sid-b unaffected by sid-a traffic');
  ok('logUsage: concurrent sessions on the same model do not clobber each other');
}

// --- missing sessionId falls back to a single "unknown" bucket ---------------
{
  sessionUsage.delete('unknown');
  logUsage('claude-haiku-4-5', { input: 1, output: 1, cacheCreate: 0, cacheRead: 0 });
  assert.ok(sessionUsage.get('unknown'), 'undefined sessionId must not throw and must land in "unknown"');
  ok('logUsage: undefined sessionId is handled without throwing');
}

console.log(`pha2194 usage-attribution unit: ${pass} checks passed`);
process.exit(0);
