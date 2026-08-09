#!/usr/bin/env node
// PHA-1842 regression: the billing fingerprint must go out as a real HTTP
// header, not as system[0] in the request body. Anthropic's prompt cache is
// prefix-based (tools -> system -> messages); an ever-changing system[0]
// (cc_prev_req changes every request, cc_version rotates every 6h) broke
// every cache_control breakpoint on every request. Covers:
//
//   1. processBody() output is byte-identical across two calls with the same
//      input even when the billing chain state (cc_prev_req) differs — the
//      system array must no longer carry the fingerprint block.
//   2. buildBillingHeaderValue() still produces the right cc_version/
//      cc_entrypoint/cc_prev_req shape, independent of the body.
//   3. cc_prev_req is now keyed per session (M3) — two sessions don't chain
//      into each other's prior request-id.
//   4. H1: the REVERSE_MAP/REPLACEMENTS 'external'/'third-party' and
//      'usage quota'/'extra usage' single-word swaps are gone, so genuine
//      model output using those common words round-trips unmodified.
//
// Run: node scripts/pha-1842-cache-header-unit.js

'use strict';

const path = require('path');
const assert = require('assert');

process.env.PROXY_MODE = 'billing';
process.env.OAUTH_TOKEN = process.env.OAUTH_TOKEN || 'sk-ant-oat-test-token';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const BILLING = require(path.join(__dirname, '..', 'billing-mode.js'));

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

const reqBody = JSON.stringify({
  model: 'claude-opus-4-1',
  system: [{ type: 'text', text: 'You are a helpful assistant.', cache_control: { type: 'ephemeral' } }],
  messages: [{ role: 'user', content: 'hello there' }],
});

// --- 1. processBody() body output is byte-stable across a changed cc_prev_req chain
{
  const out1 = BILLING.processBody(reqBody, 'session-a');
  BILLING.setLastRequestId('req-id-111', 'session-a');
  const out2 = BILLING.processBody(reqBody, 'session-a');
  assert.strictEqual(out1, out2, 'processBody output must not depend on LAST_REQUEST_ID state');
  assert.ok(!out1.includes('x-anthropic-billing-header'), 'body must not contain the billing header text');
  assert.ok(!out1.includes('cc_prev_req'), 'body must not contain cc_prev_req');
  ok('processBody output is byte-stable across requests (system array untouched)');
}

// --- 2. buildBillingHeaderValue shape
{
  const processed = BILLING.processBody(reqBody, 'session-b');
  const headerVal = BILLING.buildBillingHeaderValue(processed, 'session-b');
  assert.ok(/^cc_version=\d+\.\d+\.\d+\.[0-9a-f]{3}; cc_entrypoint=sdk-cli;$/.test(headerVal),
    `unexpected header shape (no prior request-id): ${headerVal}`);
  BILLING.setLastRequestId('req-id-222', 'session-b');
  const headerVal2 = BILLING.buildBillingHeaderValue(processed, 'session-b');
  assert.ok(headerVal2.includes('cc_prev_req=req-id-222;'), `expected cc_prev_req chained: ${headerVal2}`);
  ok('buildBillingHeaderValue() produces correct header shape and chains cc_prev_req');
}

// --- 3. cc_prev_req is keyed per session
{
  BILLING.setLastRequestId('req-session-x', 'session-x');
  BILLING.setLastRequestId('req-session-y', 'session-y');
  const hx = BILLING.buildBillingHeaderValue(reqBody, 'session-x');
  const hy = BILLING.buildBillingHeaderValue(reqBody, 'session-y');
  assert.ok(hx.includes('cc_prev_req=req-session-x;'), `session-x should chain its own prev req: ${hx}`);
  assert.ok(hy.includes('cc_prev_req=req-session-y;'), `session-y should chain its own prev req: ${hy}`);
  ok('cc_prev_req chains per-session, not across a shared global');
}

// --- 4. H1: genuine output containing common words round-trips unmodified
{
  const genuine = 'This uses an external API and may hit your usage quota depending on the plan.';
  const roundTripped = BILLING.reverseMap(genuine);
  assert.strictEqual(roundTripped, genuine, `genuine text corrupted by reverse-map: ${roundTripped}`);
  ok('reverseMap() no longer corrupts genuine text containing "external"/"usage quota"');
}

console.log(`\npha-1842 cache-header unit: ${pass} passed, 0 failed`);
process.exit(0);
