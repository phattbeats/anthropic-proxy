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
// PHA-1887 made the real header opt-in (it drew an immediate 529 from Anthropic's
// edge — `x-anthropic-*` is their reserved request-header namespace). The PHA-1842
// behaviour this file covers is now BILLING_HEADER_MODE=header, so opt in here.
// The default-off guarantee is asserted separately in the child process below.
process.env.BILLING_HEADER_MODE = 'header';

const BILLING = require(path.join(__dirname, '..', 'billing-mode.js'));

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

const reqBody = JSON.stringify({
  model: 'claude-opus-4-1',
  system: [{ type: 'text', text: 'You are a helpful assistant.', cache_control: { type: 'ephemeral' } }],
  // Two breakpoints on purpose: Claude Code marks the system preamble AND the
  // conversation history, and the messages one sits after the entire system array.
  // Anything injected into `system` is inside that second prefix no matter where.
  messages: [
    { role: 'user', content: 'hello there' },
    { role: 'assistant', content: [{ type: 'text', text: 'hi', cache_control: { type: 'ephemeral' } }] },
    { role: 'user', content: 'and again' },
  ],
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

// --- 5. PHA-1887: both carriers work. `body` (the default) appends the
// fingerprint as the LAST system block, so it ships without moving any byte
// ahead of the client's cache_control breakpoint; `header` sends the reserved
// header but latches back to the body block on the first upstream 529 instead
// of failing every request. Run in child processes because BILLING_HEADER_MODE
// is read at module load.
{
  const { execFileSync } = require('child_process');
  const modPath = path.join(__dirname, '..', 'billing-mode.js');
  const probe = `
    const B = require(${JSON.stringify(modPath)});
    const body = ${JSON.stringify(reqBody)};
    const first = B.processBody(body, 's');
    B.setLastRequestId('req-id-999', 's');
    const second = B.processBody(body, 's');
    const out = {
      mode: B.billingHeaderMode,
      header: B.buildBillingHeaderValue(body, 's'),
      bodyHasBlock: first.includes('x-anthropic-billing-header'),
      // Everything up to (and including) the client's cached block must be
      // identical between the two calls even though cc_prev_req changed.
      prefixStable: first.slice(0, first.indexOf('"cache_control"'))
        === second.slice(0, second.indexOf('"cache_control"')),
      // The block must sit AFTER the system breakpoint, not before it.
      blockAfterBreakpoint: first.indexOf('x-anthropic-billing-header') > first.indexOf('"cache_control"'),
      // ...and, because message-level breakpoints all sit after the whole system
      // array, the block must additionally be byte-constant: the prefix up to the
      // LAST breakpoint has to be stable too, which appending alone cannot buy.
      lastBreakpointStable: first.slice(0, first.lastIndexOf('"cache_control"'))
        === second.slice(0, second.lastIndexOf('"cache_control"')),
      blockHasNoRotatingField: !first.includes('cc_prev_req') && !second.includes('cc_prev_req'),
      systemValid: (() => { try { return Array.isArray(JSON.parse(first).system); } catch (e) { return false; } })(),
    };
    B.noteUpstreamStatus(529);
    out.afterShed = {
      mode: B.billingHeaderMode,
      header: B.buildBillingHeaderValue(body, 's'),
      bodyHasBlock: B.processBody(body, 's').includes('x-anthropic-billing-header'),
    };
    console.log(JSON.stringify(out));
  `;
  const run = (mode) => {
    const env = { ...process.env, PROXY_MODE: 'billing', CC_VERSION: '2.1.205' };
    if (mode === null) delete env.BILLING_HEADER_MODE; else env.BILLING_HEADER_MODE = mode;
    const raw = execFileSync(process.execPath, ['-e', probe], { env, encoding: 'utf8' });
    return JSON.parse(raw.trim().split('\n').pop());
  };

  const dflt = run(null);
  assert.strictEqual(dflt.mode, 'body', 'default mode must be body');
  assert.strictEqual(dflt.header, null, 'default must not emit the reserved header');
  assert.strictEqual(dflt.bodyHasBlock, true, 'default must ship the fingerprint in the body');
  assert.strictEqual(dflt.systemValid, true, 'appended block must leave system a valid JSON array');
  ok('default (BILLING_HEADER_MODE unset) ships the fingerprint as a body block, no reserved header');

  assert.strictEqual(dflt.blockAfterBreakpoint, true,
    'fingerprint must be appended after the cache_control breakpoint, not prepended');
  assert.strictEqual(dflt.prefixStable, true,
    'cached prefix must be byte-identical across requests despite a changed cc_prev_req');
  ok('body mode keeps the cache prefix byte-stable — fingerprint and prompt cache both work');

  assert.strictEqual(dflt.blockHasNoRotatingField, true,
    'the body block must not carry cc_prev_req — it rotates every request');
  assert.strictEqual(dflt.lastBreakpointStable, true,
    'prefix up to the LAST (message-level) breakpoint must also be byte-identical');
  ok('body block is byte-constant, so message-level cache breakpoints survive too');

  const off = run('off');
  assert.strictEqual(off.header, null, 'off must not emit the reserved header');
  assert.strictEqual(off.bodyHasBlock, false, 'off must not inject the body block');
  ok('BILLING_HEADER_MODE=off still sends neither carrier');

  const hdr = run('header');
  assert.ok(hdr.header && hdr.header.startsWith('cc_version='), 'header mode must emit the header');
  assert.strictEqual(hdr.bodyHasBlock, false, 'header mode must not double-ship in the body');
  assert.strictEqual(hdr.afterShed.header, null, 'a 529 must latch the reserved header off');
  assert.strictEqual(hdr.afterShed.bodyHasBlock, true, 'after the latch the fingerprint must fall back to the body');
  assert.strictEqual(hdr.afterShed.mode, 'header(shed→body)', '/health must surface the latched state');
  ok('BILLING_HEADER_MODE=header degrades to the body block on the first 529 instead of failing');
}

console.log(`\npha-1842 cache-header unit: ${pass} passed, 0 failed`);
process.exit(0);
