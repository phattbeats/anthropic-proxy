#!/usr/bin/env node
// PHA-1848 (M6): billing-mode header passthrough must be an allowlist, not a
// denylist. Before this fix, buildBillingHeaders() copied every client header
// onto the outbound (proxy-OAuth-authenticated) request except a small
// denylist (host/connection/authorization/x-api-key/content-length/
// x-session-affinity). Any other header — including a spoofed authorization
// override under a different casing, a hostile x-api-key, a forged
// anthropic-beta, or an arbitrary custom header — rode along unfiltered.
//
// This test sends a battery of "hostile" headers a real attacker/client could
// set and verifies:
//   1. None of them survive into the headers actually sent upstream.
//   2. The legitimate, server-controlled headers (authorization built from the
//      proxy's OWN oauth token, anthropic-version, anthropic-beta, the
//      stainless/user-agent block) are still present and correct — i.e. the
//      fix does not break real traffic, it only stops raw copy-through.
//   3. The one thing billing mode legitimately derives from client headers —
//      the session-id hint — still works, because it is read + validated by
//      deriveSessionId(), not copied raw (that path is untouched by this fix
//      since BILLING_HEADER_ALLOWLIST intentionally excludes it too, but
//      getStainlessHeaders() re-derives it from deriveSessionId()).
//
// Run: node scripts/pha-1848-header-allowlist-unit.js

'use strict';

const path = require('path');
const assert = require('assert');

process.env.PROXY_MODE = 'billing';
process.env.OAUTH_TOKEN = process.env.OAUTH_TOKEN || 'sk-ant-oat-test-token';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const BILLING = require(path.join(__dirname, '..', 'billing-mode.js'));

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

const PROXY_OAUTH_TOKEN = 'sk-ant-oat-PROXY-REAL-TOKEN';

// --- 1. Hostile headers are dropped: none of them reach the outbound request ---
{
  const hostileHeaders = {
    // Attempted identity override — the whole point of the vuln. If this
    // leaked through unmodified case-sensitively it wouldn't even matter
    // (headers array below overwrites lowercase 'authorization' anyway,
    // proving the OLD code's denylist coverage on this one was accidental,
    // not structural) — but we also check odd casings and a bogus
    // x-api-key that the OLD code's denylist also caught, plus headers the
    // OLD denylist did NOT catch (the actual gap this fix closes).
    'authorization': 'Bearer attacker-token',
    'Authorization': 'Bearer attacker-token-2',
    'x-api-key': 'attacker-provided-key',
    // Headers the OLD denylist-based code did NOT block — these are the
    // real gap PHA-1848 closes:
    'anthropic-beta': 'attacker-injected-beta-flag',
    'anthropic-version': '1999-01-01',
    'user-agent': 'attacker-custom-agent/0.0.1',
    'x-app': 'attacker-app',
    'x-stainless-os': 'AttackerOS',
    'x-stainless-package-version': '0.0.0-attacker',
    'x-arbitrary-custom-header': 'anything-a-client-can-set',
    'accept-encoding': 'gzip', // would have broken reverse-map/SSE parsing too
  };

  const headers = BILLING.buildBillingHeaders(PROXY_OAUTH_TOKEN, hostileHeaders, 'test-session-hostile');

  assert.strictEqual(headers['authorization'], `Bearer ${PROXY_OAUTH_TOKEN}`,
    `authorization must be the proxy's own token, got: ${headers['authorization']}`);
  assert.notStrictEqual(headers['authorization'], 'Bearer attacker-token',
    'hostile authorization header must not survive');
  ok('hostile authorization/Authorization/x-api-key headers dropped; proxy OAuth identity used');

  assert.notStrictEqual(headers['anthropic-beta'], 'attacker-injected-beta-flag',
    'hostile anthropic-beta must not survive');
  assert.ok(headers['anthropic-beta'].includes('claude-code-20250219'),
    'anthropic-beta must be the proxy-controlled REQUIRED_BETAS list');
  ok('hostile anthropic-beta override dropped; genuine beta list enforced');

  assert.strictEqual(headers['anthropic-version'], '2023-06-01',
    `hostile anthropic-version override must not survive, got: ${headers['anthropic-version']}`);
  ok('hostile anthropic-version override dropped');

  assert.notStrictEqual(headers['user-agent'], 'attacker-custom-agent/0.0.1',
    'hostile user-agent must not survive');
  assert.ok(headers['user-agent'].includes('claude-cli'),
    `user-agent must be the proxy-controlled stainless value, got: ${headers['user-agent']}`);
  ok('hostile user-agent override dropped; genuine stainless user-agent used');

  assert.notStrictEqual(headers['x-app'], 'attacker-app', 'hostile x-app must not survive');
  assert.strictEqual(headers['x-app'], 'cli', 'x-app must be the proxy-controlled value');
  ok('hostile x-app override dropped');

  assert.notStrictEqual(headers['x-stainless-os'], 'AttackerOS', 'hostile x-stainless-os must not survive');
  assert.notStrictEqual(headers['x-stainless-package-version'], '0.0.0-attacker',
    'hostile x-stainless-package-version must not survive');
  ok('hostile x-stainless-* overrides dropped; genuine stainless block used');

  assert.strictEqual(headers['x-arbitrary-custom-header'], undefined,
    'arbitrary client header must not be forwarded at all');
  ok('arbitrary unknown client header not forwarded (allowlist, not denylist)');

  assert.strictEqual(headers['accept-encoding'], 'identity',
    `hostile accept-encoding override must not survive, got: ${headers['accept-encoding']}`);
  ok('hostile accept-encoding override dropped; identity encoding enforced (SSE/reverse-map dependency)');
}

// --- 2. Legitimate traffic still works: expected headers are present and correct ---
{
  const legitimateClientHeaders = {
    'content-type': 'application/json',
    'x-claude-code-session-id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  };
  const headers = BILLING.buildBillingHeaders(PROXY_OAUTH_TOKEN, legitimateClientHeaders, null);

  assert.strictEqual(headers['authorization'], `Bearer ${PROXY_OAUTH_TOKEN}`);
  assert.strictEqual(headers['anthropic-version'], '2023-06-01');
  assert.strictEqual(headers['accept-encoding'], 'identity');
  assert.ok(headers['anthropic-beta'] && headers['anthropic-beta'].length > 0,
    'anthropic-beta must be populated');
  assert.ok(headers['user-agent'] && headers['user-agent'].includes('claude-cli'),
    'user-agent must be populated with genuine stainless value');
  assert.strictEqual(headers['x-app'], 'cli');
  assert.ok(headers['x-stainless-arch'], 'x-stainless-arch must be populated');
  assert.ok(headers['x-stainless-lang'], 'x-stainless-lang must be populated');
  assert.ok(headers['x-stainless-os'], 'x-stainless-os must be populated');
  // The legitimate session-id hint IS honored — via deriveSessionId()'s
  // regex-validated read, re-emitted as the canonical header — not via raw
  // copy-through.
  assert.strictEqual(headers['x-claude-code-session-id'], 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    'valid client session-id hint should still be honored via deriveSessionId(), not raw copy');
  ok('legitimate request still produces a complete, correct outbound header set');
  ok('valid session-id hint still flows through via validated deriveSessionId(), not raw header copy');
}

// --- 3. Explicit sessionId param still wins over header-derived one (unchanged behavior) ---
{
  const headers = BILLING.buildBillingHeaders(PROXY_OAUTH_TOKEN, {}, 'explicit-session-id');
  assert.strictEqual(headers['x-claude-code-session-id'], 'explicit-session-id');
  ok('explicit sessionId argument still takes precedence over header-derived one');
}

// --- 4. No accidental content-length/host/connection leakage (regression, old denylist items) ---
{
  const headers = BILLING.buildBillingHeaders(PROXY_OAUTH_TOKEN, {
    host: 'attacker.example.com',
    connection: 'keep-alive',
    'content-length': '99999',
    'x-session-affinity': 'evil-affinity-id',
  }, 'test-session-2');
  assert.strictEqual(headers['host'], undefined);
  assert.strictEqual(headers['connection'], undefined);
  assert.strictEqual(headers['content-length'], undefined);
  assert.strictEqual(headers['x-session-affinity'], undefined);
  ok('previously-denylisted headers (host/connection/content-length/x-session-affinity) still absent');
}

console.log(`\npha-1848 header-allowlist unit: ${pass} passed, 0 failed`);
process.exit(0);
