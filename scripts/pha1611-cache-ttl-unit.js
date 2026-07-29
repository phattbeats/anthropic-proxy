#!/usr/bin/env node
// PHA-1611 regression: the 1h cache-TTL beta must be present in BOTH header
// paths and the startup log must name it. Run with: node scripts/pha1611-cache-ttl-unit.js
//
// Fails closed if either list silently drops the TTL beta — that is the
// failure mode that motivated the issue (silent 5m fallback, no error).

const fs = require('fs');
const path = require('path');
const PROXY_DIR = path.resolve(__dirname, '..');
const BILLING = require(path.join(PROXY_DIR, 'billing-mode.js'));
const TTL_BETA = 'extended-cache-ttl-2025-04-11';

const src = fs.readFileSync(path.join(PROXY_DIR, 'anthropic-proxy.js'), 'utf8');
const cases = [];

// 1. OAUTH_BETAS list exists and contains the TTL beta.
const match = src.match(/const OAUTH_BETAS = \[([\s\S]*?)\];/);
if (!match) cases.push(['OAUTH_BETAS list defined', false]);
else {
  const betas = [...match[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
  cases.push(['OAUTH_BETAS contains ' + TTL_BETA, betas.includes(TTL_BETA)]);
}

// 2. oauthHeaders() emits OAUTH_BETAS.join(','), not a stale literal.
cases.push(["oauthHeaders() body uses OAUTH_BETAS.join(',')", /function oauthHeaders\(\)[\s\S]*?'anthropic-beta':\s*OAUTH_BETAS\.join\(','\)/.test(src)]);

// 3. billing-mode REQUIRED_BETAS still contains the TTL beta.
cases.push(['billing REQUIRED_BETAS contains ' + TTL_BETA, BILLING.REQUIRED_BETAS.includes(TTL_BETA)]);

// 4. billing-mode required-betas accessor is exported.
cases.push(['billing-mode exports REQUIRED_BETAS accessor', typeof BILLING.REQUIRED_BETAS !== 'undefined']);

// 5. Startup log line names the active beta + PROXY_MODE with present/MISSING.
cases.push(['Startup log line names the active beta', /Cache TTL beta: \$\{TTL_BETA\}/.test(src)]);

// 6. Loud FATAL assertion when the beta is missing.
cases.push(['FATAL-log assertion when beta missing', /FATAL: \$\{TTL_BETA\} not in active beta list/.test(src)]);

let pass = 0, fail = 0;
for (const [name, ok] of cases) {
  if (ok) { console.log('[OK]   ' + name); pass++; }
  else { console.log('[FAIL] ' + name); fail++; }
}
console.log(`\npha1611 cache-ttl unit: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
