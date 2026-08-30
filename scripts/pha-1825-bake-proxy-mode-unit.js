#!/usr/bin/env node
// PHA-1825 regression: Dockerfile must bake PROXY_MODE=billing into the image
// so a bare `docker run` / unraid template recreate / compose up cannot
// silently fall back to PROXY_MODE=regular (the silent 5m cache_ttl failure
// mode from the 2026-08-07 incident).
//
// Three layers of test, all must pass:
//   1. Source-level Dockerfile check: ENV PROXY_MODE=billing line exists on
//      the merge commit (cf1dd862); orchestrator env still wins at runtime.
//   2. PHA-1611 source invariants: OAUTH_BETAS + REQUIRED_BETAS still carry
//      the TTL beta (regression — we are tightening defaults, not weakening
//      safety nets).
//   3. Published Docker image check: v1.5.9 (and later) image Config.Env
//      contains PROXY_MODE=billing when pulled from Docker Hub. This is the
//      end-to-end assertion — the thing that survives container recreation.
//
// Run: node scripts/pha-1825-bake-proxy-mode-unit.js [--image v1.5.9]
// Exits 0 if every assertion holds, 1 otherwise.

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const PROXY_DIR = path.resolve(__dirname, '..');
const IMAGE = (process.argv.find(a => a.startsWith('--image=')) || '--image=v1.5.9').split('=')[1];
const HUB_REPO = 'therealphatt/anthropic-proxy';

function readDockerfile() {
  return fs.readFileSync(path.join(PROXY_DIR, 'Dockerfile'), 'utf8');
}

function isBetaIncluded(src) {
  const match = src.match(/const OAUTH_BETAS = \[([\s\S]*?)\];/);
  if (!match) return false;
  const betas = [...match[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
  return betas.includes('extended-cache-ttl-2025-04-11');
}

function oauthHeadersJoinsOauth(src) {
  return /function oauthHeaders\(\)[\s\S]*?'anthropic-beta':\s*OAUTH_BETAS\.join\(','\)/.test(src);
}

function billingRequiredBetas() {
  const BILLING = require(path.join(PROXY_DIR, 'billing-mode.js'));
  return BILLING.REQUIRED_BETAS;
}

function currentCommit() {
  return execSync('git rev-parse HEAD', { cwd: PROXY_DIR }).toString().trim();
}

function assertEnvInDockerfile(dockerfile) {
  // The Dockerfile must set PROXY_MODE=billing, and only once (idempotency).
  const lines = dockerfile.split('\n').map(l => l.trim()).filter(l => l.startsWith('ENV PROXY_MODE'));
  if (lines.length === 0) return [false, 'ENV PROXY_MODE=* not present'];
  if (lines.length > 1) return [false, `ENV PROXY_MODE declared ${lines.length} times; expected 1`];
  if (lines[0] !== 'ENV PROXY_MODE=billing') {
    return [false, `ENV PROXY_MODE is "${lines[0]}", expected "ENV PROXY_MODE=billing"`];
  }
  return [true, `Dockerfile sets ${lines[0]}`];
}

function assertCommentAboveEnv(dockerfile) {
  // A comment block should explain the rationale above the ENV line, so the
  // next person to remove it understands why it exists.
  const lines = dockerfile.split('\n');
  const idx = lines.findIndex(l => l.trim().startsWith('ENV PROXY_MODE'));
  if (idx < 1) return [false, 'ENV PROXY_MODE line has no comment above it'];
  // Walk back through any number of comment lines (allow long rationale blocks).
  let scanEnd = idx;
  while (scanEnd > 0 && (lines[scanEnd - 1].trim().startsWith('#') || lines[scanEnd - 1].trim() === '')) {
    scanEnd--;
  }
  const above = lines.slice(scanEnd, idx).join('\n');
  if (!/PHA-?1825/i.test(above)) return [false, 'Comment above ENV PROXY_MODE does not reference PHA-1825'];
  if (!/billing/i.test(above)) return [false, 'Comment above ENV PROXY_MODE does not explain billing rationale'];
  return [true, 'PHA-1825 rationale comment present above ENV line'];
}

function fetchDockerHubAuthToken(repo) {
  return new Promise((resolve, reject) => {
    const url = `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull`;
    https.get(url, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body).token); }
        catch (e) { reject(new Error(`auth parse: ${body.slice(0, 200)}`)); }
      });
    }).on('error', reject);
  });
}

function fetchUrl(url, headers) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location, headers).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

async function fetchImageConfig(tag, repo, authToken) {
  const headers = {
    Authorization: `Bearer ${authToken}`,
    Accept: 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json',
  };
  const indexJson = JSON.parse((await fetchUrl(`https://registry-1.docker.io/v2/${repo}/manifests/${tag}`, headers)).toString('utf8'));
  const amd = (indexJson.manifests || []).find(m => m.platform && m.platform.architecture === 'amd64');
  if (!amd) throw new Error(`no amd64 manifest in tag ${tag}`);
  const amdManifest = JSON.parse((await fetchUrl(`https://registry-1.docker.io/v2/${repo}/manifests/${amd.digest}`, {
    ...headers, Accept: 'application/vnd.docker.distribution.manifest.v2+json',
  })).toString('utf8'));
  const configDigest = amdManifest.config.digest;
  const configBytes = await fetchUrl(`https://registry-1.docker.io/v2/${repo}/blobs/${configDigest}`, {
    Authorization: `Bearer ${authToken}`,
    Accept: 'application/vnd.oci.image.config.v1+json,application/vnd.docker.container.image.v1+json',
  });
  return JSON.parse(configBytes.toString('utf8'));
}

function assertImageEnv(cfg, tag) {
  const env = (cfg.config && cfg.config.Env) || [];
  const proxyMode = env.find(e => e.startsWith('PROXY_MODE='));
  const proxyVersion = env.find(e => e.startsWith('PROXY_VERSION='));
  if (!proxyMode) return [false, `image ${tag} Config.Env has no PROXY_MODE entry`];
  if (proxyMode !== 'PROXY_MODE=billing') return [false, `image ${tag} PROXY_MODE="${proxyMode}", expected "PROXY_MODE=billing"`];
  if (!proxyVersion) return [false, `image ${tag} Config.Env has no PROXY_VERSION entry`];
  if (proxyVersion !== `PROXY_VERSION=${tag}`) {
    return [false, `image ${tag} PROXY_VERSION="${proxyVersion}", expected "PROXY_VERSION=${tag}"`];
  }
  return [true, `image ${tag} Config.Env: PROXY_MODE=billing, PROXY_VERSION=${tag}`];
}

async function main() {
  const cases = [];
  const commit = currentCommit();

  // 1. Dockerfile on the working tree
  const dockerfile = readDockerfile();
  let ok, msg;
  [ok, msg] = assertEnvInDockerfile(dockerfile);
  cases.push(['Dockerfile bakes ENV PROXY_MODE=billing', ok, msg]);
  [ok, msg] = assertCommentAboveEnv(dockerfile);
  cases.push(['Dockerfile comment explains the rationale', ok, msg]);

  // 2. PHA-1611 invariants still hold
  const src = fs.readFileSync(path.join(PROXY_DIR, 'anthropic-proxy.js'), 'utf8');
  cases.push(['OAUTH_BETAS still contains extended-cache-ttl-2025-04-11', isBetaIncluded(src),
              isBetaIncluded(src) ? 'OAUTH_BETAS includes the TTL beta' : 'OAUTH_BETAS missing the TTL beta']);
  cases.push(["oauthHeaders() body uses OAUTH_BETAS.join(',')", oauthHeadersJoinsOauth(src),
              oauthHeadersJoinsOauth(src) ? 'oauthHeaders emits the joined beta list' : 'oauthHeaders stale literal detected']);
  const requiredBetas = billingRequiredBetas();
  cases.push(['billing REQUIRED_BETAS contains extended-cache-ttl-2025-04-11',
              requiredBetas.includes('extended-cache-ttl-2025-04-11'),
              requiredBetas.includes('extended-cache-ttl-2025-04-11') ? 'required_betas ok' : 'required_betas missing TTL beta']);

  // 3. Image config pull from Docker Hub
  try {
    const token = await fetchDockerHubAuthToken(HUB_REPO);
    const cfg = await fetchImageConfig(IMAGE, HUB_REPO, token);
    [ok, msg] = assertImageEnv(cfg, IMAGE);
    cases.push([`image ${IMAGE}: Config.Env bakes PROXY_MODE=billing`, ok, msg]);
  } catch (e) {
    cases.push([`image ${IMAGE}: Config.Env probe (network)`, false, `probe failed: ${e.message}`]);
  }

  let pass = 0, fail = 0;
  console.log(`# PHA-1825 bake-proxy-mode unit (commit ${commit.slice(0, 7)}, image ${IMAGE})`);
  for (const [name, ok, msg] of cases) {
    if (ok) { console.log(`[OK]   ${name}  --  ${msg}`); pass++; }
    else    { console.log(`[FAIL] ${name}  --  ${msg}`); fail++; }
  }
  console.log(`\npha-1825 bake-proxy-mode unit: ${pass} passed, ${fail} failed (commit ${commit}, image ${IMAGE})`);
  process.exit(fail ? 1 : 0);
}

main();
