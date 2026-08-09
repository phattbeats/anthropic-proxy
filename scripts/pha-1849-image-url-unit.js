#!/usr/bin/env node
// PHA-1849 (M4): OpenAI image_url → Anthropic image block translation.
//
// Before the fix, mapOpenAIContentParts only handled type === 'text' and fell
// every other part through unchanged. image_url parts reached Anthropic as
// {type:'image_url', image_url:{url:'data:...'}}, which Anthropic rejects
// with a 400 (it expects {type:'image', source:{type:'base64'|'url', ...}}).
//
// This test verifies the translation rules from the issue:
//   1. data: URL  → {type:'image', source:{type:'base64', media_type, data}}
//   2. http(s) URL → {type:'image', source:{type:'url', url}} (warns about reachability)
//   3. anything else → log once per type, skip
//
// Run: node scripts/pha-1849-image-url-unit.js   (exit 0 = pass, non-zero = fail)

'use strict';

const path = require('path');
const assert = require('assert');

// Bind ephemeral so requiring the proxy doesn't collide with a running instance.
process.env.PROXY_PORT = '0';

const proxy = require(path.join(__dirname, '..', 'anthropic-proxy.js'));
const { mapOpenAIContentParts, openAIToAnthropic } = proxy;

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// Capture [PROXY] log lines so we can assert on the warnings.
const origLog = console.log;
const logLines = [];
console.log = (...args) => { logLines.push(args.map(String).join(' ')); };
function resetLogs() { logLines.length = 0; }
function restoreLog() { console.log = origLog; }

// --- Test 1: data: URL → base64 image block (the spec's required test) ---
{
  resetLogs();
  const out = mapOpenAIContentParts([
    { type: 'text', text: 'hi' },
    { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'text', text: 'hi' },
    { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } },
  ], `unexpected translation: ${JSON.stringify(out)}`);
  ok('data: URL → base64 image block (text + image mixed)');
}

// --- Test 2: http URL → URL source passthrough (the spec's required test) ---
{
  resetLogs();
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'http://example.com/cat.png' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'url', url: 'http://example.com/cat.png' } },
  ], `unexpected http translation: ${JSON.stringify(out)}`);
  assert.ok(
    logLines.some(l => l.includes('PROXY') && l.includes('http://example.com/cat.png')),
    `expected a warning for the URL passthrough; got: ${JSON.stringify(logLines)}`,
  );
  ok('http URL → URL source (warns about reachability)');
}

// --- Test 3: https URL → URL source passthrough ---
{
  resetLogs();
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'https://cdn.example.com/photo.jpg' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'url', url: 'https://cdn.example.com/photo.jpg' } },
  ], `unexpected https translation: ${JSON.stringify(out)}`);
  ok('https URL → URL source');
}

// --- Test 4: data: URL without ;base64 marker (raw base64) ---
{
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'data:image/jpeg,BBBB' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: 'BBBB' } },
  ], `unexpected raw-base64 translation: ${JSON.stringify(out)}`);
  ok('data: URL without ;base64 marker still parses media_type');
}

// --- Test 5: data: URL with multiple media parameters ---
{
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'data:image/webp;charset=binary;base64,CCCC' } },
  ]);
  // media_type is the header before the first ';' — encoding markers like
  // charset=binary;base64 are dropped, which is what Anthropic's base64
  // source implicitly expects.
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'base64', media_type: 'image/webp', data: 'CCCC' } },
  ], `unexpected multi-param translation: ${JSON.stringify(out)}`);
  ok('data: URL with charset param: media_type parsed before first ";"');
}

// --- Test 6: string content passes through unchanged ---
{
  const out = mapOpenAIContentParts('hello');
  assert.strictEqual(out, 'hello');
  ok('string content passes through unchanged');
}

// --- Test 7: text-only array passes through ---
{
  const out = mapOpenAIContentParts([{ type: 'text', text: 'plain' }]);
  assert.deepStrictEqual(out, [{ type: 'text', text: 'plain' }]);
  ok('text-only array passes through');
}

// --- Test 8: cache_control on text parts is preserved ---
{
  const out = mapOpenAIContentParts([
    { type: 'text', text: 'with cache', cache_control: { type: 'ephemeral' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'text', text: 'with cache', cache_control: { type: 'ephemeral' } },
  ], `text cache_control lost: ${JSON.stringify(out)}`);
  ok('cache_control on text parts is preserved');
}

// --- Test 9: multiple images in one message (base64 + URL mixed) ---
{
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'data:image/png;base64,AAA' } },
    { type: 'image_url', image_url: { url: 'https://x.example/2.png' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAA' } },
    { type: 'image', source: { type: 'url', url: 'https://x.example/2.png' } },
  ], `unexpected multi-image translation: ${JSON.stringify(out)}`);
  ok('multiple images in one message: base64 + URL pass through');
}

// --- Test 10: image-only message (no text) ---
{
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'data:image/gif;base64,DDDD' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'image', source: { type: 'base64', media_type: 'image/gif', data: 'DDDD' } },
  ]);
  ok('image-only message (no text part) translates cleanly');
}

// --- Test 11: unsupported types log once per type, skip silently on subsequent ---
{
  resetLogs();
  // 3 audio parts (one type, multiple parts) — should warn exactly once.
  mapOpenAIContentParts([
    { type: 'audio', audio: 'x' },
    { type: 'audio', audio: 'x' },
    { type: 'audio', audio: 'x' },
  ]);
  // 2 file:// image_url parts (type: image_url) — should warn exactly once.
  mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'file:///etc/passwd' } },
    { type: 'image_url', image_url: { url: 'file:///etc/shadow' } },
  ]);
  // 1 malformed data URL image_url (type: image_url — already in the set, no log).
  mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'data:image/png;base64' } },
  ]);
  // 2 video parts (type: video) — should warn exactly once.
  mapOpenAIContentParts([
    { type: 'video', video: 'x' },
    { type: 'video', video: 'x' },
  ]);

  const audioWarns = logLines.filter(l => l.includes('ignoring unsupported OpenAI content part: audio'));
  const videoWarns = logLines.filter(l => l.includes('ignoring unsupported OpenAI content part: video'));
  const imageUrlWarns = logLines.filter(l => l.includes('ignoring unsupported OpenAI content part: image_url'));

  assert.strictEqual(audioWarns.length, 1, `audio: expected 1 warning, got ${audioWarns.length}: ${JSON.stringify(logLines)}`);
  assert.strictEqual(videoWarns.length, 1, `video: expected 1 warning, got ${videoWarns.length}: ${JSON.stringify(logLines)}`);
  assert.strictEqual(imageUrlWarns.length, 1, `image_url: expected 1 warning, got ${imageUrlWarns.length}: ${JSON.stringify(logLines)}`);

  ok('unsupported types: log once per type, skip silently on subsequent occurrences');
}

// --- Test 12: image_url variants (unknown scheme, malformed, missing url) return [] ---
{
  resetLogs();
  const out = mapOpenAIContentParts([
    { type: 'image_url', image_url: { url: 'ftp://server/file.png' } },
    { type: 'image_url', image_url: { url: 'data:image/png;base64' } }, // no comma
    { type: 'image_url', image_url: {} }, // missing url
    { type: 'image_url' }, // missing image_url
  ]);
  assert.deepStrictEqual(out, [], `expected empty output for invalid image_url variants, got: ${JSON.stringify(out)}`);
  ok('image_url with unknown scheme / malformed data / missing fields → skipped');
}

// --- Test 13: end-to-end via openAIToAnthropic with image_url mixed in user msg ---
{
  const reqBody = JSON.stringify({
    model: 'claude-sonnet-4-5',
    messages: [{ role: 'user', content: [
      { type: 'text', text: 'what is in this image?' },
      { type: 'image_url', image_url: { url: 'data:image/png;base64,iVBORw0K' } },
    ] }],
  });
  const out = JSON.parse(openAIToAnthropic(reqBody, false));
  assert.strictEqual(out.messages[0].role, 'user');
  assert.deepStrictEqual(out.messages[0].content, [
    { type: 'text', text: 'what is in this image?' },
    { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0K' } },
  ], `unexpected end-to-end translation: ${JSON.stringify(out.messages[0].content)}`);
  ok('end-to-end: openAIToAnthropic translates image_url mixed with text');
}

// --- Test 14: mapOpenAIContentParts works as inner translator for arbitrary roles ---
{
  // It's called from convertOpenAIMessage for both `user` and `tool` roles.
  // The function shouldn't care about role; it just translates content.
  const out = mapOpenAIContentParts([
    { type: 'text', text: 'result' },
    { type: 'image_url', image_url: { url: 'https://example.com/screenshot.png' } },
  ]);
  assert.strictEqual(out.length, 2);
  assert.strictEqual(out[0].type, 'text');
  assert.strictEqual(out[1].type, 'image');
  ok('mapOpenAIContentParts works as inner translator for any role');
}

// --- Test 15: null / undefined / non-array content returns empty string ---
{
  assert.strictEqual(mapOpenAIContentParts(null), '');
  assert.strictEqual(mapOpenAIContentParts(undefined), '');
  assert.strictEqual(mapOpenAIContentParts({}), '');
  assert.strictEqual(mapOpenAIContentParts(42), '');
  ok('null / undefined / non-array / non-string content returns empty string');
}

// --- Test 16: null part entries in the array are skipped safely ---
{
  const out = mapOpenAIContentParts([
    null,
    { type: 'text', text: 'after-null' },
    undefined,
    { type: 'image_url', image_url: { url: 'data:image/png;base64,ZZ' } },
  ]);
  assert.deepStrictEqual(out, [
    { type: 'text', text: 'after-null' },
    { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'ZZ' } },
  ], `unexpected output with null parts: ${JSON.stringify(out)}`);
  ok('null / undefined entries in the array are skipped safely');
}

restoreLog();
console.log(`\npha-1849 image-url unit: ${pass} passed, 0 failed`);
process.exit(0);
