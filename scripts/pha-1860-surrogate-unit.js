#!/usr/bin/env node
// PHA-1860: the billing-mode SSE transformer held back a tail of text by
// slicing a JS string at a fixed UTF-16 offset. When that offset landed inside
// a surrogate pair (any emoji / astral char) the emitted delta ended with a
// lone high surrogate, JSON.stringify encoded it as \udXXX, and strict UTF-8
// consumers (LiteLLM / pydantic-core) rejected the chunk with
//   "str is not valid UTF-8: surrogates not allowed"
// killing the stream mid-generation.
//
// This test drives the real transformer with emoji-heavy text at EVERY
// alignment and asserts: (1) no emitted JSON contains a lone surrogate, and
// (2) the concatenated text is byte-identical to the input (no truncation).
process.env.PROXY_MODE = 'billing';
const billing = require('../billing-mode');

const sse = (obj) => `event: ${obj.type}\ndata: ${JSON.stringify(obj)}\n\n`;

function collectText(out) {
  let text = '';
  for (const line of out.split('\n')) {
    if (!line.startsWith('data: ')) continue;
    const raw = line.slice(6).trim();
    if (!raw.startsWith('{')) continue;
    // A lone surrogate survives JSON.parse but cannot be encoded to UTF-8.
    if (/\\ud[89ab][0-9a-f]{2}(?!\\ud[c-f])/i.test(raw)) {
      throw new Error(`lone high surrogate in emitted event: ${raw}`);
    }
    if (Buffer.from(raw, 'utf8').includes(0xef) === false) { /* no-op */ }
    let ev;
    try { ev = JSON.parse(raw); } catch (_) { continue; }
    if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') text += ev.delta.text;
  }
  return text;
}

function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

let failures = 0;
const BODY = 'ok 🎉 done 🚀 and 😀 more 🧠 text 🔥 end';

// Sweep the split alignment by prefixing 0..40 filler chars, so the held-back
// tail boundary lands on every position including mid-surrogate-pair.
for (let pad = 0; pad <= 40; pad++) {
  const full = 'x'.repeat(pad) + BODY;
  const x = billing.createSSETransformer();
  let out = '';
  out += x.onData(Buffer.from(sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } })));
  // one char per event — worst case for the carry logic
  for (const ch of Array.from(full)) {
    out += x.onData(Buffer.from(sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ch } })));
  }
  out += x.onData(Buffer.from(sse({ type: 'content_block_stop', index: 0 })));
  out += x.onEnd();

  try {
    const got = collectText(out);
    if (hasLoneSurrogate(got)) throw new Error('lone surrogate in reassembled text');
    if (got !== full) throw new Error(`text mismatch:\n  want ${JSON.stringify(full)}\n  got  ${JSON.stringify(got)}`);
  } catch (e) {
    console.error(`FAIL pad=${pad}: ${e.message}`);
    failures++;
  }
}

// Abnormal end (no content_block_stop) must still flush the tail as a
// well-formed text_delta, not as a bare unparseable line.
{
  const x = billing.createSSETransformer();
  let out = '';
  out += x.onData(Buffer.from(sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } })));
  out += x.onData(Buffer.from(sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'tail end 🚀' } })));
  out += x.onEnd();
  const got = collectText(out);
  if (got !== 'tail end 🚀') {
    console.error(`FAIL abnormal-end: want "tail end 🚀", got ${JSON.stringify(got)}`);
    failures++;
  }
  for (const line of out.split('\n')) {
    if (line && !line.startsWith('data: ') && !line.startsWith('event: ')) {
      console.error(`FAIL abnormal-end: raw non-SSE line emitted: ${JSON.stringify(line)}`);
      failures++;
    }
  }
}

// Multi-byte characters split across TCP chunk boundaries must not corrupt.
{
  const x = billing.createSSETransformer();
  const buf = Buffer.from(
    sse({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }) +
    sse({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'split 🚀 here and more padding text' } }) +
    sse({ type: 'content_block_stop', index: 0 })
  );
  let out = '';
  for (let i = 0; i < buf.length; i++) out += x.onData(buf.subarray(i, i + 1));
  out += x.onEnd();
  const got = collectText(out);
  if (got !== 'split 🚀 here and more padding text') {
    console.error(`FAIL byte-split: got ${JSON.stringify(got)}`);
    failures++;
  }
}

if (failures) { console.error(`\n${failures} failure(s)`); process.exit(1); }
console.log('PHA-1860 surrogate/carry unit: PASS');
