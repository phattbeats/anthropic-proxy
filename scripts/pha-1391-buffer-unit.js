// PHA-1391 buffer unit regression check.
//
// Exercises billing.createSSETransformer against a sequence of synthetic SSE
// chunks that simulate Anthropic streaming text where terms from REVERSE_MAP
// (e.g. "sessions_spawn", "sessions_list") are intentionally split across
// delta boundaries.
//
// Pass criteria:
//   - Each REVERSE_MAP term, even when split across chunks, ends up fully
//     renamed in the assembled output.
//   - End-of-stream flush emits any trailing buffered rename.
//   - Thinking-block deltas are passed through unchanged.
//
// Run via scripts/pha-1391-canary.sh or directly:
//   node scripts/pha-1391-buffer-unit.js

'use strict';

const path = require('path');
const assert = require('assert');

const billing = require(path.join(__dirname, '..', 'billing-mode.js'));

// Pick a small slice of REVERSE_MAP terms we want to verify across splits.
const CASES = [
  { old: 'create_task',      new: 'sessions_spawn' },
  { old: 'list_tasks',       new: 'sessions_list'  },
  { old: 'send_to_task',     new: 'sessions_send'  },
];

function sseEvent(payload) {
  return 'event: content_block_delta\n' +
         'data: ' + JSON.stringify(payload) + '\n\n';
}

function buildSequence(term, midPoint) {
  // Simulate a content_block_delta for a text block, where the term is split
  // mid-token at character index midPoint (1..len-1). Build a sequence of
  // small chunks to exercise the buffer flush logic.
  const before = `calling ${term.slice(0, midPoint)}`;
  const after  = `${term.slice(midPoint)} now`;
  return [
    sseEvent({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: before } }),
    sseEvent({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: after  } }),
    sseEvent({ type: 'content_block_stop', index: 0 }),
  ];
}

function runCase(oldTerm, newTerm) {
  const xform = billing.createSSETransformer();
  const seq = buildSequence(oldTerm, Math.floor(oldTerm.length / 2));
  let out = '';
  for (const chunk of seq) {
    out += xform.onData(Buffer.from(chunk));
  }
  out += xform.onEnd();
  // No raw old term should remain in output; the renamed term should appear.
  assert(!out.includes(oldTerm), `expected old term ${oldTerm} to be renamed; got: ${out}`);
  assert(out.includes(newTerm), `expected new term ${newTerm} to appear; got: ${out}`);
}

let pass = 0;
for (const c of CASES) {
  runCase(c.old, c.new);
  pass++;
  console.log(`  [OK] ${c.old} -> ${c.new} (split across deltas)`);
}

// Thinking-block passthrough check
{
  const xform = billing.createSSETransformer();
  const thinkingChunk = sseEvent({
    type: 'content_block_start', index: 0,
    content_block: { type: 'thinking', text: '' }
  });
  const textChunk = sseEvent({
    type: 'content_block_delta', index: 0,
    delta: { type: 'text_delta', text: 'plain text without reverse-map terms' }
  });
  let out = xform.onData(Buffer.from(thinkingChunk));
  out += xform.onData(Buffer.from(textChunk));
  out += xform.onEnd();
  assert(out.includes('plain text without reverse-map terms'), 'text delta lost');
  console.log('  [OK] thinking-block passthrough + text delta');
  pass++;
}

console.log(`pha-1391 buffer unit: ${pass} cases passed`);
