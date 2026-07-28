#!/usr/bin/env node
// PHA-1596 follow-up: cache_control survival across every convertOpenAIMessage shape.
//
// v1.4.9 fixed the system / text-part / tools paths but left convertOpenAIMessage's
// rebuilt shapes dropping the marker:
//
//   * assistant messages carrying BOTH content and tool_calls (the known gap)
//   * `tool` role messages, rebuilt as tool_result
//   * any message whose marker sits on the message object rather than a content part
//     (OpenAI's wire format has no cache_control, so clients put it in either place)
//
// A dropped breakpoint is silent: the request succeeds and the whole prefix is
// re-billed as fresh input. These checks are the only thing that catches it.
//
// Run: node scripts/pha1596b-translate-unit.js   (exit 0 = pass, non-zero = fail)

'use strict';

const path = require('path');
const assert = require('assert');

// Requiring the proxy boots its HTTP server and version poller — bind ephemeral
// and pin the version so this never collides with a running proxy or hits npm.
process.env.PROXY_PORT = '0';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const { openAIToAnthropic, capCacheControl } = require(path.join(__dirname, '..', 'anthropic-proxy.js'));

const EPH = { type: 'ephemeral' };
let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }
const convert = (messages, extra) => JSON.parse(openAIToAnthropic(JSON.stringify({
  model: 'claude-sonnet-4-5', messages, ...extra,
}), false));

// --- the known gap: assistant with content + tool_calls -----------------------
{
  const out = convert([
    { role: 'user', content: 'go' },
    {
      role: 'assistant',
      content: 'Looking that up.',
      tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'search', arguments: '{"q":"cs2"}' } }],
      cache_control: EPH,
    },
  ]);
  const blocks = out.messages[1].content;
  assert.strictEqual(blocks.length, 2, 'text + tool_use blocks');
  assert.strictEqual(blocks[0].type, 'text');
  assert.strictEqual(blocks[1].type, 'tool_use');
  // The marker goes on the LAST block: cache_control caches through its own
  // block, and a message-level marker means "cache through the end of this turn".
  assert.deepStrictEqual(blocks[1].cache_control, EPH, 'breakpoint must land on the last block');
  assert.strictEqual(blocks[0].cache_control, undefined, 'exactly one breakpoint per message');
  // The tool call itself must survive intact.
  assert.strictEqual(blocks[1].id, 'call_1');
  assert.strictEqual(blocks[1].name, 'search');
  assert.deepStrictEqual(blocks[1].input, { q: 'cs2' });
  ok('assistant with content + tool_calls: message-level marker preserved');
}

// Same shape, marker on a content part instead of the message.
{
  const out = convert([
    { role: 'user', content: 'go' },
    {
      role: 'assistant',
      content: [{ type: 'text', text: 'Looking that up.', cache_control: EPH }],
      tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'search', arguments: '{}' } }],
    },
  ]);
  const blocks = out.messages[1].content;
  assert.deepStrictEqual(blocks[blocks.length - 1].cache_control, EPH, 'part-level marker must survive too');
  ok('assistant with content + tool_calls: part-level marker preserved');
}

// Tool-call-only assistant turn (no content) still takes the marker.
{
  const out = convert([
    { role: 'user', content: 'go' },
    {
      role: 'assistant',
      tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'search', arguments: 'not json' } }],
      cache_control: EPH,
    },
  ]);
  const blocks = out.messages[1].content;
  assert.strictEqual(blocks.length, 1, 'no empty text block when content is absent');
  assert.deepStrictEqual(blocks[0].cache_control, EPH, 'marker lands on the tool_use block');
  assert.deepStrictEqual(blocks[0].input, {}, 'unparseable arguments still degrade to {}');
  ok('assistant with tool_calls only: marker on the tool_use block');
}

// --- tool role → tool_result --------------------------------------------------
{
  const out = convert([
    { role: 'user', content: 'go' },
    { role: 'assistant', tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'search', arguments: '{}' } }] },
    { role: 'tool', tool_call_id: 'call_1', content: 'results here', cache_control: EPH },
  ]);
  const block = out.messages[2].content[0];
  assert.strictEqual(block.type, 'tool_result');
  assert.strictEqual(block.tool_use_id, 'call_1');
  assert.strictEqual(block.content, 'results here');
  assert.deepStrictEqual(block.cache_control, EPH, 'tool_result must keep the breakpoint');
  ok('tool role: marker preserved on tool_result');
}

// A marker nested inside tool_result content is hoisted to the tool_result block:
// capCacheControl only walks top-level blocks, so a nested one would be
// uncounted and could push the request past Anthropic's max of 4.
{
  const out = convert([
    { role: 'user', content: 'go' },
    { role: 'assistant', tool_calls: [{ id: 'c1', type: 'function', function: { name: 's', arguments: '{}' } }] },
    { role: 'tool', tool_call_id: 'c1', content: [{ type: 'text', text: 'results', cache_control: EPH }] },
  ]);
  const block = out.messages[2].content[0];
  assert.deepStrictEqual(block.cache_control, EPH, 'hoisted onto the tool_result');
  assert.strictEqual(block.content[0].cache_control, undefined, 'nested marker removed');
  assert.strictEqual(block.content[0].text, 'results', 'nested content otherwise untouched');
  ok('tool role: nested marker hoisted where the 4-cap can see it');
}

// --- plain messages -----------------------------------------------------------
{
  const out = convert([{ role: 'user', content: 'a long prefix', cache_control: EPH }]);
  const content = out.messages[0].content;
  assert.ok(Array.isArray(content), 'a string cannot hold a marker — promote to a text block');
  assert.deepStrictEqual(content, [{ type: 'text', text: 'a long prefix', cache_control: EPH }]);
  ok('user string content: promoted to a marked text block');
}

{
  const out = convert([{
    role: 'user',
    content: [{ type: 'text', text: 'one' }, { type: 'text', text: 'two' }],
    cache_control: EPH,
  }]);
  const content = out.messages[0].content;
  assert.strictEqual(content.length, 2);
  assert.strictEqual(content[0].cache_control, undefined);
  assert.deepStrictEqual(content[1].cache_control, EPH, 'message-level marker lands on the last part');
  ok('user array content: message-level marker lands on the last block');
}

// Part-level markers already worked (v1.4.9) — guard against a regression, and
// make sure a message-level marker does not add a *second* breakpoint.
{
  const out = convert([{
    role: 'user',
    content: [{ type: 'text', text: 'one', cache_control: EPH }, { type: 'text', text: 'two' }],
    cache_control: EPH,
  }]);
  const content = out.messages[0].content;
  const markers = content.filter(b => b.cache_control).length;
  assert.strictEqual(markers, 1, 'never two breakpoints for one message');
  assert.deepStrictEqual(content[0].cache_control, EPH, 'the specific part-level marker wins');
  ok('part-level marker wins and is not duplicated');
}

// --- no marker anywhere: output must be byte-identical to the old translator ---
{
  const messages = [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'hi' },
    { role: 'assistant', content: 'sure', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'f', arguments: '{"a":1}' } }] },
    { role: 'tool', tool_call_id: 'c1', content: 'r' },
    { role: 'user', content: [{ type: 'text', text: 'again' }] },
  ];
  const out = convert(messages);
  assert.strictEqual(JSON.stringify(out).includes('cache_control'), false, 'no marker invented');
  assert.deepStrictEqual(out.messages[0].content, 'hi', 'unmarked string content stays a plain string');
  assert.deepStrictEqual(out.messages[1].content, [
    { type: 'text', text: 'sure' },
    { type: 'tool_use', id: 'c1', name: 'f', input: { a: 1 } },
  ], 'unmarked assistant+tool_calls shape unchanged');
  // tool_result is a `user` turn, so it merges with the user message after it.
  assert.deepStrictEqual(out.messages[2].content, [
    { type: 'tool_result', tool_use_id: 'c1', content: 'r' },
    { type: 'text', text: 'again' },
  ], 'unmarked tool_result shape unchanged, and role merging still applies');
  ok('no marker: translation output unchanged');
}

// --- system prompt: stable prefix and dynamic suffix stay separate blocks ------
{
  // The shape OpenClaw sends: it splits its system prompt at OPENCLAW_CACHE_BOUNDARY
  // and marks only the stable half. Joining the two into one block moved the
  // breakpoint past the volatile half, so the biggest block in the request missed
  // cache on every single turn.
  const out = convert([
    { role: 'system', content: [
      { type: 'text', text: 'STABLE PREAMBLE', cache_control: EPH },
      { type: 'text', text: 'dynamic: 03:41:07' },
    ] },
    { role: 'user', content: 'hi' },
  ]);
  assert.strictEqual(out.system.length, 2, 'system parts must not be joined');
  assert.strictEqual(out.system[0].text, 'STABLE PREAMBLE');
  assert.deepStrictEqual(out.system[0].cache_control, EPH, 'breakpoint stays on the stable prefix');
  assert.strictEqual(out.system[1].text, 'dynamic: 03:41:07');
  assert.strictEqual(out.system[1].cache_control, undefined, 'the volatile half stays outside the cache');
  ok('system prompt: stable/dynamic split preserved');
}

{
  const out = convert([
    { role: 'system', content: [{ type: 'text', text: 'a' }, { type: 'text', text: '' }, { type: 'text', text: 'b' }], cache_control: EPH },
    { role: 'user', content: 'hi' },
  ]);
  assert.strictEqual(out.system.length, 2, 'empty text parts dropped — Anthropic rejects them');
  assert.strictEqual(out.system[0].cache_control, undefined);
  assert.deepStrictEqual(out.system[1].cache_control, EPH, 'message-level marker lands on the last system block');
  ok('system prompt: empty parts dropped, message-level marker on the last block');
}

// --- the new markers are counted by the 4-cap ---------------------------------
{
  const messages = [{ role: 'system', content: 'sys', cache_control: EPH }];
  // 10 more breakpoints across the shapes this patch touches → 11 total, cap to 4.
  for (let i = 0; i < 5; i++) {
    messages.push({ role: 'user', content: `u${i}`, cache_control: EPH });
    messages.push({
      role: 'assistant', content: `a${i}`, cache_control: EPH,
      tool_calls: [{ id: `c${i}`, type: 'function', function: { name: 'f', arguments: '{}' } }],
    });
  }
  const capped = capCacheControl(convert(messages));
  const markers = JSON.stringify(capped).split('"cache_control"').length - 1;
  assert.strictEqual(markers, 4, 'capCacheControl must see the new markers and cap at 4');
  assert.deepStrictEqual(capped.system[0].cache_control, EPH, 'the system breakpoint survives');
  ok('new markers are visible to the 4-breakpoint cap');
}

console.log(`pha1596b translate unit: ${pass} checks passed`);
process.exit(0);
