#!/usr/bin/env node
// PHA-1596 cache-usage unit check.
//
// Two regressions are covered:
//
//   1. Anthropic reports cached prompt tokens in cache_creation_input_tokens /
//      cache_read_input_tokens, which are NOT included in input_tokens. The proxy
//      used to read only input_tokens/output_tokens, so every cached request
//      looked ~free in the logs and reported a wrong prompt_tokens to OpenAI
//      clients. extractUsage/mergeUsage/openAIUsage + makeSSEUsageWatcher must
//      carry all four counters, and the cache counters (which only arrive on
//      message_start) must survive the later message_delta.
//
//   2. openAIToAnthropic rebuilt system blocks, text content parts and tools from
//      scratch and dropped any client-supplied cache_control — so a client
//      talking OpenAI to the proxy got zero prompt caching. Those markers must
//      pass through, and capCacheControl must still cap them at Anthropic's
//      hard maximum of 4.
//
// Run: node scripts/pha1596-usage-unit.js   (exit 0 = pass, non-zero = fail)

'use strict';

const path = require('path');
const assert = require('assert');

// Requiring the proxy also boots its HTTP server and its Claude Code version
// poller. Bind to an ephemeral port and pin the version so this script never
// collides with a running proxy or reaches out to the npm registry; the
// explicit process.exit at the end drops the listening handle.
process.env.PROXY_PORT = '0';
process.env.CC_VERSION = process.env.CC_VERSION || '2.1.205';

const proxy = require(path.join(__dirname, '..', 'anthropic-proxy.js'));
const { extractUsage, mergeUsage, openAIUsage, makeSSEUsageWatcher, openAIToAnthropic, capCacheControl } = proxy;

let pass = 0;
function ok(label) { pass++; console.log(`  [OK] ${label}`); }

// --- extractUsage ------------------------------------------------------------
{
  assert.deepStrictEqual(extractUsage(null), {
    input: 0, output: 0, cacheCreate: 0, cacheRead: 0, cache5m: 0, cache1h: 0,
  }, 'missing usage should normalize to zeros');
  assert.deepStrictEqual(extractUsage(undefined).input, 0, 'undefined usage should not throw');

  assert.deepStrictEqual(extractUsage({
    input_tokens: 11,
    output_tokens: 22,
    cache_creation_input_tokens: 3300,
    cache_read_input_tokens: 44000,
    cache_creation: { ephemeral_5m_input_tokens: 300, ephemeral_1h_input_tokens: 3000 },
  }), {
    input: 11, output: 22, cacheCreate: 3300, cacheRead: 44000, cache5m: 300, cache1h: 3000,
  }, 'all four counters + ttl split must be extracted');
  ok('extractUsage: nulls, zeros and full cache payload');
}

// --- mergeUsage --------------------------------------------------------------
{
  const start = extractUsage({
    input_tokens: 10,
    cache_creation_input_tokens: 500,
    cache_read_input_tokens: 9000,
    cache_creation: { ephemeral_1h_input_tokens: 500 },
  });
  // message_delta reports output only, and omits every cache field.
  const delta = extractUsage({ output_tokens: 77 });
  const merged = mergeUsage(start, delta);
  assert.strictEqual(merged.output, 77, 'delta output must win');
  assert.strictEqual(merged.input, 10, 'message_start input must survive the delta');
  assert.strictEqual(merged.cacheCreate, 500, 'cacheCreate must not be zeroed by the delta');
  assert.strictEqual(merged.cacheRead, 9000, 'cacheRead must not be zeroed by the delta');
  assert.strictEqual(merged.cache1h, 500, 'cache1h must not be zeroed by the delta');
  // Non-destructive.
  assert.strictEqual(start.output, 0, 'mergeUsage must not mutate its first argument');
  ok('mergeUsage: delta cannot erase message_start cache counters');
}

// --- openAIUsage -------------------------------------------------------------
{
  const u = extractUsage({
    input_tokens: 100,
    output_tokens: 40,
    cache_creation_input_tokens: 200,
    cache_read_input_tokens: 700,
  });
  const o = openAIUsage(u);
  // OpenAI semantics: cached tokens are a SUBSET of prompt_tokens.
  assert.strictEqual(o.prompt_tokens, 1000, 'prompt_tokens = input + cacheRead + cacheCreate');
  assert.strictEqual(o.completion_tokens, 40, 'completion_tokens = output');
  assert.strictEqual(o.total_tokens, 1040, 'total_tokens = prompt + completion');
  assert.strictEqual(o.prompt_tokens_details.cached_tokens, 700, 'cached_tokens = cacheRead');
  assert.strictEqual(o.cache_creation_input_tokens, 200, 'anthropic passthrough field');
  assert.strictEqual(o.cache_read_input_tokens, 700, 'anthropic passthrough field');
  ok('openAIUsage: cached tokens counted inside prompt_tokens');
}

// --- makeSSEUsageWatcher over synthetic Anthropic SSE ------------------------
{
  const sse = [
    `event: message_start\ndata: ${JSON.stringify({
      type: 'message_start',
      message: {
        id: 'msg_pha1596',
        usage: {
          input_tokens: 12,
          output_tokens: 1,
          cache_creation_input_tokens: 2048,
          cache_read_input_tokens: 61440,
          cache_creation: { ephemeral_5m_input_tokens: 0, ephemeral_1h_input_tokens: 2048 },
        },
      },
    })}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify({
      type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hi' },
    })}\n\n`,
    `event: message_delta\ndata: ${JSON.stringify({
      type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 256 },
    })}\n\n`,
    'data: [DONE]\n\n',
  ].join('');

  // Feed in awkward slices so events straddle chunk boundaries, the way a real
  // socket delivers them.
  const w = makeSSEUsageWatcher('claude-opus-4-6');
  for (let i = 0; i < sse.length; i += 37) w.feed(Buffer.from(sse.slice(i, i + 37)));

  const u = w.get();
  assert.strictEqual(u.input, 12, 'input_tokens from message_start');
  assert.strictEqual(u.output, 256, 'output_tokens from message_delta');
  assert.strictEqual(u.cacheCreate, 2048, 'cache_creation_input_tokens survived to end of stream');
  assert.strictEqual(u.cacheRead, 61440, 'cache_read_input_tokens survived to end of stream');
  assert.strictEqual(u.cache1h, 2048, 'ephemeral_1h_input_tokens survived to end of stream');
  assert.strictEqual(u.cache5m, 0, 'no 5m creation reported');

  const o = openAIUsage(u);
  assert.strictEqual(o.prompt_tokens, 12 + 2048 + 61440, 'streamed prompt_tokens includes cache');
  assert.strictEqual(o.prompt_tokens_details.cached_tokens, 61440, 'streamed cached_tokens');
  ok('makeSSEUsageWatcher: split-chunk SSE yields all four counters');
}

// A stream that reports no usage at all must stay all-zero (flush is a no-op).
{
  const w = makeSSEUsageWatcher('claude-opus-4-6');
  w.feed(Buffer.from(`data: ${JSON.stringify({ type: 'ping' })}\n\n`));
  assert.deepStrictEqual(w.get(), {
    input: 0, output: 0, cacheCreate: 0, cacheRead: 0, cache5m: 0, cache1h: 0,
  }, 'usage-free stream must stay zeroed');
  ok('makeSSEUsageWatcher: usage-free stream stays zeroed');
}

// --- openAIToAnthropic cache_control pass-through ----------------------------
{
  const body = JSON.stringify({
    model: 'claude-opus-4-6',
    messages: [
      {
        role: 'system',
        content: [{ type: 'text', text: 'BIG STATIC PREAMBLE', cache_control: { type: 'ephemeral' } }],
      },
      {
        role: 'user',
        content: [
          { type: 'text', text: 'cached history', cache_control: { type: 'ephemeral', ttl: '1h' } },
          { type: 'text', text: 'fresh turn' },
        ],
      },
    ],
    tools: [{
      type: 'function',
      function: { name: 'get_weather', description: 'w', parameters: { type: 'object', properties: {} } },
      cache_control: { type: 'ephemeral' },
    }],
  });

  const out = JSON.parse(openAIToAnthropic(body, false));

  assert.deepStrictEqual(out.system[0].cache_control, { type: 'ephemeral' },
    'system block cache_control must survive translation');
  assert.deepStrictEqual(out.messages[0].content[0].cache_control, { type: 'ephemeral', ttl: '1h' },
    'message content-part cache_control (incl. ttl) must survive translation');
  assert.strictEqual(out.messages[0].content[1].cache_control, undefined,
    'unmarked parts must not gain a cache_control key');
  assert.ok(!Object.prototype.hasOwnProperty.call(out.messages[0].content[1], 'cache_control'),
    'unmarked parts must not carry an explicit cache_control: undefined');
  assert.deepStrictEqual(out.tools[0].cache_control, { type: 'ephemeral' },
    'tool cache_control must survive translation');
  assert.strictEqual(out.tools[0].input_schema.type, 'object', 'tool schema still mapped');
  ok('openAIToAnthropic: cache_control preserved on system, content part and tool');
}

// Nothing marked => nothing invented (pass-through only, no injection).
{
  const out = JSON.parse(openAIToAnthropic(JSON.stringify({
    model: 'claude-opus-4-6',
    messages: [{ role: 'system', content: 'plain' }, { role: 'user', content: 'hello' }],
  }), false));
  assert.strictEqual(out.system[0].cache_control, undefined, 'no cache_control injected into system');
  assert.strictEqual(JSON.stringify(out).includes('cache_control'), false,
    'proxy must not invent cache breakpoints');
  ok('openAIToAnthropic: no cache_control invented when the client sent none');
}

// --- capCacheControl: >4 breakpoints capped to 4 -----------------------------
{
  const parts = [];
  for (let i = 0; i < 6; i++) {
    parts.push({ type: 'text', text: `part ${i}`, cache_control: { type: 'ephemeral' } });
  }
  const body = JSON.stringify({
    model: 'claude-opus-4-6',
    messages: [
      { role: 'system', content: [{ type: 'text', text: 'sys', cache_control: { type: 'ephemeral' } }] },
      { role: 'user', content: parts },
    ],
  });

  const translated = JSON.parse(openAIToAnthropic(body, false));
  const before = JSON.stringify(translated).split('"cache_control"').length - 1;
  assert.strictEqual(before, 7, 'translation should preserve all 7 client breakpoints before capping');

  const capped = capCacheControl(translated);
  const after = JSON.stringify(capped).split('"cache_control"').length - 1;
  assert.strictEqual(after, 4, 'capCacheControl must leave exactly 4 breakpoints');
  // Document order: system first, then the first three message parts.
  assert.ok(capped.system[0].cache_control, 'the system breakpoint must be one of the survivors');
  assert.ok(capped.messages[0].content[0].cache_control, 'first content breakpoint kept');
  assert.ok(capped.messages[0].content[2].cache_control, 'third content breakpoint kept');
  assert.strictEqual(capped.messages[0].content[3].cache_control, undefined, 'fourth content breakpoint stripped');
  assert.strictEqual(capped.messages[0].content[5].cache_control, undefined, 'last content breakpoint stripped');
  // Capping strips only the marker, never the block itself.
  assert.strictEqual(capped.messages[0].content.length, 6, 'no content blocks dropped');
  assert.strictEqual(capped.messages[0].content[5].text, 'part 5', 'block text preserved when marker stripped');
  ok('capCacheControl: 7 breakpoints capped to Anthropic\'s max of 4');
}

// Under the limit, capCacheControl is a no-op.
{
  const parsed = { system: [{ type: 'text', text: 's', cache_control: { type: 'ephemeral' } }], messages: [] };
  const snapshot = JSON.stringify(parsed);
  assert.strictEqual(JSON.stringify(capCacheControl(parsed)), snapshot, 'under-limit body must be untouched');
  assert.strictEqual(capCacheControl(null), null, 'capCacheControl must be null-safe');
  ok('capCacheControl: no-op under the limit, null-safe');
}

console.log(`pha1596 usage/cache unit: ${pass} checks passed`);
process.exit(0);
