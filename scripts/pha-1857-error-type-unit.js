'use strict';
// PHA-1857 unit test: extractAnthropicErrorType() pulls the error.type field
// out of upstream error JSON so the structured access log can distinguish
// "0 tokens because upstream 429" (normal — Anthropic 429 carries no usage)
// from "0 tokens because logging bug". Pure-function test, no network.
//
// We inline the function (rather than `require('../anthropic-proxy.js')`)
// because requiring the proxy starts a real HTTP listener on PORT — that
// races against every other test. The function body is verified to match
// the live anthropic-proxy.js copy via the canary (see
// scripts/pha-1857-error-type-canary.sh for the full end-to-end version).

function extractAnthropicErrorType(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.replace(/^data:\s*/, '').trim();
  if (!trimmed.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed.error === 'object' && typeof parsed.error.type === 'string') {
      return parsed.error.type;
    }
  } catch (_) {}
  return null;
}

let pass = 0, fail = 0;
function ok(label, cond, detail) {
  if (cond) { pass++; console.log(`[OK] ${label}`); }
  else { fail++; console.log(`[FAIL] ${label}${detail ? ' -- ' + detail : ''}`); }
}

// 1. Standard Anthropic rate_limit_error JSON body
ok('rate_limit_error JSON body',
  extractAnthropicErrorType(JSON.stringify({
    type: 'error',
    error: { type: 'rate_limit_error', message: 'rate limited' },
  })) === 'rate_limit_error');

// 2. Other Anthropic error types
ok('authentication_error', extractAnthropicErrorType(JSON.stringify({
  type: 'error',
  error: { type: 'authentication_error', message: 'bad token' },
})) === 'authentication_error');

ok('overloaded_error', extractAnthropicErrorType(JSON.stringify({
  type: 'error',
  error: { type: 'overloaded_error', message: 'try again' },
})) === 'overloaded_error');

// 3. JSON wrapped with "data: " SSE prefix (streaming-path leakage)
ok('rate_limit_error with SSE data: prefix',
  extractAnthropicErrorType('data: ' + JSON.stringify({
    type: 'error',
    error: { type: 'rate_limit_error', message: 'rate limited' },
  })) === 'rate_limit_error');

// 4. Plain success JSON — no error.type, returns null
ok('success JSON body returns null',
  extractAnthropicErrorType(JSON.stringify({
    id: 'msg_1', type: 'message', usage: { input_tokens: 12, output_tokens: 7 },
  })) === null);

// 5. SSE event data — not JSON envelope, returns null
ok('SSE event data returns null',
  extractAnthropicErrorType('event: message_start\ndata: {"type":"message_start"}') === null);

// 6. Malformed JSON returns null
ok('malformed JSON returns null', extractAnthropicErrorType('not json{') === null);

// 7. Empty / null / non-string returns null
ok('empty string returns null', extractAnthropicErrorType('') === null);
ok('null returns null', extractAnthropicErrorType(null) === null);
ok('undefined returns null', extractAnthropicErrorType(undefined) === null);
ok('number returns null', extractAnthropicErrorType(42) === null);

// 8. JSON missing error.type returns null
ok('JSON missing error.type returns null',
  extractAnthropicErrorType(JSON.stringify({ error: { message: 'oops' } })) === null);

// 9. JSON where error is a string (not an object) returns null
ok('error-as-string returns null',
  extractAnthropicErrorType(JSON.stringify({ error: 'something broke' })) === null);

// 10. JSON with leading whitespace
ok('JSON with leading whitespace',
  extractAnthropicErrorType('  \n  ' + JSON.stringify({
    type: 'error',
    error: { type: 'rate_limit_error', message: 'rate limited' },
  })) === 'rate_limit_error');

console.log(`\nextractAnthropicErrorType unit: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);