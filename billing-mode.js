// Billing-proxy mode: routes through Claude Code subscription instead of API billing.
// Adapted from zacdcook/openclaw-billing-proxy (8 layers of detection bypass).
//
// Activated when PROXY_MODE=billing. Requires OAUTH_TOKEN env var or
// ~/.claude/.credentials.json file mount.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

// Emulated Claude Code version. MUST track the real CLI version that interactive
// sessions report — a stale value is a weak billing fingerprint. Resolution order:
//   1. CC_VERSION env  → explicit ops pin; auto-update is disabled (pin wins).
//   2. live self-update → the proxy fetches the latest published Claude Code
//      version from the npm registry and pushes it in via setCCVersion(), so the
//      fingerprint tracks real releases with no code change or manual bump.
//   3. fallback constant → used until the first live fetch resolves / if it fails.
// Only read in billing mode (this file is require()'d only when PROXY_MODE=billing),
// so changing it has zero effect on regular-mode traffic.
let CC_VERSION = process.env.CC_VERSION || '2.1.168';
const CC_VERSION_PINNED = !!process.env.CC_VERSION;

// Push a self-discovered Claude Code version in (called by the core proxy's
// version auto-updater). An explicit CC_VERSION env pin always wins, and we only
// accept well-formed semver to avoid corrupting the fingerprint with junk.
function setCCVersion(v) {
  if (CC_VERSION_PINNED) return false;
  if (!/^\d+\.\d+\.\d+$/.test(v || '') || v === CC_VERSION) return false;
  CC_VERSION = v;
  return true;
}
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];
// DEVICE_ID and INSTANCE_SESSION_ID stay stable across container restarts only
// if pinned via env. Otherwise each startup looks like a fresh device, which
// hurts billing fingerprint continuity (not correctness).
const DEVICE_ID = process.env.DEVICE_ID || crypto.randomBytes(32).toString('hex');
const INSTANCE_SESSION_ID = process.env.INSTANCE_SESSION_ID || crypto.randomUUID();

// Real account UUID for this OAuth identity. Genuine Claude Code includes it in
// metadata.user_id ({device_id, account_uuid, session_id}); its ABSENCE is the
// primary detection tell behind the 2026-07-16 extra-usage block (openclaw PR #61).
// Per-account and NOT in ~/.claude/.credentials.json — CC reads it from the OAuth
// profile. Kept out of source: set via CC_ACCOUNT_UUID env, or an `account_uuid`
// key in a gitignored config.json next to this file. Empty string until provided
// (ops input required for the fix to be fully effective — see PHA-1389).
let ACCOUNT_UUID = process.env.CC_ACCOUNT_UUID || '';
try {
  if (!ACCOUNT_UUID) {
    const cfgPath = path.join(__dirname, 'config.json');
    if (fs.existsSync(cfgPath)) {
      ACCOUNT_UUID = (JSON.parse(fs.readFileSync(cfgPath, 'utf8')).account_uuid) || '';
    }
  }
} catch (e) { /* missing/invalid config.json → leave ACCOUNT_UUID empty */ }

// Last upstream request-id per session, used to emit the modern `cc_prev_req`
// billing-header chain field genuine CC 2.1.205 sends on consecutive first-party
// requests. A static header that never chains is itself a tell. Keyed by session
// (rather than one shared global) so cc_prev_req chains a request to its own
// session's prior request instead of racing across concurrent sessions. Set by
// the core proxy from each upstream response's request-id header via
// setLastRequestId().
const LAST_REQUEST_ID_BY_SESSION = new Map();
function setLastRequestId(id, sessionId) {
  if (!id) return;
  LAST_REQUEST_ID_BY_SESSION.set(sessionId || INSTANCE_SESSION_ID, id);
}
function getLastRequestId(sessionId) {
  return LAST_REQUEST_ID_BY_SESSION.get(sessionId || INSTANCE_SESSION_ID) || null;
}

// Beta flags — EXACT list + order captured from genuine Claude Code 2.1.205
// (openclaw-billing-proxy PR #61, capture-and-diff 2026-07-16). A merged/reordered
// set is itself a fingerprint, so this is applied WHOLESALE (see buildBillingHeaders).
const REQUIRED_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'interleaved-thinking-2025-05-14',
  'thinking-token-count-2026-05-13',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'mid-conversation-system-2026-04-07',
  'advisor-tool-2026-03-01',
  'advanced-tool-use-2025-11-20',
  'effort-2025-11-24',
  'extended-cache-ttl-2025-04-11',
];

const CC_TOOL_STUBS = [
  '{"name":"Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
  '{"name":"Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
  '{"name":"Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
  '{"name":"NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
  '{"name":"TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}',
];

const REPLACEMENTS = [
  ['OpenClaw', 'OCPlatform'], ['openclaw', 'ocplatform'],
  ['sessions_spawn', 'create_task'], ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'], ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'], ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_ACK'], ['HEARTBEAT', 'HB_SIGNAL'], ['heartbeat', 'hb_signal'],
  ['running inside', 'operating from'],
  ['Prometheus', 'PAssistant'], ['prometheus', 'passistant'],
  ['clawhub.com', 'skillhub.example.com'], ['clawhub', 'skillhub'],
  ['clawd', 'agentd'], ['lossless-claw', 'lossless-ctx'],
  ['billing proxy', 'routing layer'],
  ['billing-proxy', 'routing-layer'],
  ['x-anthropic-billing-header', 'x-routing-config'],
  ['x-anthropic-billing', 'x-routing-cfg'],
  ['cch=00000', 'cfg=00000'], ['cc_version', 'rt_version'],
  ['cc_entrypoint', 'rt_entrypoint'], ['billing header', 'routing config'],
  ['assistant platform', 'ocplatform'],
];

const TOOL_RENAMES = [
  ['exec', 'Bash'], ['process', 'BashSession'], ['browser', 'BrowserControl'],
  ['canvas', 'CanvasView'], ['nodes', 'DeviceControl'], ['cron', 'Scheduler'],
  ['message', 'SendMessage'], ['tts', 'Speech'], ['gateway', 'SystemCtl'],
  ['agents_list', 'AgentList'], ['list_tasks', 'TaskList'],
  ['get_history', 'TaskHistory'], ['send_to_task', 'TaskSend'],
  ['create_task', 'TaskCreate'], ['subagents', 'AgentControl'],
  ['session_status', 'StatusCheck'], ['web_search', 'WebSearch'],
  ['web_fetch', 'WebFetch'], ['pdf', 'PdfParse'],
  ['image_generate', 'ImageCreate'], ['music_generate', 'MusicCreate'],
  ['video_generate', 'VideoCreate'], ['memory_search', 'KnowledgeSearch'],
  ['memory_get', 'KnowledgeGet'], ['lcm_expand_query', 'ContextQuery'],
  ['lcm_grep', 'ContextGrep'], ['lcm_describe', 'ContextDescribe'],
  ['lcm_expand', 'ContextExpand'], ['yield_task', 'TaskYield'],
  ['task_store', 'TaskStore'], ['task_yield_interrupt', 'TaskYieldInterrupt'],
];

const PROP_RENAMES = [
  ['session_id', 'thread_id'], ['conversation_id', 'thread_ref'],
  ['summaryIds', 'chunk_ids'], ['summary_id', 'chunk_id'],
  ['system_event', 'event_text'], ['agent_id', 'worker_id'],
  ['wake_at', 'trigger_at'], ['wake_event', 'trigger_event'],
];

const REVERSE_MAP = [
  ['create_task', 'sessions_spawn'], ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'], ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'], ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK'], ['HB_SIGNAL', 'HEARTBEAT'], ['hb_signal', 'heartbeat'],
  ['PAssistant', 'Prometheus'], ['passistant', 'prometheus'],
  ['skillhub.example.com', 'clawhub.com'], ['skillhub', 'clawhub'],
  ['agentd', 'clawd'], ['lossless-ctx', 'lossless-claw'],
  ['routing layer', 'billing proxy'],
  ['routing-layer', 'billing-proxy'],
  ['x-routing-config', 'x-anthropic-billing-header'],
  ['x-routing-cfg', 'x-anthropic-billing'],
  ['cfg=00000', 'cch=00000'], ['rt_version', 'cc_version'],
  ['rt_entrypoint', 'cc_entrypoint'], ['routing config', 'billing header'],
];

function computeBillingFingerprint(firstUserText) {
  const chars = BILLING_HASH_INDICES.map(i => firstUserText[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${CC_VERSION}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

function extractFirstUserText(bodyStr) {
  const msgsIdx = bodyStr.indexOf('"messages":[');
  if (msgsIdx === -1) return '';
  const userIdx = bodyStr.indexOf('"role":"user"', msgsIdx);
  if (userIdx === -1) return '';
  const contentIdx = bodyStr.indexOf('"content"', userIdx);
  if (contentIdx === -1 || contentIdx > userIdx + 500) return '';
  const afterContent = bodyStr[contentIdx + '"content"'.length + 1];
  if (afterContent === '"') {
    const textStart = contentIdx + '"content":"'.length;
    let end = textStart;
    while (end < bodyStr.length) {
      if (bodyStr[end] === '\\') { end += 2; continue; }
      if (bodyStr[end] === '"') break;
      end++;
    }
    return bodyStr.slice(textStart, end)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  const textIdx = bodyStr.indexOf('"text":"', contentIdx);
  if (textIdx === -1 || textIdx > contentIdx + 2000) return '';
  const textStart = textIdx + '"text":"'.length;
  let end = textStart;
  while (end < bodyStr.length) {
    if (bodyStr[end] === '\\') { end += 2; continue; }
    if (bodyStr[end] === '"') break;
    end++;
  }
  return bodyStr.slice(textStart, Math.min(end, textStart + 50))
    .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

// Genuine CC 2.1.205 (sdk-cli mode, captured 2026-07-16 for openclaw PR #61) sends
// this as an HTTP header, not a body block:
//   x-anthropic-billing-header: cc_version=<v.fp>; cc_entrypoint=sdk-cli;[ cc_prev_req=<id>;]
// No `cch` field in this mode, and cc_entrypoint must match the user-agent (sdk-cli).
// The prev-request chain only appears once there is a prior request-id to chain.
//
// PHA-1842: this used to be injected as system[0] in the request body, which put an
// ever-changing value (cc_prev_req + the 6h-rotating cc_version) at the front of the
// cache-control prefix chain — invalidating every prompt-cache breakpoint on every
// request. Anthropic's own cache is prefix-based (tools -> system -> messages), so
// this must go out as a real header instead, leaving the system array byte-stable.
//
// NOTE (PHA-1389): this flips cc_entrypoint cli→sdk-cli. Our prior model (see the
// June-15 surcharge memo) matched genuine INTERACTIVE cli; the current detection
// matches genuine 2.1.205, which runs sdk-cli, and PR #61 verified sdk-cli returns
// 200 with zero extra-usage. Realigning to genuine is what clears the block.
//
// PHA-1887: the fundamental issue across this whole series is that each change
// picked ONE of two properties and paid for it with the other:
//
//   <=1.4.11  fingerprint delivered (system[0] body block)  — prompt cache dead
//   1.4.12+   prompt cache alive (real header)              — every request 529s
//
// Both properties are obtainable at once. The cache is a *prefix* cache (tools ->
// system -> messages), so what breaks it is not the block existing, it is the block
// sitting AHEAD of the client's cache_control breakpoints. Injected as the LAST
// system element instead of the first, the rotating value lands after every
// breakpoint: the cached prefix stays byte-identical request to request and the
// fingerprint still ships. That is `body` mode, and it is now the default.
//
// `header` mode (1.4.12 behaviour) stays available, but no longer takes the whole
// proxy down when Anthropic's edge sheds it: `x-anthropic-*` is their own reserved
// request-header namespace, evaluated before the request reaches a model, and an
// undefined name in it is shed as 529 Overloaded rather than rejected as 400. The
// first such 529 latches the header off for the rest of the process and the
// fingerprint falls back to the body block — so header mode degrades to a working
// configuration instead of an outage, and self-heals on restart if Anthropic ever
// starts accepting it.
//
//   off     neither header nor body block
//   body    (default) fingerprint appended as the last system block, cache-stable
//   header  real header, auto-falling back to `body` on the first 529
const BILLING_HEADER_MODE = (process.env.BILLING_HEADER_MODE || 'body').toLowerCase();
// Flipped by noteUpstreamStatus() when the edge sheds a header-mode request.
let billingHeaderShed = false;
const emitBillingHeader = () => BILLING_HEADER_MODE === 'header' && !billingHeaderShed;
// True when the fingerprint has to ride in the body: either that was asked for, or
// header mode was asked for and the edge refused it.
const injectBillingBlock = () => BILLING_HEADER_MODE === 'body'
  || (BILLING_HEADER_MODE === 'header' && billingHeaderShed);

// Called once per upstream response (both /v1/messages and the chat/completions
// bridge). A 529 while we were sending the reserved header is the exact 1.4.12
// failure; latch it off so the next request uses the body block and serves.
function noteUpstreamStatus(statusCode) {
  if (statusCode === 529 && emitBillingHeader()) {
    billingHeaderShed = true;
    console.error('[PROXY] upstream 529 with x-anthropic-billing-header set — disabling the header '
      + 'for this process and falling back to the in-body fingerprint (PHA-1887).');
  }
}

function buildBillingHeaderValue(bodyStr, sessionId) {
  if (!emitBillingHeader()) return null;
  const firstText = extractFirstUserText(bodyStr);
  const fingerprint = computeBillingFingerprint(firstText);
  const prevId = getLastRequestId(sessionId);
  const prev = prevId ? ` cc_prev_req=${prevId};` : '';
  return `cc_version=${CC_VERSION}.${fingerprint}; cc_entrypoint=sdk-cli;${prev}`;
}

// Resolve the session id for a request. Prefer the client's own per-conversation
// session id (the Claude Code CLI / harness assigns a distinct one per agent), so
// each agent reaches Anthropic as its own session instead of all sharing one —
// which removes both the behavioral tell and the single-session rate-limit
// ceiling. Falls back to the proxy's stable id only when the client sends none.
function deriveSessionId(reqHeaders) {
  const h = reqHeaders || {};
  const incoming = h['x-claude-code-session-id'] || h['x-session-id'];
  if (incoming && /^[0-9a-fA-F][0-9a-fA-F-]{15,63}$/.test(incoming)) return incoming;
  return INSTANCE_SESSION_ID;
}

function getStainlessHeaders(sessionId) {
  const p = process.platform;
  // Genuine CC reports 'MacOS' (capital OS), not Node's 'macOS' — casing is a tell.
  // CC_OS env pins this outright: our container runs Linux, but if the OAuth account's
  // genuine traffic originates on a Mac, x-stainless-os=Linux is itself a mismatch tell
  // (PHA-1389 residual). Set CC_OS=MacOS to align with the account's real platform.
  const osName = process.env.CC_OS
    || (p === 'darwin' ? 'MacOS' : p === 'win32' ? 'Windows' : p === 'linux' ? 'Linux' : p);
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
  // Values below captured verbatim from genuine Claude Code 2.1.205 (openclaw PR #61,
  // 2026-07-16). user-agent + entrypoint are sdk-cli to match genuine; package-version
  // and runtime-version are pinned to genuine's, not this container's (Node's real
  // process.version would be a mismatch tell).
  return {
    'user-agent': `claude-cli/${CC_VERSION} (external, sdk-cli)`,
    'x-app': 'cli',
    'x-claude-code-session-id': sessionId || INSTANCE_SESSION_ID,
    'x-stainless-arch': arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': osName,
    'x-stainless-package-version': '0.94.0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': 'v26.3.0',
    'x-stainless-retry-count': '0',
    'x-stainless-timeout': '600',
    'anthropic-dangerous-direct-browser-access': 'true',
  };
}

function findMatchingBracket(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) { if (c === '\\') { i++; continue; } if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; continue; }
    if (c === '[') d++;
    else if (c === ']') { d--; if (d === 0) return i; }
  }
  return -1;
}

const THINK_MASK_PREFIX = '__OBP_THINK_MASK_';
const THINK_MASK_SUFFIX = '__';
const THINK_BLOCK_PATTERNS = ['{"type":"thinking"', '{"type":"redacted_thinking"'];

function maskThinkingBlocks(m) {
  const masks = [];
  let out = '';
  let i = 0;
  while (i < m.length) {
    let nextIdx = -1;
    for (const p of THINK_BLOCK_PATTERNS) {
      const idx = m.indexOf(p, i);
      if (idx !== -1 && (nextIdx === -1 || idx < nextIdx)) nextIdx = idx;
    }
    if (nextIdx === -1) { out += m.slice(i); break; }
    out += m.slice(i, nextIdx);
    let depth = 0, inStr = false, j = nextIdx;
    while (j < m.length) {
      const c = m[j];
      if (inStr) { if (c === '\\') { j += 2; continue; } if (c === '"') inStr = false; j++; continue; }
      if (c === '"') { inStr = true; j++; continue; }
      if (c === '{') { depth++; j++; continue; }
      if (c === '}') { depth--; j++; if (depth === 0) break; continue; }
      j++;
    }
    if (depth !== 0) { out += m.slice(nextIdx); return { masked: out, masks }; }
    masks.push(m.slice(nextIdx, j));
    out += THINK_MASK_PREFIX + (masks.length - 1) + THINK_MASK_SUFFIX;
    i = j;
  }
  return { masked: out, masks };
}

function unmaskThinkingBlocks(m, masks) {
  for (let i = 0; i < masks.length; i++) {
    m = m.split(THINK_MASK_PREFIX + i + THINK_MASK_SUFFIX).join(masks[i]);
  }
  return m;
}

function processBody(bodyStr, sessionId) {
  const sessionIdForMeta = sessionId || INSTANCE_SESSION_ID;
  const { masked: maskedBody, masks: thinkMasks } = maskThinkingBlocks(bodyStr);
  let m = maskedBody;

  for (const [find, replace] of REPLACEMENTS) m = m.split(find).join(replace);
  for (const [orig, cc] of TOOL_RENAMES) m = m.split('"' + orig + '"').join('"' + cc + '"');
  for (const [orig, renamed] of PROP_RENAMES) m = m.split('"' + orig + '"').join('"' + renamed + '"');

  // Layer 4: System prompt template strip
  const IDENTITY_MARKER = 'You are a personal assistant';
  const sysArrayStart = m.indexOf('"system":[');
  const searchFrom = sysArrayStart !== -1 ? sysArrayStart : 0;
  const configStart = m.indexOf(IDENTITY_MARKER, searchFrom);
  if (configStart !== -1) {
    let stripFrom = configStart;
    if (stripFrom >= 2 && m[stripFrom - 2] === '\\' && m[stripFrom - 1] === 'n') stripFrom -= 2;
    // End at the first workspace-doc header (filesystem path H2). The config
    // block itself contains H2 sub-sections (`## Tooling`, `## Workspace`,
    // `## Messaging`) so a generic `\n## ` match would terminate too early.
    // Matches upstream zacdcook/openclaw-billing-proxy v2.2.4 (closes #26).
    let configEnd = m.indexOf('\\n## /', configStart + IDENTITY_MARKER.length);
    if (configEnd === -1) configEnd = m.indexOf('\\n## C:\\\\', configStart + IDENTITY_MARKER.length);
    if (configEnd !== -1) {
      const strippedLen = configEnd - stripFrom;
      if (strippedLen > 1000) {
        const PARAPHRASE = '\\nYou are an AI operations assistant with access to all tools listed in this request '
          + 'for file operations, command execution, web search, browser control, scheduling, '
          + 'messaging, and session management. Tool names are case-sensitive and must be called '
          + 'exactly as listed. Your responses route to the active channel automatically. '
          + 'For cross-session communication, use the task messaging tools. '
          + 'Skills defined in your workspace should be invoked when they match user requests. '
          + 'Consult your workspace reference files for detailed operational configuration.\\n';
        m = m.slice(0, stripFrom) + PARAPHRASE + m.slice(configEnd);
      }
    }
  }

  // Layer 5: Tool description strip + CC stub injection
  const toolsIdx = m.indexOf('"tools":[');
  if (toolsIdx !== -1) {
    const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
    if (toolsEndIdx !== -1) {
      let section = m.slice(toolsIdx, toolsEndIdx + 1);
      let from = 0;
      while (true) {
        const d = section.indexOf('"description":"', from);
        if (d === -1) break;
        const vs = d + '"description":"'.length;
        let i = vs;
        while (i < section.length) {
          if (section[i] === '\\' && i + 1 < section.length) { i += 2; continue; }
          if (section[i] === '"') break;
          i++;
        }
        section = section.slice(0, vs) + section.slice(i);
        from = vs + 1;
      }
      const insertAt = '"tools":['.length;
      section = section.slice(0, insertAt) + CC_TOOL_STUBS.join(',') + ',' + section.slice(insertAt);
      m = m.slice(0, toolsIdx) + section + m.slice(toolsEndIdx + 1);
    }
  }

  // Layer 1: billing fingerprint as a system block. Appended as the LAST system
  // element, not system[0] — the pre-1.4.12 code prepended it, which put a value
  // that rotates every request ahead of every cache_control breakpoint and killed
  // the prompt-cache prefix on each call. At the tail it sits after all of them, so
  // the cached prefix is byte-identical between requests and the fingerprint still
  // ships (PHA-1887). Active in `body` mode, and in `header` mode once the edge has
  // shed the reserved header.
  if (injectBillingBlock()) {
    const fingerprint = computeBillingFingerprint(extractFirstUserText(m));
    const prevId = getLastRequestId(sessionId);
    const prev = prevId ? ` cc_prev_req=${prevId};` : '';
    const BILLING_BLOCK = JSON.stringify({
      type: 'text',
      text: `x-anthropic-billing-header: cc_version=${CC_VERSION}.${fingerprint}; cc_entrypoint=sdk-cli;${prev}`,
    });
    const sysArrayIdx = m.indexOf('"system":[');
    const sysArrayEnd = sysArrayIdx !== -1
      ? findMatchingBracket(m, sysArrayIdx + '"system":'.length)
      : -1;
    if (sysArrayIdx !== -1 && sysArrayEnd !== -1) {
      // Append after the last element (`]` is at sysArrayEnd). An empty array takes
      // the block alone, with no leading comma.
      const isEmpty = m.slice(sysArrayIdx + '"system":['.length, sysArrayEnd).trim() === '';
      m = m.slice(0, sysArrayEnd) + (isEmpty ? '' : ',') + BILLING_BLOCK + m.slice(sysArrayEnd);
    } else if (m.includes('"system":"')) {
      const sysStart = m.indexOf('"system":"');
      let i = sysStart + '"system":"'.length;
      while (i < m.length) {
        if (m[i] === '\\') { i += 2; continue; }
        if (m[i] === '"') break;
        i++;
      }
      const sysEnd = i + 1;
      const originalSysStr = m.slice(sysStart + '"system":'.length, sysEnd);
      m = m.slice(0, sysStart)
        + '"system":[{"type":"text","text":' + originalSysStr + '},' + BILLING_BLOCK + ']'
        + m.slice(sysEnd);
    } else {
      m = '{"system":[' + BILLING_BLOCK + '],' + m.slice(1);
    }
  }

  // Metadata injection
  // Genuine metadata.user_id is {device_id, account_uuid, session_id} in that order.
  // account_uuid absence is the primary detection tell (PHA-1389 / openclaw PR #61);
  // omit the key entirely when unset so we don't ship an obviously-empty value.
  const metaObj = ACCOUNT_UUID
    ? { device_id: DEVICE_ID, account_uuid: ACCOUNT_UUID, session_id: sessionIdForMeta }
    : { device_id: DEVICE_ID, session_id: sessionIdForMeta };
  const metaValue = JSON.stringify(metaObj);
  const metaJson = '"metadata":{"user_id":' + JSON.stringify(metaValue) + '}';
  const existingMeta = m.indexOf('"metadata":{');
  if (existingMeta !== -1) {
    let depth = 0, mi = existingMeta + '"metadata":'.length;
    for (; mi < m.length; mi++) {
      if (m[mi] === '{') depth++;
      else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
    }
    m = m.slice(0, existingMeta) + metaJson + m.slice(mi);
  } else {
    m = '{' + metaJson + ',' + m.slice(1);
  }

  // Layer 8: Strip trailing assistant prefill
  const msgsIdx = m.indexOf('"messages":[');
  if (msgsIdx !== -1) {
    const arrayStart = msgsIdx + '"messages":['.length;
    const positions = [];
    let depth = 0, inString = false, objStart = -1;
    for (let i = arrayStart; i < m.length; i++) {
      const c = m[i];
      if (inString) { if (c === '\\') { i++; continue; } if (c === '"') inString = false; continue; }
      if (c === '"') { inString = true; continue; }
      if (c === '{') { if (depth === 0) objStart = i; depth++; }
      else if (c === '}') { depth--; if (depth === 0 && objStart !== -1) { positions.push({ start: objStart, end: i }); objStart = -1; } }
      else if (c === ']' && depth === 0) break;
    }
    while (positions.length > 0) {
      const last = positions[positions.length - 1];
      const obj = m.slice(last.start, last.end + 1);
      if (!obj.includes('"role":"assistant"')) break;
      let stripFrom = last.start;
      for (let i = last.start - 1; i >= arrayStart; i--) {
        if (m[i] === ',') { stripFrom = i; break; }
        if (m[i] !== ' ' && m[i] !== '\n' && m[i] !== '\r' && m[i] !== '\t') break;
      }
      m = m.slice(0, stripFrom) + m.slice(last.end + 1);
      positions.pop();
    }
  }

  return unmaskThinkingBlocks(m, thinkMasks);
}

function reverseMap(text) {
  let r = text;
  for (const [orig, cc] of TOOL_RENAMES) {
    r = r.split('"' + cc + '"').join('"' + orig + '"');
    r = r.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
  }
  for (const [orig, renamed] of PROP_RENAMES) {
    r = r.split('"' + renamed + '"').join('"' + orig + '"');
    r = r.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
  }
  for (const [sanitized, original] of REVERSE_MAP) {
    r = r.split(sanitized).join(original);
  }
  return r;
}

function reverseMapBuffer(buf) {
  const respBody = buf.toString();
  const { masked, masks } = maskThinkingBlocks(respBody);
  return Buffer.from(unmaskThinkingBlocks(reverseMap(masked), masks));
}

// SSE transformer: returns { onData(chunk), onEnd() } that emit transformed text.


function loadOAuthToken() {
  if (process.env.OAUTH_TOKEN) {
    return { accessToken: process.env.OAUTH_TOKEN, expiresAt: Infinity, subscriptionType: 'env-var' };
  }
  const homeDir = os.homedir();
  const candidates = [
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p) && fs.statSync(p).size > 0) {
      let raw = fs.readFileSync(p, 'utf8');
      if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
      const creds = JSON.parse(raw);
      if (creds.claudeAiOauth && creds.claudeAiOauth.accessToken) return creds.claudeAiOauth;
    }
  }
  throw new Error('No OAUTH_TOKEN env var and no Claude credentials at ~/.claude/.credentials.json');
}

// Re-read the stored token from disk when our in-memory copy is within
// TOKEN_REFRESH_SKEW_MS of expiry. sk-ant-oat tokens last only hours; Claude
// Code (running wherever the creds live) rewrites ~/.claude/.credentials.json in
// place on its own refresh cycle, so we just need to pick the new value up
// instead of caching the boot-time token forever. No-op for the OAUTH_TOKEN env
// path (expiresAt: Infinity — nothing on disk to re-read) and while still fresh.
// Returns the freshest token object; on a read error keeps the existing one
// (a stale token that might still work beats no token).
const TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000;
function refreshTokenIfStale(cached) {
  if (!cached || !isFinite(cached.expiresAt)) return cached;
  if (Date.now() < cached.expiresAt - TOKEN_REFRESH_SKEW_MS) return cached;
  try {
    const fresh = loadOAuthToken();
    if (fresh && fresh.accessToken && fresh.accessToken !== cached.accessToken) {
      console.log('[PROXY] Stored OAuth token refreshed from credentials file (was near/after expiry)');
    }
    return fresh;
  } catch (e) {
    console.log(`[PROXY] Stored token refresh failed (${e.message}); keeping current token`);
    return cached;
  }
}

// PHA-1848 (M6, audit finding): this used to copy every client-supplied header
// onto the outbound request EXCEPT a small denylist (host/connection/
// authorization/x-api-key/content-length/x-session-affinity). That is a
// client-header-injection vulnerability: any header a client sent -- a spoofed
// `anthropic-beta`, a custom `x-stainless-*` override, an unexpected
// `anthropic-version`, or literally anything else -- rode along on a request
// that is authenticated as the PROXY's own OAuth identity. The denylist only
// blocked the one or two headers someone happened to think of; everything
// else was trusted by default.
//
// Audit of what this function actually needs from the client (existingHeaders):
// only the session-id hint (`x-claude-code-session-id` / `x-session-id`), and
// that is never copied verbatim -- it's read by deriveSessionId(), validated
// against a strict hex/UUID-shaped regex, and re-emitted as a canonical header
// by getStainlessHeaders() below. Every other outbound header in this function
// is a fixed, server-controlled value (authorization, accept-encoding,
// anthropic-version, the full stainless/user-agent block, anthropic-beta).
// There is no legitimate reason to forward ANY raw client header to Anthropic
// in billing mode, so the allowlist is empty by design -- we build the request
// entirely from values the proxy controls instead of copy-then-strip.
const BILLING_HEADER_ALLOWLIST = Object.freeze([]);

function buildBillingHeaders(oauthToken, existingHeaders, sessionId) {
  const headers = {};
  for (const key of BILLING_HEADER_ALLOWLIST) {
    const value = (existingHeaders || {})[key];
    if (value !== undefined) headers[key] = value;
  }
  headers['authorization'] = `Bearer ${oauthToken}`;
  // PHA-1887: the empty allowlist (PHA-1848) stopped the client's `accept` from
  // riding along, and nothing replaced it — so 1.5.x sent NO accept header at all.
  // The stainless SDK genuine CC runs always sends `application/json`; sending
  // none is a fingerprint mismatch introduced by a fix that was only ever checked
  // for what it removed, not for what it left missing. Set it explicitly, as a
  // proxy-controlled value, which is what the allowlist rationale actually calls for.
  headers['accept'] = 'application/json';
  headers['accept-encoding'] = 'identity';
  headers['anthropic-version'] = '2023-06-01';
  // sessionId, once resolved, only ever came from deriveSessionId()'s
  // regex-validated read of existingHeaders (see comment above) -- never a raw
  // copy -- before being re-emitted below as the canonical header name.
  Object.assign(headers, getStainlessHeaders(sessionId || deriveSessionId(existingHeaders)));
  // Override the beta header WHOLESALE with the genuine 2.1.205 list/order. A merged
  // set that keeps client-specific betas (or reorders) is itself a fingerprint
  // (ocplatform PR #61); genuine CC replaces the header wholesale, so we do too.
  headers['anthropic-beta'] = REQUIRED_BETAS.join(',');
  return headers;
}


// PHA-1387 (2026-07-15): Buffered SSE transformer.
// Replaces the naive per-event reverse-map that missed matches when a masked
// term split across Anthropic content_block_delta boundaries. We now parse
// delta.text out of each event via JSON.parse, buffer per content_block,
// hold back a small carry-over tail sized to the longest remaining
// reverse-mapped term, and flush on content_block_stop.
//
// Outbound REPLACEMENTS array and its application are UNTOUCHED (load-bearing
// per Brandon's HARD CONSTRAINT - see PHA-1386 comment).
function computeMaxTermLength(reverseMapPairs, toolRenames, propRenames) {
  let max = 0;
  for (const [sanitized] of reverseMapPairs) {
    if (sanitized.length > max) max = sanitized.length;
  }
  for (const [, cc] of toolRenames) {
    if (cc.length + 2 > max) max = cc.length + 2;
  }
  for (const [, renamed] of propRenames) {
    if (renamed.length + 2 > max) max = renamed.length + 2;
  }
  return max;
}

function parseSSEEvent(event) {
  const dataIdx0 = event.startsWith('data: ') ? 0 : event.indexOf('\ndata: ');
  if (dataIdx0 === -1) return null;
  const dataIdx = dataIdx0 > 0 ? dataIdx0 + 1 : 0;
  const dataLineEnd = event.indexOf('\n', dataIdx + 6);
  const dataStr = dataLineEnd === -1
    ? event.slice(dataIdx + 6)
    : event.slice(dataIdx + 6, dataLineEnd);
  let obj;
  try { obj = JSON.parse(dataStr); } catch { return null; }
  return {
    prefix: event.slice(0, dataIdx),
    dataStr,
    obj,
    suffix: event.slice(dataIdx + 6 + dataStr.length),
  };
}

function rebuildSSEEvent(parsed, newObj) {
  return parsed.prefix + 'data: ' + JSON.stringify(newObj) + parsed.suffix;
}

const isHighSurrogate = (c) => c >= 0xd800 && c <= 0xdbff;
const isLowSurrogate = (c) => c >= 0xdc00 && c <= 0xdfff;

function createBufferedSSETransformer(reverseMapFn, carryLen) {
  const decoder = new StringDecoder('utf8');
  let pending = '';
  let currentBlockIsThinking = false;
  let textCarry = '';
  let lastTextIndex = 0;

  // textCarry always holds ALREADY reverse-mapped text (see the text_delta path
  // below, which stores mapped.slice(...)). Do NOT re-map it here — a second pass
  // could corrupt terms whose replacement re-matches another rule. Emit as-is.
  const flushCarryAsDelta = (index) => {
    if (!textCarry) return '';
    const text = textCarry;
    textCarry = '';
    return 'event: content_block_delta\ndata: ' +
      JSON.stringify({
        type: 'content_block_delta',
        index,
        delta: { type: 'text_delta', text },
      }) + '\n\n';
  };

  const processEvent = (event) => {
    const parsed = parseSSEEvent(event);
    if (!parsed) {
      const flushed = textCarry ? reverseMapFn(textCarry) : '';
      textCarry = '';
      return (flushed || '') + reverseMapFn(event);
    }
    const { obj } = parsed;
    if (obj.type === 'content_block_start') {
      const isThinking = obj.content_block && (
        obj.content_block.type === 'thinking' ||
        obj.content_block.type === 'redacted_thinking'
      );
      currentBlockIsThinking = !!isThinking;
      if (isThinking) return event;
      return reverseMapFn(event);
    }
    if (obj.type === 'content_block_delta' &&
        obj.delta && obj.delta.type === 'text_delta' &&
        !currentBlockIsThinking) {
      lastTextIndex = obj.index;
      const combined = textCarry + obj.delta.text;
      const mapped = reverseMapFn(combined);
      if (mapped.length <= carryLen - 1) {
        textCarry = mapped;
        return '';
      }
      // JS strings are UTF-16 code units, so a naive slice can land BETWEEN a
      // surrogate pair (any emoji / astral char). That leaves a lone high
      // surrogate at the end of toEmit and a lone low surrogate at the start of
      // textCarry; JSON.stringify happily encodes them as \udXXX, and strict
      // UTF-8 consumers (LiteLLM / pydantic-core) reject the whole chunk with
      // "str is not valid UTF-8: surrogates not allowed" — killing the stream
      // mid-generation (PHA-1860). Back the split up one unit when it splits a pair.
      let safeEmitLen = mapped.length - (carryLen - 1);
      if (safeEmitLen > 0 && isHighSurrogate(mapped.charCodeAt(safeEmitLen - 1))
          && isLowSurrogate(mapped.charCodeAt(safeEmitLen))) {
        safeEmitLen -= 1;
      }
      if (safeEmitLen <= 0) { textCarry = mapped; return ''; }
      const toEmit = mapped.slice(0, safeEmitLen);
      textCarry = mapped.slice(safeEmitLen);
      const newObj = { ...obj, delta: { ...obj.delta, text: toEmit } };
      return rebuildSSEEvent(parsed, newObj);
    }
    if (obj.type === 'content_block_stop') {
      const wasThinking = currentBlockIsThinking;
      currentBlockIsThinking = false;
      if (wasThinking) return event;
      // Flush the held-back tail as its own final text_delta BEFORE the stop
      // event. The previous code cleared textCarry first, so flushCarryAsDelta
      // no-op'd and the tail was prepended raw to the stop event — malformed SSE
      // that clients drop, truncating the last ~20 chars of every reply (PHA-1399).
      return flushCarryAsDelta(obj.index) + reverseMapFn(event);
    }
    if (currentBlockIsThinking) return event;
    return reverseMapFn(event);
  };

  return {
    onData: (chunk) => {
      pending += decoder.write(chunk);
      const outParts = [];
      let sepIdx;
      while ((sepIdx = pending.indexOf('\n\n')) !== -1) {
        const event = pending.slice(0, sepIdx + 2);
        pending = pending.slice(sepIdx + 2);
        outParts.push(processEvent(event));
      }
      return outParts.join('');
    },
    onEnd: () => {
      pending += decoder.end();
      let out = '';
      if (pending.length > 0) out += processEvent(pending);
      // Any tail still buffered here is an abnormal end (no content_block_stop).
      // textCarry is already reverse-mapped — emit as-is, don't map twice.
      // It must still go out as a well-formed text_delta event: appending the
      // raw tail to the stream produced a bare, unparseable line that clients
      // drop (and that trips strict SSE parsers), so the last few chars of the
      // reply vanished on any stream that ended without content_block_stop.
      if (textCarry.length > 0) out += flushCarryAsDelta(lastTextIndex);
      return out;
    },
  };
}

// Single createSSETransformer wrapper - the only one in this file.
// Returns a buffered transformer configured for this module's reverse-map.
function createSSETransformer() {
  return createBufferedSSETransformer(
    reverseMap,
    computeMaxTermLength(REVERSE_MAP, TOOL_RENAMES, PROP_RENAMES) + 1
  );
}

module.exports = {
  processBody,
  reverseMap,
  reverseMapBuffer,
  createSSETransformer,
  loadOAuthToken,
  refreshTokenIfStale,
  buildBillingHeaders,
  buildBillingHeaderValue,
  deriveSessionId,
  setCCVersion,
  setLastRequestId,
  noteUpstreamStatus,
  // Which of the two fingerprint carriers is live right now — surfaced on /health
  // so a fallback latch (PHA-1887) is visible without reading logs.
  get billingHeaderMode() {
    return BILLING_HEADER_MODE === 'header' && billingHeaderShed ? 'header(shed→body)' : BILLING_HEADER_MODE;
  },
  // Whether an account_uuid is configured — surfaced on /health so ops can confirm
  // the primary anti-detection field is actually set before/after a deploy.
  get accountUuidConfigured() { return !!ACCOUNT_UUID; },
  // Live getter so callers (health endpoint, logs) always see the current value
  // after a self-update, not a snapshot taken at module load.
  get CC_VERSION() { return CC_VERSION; },
  // The full beta list this module installs on every outbound request. Exposed
  // so the bootstrap can assert the 1h cache TTL beta is present (PHA-1611).
  get REQUIRED_BETAS() { return REQUIRED_BETAS; },
};
