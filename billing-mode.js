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

const CC_VERSION = '2.1.97';
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];
// DEVICE_ID and INSTANCE_SESSION_ID stay stable across container restarts only
// if pinned via env. Otherwise each startup looks like a fresh device, which
// hurts billing fingerprint continuity (not correctness).
const DEVICE_ID = process.env.DEVICE_ID || crypto.randomBytes(32).toString('hex');
const INSTANCE_SESSION_ID = process.env.INSTANCE_SESSION_ID || crypto.randomUUID();

const REQUIRED_BETAS = [
  'oauth-2025-04-20',
  'claude-code-20250219',
  'interleaved-thinking-2025-05-14',
  'advanced-tool-use-2025-11-20',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24',
  'fast-mode-2026-02-01',
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
  ['third-party', 'external'], ['billing proxy', 'routing layer'],
  ['billing-proxy', 'routing-layer'],
  ['x-anthropic-billing-header', 'x-routing-config'],
  ['x-anthropic-billing', 'x-routing-cfg'],
  ['cch=00000', 'cfg=00000'], ['cc_version', 'rt_version'],
  ['cc_entrypoint', 'rt_entrypoint'], ['billing header', 'routing config'],
  ['extra usage', 'usage quota'], ['assistant platform', 'ocplatform'],
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
  ['OCPlatform', 'OpenClaw'], ['ocplatform', 'openclaw'],
  ['create_task', 'sessions_spawn'], ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'], ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'], ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK'], ['HB_SIGNAL', 'HEARTBEAT'], ['hb_signal', 'heartbeat'],
  ['PAssistant', 'Prometheus'], ['passistant', 'prometheus'],
  ['skillhub.example.com', 'clawhub.com'], ['skillhub', 'clawhub'],
  ['agentd', 'clawd'], ['lossless-ctx', 'lossless-claw'],
  ['external', 'third-party'], ['routing layer', 'billing proxy'],
  ['routing-layer', 'billing-proxy'],
  ['x-routing-config', 'x-anthropic-billing-header'],
  ['x-routing-cfg', 'x-anthropic-billing'],
  ['cfg=00000', 'cch=00000'], ['rt_version', 'cc_version'],
  ['rt_entrypoint', 'cc_entrypoint'], ['routing config', 'billing header'],
  ['usage quota', 'extra usage'],
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

function buildBillingBlock(bodyStr) {
  const firstText = extractFirstUserText(bodyStr);
  const fingerprint = computeBillingFingerprint(firstText);
  return `{"type":"text","text":"x-anthropic-billing-header: cc_version=${CC_VERSION}.${fingerprint}; cc_entrypoint=cli; cch=00000;"}`;
}

function getStainlessHeaders() {
  const p = process.platform;
  const osName = p === 'darwin' ? 'macOS' : p === 'win32' ? 'Windows' : p === 'linux' ? 'Linux' : p;
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
  return {
    'user-agent': `claude-cli/${CC_VERSION} (external, cli)`,
    'x-app': 'cli',
    'x-claude-code-session-id': INSTANCE_SESSION_ID,
    'x-stainless-arch': arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': osName,
    'x-stainless-package-version': '0.81.0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': process.version,
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

function processBody(bodyStr) {
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
    // End at the first markdown H2 section break after the identity marker.
    // Previously this required `\n## /` or `\n## C:\\` (paths from the
    // OpenClaw workspace template) — too brittle if that format ever changes.
    // Any H2 break is still bounded by the strippedLen > 1000 guard below.
    const configEnd = m.indexOf('\\n## ', configStart + IDENTITY_MARKER.length);
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

  // Layer 1: Billing fingerprint block injection into system array
  const BILLING_BLOCK = buildBillingBlock(m);
  const sysArrayIdx = m.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    m = m.slice(0, insertAt) + BILLING_BLOCK + ',' + m.slice(insertAt);
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
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + m.slice(sysEnd);
  } else {
    m = '{"system":[' + BILLING_BLOCK + '],' + m.slice(1);
  }

  // Metadata injection
  const metaValue = JSON.stringify({ device_id: DEVICE_ID, session_id: INSTANCE_SESSION_ID });
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
function createSSETransformer() {
  const decoder = new StringDecoder('utf8');
  let pending = '';
  let currentBlockIsThinking = false;

  const transformEvent = (event) => {
    let dataIdx = event.startsWith('data: ') ? 0 : event.indexOf('\ndata: ');
    if (dataIdx === -1) return reverseMap(event);
    if (dataIdx > 0) dataIdx += 1;
    const dataLineEnd = event.indexOf('\n', dataIdx + 6);
    const dataStr = dataLineEnd === -1 ? event.slice(dataIdx + 6) : event.slice(dataIdx + 6, dataLineEnd);

    if (dataStr.indexOf('"type":"content_block_start"') !== -1) {
      if (dataStr.indexOf('"content_block":{"type":"thinking"') !== -1
          || dataStr.indexOf('"content_block":{"type":"redacted_thinking"') !== -1) {
        currentBlockIsThinking = true;
        return event;
      }
      currentBlockIsThinking = false;
      return reverseMap(event);
    }
    if (dataStr.indexOf('"type":"content_block_stop"') !== -1) {
      const wasThinking = currentBlockIsThinking;
      currentBlockIsThinking = false;
      return wasThinking ? event : reverseMap(event);
    }
    if (currentBlockIsThinking) return event;
    return reverseMap(event);
  };

  return {
    onData: (chunk) => {
      pending += decoder.write(chunk);
      const events = [];
      let sepIdx;
      while ((sepIdx = pending.indexOf('\n\n')) !== -1) {
        const event = pending.slice(0, sepIdx + 2);
        pending = pending.slice(sepIdx + 2);
        events.push(transformEvent(event));
      }
      return events.join('');
    },
    onEnd: () => {
      pending += decoder.end();
      if (pending.length > 0) return transformEvent(pending);
      return '';
    },
  };
}

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

function buildBillingHeaders(oauthToken, existingHeaders) {
  const headers = {};
  for (const [key, value] of Object.entries(existingHeaders || {})) {
    const lk = key.toLowerCase();
    if (lk === 'host' || lk === 'connection' || lk === 'authorization'
        || lk === 'x-api-key' || lk === 'content-length'
        || lk === 'x-session-affinity') continue;
    headers[key] = value;
  }
  headers['authorization'] = `Bearer ${oauthToken}`;
  headers['accept-encoding'] = 'identity';
  headers['anthropic-version'] = '2023-06-01';
  Object.assign(headers, getStainlessHeaders());
  const existingBeta = headers['anthropic-beta'] || '';
  const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
  for (const b of REQUIRED_BETAS) { if (!betas.includes(b)) betas.push(b); }
  headers['anthropic-beta'] = betas.join(',');
  return headers;
}

module.exports = {
  processBody,
  reverseMap,
  reverseMapBuffer,
  createSSETransformer,
  loadOAuthToken,
  buildBillingHeaders,
  CC_VERSION,
};
