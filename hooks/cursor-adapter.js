'use strict';
// Cursor IDE / CLI Lifecycle Hook Adapter for neckbeard (hooks/cursor-adapter.js).
// Bridges Cursor's hooks.json v1 stdin/stdout protocol (sessionStart, subagentStart,
// beforeSubmitPrompt, preToolUse) cleanly onto the persona's native hooks with zero shell
// interpolation (shell: false) and fail-closed exit code 2 on PreToolUse denials.

const path = require('path');
const { execFileSync } = require('child_process');

const HOOKS_DIR = __dirname;
const MAX_STDIN = 4 * 1024 * 1024;
const EVENT_MAP = Object.freeze({
  sessionStart: { script: 'session-start.js', nativeEvent: 'SessionStart' },
  subagentStart: { script: 'subagent-start.js', nativeEvent: 'SubagentStart' },
  beforeSubmitPrompt: { script: 'prompt.js', nativeEvent: 'UserPromptSubmit' },
  preToolUse: { script: 'guard.js', nativeEvent: 'PreToolUse' },
});

function readStdin(timeoutMs = 1000) {
  return new Promise((resolve) => {
    let raw = '';
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      try { resolve(JSON.parse(raw.replace(/^\uFEFF/, '') || '{}')); } catch { resolve({}); }
    };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      if (raw.length < MAX_STDIN) raw += chunk.slice(0, MAX_STDIN - raw.length);
      if (raw.length >= MAX_STDIN) finish();
    });
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
    setTimeout(finish, timeoutMs).unref();
  });
}

function mapCursorToolName(rawName) {
  const n = String(rawName || '').trim();
  const lower = n.toLowerCase();
  if (lower === 'shell' || lower === 'run_terminal_cmd' || lower === 'terminal' || lower === 'bash') return 'Bash';
  if (lower === 'strreplace' || lower === 'str_replace' || lower === 'edit_file' || lower === 'edit') return 'Edit';
  if (lower === 'write' || lower === 'write_file' || lower === 'create_file') return 'Write';
  if (lower === 'multiedit' || lower === 'multi_edit') return 'MultiEdit';
  return n || 'Unknown';
}

function normalizeCursorPayload(event, cursorInput) {
  const safe = cursorInput && typeof cursorInput === 'object' ? cursorInput : {};
  const roots = Array.isArray(safe.workspace_roots) ? safe.workspace_roots : [];
  const cwd = safe.cwd || (roots.length > 0 ? roots[0] : process.cwd());
  const sessionId = safe.session_id || safe.conversation_id || safe.generation_id || 'cursor-default';

  const base = {
    session_id: String(sessionId),
    cwd: String(cwd),
    source: safe.source || 'startup',
    harness: 'cursor',
  };

  if (event === 'beforeSubmitPrompt') {
    base.prompt = typeof safe.prompt === 'string' ? safe.prompt : String(safe.user_prompt || safe.message || '');
  } else if (event === 'subagentStart') {
    const agentType = safe.agent_type || safe.subagent_type || safe.agent_name || safe.agent || '';
    if (agentType) base.agent_type = String(agentType);
    if (typeof safe.prompt === 'string') base.prompt = safe.prompt;
  } else if (event === 'preToolUse') {
    base.tool_name = mapCursorToolName(safe.tool_name || safe.tool || (safe.command ? 'Shell' : ''));
    const ti = safe.tool_input && typeof safe.tool_input === 'object' ? { ...safe.tool_input } : {};
    if (safe.command && !ti.command) ti.command = safe.command;
    if (safe.file_path && !ti.file_path) ti.file_path = safe.file_path;
    if (safe.path && !ti.file_path) ti.file_path = safe.path;
    if (safe.content !== undefined && ti.content === undefined) ti.content = safe.content;
    if (safe.new_string !== undefined && ti.new_string === undefined) ti.new_string = safe.new_string;
    base.tool_input = ti;
  }

  return base;
}

function translateNativeOutput(event, rawStdout) {
  let parsed = null;
  try {
    parsed = rawStdout && rawStdout.trim() ? JSON.parse(rawStdout) : null;
  } catch {
    parsed = null;
  }
  const hso = parsed && parsed.hookSpecificOutput ? parsed.hookSpecificOutput : {};
  const ctx = typeof hso.additionalContext === 'string' ? hso.additionalContext : '';

  if (event === 'preToolUse') {
    if (hso.permissionDecision === 'deny') {
      const reason = hso.permissionDecisionReason || 'Blocked by neckbeard PreToolUse guard.';
      return {
        exitCode: 2,
        output: {
          permission: 'deny',
          agentMessage: reason,
          userMessage: reason,
          additional_context: reason,
        },
      };
    }
    return { exitCode: 0, output: { permission: 'allow' } };
  }

  if (event === 'beforeSubmitPrompt') {
    const out = { continue: true };
    if (ctx) out.additional_context = ctx;
    return { exitCode: 0, output: out };
  }

  if (event === 'subagentStart') {
    const out = { permission: 'allow' };
    if (ctx) out.additional_context = ctx;
    return { exitCode: 0, output: out };
  }

  // sessionStart
  const out = {};
  if (ctx) out.additional_context = ctx;
  return { exitCode: 0, output: out };
}

function runCursorEvent(event, cursorInput, env = process.env) {
  const entry = EVENT_MAP[event];
  if (!entry) {
    return { exitCode: 0, output: {} };
  }
  const scriptPath = path.join(HOOKS_DIR, entry.script);
  const nativePayload = normalizeCursorPayload(event, cursorInput);
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, [scriptPath], {
      input: JSON.stringify(nativePayload),
      encoding: 'utf8',
      timeout: 8000,
      maxBuffer: 2 * 1024 * 1024,
      env,
      shell: false,
      stdio: ['pipe', 'pipe', 'ignore'],
    });
  } catch (err) {
    stdout = err && err.stdout ? String(err.stdout) : '';
  }
  return translateNativeOutput(event, stdout);
}

module.exports = {
  EVENT_MAP,
  mapCursorToolName,
  normalizeCursorPayload,
  translateNativeOutput,
  runCursorEvent,
};

if (require.main === module) {
  const event = process.argv[2] || '';
  (async () => {
    const input = await readStdin();
    const res = runCursorEvent(event, input, process.env);
    process.stdout.write(JSON.stringify(res.output));
    process.exitCode = res.exitCode;
  })().finally(() => setTimeout(() => process.exit(process.exitCode || 0), 0));
}
