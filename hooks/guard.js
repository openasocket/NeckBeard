'use strict';
// PreToolUse guard. Only high-confidence patterns, so it rarely fires on legitimate work.
//   full:     blocks hard-coded secrets and direct tampering with immutable VIBES .ai-audit/ files.
//   paranoid: also blocks pipe-to-shell installs, disabled TLS checks,
//             world-writable permissions, skipped git hooks, and literal credentials.
//   lite/off: does nothing.
// A block names the kind of violation and where it is, never a secret's value.

const path = require('path');
const { readInput, readLevel, emitDeny } = require('./lib');

const SECRETS = [
  ['private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/],
  ['AWS access key', /\b(?:AKIA|ASIA)(?![A-Z0-9]*EXAMPLE)[A-Z0-9]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Stripe live key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]+/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
];

// Paranoid adds a generic "credential assigned a literal" rule; placeholders pass.
const GENERIC_SECRET = /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/i;
const PLACEHOLDER = /(example|changeme|change_me|dummy|placeholder|your[_-]|xxxx|\*\*\*\*|<[^>]+>|\$\{|process\.env|os\.environ|getenv|test|fake|redacted)/i;

const UNSAFE_CODE = [
  ['TLS verification turned off', /\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/],
];

const UNSAFE_SHELL = [
  ['piping a download straight into a shell', /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/],
  ['TLS verification turned off', /\bcurl\b[^\n;&|]*\s(?:-k|--insecure)\b|NODE_TLS_REJECT_UNAUTHORIZED=0|GIT_SSL_NO_VERIFY=(?:1|true)|\bgit\s+config\b[^\n]*http\.sslVerify\s+false/],
  ['world-writable permissions', /\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|o\+w)\b/],
  ['skipping git hooks', /\bgit\s+(?:commit|push)\b[^\n;&|]*\s--no-verify\b/],
];

// VIBES (itsavibe.ai) immutable provenance and sealed evidence artifacts under .ai-audit/.
// Owned exclusively by VIBES producer hooks and vibecheck/vibetrace CLIs; hand-editing breaks
// SHA-256 content hashes and DSSE/in-toto attestations. Declarative rules in .ai-audit/iocs.d/,
// .ai-audit/extensions/, and policy in .ai-audit/config.json remain editable.
const VIBES_IMMUTABLE_PATH = /(?:^|\/)\.ai-audit\/(?:manifest\.json|annotations\.jsonl|audit\.db[^/]*|\.session_state\.json|\.pending[^/]*|(?:blobs|attestations|incidents|evidence|wal)(?:\/|$))/;
const VIBES_TAMPER_SHELL = /\b(?:rm|rmdir|unlink|mv|cp|truncate|dd|shred|tee)\b[^\n;&|]*\.ai-audit(?:\/(?:manifest\.json|annotations\.jsonl|audit\.db|\.session_state\.json|blobs|attestations|incidents|evidence|wal))?(?=\s|$|[;&|"'`])|(?:>|>>)\s*['"]?[^\s;&|'"]*\.ai-audit\/(?:manifest\.json|annotations\.jsonl|audit\.db|\.session_state\.json|blobs|attestations|incidents|evidence|wal)\b|\bsed\b[^\n;&|]*\s-i\b[^\n;&|]*\.ai-audit\//;

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function normalizePosix(p) {
  return path.posix.normalize(String(p || '').replace(/\\/g, '/').trim());
}

function findVibesTamper(tool, input) {
  const i = input || {};
  if (tool === 'Bash') {
    const rawCmd = String(i.command || '');
    // Collapse redundant path segments (e.g. .ai-audit/./manifest.json or .ai-audit/iocs.d/../manifest.json) before matching.
    const normCmd = rawCmd.replace(/\.ai-audit(?:\/[^\s;&|"'`]+)+/g, (m) => normalizePosix(m));
    const m = VIBES_TAMPER_SHELL.exec(normCmd);
    if (m) return { where: 'this command', line: lineOf(normCmd, m.index) };
    return null;
  }
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
    const rawPath = String(i.file_path || i.notebook_path || '');
    if (!rawPath) return null;
    const norm = normalizePosix(rawPath);
    if (VIBES_IMMUTABLE_PATH.test(norm)) return { where: rawPath, line: 1 };
  }
  return null;
}

function findSecret(text, level) {
  for (const [kind, re] of SECRETS) {
    const m = re.exec(text);
    if (m) return { kind, line: lineOf(text, m.index) };
  }
  if (level === 'paranoid') {
    const m = GENERIC_SECRET.exec(text);
    if (m && !PLACEHOLDER.test(m[1])) return { kind: 'credential assigned a literal value', line: lineOf(text, m.index) };
  }
  return null;
}

function findUnsafe(text, list) {
  for (const [kind, re] of list) {
    const m = re.exec(text);
    if (m) return { kind, line: lineOf(text, m.index) };
  }
  return null;
}

// What a tool call would put on disk or run. Edits are judged by their new text only,
// so a secret already in a file never blocks unrelated edits to it.
function payload(tool, input) {
  const i = input || {};
  switch (tool) {
    case 'Write': return i.content;
    case 'Edit': return i.new_string;
    case 'MultiEdit': return (i.edits || []).map((e) => e && e.new_string).join('\n');
    case 'NotebookEdit': return i.new_source;
    case 'Bash': return i.command;
    default: return '';
  }
}

function check(tool, input, level) {
  if (level !== 'full' && level !== 'paranoid') return null;

  const vibes = findVibesTamper(tool, input);
  if (vibes) {
    return `neckbeard blocked this ${tool}: it modifies or deletes an immutable VIBES provenance or evidence artifact (${vibes.where}, line ${vibes.line}). ` +
      'Files under .ai-audit/ (manifest.json, annotations.jsonl, blobs/, attestations/, incidents/, evidence/, audit.db) are content-addressed audit records owned by VIBES hooks and CLIs; ' +
      'direct edits break SHA-256 integrity hashes and invalidate DSSE attestations. Use vibes, vibecheck, or vibetrace instead.';
  }

  const text = String(payload(tool, input) || '');
  if (!text) return null;
  const where = tool === 'Bash' ? 'this command' : `${(input && (input.file_path || input.notebook_path)) || 'this file'}`;

  const secret = findSecret(text, level);
  if (secret) {
    return `neckbeard blocked this ${tool}: it contains a ${secret.kind} (${where}, line ${secret.line}). ` +
      'Secrets never go in code, commands, logs or fixtures. Read it from the environment or the project\'s secret store, ' +
      'and use an obviously fake value in tests. If the user really wants this, ask them to turn the guard off with /neckbeard lite.';
  }
  if (level === 'paranoid') {
    const unsafe = findUnsafe(text, tool === 'Bash' ? UNSAFE_SHELL : UNSAFE_CODE);
    if (unsafe) {
      return `neckbeard (paranoid) blocked this ${tool}: ${unsafe.kind} (${where}, line ${unsafe.line}). ` +
        'Find a safe way (download, verify a checksum or signature, then run; fix the certificate; set exact permissions; let hooks run), ' +
        'or ask the user to allow it and switch to /neckbeard full for that step.';
    }
  }
  return null;
}

module.exports = { check, findSecret, findVibesTamper, payload };

if (require.main === module) {
  (async () => {
    if (process.env.NECKBEARD_GUARD === '0') return;
    const input = await readInput();
    const reason = check(input.tool_name, input.tool_input, readLevel(input.session_id));
    if (reason) emitDeny(reason);
  })().finally(() => setTimeout(() => process.exit(0), 0));
}
