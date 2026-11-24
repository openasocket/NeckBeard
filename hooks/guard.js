'use strict';
// PreToolUse guard. Fail-closed protection at full and paranoid levels:
//   full:     blocks hard-coded secrets (including Base64/JSON-escaped), ALL writes under .ai-audit/**,
//             writes to read-only .crew.json, ALL writes to sibling persona stores (dynamically loaded
//             from $CREW_CONFIG_DIR/registry/personas/*.json + 13-persona fallback), obfuscated/unsanitized
//             writes to .neckbeard.json or .rainmaker-inbox.jsonl, and $CREW_CONFIG_DIR memory poisoning /
//             compartment wall breaches.
//   paranoid: also blocks pipe-to-shell installs, disabled TLS checks,
//             world-writable permissions, skipped git hooks, and literal credentials.
//   lite/off: does nothing.
// A block names the kind of violation and where it is, never a secret's value, and increments local guard telemetry.

const path = require('path');
const {
  readInput,
  readLevel,
  crewConfigDir,
  getDynamicPeerStoreFiles,
  recordGuardBlock,
  emitDeny,
} = require('./lib');
const {
  RAINMAKER_INBOX_FILE,
  MAX_JSONL_LINE_BYTES,
  stripInvisibleChars,
  decodeJsonEscapes,
  decodeUrlPercent,
  buildInspectionViews,
  findSensitiveMatch,
  checkNeckbeardJson,
  checkCrewStoreJson,
} = require('./surface');
const { UNTRUSTED_PAYLOAD_RE, REGULATED_MARKING_RE } = require('./memory');

const CREW_POLICY_FILE = '.crew.json';

const FILE_TOOLS = new Set([
  'write', 'edit', 'multiedit', 'multi_edit', 'notebookedit', 'notebook_edit', 'write_file', 'edit_file',
]);
const EDIT_TOOLS = new Set([
  'edit', 'multiedit', 'multi_edit', 'notebookedit', 'notebook_edit', 'edit_file',
]);
const SHELL_TOOLS = new Set(['bash', 'shell', 'run_command', 'terminal']);

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

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function normalizeTool(tool) {
  return String(tool || '').trim().toLowerCase();
}

function normalizeSegment(seg) {
  return String(seg || '').replace(/:.*$/, '').replace(/[. ]+$/, '').toLowerCase();
}

function normalizePosix(rawPath, cwdPosix = '') {
  let s = stripInvisibleChars(String(rawPath || '')).trim();
  if (!s) return '';
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1);
  }
  if (s.includes('\\u') || s.includes('\\U') || s.includes('\\x') || s.includes('\\X')) {
    s = decodeJsonEscapes(s);
  }
  if (s.includes('%')) {
    s = decodeUrlPercent(s);
  }
  s = s.replace(/\\/g, '/');
  if (cwdPosix && !s.startsWith('/') && !/^[A-Za-z]:\//.test(s)) {
    return path.posix.normalize(path.posix.join(cwdPosix, s));
  }
  return path.posix.normalize(s);
}

function extractFilePath(input) {
  const i = input || {};
  return String(i.file_path || i.filePath || i.notebook_path || i.notebookPath || i.path || i.Path || '');
}

// Quote-aware shell splitter and mutator target extractor.
function splitShellSegments(command) {
  const s = String(command || '');
  const segments = [];
  let cur = '';
  let quote = null;
  let esc = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const next = s[i + 1];
    if (esc) { cur += ch; esc = false; continue; }
    if (ch === '\\' && quote !== "'") { cur += ch; esc = true; continue; }
    if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === ';' || ch === '\n') { if (cur.trim()) segments.push(cur.trim()); cur = ''; continue; }
    if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
      if (cur.trim()) segments.push(cur.trim());
      cur = '';
      i += 1;
      continue;
    }
    if (ch === '|' && next !== '>') { if (cur.trim()) segments.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) segments.push(cur.trim());
  return segments;
}

function tokenizeShell(segment) {
  const tokens = [];
  let cur = '';
  let quote = null;
  let esc = false;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (esc) { cur += ch; esc = false; continue; }
    if (ch === '\\' && quote !== "'") { esc = true; continue; }
    if (quote) { if (ch === quote) quote = null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { tokens.push(cur); cur = ''; } continue; }
    cur += ch;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

function extractShellMutatedPaths(command) {
  const targets = [];
  const raw = String(command || '');
  if (!raw.trim()) return targets;

  // 1. Redirections (>file, >> file, >|file, 1>file)
  const redirRe = /(?:^|[^<])(?:\d+|&)?(?:>>?|>\||<>)\s*("[^"]+"|'[^']+'|[^\s;&|]+)/g;
  let m;
  while ((m = redirRe.exec(raw)) !== null) {
    const t = m[1];
    if (t && !t.startsWith('&')) {
      targets.push({ op: 'redirect', raw: t, norm: normalizePosix(t), line: lineOf(raw, m.index) });
    }
  }

  // 2. Per-segment mutating commands
  let simCwd = '';
  for (const seg of splitShellSegments(raw)) {
    const tokens = tokenizeShell(seg);
    if (!tokens.length) continue;
    let idx = 0;
    while (idx < tokens.length) {
      const tk = tokens[idx];
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tk)) { idx += 1; continue; }
      if (tk === 'sudo' || tk === 'env' || tk === 'command' || tk === 'nohup') {
        idx += 1;
        while (idx < tokens.length && tokens[idx].startsWith('-')) idx += 1;
        continue;
      }
      break;
    }
    if (idx >= tokens.length) continue;
    const cmd = path.posix.basename(tokens[idx]).toLowerCase();
    const args = tokens.slice(idx + 1);

    if (cmd === 'cd' && args[0]) {
      simCwd = normalizePosix(args[0], simCwd);
      continue;
    }
    const pushTarget = (op, p) => {
      if (!p || p === '-' || p === '--') return;
      targets.push({ op, raw: p, norm: normalizePosix(p, simCwd), line: 1 });
    };

    if (['rm', 'unlink', 'shred', 'rmdir', 'touch', 'chmod', 'chown', 'chattr', 'sponge', 'tee'].includes(cmd)) {
      for (const a of args) if (!a.startsWith('-')) pushTarget(cmd, a);
    } else if (cmd === 'truncate') {
      for (let i = 0; i < args.length; i++) {
        if (['-s', '--size', '-r', '--reference'].includes(args[i])) { i += 1; continue; }
        if (!args[i].startsWith('-')) pushTarget('truncate', args[i]);
      }
    } else if (cmd === 'mv') {
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-t' || args[i] === '--target-directory') { if (args[i + 1]) pushTarget('mv', args[i + 1]); i += 1; continue; }
        if (args[i].startsWith('--target-directory=')) { pushTarget('mv', args[i].slice('--target-directory='.length)); continue; }
        if (!args[i].startsWith('-')) pushTarget('mv', args[i]);
      }
    } else if (cmd === 'cp' || cmd === 'install' || cmd === 'ln') {
      const pos = [];
      let targetDir = null;
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-t' || args[i] === '--target-directory') { targetDir = args[i + 1] || null; i += 1; continue; }
        if (args[i].startsWith('--target-directory=')) { targetDir = args[i].slice('--target-directory='.length); continue; }
        if (!args[i].startsWith('-')) pos.push(args[i]);
      }
      if (targetDir) {
        pushTarget(cmd, targetDir);
        for (const src of pos) pushTarget(cmd, path.posix.join(normalizePosix(targetDir, simCwd), path.posix.basename(normalizePosix(src))));
      } else if (pos.length >= 2) {
        const dest = pos[pos.length - 1];
        pushTarget(cmd, dest);
        for (let i = 0; i < pos.length - 1; i++) {
          pushTarget(cmd, path.posix.join(normalizePosix(dest, simCwd), path.posix.basename(normalizePosix(pos[i]))));
        }
      } else if (pos.length === 1) {
        pushTarget(cmd, pos[0]);
      }
    } else if (cmd === 'dd') {
      for (const a of args) if (a.startsWith('of=')) pushTarget('dd', a.slice(3));
    } else if (cmd === 'sed' || cmd === 'gsed') {
      if (args.some((a) => a === '-i' || a.startsWith('-i') || a === '--in-place' || a.startsWith('--in-place='))) {
        for (const a of args) {
          if (!a.startsWith('-') && a !== '' && (a.includes('/') || a.includes('.ai-audit') || a.endsWith('.json') || a.endsWith('.jsonl') || a.endsWith('.yaml'))) {
            pushTarget('sed -i', a);
          }
        }
      }
    } else if (cmd === 'perl' && args.some((a) => /^-[a-zA-Z]*i/.test(a))) {
      for (const a of args) if (!a.startsWith('-')) pushTarget('perl -i', a);
    } else if (cmd === 'git') {
      const sub = (args[0] || '').toLowerCase();
      if (['rm', 'mv', 'clean', 'checkout', 'restore'].includes(sub)) {
        for (const a of args.slice(1)) if (!a.startsWith('-')) pushTarget(`git ${sub}`, a);
      }
    } else if (cmd === 'sqlite3' && /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|VACUUM|REPLACE|ATTACH)\b/i.test(seg)) {
      for (const a of args) if (!a.startsWith('-')) pushTarget('sqlite3', a);
    } else if (['node', 'python', 'python3', 'ruby'].includes(cmd)) {
      if (/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rmSync|rmdirSync|renameSync|truncateSync|copyFileSync|createWriteStream|os\.remove|os\.unlink|shutil\.rmtree|Path\([^)]+\)\.write_|open\([^)]*['"][wax+])/i.test(seg)) {
        const quoted = seg.match(/["']([^"'\n]+)["']/g) || [];
        for (const q of quoted) {
          const inner = q.slice(1, -1);
          if (inner.includes('.ai-audit') || inner.includes('.crew.json') || inner.includes('memory/') || inner.includes('enclaves/') || inner.endsWith('.json') || inner.endsWith('.jsonl')) {
            pushTarget(`${cmd}-fs`, inner);
          }
        }
      }
    }
  }
  return targets;
}

// Fail-closed: ALL paths under .ai-audit/** are read-only for agent mutations.
function isVibesPath(normPath) {
  if (!normPath) return false;
  return String(normPath).replace(/\\/g, '/').split('/').filter(Boolean).some((seg) => normalizeSegment(seg) === '.ai-audit');
}

function isCrewPolicyPath(normPath) {
  if (!normPath) return false;
  return String(normPath).replace(/\\/g, '/').split('/').filter(Boolean).some((seg) => normalizeSegment(seg) === CREW_POLICY_FILE);
}

function findVibesTamper(tool, input) {
  const t = normalizeTool(tool);
  const i = input || {};
  if (SHELL_TOOLS.has(t)) {
    const targets = extractShellMutatedPaths(String(i.command || i.cmd || ''));
    for (const hit of targets) {
      if (isVibesPath(hit.norm)) return { where: hit.norm, line: hit.line || 1 };
    }
    return null;
  }
  if (FILE_TOOLS.has(t)) {
    const rawPath = extractFilePath(i);
    if (!rawPath) return null;
    const norm = normalizePosix(rawPath);
    if (isVibesPath(norm)) return { where: rawPath, line: 1 };
  }
  return null;
}

function findCrewPolicyTamper(tool, input) {
  const t = normalizeTool(tool);
  const i = input || {};
  if (SHELL_TOOLS.has(t)) {
    for (const hit of extractShellMutatedPaths(String(i.command || i.cmd || ''))) {
      if (isCrewPolicyPath(hit.norm)) return { where: hit.norm, op: hit.op };
    }
    return null;
  }
  if (FILE_TOOLS.has(t)) {
    const rawPath = extractFilePath(i);
    const norm = normalizePosix(rawPath);
    if (isCrewPolicyPath(norm)) return { where: rawPath, op: tool };
  }
  return null;
}

// Dynamically builds the set of ALL OTHER registered + built-in sibling persona store files.
function getSiblingStoreSet(env = process.env) {
  const peerFiles = getDynamicPeerStoreFiles('neckbeard', env);
  return new Set(Object.values(peerFiles).map((f) => String(f).toLowerCase()));
}

function findSiblingStoreTamper(tool, input, env = process.env) {
  const siblingSet = getSiblingStoreSet(env);
  const t = normalizeTool(tool);
  const i = input || {};

  if (FILE_TOOLS.has(t)) {
    const rawPath = extractFilePath(i);
    const norm = normalizePosix(rawPath);
    if (!norm) return null;
    const base = normalizeSegment(path.posix.basename(norm));
    if (siblingSet.has(base)) {
      return { where: rawPath, storeFile: base, op: tool };
    }
    return null;
  }
  if (SHELL_TOOLS.has(t)) {
    for (const hit of extractShellMutatedPaths(String(i.command || i.cmd || ''))) {
      const base = normalizeSegment(path.posix.basename(hit.norm));
      if (siblingSet.has(base)) {
        return { where: hit.norm, storeFile: base, op: hit.op };
      }
    }
  }
  return null;
}

function classifyMemoryTarget(normPath, env = process.env) {
  if (!normPath) return null;
  const p = normPath.replace(/\/+$/, '');
  const resolvedCrew = normalizePosix(path.resolve(crewConfigDir(env)));
  const isInsideEnclave = p.startsWith(`${resolvedCrew}/enclaves/`) || /(?:^|\/)enclaves\/[^/]+\//.test(p);
  const isInsideCommercial = !isInsideEnclave && (
    p.startsWith(`${resolvedCrew}/memory/`) ||
    /(?:^|\/)memory\/agents\/neckbeard(?:\/|$)/.test(p) ||
    /(?:^|\/)memory\/teams\/[^/]+(?:\/|$)/.test(p) ||
    /(?:^|\/)memory\/grpo-signals\.jsonl$/.test(p)
  );
  if (!isInsideEnclave && !isInsideCommercial) return null;
  return {
    path: p,
    isRegulated: isInsideEnclave,
    isProtectedBucket: /(?:^|\/)preferences\.jsonl$/.test(p) || /(?:^|\/)learned-skills(?:\/|$)/.test(p),
    isJsonl: p.endsWith('.jsonl'),
  };
}

function checkMemoryMutation(tool, input, env = process.env) {
  const t = normalizeTool(tool);
  const i = input || {};
  const text = String(payload(tool, i) || '');

  const validateTarget = (normPath, isFullWrite) => {
    const target = classifyMemoryTarget(normPath, env);
    if (!target) return null;
    const views = buildInspectionViews(text);
    for (const v of views) {
      if (target.isProtectedBucket) {
        if (UNTRUSTED_PAYLOAD_RE.test(v.text) || /"trustTier"\s*:\s*"untrusted"/i.test(v.text)) {
          return `Memory Write Authority blocked untrusted payload targeting "${target.path}"`;
        }
      }
      if (!target.isRegulated) {
        if (REGULATED_MARKING_RE.test(v.text) || /"classification"\s*:\s*"(?:cmmc|finsec|hipaa)"/i.test(v.text)) {
          return `Compartment Wall blocked regulated marking/classification in commercial memory "${target.path}"`;
        }
      }
    }
    const sensitive = findSensitiveMatch(text);
    if (sensitive) {
      return `Memory censorship blocked sensitive value (${sensitive.slice(0, 28)}) in "${target.path}"`;
    }
    if (target.isJsonl) {
      if (text.includes('\r')) return `Memory JSONL "${target.path}" must use LF-only line endings`;
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        if (Buffer.byteLength(line + '\n', 'utf8') >= MAX_JSONL_LINE_BYTES) {
          return `Memory JSONL line in "${target.path}" exceeds < ${MAX_JSONL_LINE_BYTES} byte limit`;
        }
        if (isFullWrite || line.trim().startsWith('{')) {
          try {
            const obj = JSON.parse(line);
            if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
              return `Memory JSONL line in "${target.path}" must be a JSON object`;
            }
          } catch {
            return `Invalid JSON in memory JSONL "${target.path}"`;
          }
        }
      }
    }
    return null;
  };

  if (FILE_TOOLS.has(t)) {
    const norm = normalizePosix(extractFilePath(i));
    return validateTarget(norm, !EDIT_TOOLS.has(t));
  }
  if (SHELL_TOOLS.has(t)) {
    for (const hit of extractShellMutatedPaths(text)) {
      const err = validateTarget(hit.norm, false);
      if (err) return err;
    }
  }
  return null;
}

function findSecret(text, level) {
  const raw = String(text || '');
  if (!raw) return null;

  // Raw scan first for accurate line number reporting.
  for (const [kind, re] of SECRETS) {
    const m = re.exec(raw);
    if (m) return { kind, line: lineOf(raw, m.index) };
  }
  if (level === 'paranoid') {
    const m = GENERIC_SECRET.exec(raw);
    if (m && !PLACEHOLDER.test(m[1])) {
      return { kind: 'credential assigned a literal value', line: lineOf(raw, m.index) };
    }
  }

  // Multi-view de-obfuscation scan (JSON escapes, URL encoding, Base64-encoded secrets).
  const views = buildInspectionViews(raw);
  for (const v of views) {
    if (v.view === 'raw') continue;
    for (const [kind, re] of SECRETS) {
      if (re.test(v.text)) {
        return { kind: `${kind} (${v.view})`, line: 1 };
      }
    }
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
  switch (normalizeTool(tool)) {
    case 'write':
    case 'write_file':
      return i.content ?? i.Content ?? '';
    case 'edit':
    case 'edit_file':
      return i.new_string ?? i.newString ?? i.replacement ?? i.Replacement ?? '';
    case 'multiedit':
    case 'multi_edit':
      return (i.edits || []).map((e) => e && (e.new_string ?? e.newString ?? e.replacement)).join('\n');
    case 'notebookedit':
    case 'notebook_edit':
      return i.new_source ?? i.newSource ?? i.content ?? '';
    case 'bash':
    case 'shell':
    case 'run_command':
    case 'terminal':
      return i.command ?? i.cmd ?? i.CommandLine ?? '';
    default:
      return '';
  }
}

function check(tool, input, level, env = process.env) {
  if (level !== 'full' && level !== 'paranoid') return null;

  const t = normalizeTool(tool);
  const i = input || {};

  // 1. Immutable VIBES .ai-audit/** (blocks ALL paths under .ai-audit/** on Write/Edit/MultiEdit/NotebookEdit/Bash)
  const vibes = findVibesTamper(tool, i);
  if (vibes) {
    return `neckbeard blocked this ${tool}: it modifies or deletes an immutable VIBES provenance path under .ai-audit/ (${vibes.where}, line ${vibes.line}). ` +
      'All paths under .ai-audit/** are strictly read-only for agents; use vibes, vibecheck, or vibetrace CLIs instead.';
  }

  // 2. Strictly read-only .crew.json executive policy store
  const policyHit = findCrewPolicyTamper(tool, i);
  if (policyHit) {
    return `neckbeard blocked this ${tool}: .crew.json is a read-only Crew Executive Policy store (${policyHit.where}).`;
  }

  // 3. Dynamic Sibling Persona Store Protection (Single-Owner Store Rule across built-in 12 + registered Nth personas)
  const siblingHit = findSiblingStoreTamper(tool, i, env);
  if (siblingHit) {
    return `neckbeard blocked this ${tool} to sibling crew store (${siblingHit.storeFile}): single-owner store violation. ` +
      `NeckBeard owns only .neckbeard.json; append sanitized proposals to ${RAINMAKER_INBOX_FILE} instead.`;
  }

  // 4. Unified $CREW_CONFIG_DIR Memory Anti-Poisoning & Compartment Wall
  const memErr = checkMemoryMutation(tool, i, env);
  if (memErr) {
    return `neckbeard blocked this ${tool}: ${memErr}.`;
  }

  const text = String(payload(tool, i) || '');
  if (!text) return null;
  const where = SHELL_TOOLS.has(t) ? 'this command' : `${extractFilePath(i) || 'this file'}`;

  const normWhere = SHELL_TOOLS.has(t) ? '' : normalizePosix(where);
  const baseWhere = normWhere ? normalizeSegment(path.posix.basename(normWhere)) : '';

  // 5. Strict multi-view censorship on .neckbeard.json (Write, Edit, MultiEdit, NotebookEdit, and Bash)
  if (FILE_TOOLS.has(t) && baseWhere === '.neckbeard.json') {
    const badCfg = !EDIT_TOOLS.has(t) ? checkNeckbeardJson(text) : findSensitiveMatch(text);
    if (badCfg) {
      return `neckbeard blocked this ${tool} to .neckbeard.json: ${badCfg}. Use /neckbeard load <value> or /neckbeard map so the file stays strictly censored.`;
    }
  } else if (SHELL_TOOLS.has(t)) {
    for (const hit of extractShellMutatedPaths(text)) {
      const targetBase = normalizeSegment(path.posix.basename(hit.norm));
      if (targetBase === '.neckbeard.json') {
        const badShellCfg = findSensitiveMatch(text);
        if (badShellCfg) {
          return `neckbeard blocked this ${tool} targeting .neckbeard.json: ${badShellCfg}.`;
        }
      } else if (targetBase === RAINMAKER_INBOX_FILE) {
        if (['rm', 'unlink', 'shred', 'mv', 'truncate', 'sed -i', 'perl -i'].includes(hit.op)) {
          return `neckbeard blocked this ${tool} targeting ${RAINMAKER_INBOX_FILE}: destructive mutation (${hit.op}) forbidden on append-only intake queue.`;
        }
        const badInbox = findSensitiveMatch(text);
        if (badInbox) {
          return `neckbeard blocked this ${tool} targeting crew store (${RAINMAKER_INBOX_FILE}): ${badInbox}.`;
        }
      }
    }
  }

  // 6. Censorship & JSONL format check on shared append-only .rainmaker-inbox.jsonl
  if (FILE_TOOLS.has(t) && baseWhere === RAINMAKER_INBOX_FILE) {
    const badInbox = !EDIT_TOOLS.has(t)
      ? checkCrewStoreJson(text, where)
      : (findSensitiveMatch(text) || (text.includes('\r') ? 'CRLF forbidden in JSONL' : null));
    if (badInbox) {
      return `neckbeard blocked this ${tool} to crew store (${baseWhere}): ${badInbox}. Crew stores must never contain secrets, URLs, internal hostnames, IPs, or absolute local paths.`;
    }
  }

  // 7. Hardcoded secret detection (raw + obfuscated/Base64/JSON-escaped)
  const secret = findSecret(text, level);
  if (secret) {
    return `neckbeard blocked this ${tool}: it contains a ${secret.kind} (${where}, line ${secret.line}). ` +
      'Secrets never go in code, commands, logs or fixtures. Read it from the environment or the project\'s secret store, ' +
      'and use an obviously fake value in tests. If the user really wants this, ask them to turn the guard off with /neckbeard lite.';
  }

  // 8. Paranoid unsafe operations
  if (level === 'paranoid') {
    const unsafe = findUnsafe(text, SHELL_TOOLS.has(t) ? UNSAFE_SHELL : UNSAFE_CODE);
    if (unsafe) {
      return `neckbeard (paranoid) blocked this ${tool}: ${unsafe.kind} (${where}, line ${unsafe.line}). ` +
        'Find a safe way (download, verify a checksum or signature, then run; fix the certificate; set exact permissions; let hooks run), ' +
        'or ask the user to allow it and switch to /neckbeard full for that step.';
    }
  }
  return null;
}

module.exports = {
  check,
  findSecret,
  findVibesTamper,
  findCrewPolicyTamper,
  findSiblingStoreTamper,
  getSiblingStoreSet,
  extractShellMutatedPaths,
  payload,
};

if (require.main === module) {
  (async () => {
    if (process.env.NECKBEARD_GUARD === '0') return;
    const input = await readInput();
    const reason = check(input.tool_name, input.tool_input, readLevel(input.session_id), process.env);
    if (reason) {
      const kind = reason.includes('VIBES')
        ? 'vibes-tamper'
        : reason.includes('.crew.json')
          ? 'crew-policy-tamper'
          : reason.includes('sibling crew store')
            ? 'single-owner-sibling'
            : reason.includes('Memory') || reason.includes('Compartment Wall')
              ? 'memory-poisoning'
              : reason.includes('.neckbeard.json') || reason.includes('crew store')
                ? 'config-censor'
                : reason.includes('(paranoid)')
                  ? 'unsafe-op'
                  : 'secret';
      recordGuardBlock(input.session_id, kind, input.cwd || process.cwd());
      emitDeny(reason);
    }
  })().finally(() => setTimeout(() => process.exit(0), 0));
}
