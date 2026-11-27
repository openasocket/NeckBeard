'use strict';
// Attack-surface & internal/external trust-boundary map, persistent project load config (.neckbeard.json),
// per-boundary load envelopes, boundary-expansion drift detection, and risk: load-trigger expiry checks.
// Regex over tracked source files, file paths and closed sink enums only (no raw code, URLs, hostnames, or secrets),
// inside a strict character budget. Shared in .neckbeard.json by default; `/neckbeard share off` moves it local.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHash } = require('crypto');
const { execFileSync } = require('child_process');
const { CREW_PIPELINE_ORDER, CREW_STORE_FILES, getDynamicPeerStoreFiles } = require('./ensemble');

const BUDGET = Number(process.env.NECKBEARD_SURFACE_CHARS || 1500);
const MAP_BUDGET = Number(process.env.NECKBEARD_MAP_CHARS || 1200);
const DEFAULT_MAP_MAX_AGE_MS = Number(process.env.NECKBEARD_MAP_MAX_AGE_HOURS || 24) * 60 * 60 * 1000;
const MAX_JSONL_LINE_BYTES = 4096;

// Sibling 13-Persona Crew Universe repo-local stores and shared PM intake queue.
const CREW_PEER_FILES = Object.freeze(
  CREW_PIPELINE_ORDER.reduce((acc, id) => {
    if (id !== 'neckbeard') acc[id] = CREW_STORE_FILES[id];
    return acc;
  }, {})
);
const RAINMAKER_INBOX_FILE = '.rainmaker-inbox.jsonl';
const MAX_FILES = 20000;
const MAX_BYTES = 200 * 1024;
const SRC = /\.(py|js|jsx|mjs|cjs|ts|tsx|go|rs|rb|java|kt|php|cs|swift|sh|yml|yaml)$/;
const SKIP = /(^|\/)(node_modules|vendor|dist|build|out|target|coverage|\.next|\.venv|venv|__pycache__|\.claude|\.worktrees|\.maestro|Auto Run Docs|Plans|docs|benches|fuzz|tests?|__tests__|spec|fixtures|migrations)(\/|$)|\.(test|spec|min|d)\.[a-z]+$|_(test|spec)\.(rs|go|py|ts|js)$/;
const SAFE_PATH = /^[\w.@+\/-]+$/; // a path with odd characters is skipped, never echoed

function isUncapped(opts = {}, env = process.env) {
  if (opts && opts.uncapped === true) return true;
  if (opts && opts.uncapped === false) return false;
  const srcEnv = (opts && opts.env) || env || process.env;
  const raw = String((srcEnv && srcEnv.NECKBEARD_UNCAPPED) || '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes';
}

function resolveFileCap(opts = {}, env = process.env) {
  if (isUncapped(opts, env)) return { cap: Infinity, uncapped: true };
  const custom = opts && opts.maxFiles !== undefined ? Number(opts.maxFiles) : NaN;
  const cap = Number.isFinite(custom) && custom > 0 ? Math.floor(custom) : MAX_FILES;
  return { cap, uncapped: false };
}

function formatCapNotice(totalFiles, cap, walkBounded = false) {
  const countLabel = walkBounded ? `>${totalFiles}` : String(totalFiles);
  return `File cap exceeded: ${countLabel} matching files exceed cap of ${cap} (scanned first ${cap}). Re-run with --uncapped or NECKBEARD_UNCAPPED=1 to scan all files.`;
}

const CATEGORIES = [
  ['entry points (HTTP, RPC, CLI, queues)', /\b(?:app|router|server|api|hono)\.(?:get|post|put|patch|delete|all|use|route)\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping|Controller)\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\bhttp\.HandleFunc\b|\bfetch\s*\(\s*req(?:uest)?\b|\baddEventListener\(\s*['"]fetch['"]|\bargparse\b|\bprocess\.argv\b|\bconsumer\.|\bon_message\b/],
  ['shell and code execution', /\bchild_process\b|\bexec(?:File)?Sync\s*\(|\bspawn(?:Sync)?\s*\(|\bsubprocess\.|\bos\.system\s*\(|\bos\.popen\s*\(|\beval\s*\(|\bnew Function\s*\(|\bexec\.Command\s*\(|\bRuntime\.getRuntime\(\)\.exec\b|`[^`]*\$\(/],
  ['raw SQL', /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}\b(?:FROM|INTO|SET|WHERE)\b[^\n]*(?:\$\{|\+\s*\w|%s|f["']|\.format\()|\.(?:raw|unsafe|exec)\s*\(\s*[`'"]|\bexecute\s*\(\s*f["']/i],
  ['deserialization and parsers', /\bpickle\.loads?\b|\byaml\.load\s*\((?![^)]*SafeLoader)|\bmarshal\.loads\b|\bObjectInputStream\b|\bunserialize\s*\(|\bXMLParser\b|\bDOMParser\b|\bxml2js\b|\blibxml\b/],
  ['outbound requests (SSRF)', /\bfetch\s*\(\s*(?!['"`]https?:)[^)]|\baxios\.(?:get|post|request)\s*\(\s*(?!['"`])|\brequests\.(?:get|post|request)\s*\(\s*(?!['"])|\burllib\.request\.urlopen\b|\bhttp\.Get\s*\(\s*[a-z]/],
  ['file paths built at runtime', /\b(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rm)(?:Sync)?\s*\(\s*(?:path\.join\s*\()?[^'"`)\s]|\bopen\s*\(\s*(?:os\.path\.join|f["'])|\bsend_file\s*\(|\bsendFile\s*\(/],
  ['auth, sessions and tokens', /\b(?:jwt|jsonwebtoken|jose|bcrypt|argon2|scrypt|passport|set-cookie|setCookie|authorization|oauth2?|oidc|csrf|verifyToken|verify_token|authenticate|authorize|requireAuth|checkPermission|ed25519_dalek|VerifyingKey|SigningKey|api[_-]?key)\b/i],
  ['crypto and randomness', /\bcreateCipher(?:iv)?\b|\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|\bhashlib\.(?:md5|sha1)\b|\bMath\.random\s*\(|\brandom\.(?:random|randint|choice)\s*\(|\bDES\b|\bECB\b/],
  ['secrets and config from the environment', /\bprocess\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASS|PRIVATE)[A-Z_]*|\bos\.environ\b[^\n]*(?:KEY|SECRET|TOKEN|PASS)|\benv\.[A-Z_]*(?:KEY|SECRET|TOKEN)[A-Z_]*/],
  ['LLM and agent calls (prompt injection)', /\banthropic\b|\bopenai\b|\bmessages\.create\s*\(|\bchat\.completions\b|\btool_use\b|\bfunction_call\b|\bmcp\b|\bMcpServer\b|\blangchain\b|\badditionalContext\b/i],
];

// Closed enum of allowed boundary sink tags in .neckbeard.json.
const ALLOWED_SINKS = new Set([
  'http-in', 'cli-in', 'webhook-in', 'http-out', 'ci',
  'auth', 'sql', 'fs', 'proc', 'serde', 'crypto', 'env', 'ai',
]);

// Allowed keys for per-boundary load overrides (boundaryLoad in .neckbeard.json).
const ALLOWED_LOAD_KEYS = new Set([
  ...ALLOWED_SINKS,
  'ingress', 'egress', 'supply', 'data', 'exec',
]);

// Closed enum of allowed architectural subsystem roles in .neckbeard.json.
const ALLOWED_ARCH_ROLES = new Set([
  'gateway', 'interface', 'service', 'persistence', 'security', 'runtime', 'pipeline', 'core',
]);

// Patterns that must always be censored from load strings, .neckbeard.json, inbox, or memory entries.
const SENSITIVE_TEXT = /(?:https?:\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[\w.+-]+@[\w-]+\.[\w.-]+\b|\b[\w-]+\.(?:internal|corp|local|lan|intranet|amazonaws\.com|rds\.amazonaws\.com|svc\.cluster\.local)\b|(?<![A-Za-z0-9_.-])(?:\/(?:Users|home|private|var\/folders|tmp|Volumes|etc|root)\/\S+|~\/[^\s"'<>]+)|(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s"'<>]+|-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\b(?:AKIA|ASIA)(?![A-Z0-9]*EXAMPLE)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:ant-|proj-|live-)[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk|pk)_live_[0-9A-Za-z]{20,})\b)/gi;

const SENSITIVE_SECRET_RE = /(?:-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\b(?:AKIA|ASIA)(?![A-Z0-9]*EXAMPLE)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:ant-|proj-|live-)[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk|pk)_live_[0-9A-Za-z]{20,})\b)/;

// Bounded multi-view de-obfuscation (RT-GATE-01): invisible chars, NFKC, \uXXXX/\xXX, %XX, Base64.
const MAX_DECODE_DEPTH = 3;
const MAX_BASE64_CANDIDATES = 128;
const MAX_BASE64_DECODED_BYTES = 4096;
const INVISIBLE_CHAR_RE = /[\u0000\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\uFFA0]/g;
const BASE64_SPAN_RE = /[A-Za-z0-9+/_-]{12,}={0,2}/g;
const UTF8_FATAL_DECODER = new TextDecoder('utf-8', { fatal: true });

function stripInvisibleChars(input) {
  return String(input || '').replace(INVISIBLE_CHAR_RE, '');
}

function normalizeUnicode(input) {
  return stripInvisibleChars(input)
    .normalize('NFKC')
    .replace(/[\u2215\u2044\u29F8\uFF0F]/g, '/')
    .replace(/[\u29F5\u29F9\uFE68\uFF3C]/g, '\\')
    .replace(/[\u2024\u3002\uFF0E\uFF61]/g, '.')
    .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, '-');
}

function parseHexRange(str, start, len) {
  if (start + len > str.length) return -1;
  let val = 0;
  for (let i = 0; i < len; i++) {
    const c = str.charCodeAt(start + i);
    const nib = c >= 48 && c <= 57 ? c - 48 : c >= 97 && c <= 102 ? c - 87 : c >= 65 && c <= 70 ? c - 55 : -1;
    if (nib < 0) return -1;
    val = (val << 4) | nib;
  }
  return val;
}

function decodeEscapesOnce(input) {
  const s = String(input || '');
  if (!s.includes('\\')) return s;
  let out = '';
  for (let i = 0; i < s.length; ) {
    if (s[i] === '\\' && i + 1 < s.length) {
      const next = s[i + 1];
      if ((next === 'u' || next === 'U') && i + 6 <= s.length) {
        const hi = parseHexRange(s, i + 2, 4);
        if (hi >= 0) {
          if (hi >= 0xd800 && hi <= 0xdbff && i + 12 <= s.length && s[i + 6] === '\\' && (s[i + 7] === 'u' || s[i + 7] === 'U')) {
            const lo = parseHexRange(s, i + 8, 4);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
              out += String.fromCodePoint(0x10000 + (((hi - 0xd800) << 10) | (lo - 0xdc00)));
              i += 12;
              continue;
            }
          }
          out += String.fromCharCode(hi);
          i += 6;
          continue;
        }
      }
      if ((next === 'x' || next === 'X') && i + 4 <= s.length) {
        const b = parseHexRange(s, i + 2, 2);
        if (b >= 0) { out += String.fromCharCode(b); i += 4; continue; }
      }
      if (next === '/') { out += '/'; i += 2; continue; }
      if (next === '\\') { out += '\\'; i += 2; continue; }
      if (next === '"') { out += '"'; i += 2; continue; }
      if (next === 'n') { out += '\n'; i += 2; continue; }
      if (next === 'r') { out += '\r'; i += 2; continue; }
      if (next === 't') { out += '\t'; i += 2; continue; }
    }
    out += s[i++];
  }
  return out;
}

function decodeJsonEscapes(input) {
  let cur = stripInvisibleChars(input);
  for (let pass = 0; pass < MAX_DECODE_DEPTH; pass++) {
    const next = stripInvisibleChars(decodeEscapesOnce(cur));
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function decodeUrlPercent(input) {
  let cur = String(input || '');
  for (let pass = 0; pass < MAX_DECODE_DEPTH; pass++) {
    if (!cur.includes('%')) break;
    const raw = Buffer.from(cur, 'utf8');
    const out = [];
    let changed = false;
    for (let i = 0; i < raw.length; ) {
      if (raw[i] === 0x25 && i + 2 < raw.length) {
        const val = parseHexRange(String.fromCharCode(raw[i + 1], raw[i + 2]), 0, 2);
        if (val >= 0) { out.push(val); changed = true; i += 3; continue; }
      }
      out.push(raw[i++]);
    }
    if (!changed) break;
    const next = Buffer.from(out).toString('utf8');
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function decodeBase64Text(token) {
  const trimmed = String(token || '').trim();
  if (trimmed.length < 12) return null;
  const hasStd = trimmed.includes('+') || trimmed.includes('/');
  const hasUrl = trimmed.includes('-') || trimmed.includes('_');
  if (hasStd && hasUrl) return null;
  const unpadded = trimmed.replace(/=+$/, '');
  const padCount = trimmed.length - unpadded.length;
  if (padCount > 2 || unpadded.includes('=') || (padCount > 0 && trimmed.length % 4 !== 0) || unpadded.length % 4 === 1) return null;
  const estimated = Math.floor((unpadded.length * 3) / 4);
  if (estimated === 0 || estimated > MAX_BASE64_DECODED_BYTES) return null;
  const std = hasUrl ? unpadded.replace(/-/g, '+').replace(/_/g, '/') : unpadded;
  if (!/^[A-Za-z0-9+/]+$/.test(std)) return null;
  const mod = std.length % 4;
  const buf = Buffer.from(mod === 0 ? std : std + '='.repeat(4 - mod), 'base64');
  if (!buf.length || buf.length > MAX_BASE64_DECODED_BYTES) return null;
  let text;
  try { text = UTF8_FATAL_DECODER.decode(buf); } catch { return null; }
  let total = 0;
  let printable = 0;
  for (const ch of text) {
    total += 1;
    const cp = ch.codePointAt(0);
    if (ch === '\t' || ch === '\n' || ch === '\r' || (cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp <= 0x9f))) printable += 1;
  }
  if (total < 7 || printable * 100 < total * 85) return null;
  return text;
}

function extractBase64DecodedViews(input) {
  const s = String(input || '');
  const decodedViews = [];
  const seenTokens = new Set();
  const seenDecoded = new Set();

  const tryCand = (cand) => {
    const dec = decodeBase64Text(cand);
    if (!dec) return;
    const norm = normalizeUnicode(decodeUrlPercent(decodeJsonEscapes(dec)));
    if (!norm || seenDecoded.has(norm)) return;
    seenDecoded.add(norm);
    decodedViews.push(norm);
    // One nested Base64 layer
    if (decodedViews.length < MAX_BASE64_CANDIDATES) {
      BASE64_SPAN_RE.lastIndex = 0;
      let nm;
      while ((nm = BASE64_SPAN_RE.exec(norm)) !== null) {
        const nested = decodeBase64Text(nm[0]);
        if (nested) {
          const nestedNorm = normalizeUnicode(decodeUrlPercent(decodeJsonEscapes(nested)));
          if (nestedNorm && !seenDecoded.has(nestedNorm)) {
            seenDecoded.add(nestedNorm);
            decodedViews.push(nestedNorm);
            break;
          }
        }
      }
      BASE64_SPAN_RE.lastIndex = 0;
    }
  };

  BASE64_SPAN_RE.lastIndex = 0;
  let m;
  while ((m = BASE64_SPAN_RE.exec(s)) !== null) {
    if (seenTokens.size >= MAX_BASE64_CANDIDATES) break;
    const span = m[0];
    const cands = [span];
    if (/[_\-/]/.test(span)) {
      for (const part of span.split(/[_\-/]/)) {
        if (part.length >= 12 && !cands.includes(part)) cands.push(part);
      }
    }
    for (const c of cands) {
      if (seenTokens.size >= MAX_BASE64_CANDIDATES) break;
      if (seenTokens.has(c)) continue;
      seenTokens.add(c);
      tryCand(c);
    }
  }
  BASE64_SPAN_RE.lastIndex = 0;
  return decodedViews;
}

function buildInspectionViews(text) {
  const raw = String(text || '');
  if (!raw) return [];
  const views = [];
  const seen = new Set();
  const push = (view, value) => {
    if (!value || seen.has(value)) return;
    seen.add(value);
    views.push({ view, text: value });
  };
  push('raw', raw);
  push('normalized', normalizeUnicode(raw));
  const jsonUnescaped = normalizeUnicode(decodeJsonEscapes(raw));
  push('json_unescaped', jsonUnescaped);
  if (jsonUnescaped.includes('%') || raw.includes('%')) {
    push('url_decoded', normalizeUnicode(decodeUrlPercent(jsonUnescaped)));
  }
  for (const b64 of extractBase64DecodedViews(raw)) push('base64_decoded', b64);
  if (jsonUnescaped !== raw) {
    for (const b64 of extractBase64DecodedViews(jsonUnescaped)) push('base64_decoded', b64);
  }
  return views;
}

function findSensitiveMatch(text) {
  const views = buildInspectionViews(text);
  for (const v of views) {
    SENSITIVE_TEXT.lastIndex = 0;
    const m = SENSITIVE_TEXT.exec(v.text);
    SENSITIVE_TEXT.lastIndex = 0;
    if (m) {
      const hit = m[0];
      if (SENSITIVE_SECRET_RE.test(hit)) return `[redacted-secret:${v.view}]`;
      return v.view === 'raw' ? hit : `[${v.view}] ${hit}`;
    }
  }
  return null;
}

function listFiles(root, opts = {}) {
  const { cap, uncapped } = resolveFileCap(opts);
  try {
    const out = execFileSync('git', ['ls-files', '-z'], {
      cwd: root,
      encoding: 'utf8',
      timeout: uncapped ? 15000 : 5000,
      maxBuffer: 128 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const files = out.split('\0').filter(Boolean);
    if (files.length) return files;
  } catch { /* not a git repo */ }
  const out = [];
  const walkLimit = Number.isFinite(cap) ? Math.max(cap * 4, 80000) : Infinity;
  (function walk(dir, depth) {
    if (depth > 8 || out.length >= walkLimit) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= walkLimit) return;
      if (e.name === '.git' || e.name === 'node_modules') continue;
      if (e.name.startsWith('.') && e.name !== '.github') continue;
      if (e.isSymbolicLink && e.isSymbolicLink()) continue;
      const rel = path.relative(root, path.join(dir, e.name)).split(path.sep).join('/');
      if (e.isDirectory()) { if (!SKIP.test(rel + '/')) walk(path.join(dir, e.name), depth + 1); } else out.push(rel);
    }
  })(root, 0);
  return out;
}

function selectScanFiles(root, filterFn, opts = {}, sortFn = null) {
  const { cap, uncapped } = resolveFileCap(opts);
  const all = listFiles(root, opts);
  const matched = all.filter(filterFn);
  if (typeof sortFn === 'function') matched.sort(sortFn);
  const totalFiles = matched.length;
  const truncated = !uncapped && totalFiles > cap;
  const files = truncated ? matched.slice(0, cap) : matched;
  const notice = truncated ? formatCapNotice(totalFiles, cap) : '';
  return { files, totalFiles, cap, uncapped, truncated, notice };
}

function buildSurface(root, opts = {}) {
  const scan = selectScanFiles(
    root,
    (f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f) && !/\.(yml|yaml)$/.test(f),
    opts
  );
  const files = scan.files;
  const hits = CATEGORIES.map(() => []);
  for (const f of files) {
    let text;
    try {
      const full = path.join(root, f);
      const st = fs.lstatSync(full);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      text = fs.readFileSync(full, 'utf8');
    } catch { continue; }
    CATEGORIES.forEach(([, re], i) => { if (re.test(text)) hits[i].push(f); });
  }
  const lines = [];
  let used = 0;
  CATEGORIES.forEach(([name], i) => {
    if (!hits[i].length) return;
    const shown = hits[i].slice(0, 8);
    const line = `- ${name}: ${shown.join(', ')}${hits[i].length > shown.length ? ` (+${hits[i].length - shown.length} more)` : ''}`;
    if (used + line.length > BUDGET) return;
    lines.push(line);
    used += line.length + 1;
  });
  if (!lines.length && !scan.truncated) return '';
  const body = lines.length
    ? 'Attack-surface map (files matched by pattern; read them before changing code that crosses these boundaries):\n' + lines.join('\n')
    : 'Attack-surface map (no pattern hits in scanned slice):';
  return scan.truncated ? `${body}\nNotice: ${scan.notice}` : body;
}

// High-precision multi-language boundary sink detectors (JS/TS, Rust, Python, Go, Swift, Java, Ruby)
// used by buildBoundaryMap() to map a project's real external [ext] and internal [int] architecture.
const BOUNDARY_DETECTORS = {
  cliIn: /\b(?:process\.argv|process\.stdin|readInput\s*\(|parseArgs\s*\(|commander\b|yargs\b|argparse\b|sys\.argv\b|click\.(?:command|group)|typer\.Typer|clap::|#\[derive\([^)]*(?:Parser|Subcommand|Args)\b|#\[command\(|std::env::args|env::args(?:_os)?\s*\(|os\.Args\b|flag\.(?:Parse|String|Int|Bool)|cobra\.Command|ParsableCommand)\b/,
  webhookIn: /\b(?:webhook|stripe\.webhooks|verifyWebhook|svix|consumer\.(?:run|subscribe)|on_message\b|kafka|rdkafka|amqp|sqs|pubsub)\b/i,
  httpIn: /\b(?:app|router|server|api|hono|fastify)\.(?:get|post|put|patch|delete|all|use|route)\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping|Controller)\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\bhttp\.(?:HandleFunc|ListenAndServe)\b|\baddEventListener\(\s*['"]fetch['"]|\bipcMain\.(?:handle|on)\s*\(|#\[tauri::command\]|\b(?:axum::Router|actix_web|HttpServer::new|warp::Filter|tonic::transport::Server|rocket::build|FastAPI\s*\(|APIRouter\s*\(|gin\.(?:Default|New)|chi\.NewRouter|echo\.New|fiber\.New|WebSocketServer)\b/,
  httpOut: /\b(?:fetch\s*\(|axios\.(?:get|post|put|delete|request)\s*\(|https?\.request\s*\(|got\s*\(|reqwest::|ureq::|hyper::Client|requests\.(?:get|post|put|delete|request)\s*\(|httpx\.(?:AsyncClient|Client|get|post)|aiohttp\.ClientSession|urllib\.request\.urlopen|http\.(?:Get|Post|NewRequest)\s*\(|URLSession\.shared)\b/,
  auth: /\b(?:jwt|jsonwebtoken|jose|bcrypt|argon2|scrypt|pbkdf2|passport|set-cookie|setCookie|req\.headers\.authorization|Bearer\s+|oauth2?|oidc|saml|csrf|verifyToken|verify_token|authenticate|authorize|requireAuth|require_auth|checkPermission|hasPermission|api[_-]?key|ed25519_dalek|VerifyingKey|SigningKey|cosign|dsse|timingSafeEqual)\b/i,
  sql: /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE)\b|\b(?:rusqlite|sqlx::|diesel::|sea_orm|better-sqlite3|sqlite3|prisma\.|drizzle|knex|sequelize|sqlalchemy|cursor\.execute|Connection::open)\b/i,
  fs: /\b(?:fs\.(?:readFile|writeFile|appendFile|open|unlink|rm|cp|mkdir|readdir|stat|lstat|realpath|exists)(?:Sync)?|readFileSync|writeFileSync|appendFileSync|existsSync|mkdirSync|readdirSync|unlinkSync|rmSync|cpSync|realpathSync|createReadStream|createWriteStream|std::fs::|tokio::fs::|fs::(?:read_to_string|read|write|OpenOptions|create_dir|remove_file|remove_dir|copy|rename)|File::(?:open|create)|NamedTempFile|Path\([^)]+\)\.(?:read_text|write_text|read_bytes|write_bytes|open)|shutil\.(?:copy|rmtree|move)|os\.(?:ReadFile|WriteFile|OpenFile|Create|RemoveAll)|ioutil\.(?:ReadFile|WriteFile))\b/,
  serde: /\b(?:JSON\.parse\s*\(|serde_json::(?:from_str|from_slice|from_reader|from_value)|toml::from_str|serde_yaml::from_|bincode::deserialize|yaml\.(?:load|safe_load)|pickle\.loads?|marshal\.loads|ObjectInputStream|unserialize\s*\(|XMLParser|DOMParser|xml2js|prost::Message)\b/,
  proc: /\b(?:child_process|exec(?:File)?Sync\s*\(|spawn(?:Sync)?\s*\(|execFile\s*\(|std::process::Command|tokio::process::Command|Command::new\s*\(|subprocess\.(?:run|Popen|call|check_output)|os\.system\s*\(|os\.popen\s*\(|exec\.Command\s*\(|Runtime\.getRuntime\(\)\.exec|\beval\s*\(|new Function\s*\()\b/,
  crypto: /\b(?:createHash|createHmac|createCipher(?:iv)?|createDecipher(?:iv)?|crypto\.subtle|crypto\.(?:sign|verify|randomBytes)|sha2::|Sha256|Sha512|ed25519_dalek|hmac::|ring::|aes_gcm|chacha20poly1305|rustls|hashlib\.(?:sha256|sha512|blake2b|md5|sha1)|hmac\.new|crypto\/(?:sha256|ed25519|hmac|tls|aes))\b/,
  env: /\b(?:process\.env(?:\.[A-Za-z0-9_]+|\[)|os\.environ\b|os\.getenv\s*\(|std::env::(?:var|var_os|vars)|env::(?:var|var_os)\s*\(|os\.Getenv\s*\(|dotenv)\b/,
  ai: /\b(?:anthropic|openai|gemini|messages\.create\s*\(|chat\.completions|tool_use|function_call|McpServer|mcp_schemas|langchain|additionalContext|hookSpecificOutput|embedder|candle_)\b/i,
};

// Builds the concise two-tier (external & internal) trust-boundary map for a project.
function buildBoundaryMap(root = process.cwd(), maxPerCategory = 16, opts = {}) {
  if (typeof maxPerCategory === 'object' && maxPerCategory !== null) {
    opts = maxPerCategory;
    maxPerCategory = 16;
  }
  // Prioritise core production directories (src/, crates/, apps/, packages/, hooks/, lib/, functions/, scripts/) before examples/
  const scan = selectScanFiles(
    root,
    (f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f),
    opts,
    (a, b) => {
      const aEx = /(^|\/)(examples?|demo|samples?|benchmarks?)\//i.test(a) ? 1 : 0;
      const bEx = /(^|\/)(examples?|demo|samples?|benchmarks?)\//i.test(b) ? 1 : 0;
      return aEx - bEx || (a < b ? -1 : a > b ? 1 : 0);
    }
  );
  const files = scan.files;
  const ext = { ingress: [], egress: [], supply: [] };
  const int = { auth: [], data: [], exec: [], ai: [] };
  const limit = Math.max(1, Number(maxPerCategory) || 16);
  const add = (arr, item) => { if (arr.length < limit && !arr.includes(item)) arr.push(item); };

  for (const f of files) {
    if (/^\.github\/workflows\/.+\.(?:yml|yaml)$/.test(f)) {
      add(ext.supply, `${f}->ci`);
      continue;
    }
    if (/\.(?:yml|yaml)$/.test(f)) continue;
    let text;
    try {
      const full = path.join(root, f);
      const st = fs.lstatSync(full);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      text = fs.readFileSync(full, 'utf8');
    } catch { continue; }

    // External ingress (http-in, cli-in, webhook-in) & egress (http-out)
    const inTags = [];
    if (BOUNDARY_DETECTORS.httpIn.test(text)) inTags.push('http-in');
    if (BOUNDARY_DETECTORS.cliIn.test(text)) inTags.push('cli-in');
    if (BOUNDARY_DETECTORS.webhookIn.test(text)) inTags.push('webhook-in');
    if (inTags.length) add(ext.ingress, `${f}->${inTags[0]}`);
    if (BOUNDARY_DETECTORS.httpOut.test(text)) add(ext.egress, `${f}->http-out`);

    // Internal auth, data (sql, fs, serde), exec (proc, crypto, env), ai
    if (BOUNDARY_DETECTORS.auth.test(text)) add(int.auth, `${f}->auth`);

    const dataTags = [];
    if (BOUNDARY_DETECTORS.sql.test(text)) dataTags.push('sql');
    if (BOUNDARY_DETECTORS.fs.test(text)) dataTags.push('fs');
    if (BOUNDARY_DETECTORS.serde.test(text)) dataTags.push('serde');
    if (dataTags.length) add(int.data, `${f}->${dataTags.join(',')}`);

    const execTags = [];
    if (BOUNDARY_DETECTORS.proc.test(text)) execTags.push('proc');
    if (BOUNDARY_DETECTORS.crypto.test(text)) execTags.push('crypto');
    if (BOUNDARY_DETECTORS.env.test(text)) execTags.push('env');
    if (execTags.length) add(int.exec, `${f}->${execTags.join(',')}`);

    if (BOUNDARY_DETECTORS.ai.test(text)) add(int.ai, `${f}->ai`);
  }

  return scan.truncated
    ? { external: ext, internal: int, truncated: true, totalFiles: scan.totalFiles, cap: scan.cap, notice: scan.notice }
    : { external: ext, internal: int };
}

function moduleNameForRelPath(relPath) {
  const parts = String(relPath || '').split('/').filter(Boolean);
  if (parts.length <= 1) return '(root)';
  if (parts[0] === '.github' && parts[1] === 'workflows') return '.github/workflows';
  if ((parts[0] === 'packages' || parts[0] === 'crates' || parts[0] === 'apps' || parts[0] === 'hooks' || parts[0] === 'src' || parts[0] === 'functions') && parts.length >= 3) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
}

// Quantifies project module architecture, boundary density, cross-boundary bridges, and inter-module import/data flows.
function buildArchitectureMap(root = process.cwd(), maxModules = 16, maxFlows = 24, opts = {}) {
  if (typeof maxModules === 'object' && maxModules !== null) {
    opts = maxModules;
    maxModules = 16;
    maxFlows = 24;
  } else if (typeof maxFlows === 'object' && maxFlows !== null) {
    opts = maxFlows;
    maxFlows = 24;
  }
  const scan = selectScanFiles(
    root,
    (f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f),
    opts,
    (a, b) => (a < b ? -1 : a > b ? 1 : 0)
  );
  const files = scan.files;
  const modStats = new Map();
  const knownModules = new Set();
  const fileContents = [];
  let boundaryFileCount = 0;
  let totalBridges = 0;

  for (const f of files) {
    const mod = moduleNameForRelPath(f);
    knownModules.add(mod);
    if (!modStats.has(mod)) {
      modStats.set(mod, {
        name: mod,
        files: 0,
        boundaryFiles: 0,
        bridges: 0,
        ext: new Set(),
        int: new Set(),
      });
    }
    const ms = modStats.get(mod);
    ms.files += 1;

    if (/^\.github\/workflows\/.+\.(?:yml|yaml)$/.test(f)) {
      ms.boundaryFiles += 1;
      boundaryFileCount += 1;
      ms.ext.add('ci');
      continue;
    }
    if (/\.(?:yml|yaml)$/.test(f)) continue;

    let text;
    try {
      const full = path.join(root, f);
      const st = fs.lstatSync(full);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      text = fs.readFileSync(full, 'utf8');
    } catch { continue; }

    fileContents.push({ file: f, mod, text });

    let hasExt = false;
    let hasInt = false;
    if (BOUNDARY_DETECTORS.httpIn.test(text)) { ms.ext.add('http-in'); hasExt = true; }
    if (BOUNDARY_DETECTORS.cliIn.test(text)) { ms.ext.add('cli-in'); hasExt = true; }
    if (BOUNDARY_DETECTORS.webhookIn.test(text)) { ms.ext.add('webhook-in'); hasExt = true; }
    if (BOUNDARY_DETECTORS.httpOut.test(text)) { ms.ext.add('http-out'); hasExt = true; }

    if (BOUNDARY_DETECTORS.auth.test(text)) { ms.int.add('auth'); hasInt = true; }
    if (BOUNDARY_DETECTORS.sql.test(text)) { ms.int.add('sql'); hasInt = true; }
    if (BOUNDARY_DETECTORS.fs.test(text)) { ms.int.add('fs'); hasInt = true; }
    if (BOUNDARY_DETECTORS.serde.test(text)) { ms.int.add('serde'); hasInt = true; }
    if (BOUNDARY_DETECTORS.proc.test(text)) { ms.int.add('proc'); hasInt = true; }
    if (BOUNDARY_DETECTORS.crypto.test(text)) { ms.int.add('crypto'); hasInt = true; }
    if (BOUNDARY_DETECTORS.env.test(text)) { ms.int.add('env'); hasInt = true; }
    if (BOUNDARY_DETECTORS.ai.test(text)) { ms.int.add('ai'); hasInt = true; }

    if (hasExt || hasInt) {
      ms.boundaryFiles += 1;
      boundaryFileCount += 1;
    }
    if (hasExt && hasInt) {
      ms.bridges += 1;
      totalBridges += 1;
    }
  }

  // Extract directed inter-module import / data-flow edges (JS/TS require/import, Rust crate::, Python from/import)
  const flowSet = new Set();
  const relImportRe = /(?:require\s*\(\s*['"](\.[^'"]+)['"]\s*\)|from\s+['"](\.[^'"]+)['"])/g;
  const rustImportRe = /\buse\s+crate::([a-zA-Z0-9_]+)/g;

  for (const { file, mod, text } of fileContents) {
    const dir = path.posix.dirname(file);
    for (const m of text.matchAll(relImportRe)) {
      const spec = m[1] || m[2];
      if (!spec) continue;
      const targetRel = path.posix.normalize(path.posix.join(dir, spec));
      if (targetRel.startsWith('..')) continue;
      const targetMod = moduleNameForRelPath(targetRel);
      if (targetMod && targetMod !== mod && knownModules.has(targetMod)) {
        flowSet.add(`${mod}->${targetMod}`);
      }
    }
    for (const m of text.matchAll(rustImportRe)) {
      const seg = m[1];
      if (!seg) continue;
      const cand = `src/${seg}`;
      if (cand !== mod && knownModules.has(cand)) {
        flowSet.add(`${mod}->${cand}`);
      }
    }
  }

  const classifyRole = (ms) => {
    if (ms.ext.has('ci') && ms.ext.size === 1 && ms.int.size === 0) return 'pipeline';
    if (ms.bridges > 0) return 'gateway';
    if (ms.ext.size > 0) return 'interface';
    if (ms.int.has('sql') || ms.int.has('fs') || ms.int.has('serde')) return 'persistence';
    if (ms.int.has('auth') || ms.int.has('crypto')) return 'security';
    if (ms.int.has('proc') || ms.int.has('ai') || ms.int.has('env')) return 'runtime';
    if (ms.boundaryFiles > 0) return 'service';
    return 'core';
  };

  const sortedMods = [...modStats.values()]
    .sort((a, b) => (b.bridges - a.bridges) || (b.boundaryFiles - a.boundaryFiles) || (b.files - a.files))
    .slice(0, Math.max(1, Number(maxModules) || 16));

  const modules = sortedMods.map((ms) => `${ms.name}:${classifyRole(ms)}(${ms.files}f,${ms.bridges}b)`);
  const flows = [...flowSet].slice(0, Math.max(1, Number(maxFlows) || 24));

  const archResult = {
    fileCount: files.length,
    moduleCount: modStats.size,
    boundaryFileCount,
    bridgeCount: totalBridges,
    flowCount: flowSet.size,
    modules,
    flows,
  };
  if (scan.truncated) {
    archResult.truncated = true;
    archResult.totalFiles = scan.totalFiles;
    archResult.cap = scan.cap;
    archResult.notice = scan.notice;
  }
  return archResult;
}

function flattenBoundaries(b = {}) {
  const ext = (b && b.external) || {};
  const int = (b && b.internal) || {};
  const out = [];
  for (const k of ['ingress', 'egress', 'supply']) {
    for (const item of ext[k] || []) if (!out.includes(item)) out.push(item);
  }
  for (const k of ['auth', 'data', 'exec', 'ai']) {
    for (const item of int[k] || []) if (!out.includes(item)) out.push(item);
  }
  return out;
}

// Compares a saved baseline boundary map with the current live boundary map to flag boundary expansion.
function diffBoundaryMap(baseline = {}, current = {}) {
  const baseSet = new Set(flattenBoundaries(baseline));
  const curList = flattenBoundaries(current);
  const curSet = new Set(curList);
  const added = curList.filter((item) => !baseSet.has(item));
  const removed = [...baseSet].filter((item) => !curSet.has(item));
  return { added, removed };
}

function detectBoundaryDrift(root = process.cwd(), env = process.env, opts = {}) {
  const cfg = readProjectConfig(root, env);
  if (!cfg || !cfg.boundaries) return { added: [], removed: [] };
  const hasSaved = flattenBoundaries(cfg.boundaries).length > 0;
  if (!hasSaved) return { added: [], removed: [] };
  return diffBoundaryMap(cfg.boundaries, buildBoundaryMap(root, 16, { ...opts, env }));
}

function sanitizeLoad(load) {
  if (typeof load !== 'string') return '';
  return load
    .replace(SENSITIVE_TEXT, '[redacted]')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, 160);
}

function sanitizeBoundaryLoad(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = String(k || '').trim().toLowerCase();
    if (!ALLOWED_LOAD_KEYS.has(key)) continue;
    const clean = sanitizeLoad(String(v || ''));
    if (clean) out[key] = clean;
  }
  return out;
}

function sanitizeEntry(entry) {
  if (typeof entry !== 'string') return null;
  const trimmed = entry.trim();
  if (!trimmed || SENSITIVE_TEXT.test(trimmed)) {
    SENSITIVE_TEXT.lastIndex = 0;
    return null;
  }
  SENSITIVE_TEXT.lastIndex = 0;
  const [rawFile, rawSinks] = trimmed.split('->');
  const norm = path.posix.normalize(String(rawFile || '').replace(/\\/g, '/').trim());
  if (!norm || norm === '.' || norm.startsWith('/') || norm.startsWith('..') || !SAFE_PATH.test(norm)) return null;
  if (/^(?:Users|home|private|var|tmp|etc)\//.test(norm)) return null;
  if (!rawSinks) return norm;
  const sinks = rawSinks.split(',').map((s) => s.trim()).filter((s) => ALLOWED_SINKS.has(s));
  return sinks.length ? `${norm}->${sinks.join(',')}` : norm;
}

function sanitizeList(list, maxItems = 24) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const item of list) {
    const clean = sanitizeEntry(item);
    if (clean && !out.includes(clean) && out.length < maxItems) out.push(clean);
  }
  return out;
}

function sanitizeArchitecture(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const toInt = (v) => Math.max(0, Math.floor(Number(v) || 0));
  const modRe = /^([\w.@+\/()-]+):(gateway|interface|service|persistence|security|runtime|pipeline|core)\((\d+)f,(\d+)b\)$/;
  const flowRe = /^([\w.@+\/()-]+)->([\w.@+\/()-]+)$/;

  const modules = [];
  if (Array.isArray(raw.modules)) {
    for (const item of raw.modules) {
      const s = String(item || '').trim();
      if (!s || SENSITIVE_TEXT.test(s)) { SENSITIVE_TEXT.lastIndex = 0; continue; }
      SENSITIVE_TEXT.lastIndex = 0;
      const m = modRe.exec(s);
      if (!m) continue;
      const modName = m[1];
      if (modName.startsWith('/') || modName.startsWith('..') || /(^|\/)\.env/i.test(modName) || /^(?:Users|home|private|var|tmp|etc)(?:\/|$)/.test(modName)) continue;
      if (!modules.includes(s) && modules.length < 24) modules.push(s);
    }
  }

  const flows = [];
  if (Array.isArray(raw.flows)) {
    for (const item of raw.flows) {
      const s = String(item || '').trim();
      if (!s || SENSITIVE_TEXT.test(s)) { SENSITIVE_TEXT.lastIndex = 0; continue; }
      SENSITIVE_TEXT.lastIndex = 0;
      const m = flowRe.exec(s);
      if (!m || m[1] === m[2]) continue;
      if (m[1].startsWith('/') || m[2].startsWith('/') || m[1].startsWith('..') || m[2].startsWith('..')) continue;
      if (/(^|\/)\.env/i.test(m[1]) || /(^|\/)\.env/i.test(m[2])) continue;
      if (/^(?:Users|home|private|var|tmp|etc)(?:\/|$)/.test(m[1]) || /^(?:Users|home|private|var|tmp|etc)(?:\/|$)/.test(m[2])) continue;
      if (!flows.includes(s) && flows.length < 24) flows.push(s);
    }
  }

  return {
    fileCount: toInt(raw.fileCount),
    moduleCount: toInt(raw.moduleCount) || modules.length,
    boundaryFileCount: toInt(raw.boundaryFileCount),
    bridgeCount: toInt(raw.bridgeCount),
    flowCount: toInt(raw.flowCount) || flows.length,
    modules,
    flows,
  };
}

// Censors and normalizes a .neckbeard.json object so no secrets, URLs, hostnames, IPs, or absolute paths can be stored.
function sanitizeProjectConfig(cfg = {}) {
  const b = (cfg && cfg.boundaries) || {};
  const ext = b.external || {};
  const int = b.internal || {};
  const boundaryLoad = sanitizeBoundaryLoad(cfg.boundaryLoad);
  const out = {
    shared: cfg.shared !== false,
    load: sanitizeLoad(cfg.load || ''),
  };
  if (Object.keys(boundaryLoad).length > 0) out.boundaryLoad = boundaryLoad;
  out.boundaries = {
    external: {
      ingress: sanitizeList(ext.ingress),
      egress: sanitizeList(ext.egress),
      supply: sanitizeList(ext.supply),
    },
    internal: {
      auth: sanitizeList(int.auth),
      data: sanitizeList(int.data),
      exec: sanitizeList(int.exec),
      ai: sanitizeList(int.ai),
    },
  };
  const arch = sanitizeArchitecture(cfg.architecture);
  if (arch && (arch.modules.length > 0 || arch.flows.length > 0 || arch.fileCount > 0)) {
    out.architecture = arch;
  }
  return out;
}

function collectJsonStrings(value, out = [], depth = 0) {
  if (depth > 8 || value === null || value === undefined) return out;
  if (typeof value === 'string') { out.push(value); return out; }
  if (Array.isArray(value)) { for (const item of value) collectJsonStrings(item, out, depth + 1); return out; }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) { out.push(k); collectJsonStrings(v, out, depth + 1); }
  }
  return out;
}

// Validates a raw JSON string written to .neckbeard.json by an agent tool call; returns a denial reason if unsafe.
function checkNeckbeardJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return 'invalid JSON in .neckbeard.json';
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return '.neckbeard.json must be a JSON object';
  }
  const hit = findSensitiveMatch(String(text || ''));
  if (hit) {
    return `sensitive value or absolute path/URL ("${hit.slice(0, 32)}...") in .neckbeard.json. Store only numeric load targets and repo-relative file paths with closed sink tags`;
  }
  for (const s of collectJsonStrings(parsed)) {
    const strHit = findSensitiveMatch(s);
    if (strHit) {
      return `sensitive value or absolute path/URL ("${strHit.slice(0, 32)}...") in .neckbeard.json. Store only numeric load targets and repo-relative file paths with closed sink tags`;
    }
  }
  return null;
}

// Parses numeric load metrics (rps, rpm, rows, users/concurrent, mb) from a load string or risk: trigger.
function parseLoadMetrics(text) {
  const s = String(text || '').toLowerCase();
  const metrics = {};
  const re = /(\d+(?:\.\d+)?)\s*([km])?\s*(rps|req\/s|req\/sec|requests\/s|requests\/sec|qps|rpm|req\/m|req\/min|requests\/min|rows?|records?|items?|entries|users?|clients?|tenants?|writers?|concurrent(?:\s+\w+)?|kb|mb|gb|tb)\b/g;
  for (const m of s.matchAll(re)) {
    let val = Number(m[1]);
    if (m[2] === 'k') val *= 1000;
    if (m[2] === 'm') val *= 1000000;
    const u = m[3];
    let key = 'other';
    if (/^(rps|req\/s|req\/sec|requests\/s|requests\/sec|qps)$/.test(u)) key = 'rps';
    else if (/^(rpm|req\/m|req\/min|requests\/min)$/.test(u)) key = 'rpm';
    else if (/^(rows?|records?|items?|entries)$/.test(u)) key = 'rows';
    else if (/^(users?|clients?|tenants?|writers?|concurrent)/.test(u)) key = 'users';
    else if (/^(kb|mb|gb|tb)$/.test(u)) {
      key = 'mb';
      if (u === 'kb') val /= 1024;
      if (u === 'gb') val *= 1024;
      if (u === 'tb') val *= 1024 * 1024;
    }
    if (key !== 'other') metrics[key] = Math.max(metrics[key] || 0, val);
  }
  return metrics;
}

// Checks whether a `risk:` comment's revisit trigger has been reached or exceeded by the project's load in .neckbeard.json.
function checkRiskLoadExpiry(commentText, projectLoadOrConfig) {
  const raw = String(commentText || '');
  // Extract the revisit/trigger tail if present (e.g. after "revisit", "when", ">", ">=", "above", "exceeds", or the last comma).
  const triggerMatch = /(?:revisit\b[^,;]*|when\b[^,;]*|(?:>|>=|above|over|exceeds|past)\s*\d[\s\S]*)$/i.exec(raw);
  const triggerPart = triggerMatch ? triggerMatch[0] : (raw.split(',').slice(2).join(',') || raw);
  const triggerMetrics = parseLoadMetrics(triggerPart);
  if (Object.keys(triggerMetrics).length === 0) return { expired: false };

  let loadStrings = [];
  if (typeof projectLoadOrConfig === 'string') {
    loadStrings.push(projectLoadOrConfig);
  } else if (projectLoadOrConfig && typeof projectLoadOrConfig === 'object') {
    if (projectLoadOrConfig.load) loadStrings.push(projectLoadOrConfig.load);
    if (projectLoadOrConfig.boundaryLoad) loadStrings.push(...Object.values(projectLoadOrConfig.boundaryLoad));
  }
  const currentMetrics = parseLoadMetrics(loadStrings.join(' '));
  for (const [unit, threshold] of Object.entries(triggerMetrics)) {
    const current = currentMetrics[unit];
    if (typeof current === 'number' && current >= threshold) {
      return {
        expired: true,
        unit,
        triggerValue: threshold,
        currentValue: current,
        reason: `current project load (${current} ${unit}) >= revisit trigger (${threshold} ${unit})`,
      };
    }
  }
  return { expired: false };
}

function localProjectFile(root = process.cwd(), env = process.env) {
  const base = env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  const key = createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 16);
  const name = path.basename(path.resolve(root)).replace(/[^\w.-]/g, '_') || 'project';
  return path.join(base, 'neckbeard', 'projects', `${name}-${key}.json`);
}

function sharedProjectFile(root = process.cwd()) {
  return path.join(root, '.neckbeard.json');
}

function setGitExclude(root, excluded) {
  try {
    const excludeFile = path.join(root, '.git', 'info', 'exclude');
    if (!fs.existsSync(path.dirname(excludeFile))) return;
    let current = '';
    try { current = fs.readFileSync(excludeFile, 'utf8'); } catch { /* empty */ }
    const lines = current.split('\n').filter((l) => l.trim() !== '.neckbeard.json');
    if (excluded) lines.push('.neckbeard.json');
    fs.writeFileSync(excludeFile, lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n');
  } catch { /* best-effort */ }
}

function readProjectConfig(root = process.cwd(), env = process.env) {
  const localFile = localProjectFile(root, env);
  const sharedFile = sharedProjectFile(root);
  try {
    if (fs.existsSync(localFile)) {
      const localCfg = sanitizeProjectConfig(JSON.parse(fs.readFileSync(localFile, 'utf8')));
      if (localCfg.shared === false) return localCfg;
    }
  } catch { /* fall through */ }
  try {
    if (fs.existsSync(sharedFile)) {
      return sanitizeProjectConfig(JSON.parse(fs.readFileSync(sharedFile, 'utf8')));
    }
  } catch { /* fall through */ }
  return null;
}

function writeProjectConfig(root = process.cwd(), patch = {}, env = process.env, opts = {}) {
  const scanOpts = { ...opts, env };
  const existing = readProjectConfig(root, env) || {
    shared: true,
    load: '',
    boundaryLoad: {},
    boundaries: buildBoundaryMap(root, 16, scanOpts),
  };
  const nextBoundaryLoad = { ...(existing.boundaryLoad || {}), ...(patch.boundaryLoad || {}) };
  for (const [k, v] of Object.entries(nextBoundaryLoad)) {
    if (v === null || v === '') delete nextBoundaryLoad[k];
  }
  const candidateBounds = patch.boundaries || existing.boundaries;
  const resolvedBounds = flattenBoundaries(candidateBounds).length > 0 ? candidateBounds : buildBoundaryMap(root, 16, scanOpts);
  const candidateArch = patch.architecture || existing.architecture;
  const resolvedArch = (candidateArch && Array.isArray(candidateArch.modules) && candidateArch.modules.length > 0)
    ? candidateArch
    : buildArchitectureMap(root, 16, 24, scanOpts);
  const merged = sanitizeProjectConfig({
    shared: patch.shared !== undefined ? patch.shared : existing.shared,
    load: patch.load !== undefined ? patch.load : existing.load,
    boundaryLoad: nextBoundaryLoad,
    boundaries: resolvedBounds,
    architecture: resolvedArch,
  });

  const localFile = localProjectFile(root, env);
  const sharedFile = sharedProjectFile(root);

  if (merged.shared === false) {
    fs.mkdirSync(path.dirname(localFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(localFile, JSON.stringify(merged, null, 2) + '\n', { mode: 0o600 });
    try { if (fs.existsSync(sharedFile)) fs.unlinkSync(sharedFile); } catch { /* ignore */ }
    try {
      execFileSync('git', ['rm', '--cached', '-f', '.neckbeard.json'], { cwd: root, stdio: 'ignore', timeout: 1500 });
    } catch { /* not tracked */ }
    setGitExclude(root, true);
  } else {
    setGitExclude(root, false);
    fs.writeFileSync(sharedFile, JSON.stringify(merged, null, 2) + '\n');
    try { if (fs.existsSync(localFile)) fs.unlinkSync(localFile); } catch { /* ignore */ }
  }
  return merged;
}

// Ensures a project's persisted boundary map is populated and refreshed if empty, referencing deleted files, or older than maxAgeMs.
function ensureFreshBoundaryMap(root = process.cwd(), env = process.env, maxAgeMs = DEFAULT_MAP_MAX_AGE_MS, opts = {}) {
  const cfg = readProjectConfig(root, env);
  if (!cfg) return null;
  const activeFile = cfg.shared === false ? localProjectFile(root, env) : sharedProjectFile(root);
  const flat = flattenBoundaries(cfg.boundaries);
  let needsRefresh = flat.length === 0;
  if (!needsRefresh && maxAgeMs > 0) {
    try {
      const st = fs.statSync(activeFile);
      if (Date.now() - st.mtimeMs > maxAgeMs) needsRefresh = true;
    } catch { /* ignore */ }
  }
  if (!needsRefresh) {
    // Also refresh if any saved boundary file was deleted or moved
    for (const entry of flat) {
      const relFile = String(entry).split('->')[0];
      if (relFile && !fs.existsSync(path.join(root, relFile))) {
        needsRefresh = true;
        break;
      }
    }
  }
  if (needsRefresh || !cfg.architecture || !Array.isArray(cfg.architecture.modules) || cfg.architecture.modules.length === 0) {
    const scanOpts = { ...opts, env };
    return writeProjectConfig(root, {
      boundaries: buildBoundaryMap(root, 16, scanOpts),
      architecture: buildArchitectureMap(root, 16, 24, scanOpts),
    }, env, scanOpts);
  }
  return cfg;
}

// Formats the concise, token-efficient load + per-boundary overrides + external/internal map + boundary drift alert.
function formatProjectContext(root = process.cwd(), env = process.env, opts = {}) {
  const scanOpts = { ...opts, env };
  const cfg = readProjectConfig(root, env);
  const liveMap = opts.liveMap || buildBoundaryMap(root, 16, scanOpts);
  const hasSavedBounds = Boolean(cfg && cfg.boundaries && flattenBoundaries(cfg.boundaries).length > 0);
  const map = hasSavedBounds ? cfg.boundaries : liveMap;
  const ext = (map && map.external) || {};
  const int = (map && map.internal) || {};

  const fmtGroup = (obj, keys) => keys
    .map((k) => (Array.isArray(obj[k]) && obj[k].length ? `${k}:${obj[k].slice(0, 4).join(',')}` : ''))
    .filter(Boolean)
    .join(' | ');

  const extLine = fmtGroup(ext, ['ingress', 'egress', 'supply']);
  const intLine = fmtGroup(int, ['auth', 'data', 'exec', 'ai']);

  const overrides = cfg && cfg.boundaryLoad && Object.keys(cfg.boundaryLoad).length
    ? ` [per-boundary: ${Object.entries(cfg.boundaryLoad).map(([k, v]) => `${k}=${v}`).join('; ')}]`
    : '';

  const lines = [];
  if (cfg && cfg.load) {
    lines.push(`Load default (${cfg.shared === false ? 'local' : '.neckbeard.json, shared'}): ${cfg.load}${overrides}`);
  } else if (overrides) {
    lines.push(`Load default (${cfg.shared === false ? 'local' : '.neckbeard.json, shared'}):${overrides}`);
  } else {
    lines.push('Load default: unset (save via /neckbeard load <value>)');
  }
  if (extLine) lines.push(`Trust Map [ext] ${extLine}`);
  if (intLine) lines.push(`Trust Map [int] ${intLine}`);
  const arch = opts.architecture || ((cfg && cfg.architecture && Array.isArray(cfg.architecture.modules) && cfg.architecture.modules.length > 0)
    ? cfg.architecture
    : buildArchitectureMap(root, 16, 24, scanOpts));
  if (arch && arch.modules && arch.modules.length > 0) {
    const flowPart = arch.flows && arch.flows.length > 0 ? ` | flows:${arch.flows.slice(0, 4).join(',')}` : '';
    lines.push(`Arch Map [${arch.moduleCount} mods · ${arch.bridgeCount} bridges] ${arch.modules.slice(0, 4).join(',')}${flowPart}`);
  }

  if (cfg && cfg.boundaries && flattenBoundaries(cfg.boundaries).length > 0) {
    const drift = diffBoundaryMap(cfg.boundaries, liveMap);
    if (drift.added.length > 0) {
      lines.push(`Boundary Drift [new]: +${drift.added.length} unreviewed (${drift.added.slice(0, 3).join(', ')}) — verify in /neckbeard-review or run /neckbeard map`);
    }
  }
  if (opts.includeCrewContext !== false) {
    const crewLines = formatCrewContext(root);
    if (crewLines) lines.push(crewLines);
  }
  const capNotice = liveMap.notice || (arch && arch.notice) || '';
  if (capNotice) {
    const noticeLine = `Notice: ${capNotice}`;
    const bodyBudget = Math.max(0, MAP_BUDGET - noticeLine.length - 1);
    const body = lines.join('\n').slice(0, bodyBudget);
    return body ? `${body}\n${noticeLine}` : noticeLine;
  }
  return lines.join('\n').slice(0, MAP_BUDGET);
}

// Validates any Crew Universe store JSON (.{id}.json) or JSONL (.rainmaker-inbox.jsonl)
// against secrets, URLs, hostnames, IPs, emails, absolute local paths (raw + escaped + Base64),
// CRLF line endings, and < 4096B JSONL line bounds.
function checkCrewStoreJson(rawText, fileName = '') {
  const raw = String(rawText || '');
  const s = raw.trim();
  if (!s) return 'empty crew store file';
  const hit = findSensitiveMatch(raw);
  if (hit) {
    return `contains a secret, URL, internal hostname, IP address, email, or absolute local path (${hit.slice(0, 32)})`;
  }
  if (String(fileName).endsWith('.jsonl')) {
    if (raw.includes('\r')) return 'JSONL file must use LF-only line endings (CR/CRLF forbidden)';
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);
    for (let i = 0; i < lines.length; i++) {
      const byteLen = Buffer.byteLength(lines[i] + '\n', 'utf8');
      if (byteLen >= MAX_JSONL_LINE_BYTES) {
        return `line ${i + 1} exceeds strict < ${MAX_JSONL_LINE_BYTES} UTF-8 byte limit (${byteLen} bytes)`;
      }
      let row;
      try { row = JSON.parse(lines[i]); } catch { return `invalid JSONL on line ${i + 1}`; }
      if (!row || typeof row !== 'object' || Array.isArray(row)) return `line ${i + 1} must be a JSON object`;
      for (const val of collectJsonStrings(row)) {
        const valHit = findSensitiveMatch(val);
        if (valHit) return `line ${i + 1} contains sensitive value (${valHit.slice(0, 32)})`;
      }
    }
    return null;
  }
  let parsed;
  try { parsed = JSON.parse(s); } catch { return 'invalid JSON'; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'root must be a JSON object';
  for (const val of collectJsonStrings(parsed)) {
    const valHit = findSensitiveMatch(val);
    if (valHit) return `contains sensitive value (${valHit.slice(0, 32)})`;
  }
  return null;
}

// Reads sibling Crew Universe stores (built-in 12 + dynamically registered Nth peers, plus .rainmaker-inbox.jsonl).
function readCrewPeerStores(root = process.cwd(), env = process.env) {
  const peers = {};
  const peerFileMap = getDynamicPeerStoreFiles('neckbeard', env);
  for (const [key, relFile] of Object.entries(peerFileMap)) {
    const fp = path.join(root, relFile);
    if (!fs.existsSync(fp)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(fp, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) peers[key] = parsed;
    } catch { /* ignore malformed peer store */ }
  }
  const inboxPath = path.join(root, RAINMAKER_INBOX_FILE);
  let inboxPending = 0;
  if (fs.existsSync(inboxPath)) {
    try {
      const raw = fs.readFileSync(inboxPath, 'utf8');
      for (const line of raw.split('\n')) {
        const t = line.trim();
        if (!t.startsWith('{')) continue;
        try {
          const item = JSON.parse(t);
          if (!item.status || item.status === 'pending' || item.status === 'proposed') inboxPending++;
        } catch {}
      }
    } catch {}
  }
  return { peers, inboxPending };
}

// Formats a concise, sanitized summary of active sibling Crew stores for SessionStart / SubagentStart.
function formatCrewContext(root = process.cwd()) {
  const { peers, inboxPending } = readCrewPeerStores(root);
  const parts = [];
  if (peers.headhoncho) {
    const hh = peers.headhoncho;
    const mode = sanitizeLoad(String(hh.mode || hh.posture || 'chief-of-staff')).slice(0, 24);
    const decisions = Array.isArray(hh.decisions) ? hh.decisions.length : (Number(hh.decisionCount) || 0);
    parts.push(`HeadHoncho(Mike): mode=${mode} (${decisions} decisions)`);
  }
  if (peers.rainmaker) {
    const rm = peers.rainmaker;
    const outcome = sanitizeLoad(String(rm.activeOutcome || rm.northStar || 'active')).slice(0, 60);
    const cut = sanitizeLoad(String(Array.isArray(rm.cutline) ? rm.cutline.slice(0, 2).join(', ') : (rm.cutline || ''))).slice(0, 50);
    parts.push(`RainMaker(Val): ${outcome}${cut ? ` [cut: ${cut}]` : ''}${inboxPending > 0 ? ` (${inboxPending} inbox)` : ''}`);
  } else if (inboxPending > 0) {
    parts.push(`RainMaker Inbox: ${inboxPending} pending proposal(s)`);
  }
  if (peers.propellerhead) {
    const ph = peers.propellerhead;
    const inv = sanitizeLoad(String(Array.isArray(ph.invariants) && ph.invariants[0] ? (ph.invariants[0].rule || ph.invariants[0]) : (ph.activeInvariant || ''))).slice(0, 60);
    const task = sanitizeLoad(String(ph.activeSlice || ph.rootMechanism || '')).slice(0, 50);
    if (inv || task) parts.push(`PropellerHead(Danny): ${[inv && `inv:${inv}`, task && `focus:${task}`].filter(Boolean).join(' ')}`);
  }
  if (peers.hipster) {
    const hp = peers.hipster;
    const ux = sanitizeLoad(String(hp.activeFlow || hp.glassStatus || 'armed')).slice(0, 50);
    parts.push(`Hipster(Sammy): ${ux}`);
  }
  if (peers.edgelord) {
    const el = peers.edgelord;
    const rawOpen = el.openFaults ?? el.openBreaches ?? (Array.isArray(el.faults) ? el.faults.length : (Array.isArray(el.breaches) ? el.breaches.length : 0));
    const br = Number(rawOpen) || 0;
    parts.push(`EdgeLord(Ronnie): ${br} open breach(es)`);
  }
  if (peers.infrasmith) {
    const is = peers.infrasmith;
    const status = is.rollbackReady === false
      ? 'rollback=NO'
      : (is.rollbackReady === true ? 'rollback=OK' : sanitizeLoad(String(is.status || is.deployStatus || 'armed')).slice(0, 24));
    parts.push(`InfraSmith(Zack): ${status}`);
  }
  if (peers.storyteller) {
    const st = peers.storyteller;
    const status = sanitizeLoad(String(st.status || st.activeCampaign || st.positioning || 'armed')).slice(0, 28);
    parts.push(`StoryTeller(Nate): ${status}`);
  }
  if (peers.cloutchaser) {
    const cc = peers.cloutchaser;
    const status = cc.safeToPublish === false
      ? 'publish=HOLD'
      : sanitizeLoad(String(cc.status || cc.activeCampaign || (cc.safeToPublish === true ? 'publish=OK' : 'armed'))).slice(0, 28);
    parts.push(`CloutChaser(Vic): ${status}`);
  }
  if (peers.userchamp) {
    const uc = peers.userchamp;
    const status = uc.reproVerified === true
      ? 'repro=YES'
      : sanitizeLoad(String(uc.status || uc.activeQueue || 'armed')).slice(0, 28);
    parts.push(`UserChamp(Ray): ${status}`);
  }
  if (peers.redline) {
    const rl = peers.redline;
    const status = sanitizeLoad(String(rl.policyStatus || rl.status || 'armed')).slice(0, 24);
    parts.push(`RedLine(Jules): policy=${status}`);
  }
  if (peers.measureup) {
    const mu = peers.measureup;
    const status = sanitizeLoad(String(mu.marginStatus || mu.status || 'armed')).slice(0, 24);
    parts.push(`MeasureUp(Dave): margin=${status}`);
  }
  if (peers.dealmaker) {
    const dm = peers.dealmaker;
    const status = sanitizeLoad(String(dm.pipelineStatus || dm.status || dm.activeCampaign || 'armed')).slice(0, 28);
    parts.push(`DealMaker(Quinn): ${status}`);
  }
  return parts.length > 0 ? `Crew Peers [active] ${parts.join(' | ')}` : '';
}

// Appends a strictly censored work/remediation proposal from NeckBeard (Ashy Larry / Lari) to RainMaker's shared intake queue (.rainmaker-inbox.jsonl).
function appendCrewInboxProposal(root = process.cwd(), proposal = {}) {
  const cleanSummary = sanitizeLoad(String(proposal.summary || proposal.title || '')).slice(0, 160);
  if (!cleanSummary) return null;
  const record = {
    id: sanitizeLoad(String(proposal.id || `nb-${Date.now().toString(36)}`)).slice(0, 32),
    timestampIso: new Date().toISOString(),
    from: 'neckbeard',
    persona: proposal.persona === 'lari' ? 'Ashy Lari' : 'Ashy Larry',
    kind: ['audit-finding', 'boundary-drift', 'expired-debt', 'security-gate', 'fast-gate', 'done-gate'].includes(proposal.kind)
      ? proposal.kind
      : 'audit-finding',
    boundary: sanitizeEntry(String(proposal.boundary || '')) || '',
    ePatch: sanitizeLoad(String(proposal.ePatch || '')).slice(0, 48),
    summary: cleanSummary,
    status: 'pending',
  };
  const fp = path.join(root, RAINMAKER_INBOX_FILE);
  const line = JSON.stringify(record).replace(/\r/g, '') + '\n';
  if (Buffer.byteLength(line, 'utf8') >= MAX_JSONL_LINE_BYTES) {
    record.summary = record.summary.slice(0, 120);
  }
  const safeLine = JSON.stringify(record).replace(/\r/g, '') + '\n';
  fs.appendFileSync(fp, safeLine, 'utf8');
  return record;
}

module.exports = {
  buildSurface,
  buildBoundaryMap,
  buildArchitectureMap,
  flattenBoundaries,
  diffBoundaryMap,
  detectBoundaryDrift,
  sanitizeLoad,
  sanitizeBoundaryLoad,
  sanitizeArchitecture,
  sanitizeProjectConfig,
  stripInvisibleChars,
  normalizeUnicode,
  decodeJsonEscapes,
  decodeUrlPercent,
  extractBase64DecodedViews,
  buildInspectionViews,
  findSensitiveMatch,
  checkNeckbeardJson,
  checkCrewStoreJson,
  readCrewPeerStores,
  formatCrewContext,
  appendCrewInboxProposal,
  CREW_PEER_FILES,
  RAINMAKER_INBOX_FILE,
  MAX_JSONL_LINE_BYTES,
  MAX_FILES,
  isUncapped,
  resolveFileCap,
  formatCapNotice,
  listFiles,
  selectScanFiles,
  parseLoadMetrics,
  checkRiskLoadExpiry,
  readProjectConfig,
  writeProjectConfig,
  ensureFreshBoundaryMap,
  formatProjectContext,
  localProjectFile,
  sharedProjectFile,
  ALLOWED_SINKS,
  ALLOWED_LOAD_KEYS,
  ALLOWED_ARCH_ROLES,
  BOUNDARY_DETECTORS,
  CATEGORIES,
};

if (require.main === module) {
  const args = process.argv.slice(2);
  const uncapped = args.includes('--uncapped') || isUncapped({}, process.env);
  const targetDir = args.find((a) => !a.startsWith('-')) || process.cwd();
  const scanOpts = { uncapped };
  if (args.includes('--map')) {
    const boundaries = buildBoundaryMap(targetDir, 16, scanOpts);
    const architecture = buildArchitectureMap(targetDir, 16, 24, scanOpts);
    writeProjectConfig(targetDir, { boundaries, architecture }, process.env, scanOpts);
    const notice = boundaries.notice || architecture.notice;
    if (notice) process.stderr.write(`[neckbeard] WARNING: ${notice}\n`);
    process.stdout.write(formatProjectContext(targetDir, process.env, { ...scanOpts, liveMap: boundaries, architecture }) + '\n');
  } else {
    const out = buildSurface(targetDir, scanOpts);
    const noticeMatch = /\nNotice:\s+(.+)$/.exec(out);
    if (noticeMatch) process.stderr.write(`[neckbeard] WARNING: ${noticeMatch[1]}\n`);
    process.stdout.write(out + '\n');
  }
}
