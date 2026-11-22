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

const BUDGET = Number(process.env.NECKBEARD_SURFACE_CHARS || 1500);
const MAP_BUDGET = Number(process.env.NECKBEARD_MAP_CHARS || 680);
const DEFAULT_MAP_MAX_AGE_MS = Number(process.env.NECKBEARD_MAP_MAX_AGE_HOURS || 24) * 60 * 60 * 1000;
const MAX_FILES = 3000;
const MAX_BYTES = 200 * 1024;
const SRC = /\.(py|js|jsx|mjs|cjs|ts|tsx|go|rs|rb|java|kt|php|cs|swift|sh|yml|yaml)$/;
const SKIP = /(^|\/)(node_modules|vendor|dist|build|out|target|coverage|\.next|\.venv|venv|__pycache__|\.claude|\.worktrees|\.maestro|Auto Run Docs|Plans|docs|benches|fuzz|tests?|__tests__|spec|fixtures|migrations)(\/|$)|\.(test|spec|min|d)\.[a-z]+$|_(test|spec)\.(rs|go|py|ts|js)$/;
const SAFE_PATH = /^[\w.@+\/-]+$/; // a path with odd characters is skipped, never echoed

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

// Patterns that must always be censored from load strings or boundary entries.
const SENSITIVE_TEXT = /(?:https?:\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[\w.+-]+@[\w-]+\.[\w.-]+\b|\b[\w-]+\.(?:internal|corp|local|lan|amazonaws\.com|rds\.amazonaws\.com|svc\.cluster\.local)\b|\/(?:Users|home|private|var\/folders)\/\S+|[A-Za-z]:\\\S+|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,})\b)/gi;

function listFiles(root) {
  try {
    const out = execFileSync('git', ['ls-files', '-z'], {
      cwd: root, encoding: 'utf8', timeout: 2000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
    });
    const files = out.split('\0').filter(Boolean);
    if (files.length) return files;
  } catch { /* not a git repo */ }
  const out = [];
  (function walk(dir, depth) {
    if (depth > 6 || out.length > MAX_FILES) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      if (e.name.startsWith('.') && e.name !== '.github') continue;
      const rel = path.relative(root, path.join(dir, e.name)).split(path.sep).join('/');
      if (e.isDirectory()) { if (!SKIP.test(rel + '/')) walk(path.join(dir, e.name), depth + 1); } else out.push(rel);
    }
  })(root, 0);
  return out;
}

function buildSurface(root) {
  const files = listFiles(root).filter((f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f) && !/\.(yml|yaml)$/.test(f)).slice(0, MAX_FILES);
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
  if (!lines.length) return '';
  return 'Attack-surface map (files matched by pattern; read them before changing code that crosses these boundaries):\n' + lines.join('\n');
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
function buildBoundaryMap(root = process.cwd(), maxPerCategory = 16) {
  let files = listFiles(root).filter((f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f)).slice(0, MAX_FILES);
  // Prioritise core production directories (src/, crates/, apps/, packages/, hooks/, lib/, functions/, scripts/) before examples/
  files.sort((a, b) => {
    const aEx = /(^|\/)(examples?|demo|samples?|benchmarks?)\//i.test(a) ? 1 : 0;
    const bEx = /(^|\/)(examples?|demo|samples?|benchmarks?)\//i.test(b) ? 1 : 0;
    return aEx - bEx || a.localeCompare(b);
  });
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

  return { external: ext, internal: int };
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
function buildArchitectureMap(root = process.cwd(), maxModules = 16, maxFlows = 24) {
  const files = listFiles(root).filter((f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f)).slice(0, MAX_FILES);
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

  return {
    fileCount: files.length,
    moduleCount: modStats.size,
    boundaryFileCount,
    bridgeCount: totalBridges,
    flowCount: flowSet.size,
    modules,
    flows,
  };
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

function detectBoundaryDrift(root = process.cwd(), env = process.env) {
  const cfg = readProjectConfig(root, env);
  if (!cfg || !cfg.boundaries) return { added: [], removed: [] };
  const hasSaved = flattenBoundaries(cfg.boundaries).length > 0;
  if (!hasSaved) return { added: [], removed: [] };
  return diffBoundaryMap(cfg.boundaries, buildBoundaryMap(root));
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
      if (modName.startsWith('/') || modName.startsWith('..') || /^(?:Users|home|private|var|tmp|etc)\//.test(modName)) continue;
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
      if (!m) continue;
      if (m[1].startsWith('/') || m[2].startsWith('/') || m[1].startsWith('..') || m[2].startsWith('..')) continue;
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

// Validates a raw JSON string written to .neckbeard.json by an agent tool call; returns a denial reason if unsafe.
function checkNeckbeardJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return 'invalid JSON in .neckbeard.json';
  }
  const raw = String(text || '');
  SENSITIVE_TEXT.lastIndex = 0;
  const m = SENSITIVE_TEXT.exec(raw);
  SENSITIVE_TEXT.lastIndex = 0;
  if (m) {
    return `sensitive value or absolute path/URL ("${m[0].slice(0, 24)}...") in .neckbeard.json. Store only numeric load targets and repo-relative file paths with closed sink tags`;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return '.neckbeard.json must be a JSON object';
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

function writeProjectConfig(root = process.cwd(), patch = {}, env = process.env) {
  const existing = readProjectConfig(root, env) || {
    shared: true,
    load: '',
    boundaryLoad: {},
    boundaries: buildBoundaryMap(root),
  };
  const nextBoundaryLoad = { ...(existing.boundaryLoad || {}), ...(patch.boundaryLoad || {}) };
  for (const [k, v] of Object.entries(nextBoundaryLoad)) {
    if (v === null || v === '') delete nextBoundaryLoad[k];
  }
  const candidateBounds = patch.boundaries || existing.boundaries;
  const resolvedBounds = flattenBoundaries(candidateBounds).length > 0 ? candidateBounds : buildBoundaryMap(root);
  const candidateArch = patch.architecture || existing.architecture;
  const resolvedArch = (candidateArch && Array.isArray(candidateArch.modules) && candidateArch.modules.length > 0)
    ? candidateArch
    : buildArchitectureMap(root);
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
function ensureFreshBoundaryMap(root = process.cwd(), env = process.env, maxAgeMs = DEFAULT_MAP_MAX_AGE_MS) {
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
    return writeProjectConfig(root, {
      boundaries: buildBoundaryMap(root),
      architecture: buildArchitectureMap(root),
    }, env);
  }
  return cfg;
}

// Formats the concise, token-efficient load + per-boundary overrides + external/internal map + boundary drift alert.
function formatProjectContext(root = process.cwd(), env = process.env) {
  const cfg = readProjectConfig(root, env);
  const liveMap = buildBoundaryMap(root);
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
    lines.push('Load default: unset (if Fast gate applies and prompt/repo gives no load, ask once and save with /neckbeard load <value> or to .neckbeard.json)');
  }
  if (extLine) lines.push(`Trust Map [ext] ${extLine}`);
  if (intLine) lines.push(`Trust Map [int] ${intLine}`);
  const arch = (cfg && cfg.architecture && Array.isArray(cfg.architecture.modules) && cfg.architecture.modules.length > 0)
    ? cfg.architecture
    : buildArchitectureMap(root);
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
  return lines.join('\n').slice(0, MAP_BUDGET);
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
  checkNeckbeardJson,
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
  if (args.includes('--map')) {
    const targetDir = args.find((a) => !a.startsWith('-')) || process.cwd();
    const boundaries = buildBoundaryMap(targetDir);
    const architecture = buildArchitectureMap(targetDir);
    writeProjectConfig(targetDir, { boundaries, architecture });
    process.stdout.write(formatProjectContext(targetDir) + '\n');
  } else {
    process.stdout.write(buildSurface(args[0] || process.cwd()) + '\n');
  }
}
