'use strict';
// Attack-surface map: which files take untrusted input and which reach dangerous sinks.
// Regex over tracked source files, file paths only (no code text reaches the model),
// inside a character budget. It points the agent at what to read; it proves nothing.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const BUDGET = Number(process.env.NECKBEARD_SURFACE_CHARS || 1500);
const MAX_FILES = 3000;
const MAX_BYTES = 200 * 1024;
const SRC = /\.(py|js|jsx|mjs|cjs|ts|tsx|go|rs|rb|java|kt|php|cs|swift|sh)$/;
const SKIP = /(^|\/)(node_modules|vendor|dist|build|out|target|coverage|\.next|\.venv|venv|__pycache__|tests?|__tests__|spec|fixtures|migrations)(\/|$)|\.(test|spec|min|d)\.[a-z]+$/;
const SAFE_PATH = /^[\w.@+\/-]+$/; // a path with odd characters is skipped, never echoed

const CATEGORIES = [
  ['entry points (HTTP, RPC, CLI, queues)', /\b(?:app|router|server|api|hono)\.(?:get|post|put|patch|delete|all|use|route)\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping|Controller)\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\bhttp\.HandleFunc\b|\bfetch\s*\(\s*req(?:uest)?\b|\baddEventListener\(\s*['"]fetch['"]|\bargparse\b|\bprocess\.argv\b|\bconsumer\.|\bon_message\b/],
  ['shell and code execution', /\bchild_process\b|\bexecSync\s*\(|\bspawn(?:Sync)?\s*\(|\bsubprocess\.|\bos\.system\s*\(|\bos\.popen\s*\(|\beval\s*\(|\bnew Function\s*\(|\bexec\.Command\s*\(|\bRuntime\.getRuntime\(\)\.exec\b|`[^`]*\$\(/],
  ['raw SQL', /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}\b(?:FROM|INTO|SET|WHERE)\b[^\n]*(?:\$\{|\+\s*\w|%s|f["']|\.format\()|\.(?:raw|unsafe|exec)\s*\(\s*[`'"]|\bexecute\s*\(\s*f["']/i],
  ['deserialization and parsers', /\bpickle\.loads?\b|\byaml\.load\s*\((?![^)]*SafeLoader)|\bmarshal\.loads\b|\bObjectInputStream\b|\bunserialize\s*\(|\bXMLParser\b|\bDOMParser\b|\bxml2js\b|\blibxml\b/],
  ['outbound requests (SSRF)', /\bfetch\s*\(\s*(?!['"`]https?:)[^)]|\baxios\.(?:get|post|request)\s*\(\s*(?!['"`])|\brequests\.(?:get|post|request)\s*\(\s*(?!['"])|\burllib\.request\.urlopen\b|\bhttp\.Get\s*\(\s*[a-z]/],
  ['file paths built at runtime', /\b(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rm)(?:Sync)?\s*\(\s*(?:path\.join\s*\()?[^'"`)\s]|\bopen\s*\(\s*(?:os\.path\.join|f["'])|\bsend_file\s*\(|\bsendFile\s*\(/],
  ['auth, sessions and tokens', /\bjwt\b|\bjsonwebtoken\b|\bbcrypt\b|\bargon2\b|\bpassport\b|\bsession\b|\bset-cookie\b|\bsetCookie\b|\bauthorization\b|\boauth\b|\bcsrf\b|\bverifyToken\b|\bapi[_-]?key\b/i],
  ['crypto and randomness', /\bcreateCipher(?:iv)?\b|\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|\bhashlib\.(?:md5|sha1)\b|\bMath\.random\s*\(|\brandom\.(?:random|randint|choice)\s*\(|\bDES\b|\bECB\b/],
  ['secrets and config from the environment', /\bprocess\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASS|PRIVATE)[A-Z_]*|\bos\.environ\b[^\n]*(?:KEY|SECRET|TOKEN|PASS)|\benv\.[A-Z_]*(?:KEY|SECRET|TOKEN)[A-Z_]*/],
  ['LLM and agent calls (prompt injection)', /\banthropic\b|\bopenai\b|\bmessages\.create\s*\(|\bchat\.completions\b|\btool_use\b|\bfunction_call\b|\bmcp\b|\bMcpServer\b|\blangchain\b/i],
];

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
      if (e.name.startsWith('.')) continue;
      const rel = path.relative(root, path.join(dir, e.name)).split(path.sep).join('/');
      if (e.isDirectory()) { if (!SKIP.test(rel + '/')) walk(path.join(dir, e.name), depth + 1); } else out.push(rel);
    }
  })(root, 0);
  return out;
}

function buildSurface(root) {
  const files = listFiles(root).filter((f) => SRC.test(f) && !SKIP.test(f) && SAFE_PATH.test(f)).slice(0, MAX_FILES);
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

module.exports = { buildSurface, CATEGORIES };

if (require.main === module) process.stdout.write(buildSurface(process.argv[2] || process.cwd()) + '\n');
