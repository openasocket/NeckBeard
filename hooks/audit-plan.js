#!/usr/bin/env node
'use strict';
// Deterministic large-repo audit planner, risk-first disjoint chunker, coverage verifier,
// and crash-resumable Maestro Auto Run playbook emitter for `/neckbeard-audit complete`.
// Zero external dependencies. Follows NeckBeard Safe / Fast / Done gates.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  MAX_FILES,
  isUncapped,
  resolveFileCap,
  formatCapNotice,
  readProjectConfig,
} = require('./surface');

const DEFAULT_MAX_CHUNK_FILES = 35;
const DEFAULT_MAX_CHUNK_BYTES = 300 * 1024; // 300 KB
const SMALL_MAX_FILES = 80;
const SMALL_MAX_BYTES = 1024 * 1024; // 1 MB
const MEDIUM_MAX_FILES = 500;
const MEDIUM_MAX_BYTES = 6 * 1024 * 1024; // 6 MB
const PRISM_HIGH_THRESHOLD = 0.6;
const MAX_PRISM_READ_BYTES = 16 * 1024 * 1024;
const MAX_REPORT_FILES = 2000;
const MAX_REPORT_BYTES = 16 * 1024 * 1024;
const BINARY_PEEK_BYTES = 512;
const CHUNKS_PER_PLAYBOOK_DOC = 10;

// ASCII control chars + bidi/invisible Unicode overrides that can spoof paths or break logs/Markdown.
const CONTROL_OR_BIDI_RE = /[\x00-\x1f\x7f\u00AD\u034F\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
// Characters that could inject HTML/Maestro markers (`<!--`), Markdown code spans, or shell expansions (`$(...)`).
const UNSAFE_PATH_CHAR_RE = /[<>$`]/;

// Vendored third-party dependency trees excluded under `Not checked:`.
const VENDORED_RE = /(^|\/)(node_modules|vendor|third_party|third-party|3rdparty|extern|external|bower_components|jspm_packages|Pods|Carthage|\.yarn\/cache)(\/|$)|(^|\/)\.pnp\.(?:cjs|loader\.mjs)$/;

// Known binary asset extensions excluded under `Not read:` (SVG is XML text and stays in-scope).
const BINARY_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.icns', '.bmp', '.tiff', '.tif',
  '.psd', '.heic', '.avif', '.raw', '.cur', '.dds', '.tga', '.exr',
  '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wmv', '.m4v',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.zst', '.dmg', '.pkg',
  '.exe', '.dll', '.so', '.dylib', '.a', '.o', '.obj', '.class', '.jar', '.war', '.ear',
  '.pyc', '.pyo', '.wasm', '.node', '.apk', '.ipa', '.deb', '.rpm', '.msi', '.bin', '.dat',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.sqlite', '.sqlite3', '.db', '.ldb', '.parquet', '.feather', '.arrow',
  '.h5', '.hdf5', '.pkl', '.pickle', '.pt', '.pth', '.onnx', '.safetensors', '.gguf', '.ckpt', '.pb', '.nib', '.car',
]);

// Known text extensions (avoids opening every file for NUL-byte sniffing on 100 MB+ repos).
const TEXT_EXTS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.d.ts',
  '.py', '.pyi', '.go', '.rs', '.rb', '.java', '.kt', '.kts', '.php', '.cs', '.swift',
  '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.m', '.mm',
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
  '.yml', '.yaml', '.json', '.jsonc', '.jsonl', '.toml', '.ini', '.cfg', '.conf', '.env', '.properties',
  '.xml', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.svg',
  '.md', '.mdx', '.txt', '.rst', '.adoc', '.tex',
  '.sql', '.graphql', '.gql', '.proto', '.tf', '.tfvars', '.hcl',
  '.mk', '.cmake', '.gradle', '.nix', '.lua', '.ex', '.exs', '.erl', '.hs', '.ml', '.mli',
  '.r', '.scala', '.clj', '.cljs', '.vue', '.svelte', '.astro', '.prisma', '.lock',
  '.csv', '.tsv', '.patch', '.diff', '.pem', '.pub',
]);

const TEXT_BASENAMES = new Set([
  'Makefile', 'Dockerfile', 'Containerfile', 'Jenkinsfile', 'Vagrantfile', 'Procfile',
  'Gemfile', 'Rakefile', 'Brewfile', 'CODEOWNERS', 'LICENSE', 'LICENCE', 'README',
  'CHANGELOG', 'NOTICE', 'AUTHORS', 'CONTRIBUTING', 'SECURITY',
  '.gitignore', '.gitattributes', '.gitmodules', '.dockerignore', '.npmignore',
  '.npmrc', '.nvmrc', '.editorconfig', '.prettierrc', '.eslintrc', '.browserslistrc', '.env',
]);

const GROUP_PREFIXES = new Set([
  'src', 'packages', 'apps', 'crates', 'hooks', 'services', 'libs', 'lib',
  'functions', 'modules', 'plugins', 'extensions', 'docs', 'test', 'tests', 'scripts',
]);

const HIGH_RISK_PATH_RE = /(^|\/)(?:\.github\/workflows\/|auth|security|crypto|session|token|oauth|jwt|rbac|acl|permission|policy|guard|sandbox|ipc|preload|main|server|router|routes|api|gateway|proxy|middleware|webhook|hooks?|exec|shell|spawn|sql|db|database|storage|fs|file|upload|download|parser|serde|mcp|agent|llm)/i;
const MANIFEST_PATH_RE = /(^|\/)(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.toml|Cargo\.lock|pyproject\.toml|requirements.*\.txt|go\.mod|go\.sum|Gemfile(?:\.lock)?|Dockerfile|Containerfile|docker-compose\.ya?ml|tsconfig\.json|vite\.config\.|webpack\.config\.|Makefile|plugin\.json|marketplace\.json|gemini-extension\.json|\.neckbeard\.json)$/i;
const DOC_ROOT_RE = /^(?:README|AGENTS|CLAUDE|SPEC|SECURITY|INSTALL)\.md$|^\.github\/copilot-instructions\.md$/i;

function cmpAscii(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function formatBytes(bytes) {
  const n = Math.max(0, Number(bytes) || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function sanitizeRejectedLabel(raw) {
  return String(raw || '')
    .replace(CONTROL_OR_BIDI_RE, '?')
    .replace(UNSAFE_PATH_CHAR_RE, '?')
    .slice(0, 80);
}

function canonicalizeExistingDir(targetPath, label) {
  let real;
  try {
    real = fs.realpathSync(path.resolve(String(targetPath || '')));
  } catch {
    throw new Error(`${label} does not exist or cannot be resolved`);
  }
  let st;
  try {
    st = fs.statSync(real);
  } catch {
    throw new Error(`${label} cannot be inspected`);
  }
  if (!st.isDirectory()) {
    throw new Error(`${label} is not a directory`);
  }
  return real;
}

function validateScopeSubpath(rootReal, rawScope) {
  if (!rawScope) return '';
  const raw = String(rawScope).trim();
  if (!raw || raw === '.') return '';
  if (CONTROL_OR_BIDI_RE.test(raw) || UNSAFE_PATH_CHAR_RE.test(raw)) {
    throw new Error('Invalid --scope path: contains disallowed control or markup characters');
  }
  if (raw.startsWith('/') || /^[A-Za-z]:/.test(raw) || raw.includes('\\')) {
    throw new Error('Invalid --scope path: must be a repo-relative POSIX path');
  }
  const parts = raw.replace(/\/+$/, '').split('/');
  if (parts.some((p) => !p || p === '.' || p === '..')) {
    throw new Error('Invalid --scope path: path traversal segments are forbidden');
  }
  const cleanRel = parts.join('/');
  const resolved = path.resolve(rootReal, cleanRel);
  if (resolved !== rootReal && !resolved.startsWith(rootReal + path.sep)) {
    throw new Error('Invalid --scope path: escapes repository root');
  }
  let realTarget;
  try {
    const lst = fs.lstatSync(resolved);
    if (lst.isSymbolicLink()) {
      throw new Error('Invalid --scope path: symlink scope target is forbidden');
    }
    realTarget = fs.realpathSync(resolved);
  } catch (err) {
    if (err && /Invalid --scope/.test(err.message)) throw err;
    throw new Error(`Invalid --scope path "${cleanRel}": does not exist inside repository`);
  }
  if (realTarget !== rootReal && !realTarget.startsWith(rootReal + path.sep)) {
    throw new Error('Invalid --scope path: symlink resolves outside repository root');
  }
  return cleanRel;
}

// Validates a repo-relative path from git/walk, canonicalising symlinks and rejecting escapes or hostile paths.
function validateRepoRelPath(rootReal, rawRel) {
  if (typeof rawRel !== 'string' || !rawRel) {
    return { ok: false, kind: 'rejected', reason: 'empty-path', display: '(empty)' };
  }
  if (CONTROL_OR_BIDI_RE.test(rawRel)) {
    return { ok: false, kind: 'rejected', reason: 'control-char', display: sanitizeRejectedLabel(rawRel) };
  }
  if (rawRel.startsWith('/') || /^[A-Za-z]:/.test(rawRel)) {
    return { ok: false, kind: 'rejected', reason: 'absolute-path', display: sanitizeRejectedLabel(rawRel) };
  }
  if (rawRel.includes('\\')) {
    return { ok: false, kind: 'rejected', reason: 'backslash-path', display: sanitizeRejectedLabel(rawRel) };
  }
  const segments = rawRel.split('/');
  if (segments.some((s) => !s || s === '.' || s === '..')) {
    return { ok: false, kind: 'rejected', reason: 'path-traversal', display: sanitizeRejectedLabel(rawRel) };
  }
  if (UNSAFE_PATH_CHAR_RE.test(rawRel)) {
    return { ok: false, kind: 'rejected', reason: 'unsafe-char', display: sanitizeRejectedLabel(rawRel) };
  }

  const full = path.resolve(rootReal, rawRel);
  if (!full.startsWith(rootReal + path.sep)) {
    return { ok: false, kind: 'rejected', reason: 'path-traversal', display: sanitizeRejectedLabel(rawRel) };
  }

  // Reject any symlink ancestor or leaf escaping rootReal
  let st;
  try {
    st = fs.lstatSync(full);
  } catch {
    return { ok: false, kind: 'missing', reason: 'missing-on-disk', rel: rawRel, display: rawRel };
  }
  if (st.isSymbolicLink()) {
    let targetReal = '';
    try {
      targetReal = fs.realpathSync(full);
    } catch {
      return { ok: false, kind: 'rejected', reason: 'symlink-escape', display: sanitizeRejectedLabel(rawRel) };
    }
    if (targetReal !== rootReal && !targetReal.startsWith(rootReal + path.sep)) {
      return { ok: false, kind: 'rejected', reason: 'symlink-escape', display: sanitizeRejectedLabel(rawRel) };
    }
    return { ok: false, kind: 'symlink', reason: 'internal-symlink', rel: rawRel, display: rawRel };
  }

  // Canonicalise parent chain to guard against symlinked intermediate directories escaping root
  try {
    const fileReal = fs.realpathSync(full);
    if (fileReal !== rootReal && !fileReal.startsWith(rootReal + path.sep)) {
      return { ok: false, kind: 'rejected', reason: 'symlink-escape', display: sanitizeRejectedLabel(rawRel) };
    }
  } catch {
    return { ok: false, kind: 'rejected', reason: 'symlink-escape', display: sanitizeRejectedLabel(rawRel) };
  }

  if (!st.isFile()) {
    return { ok: false, kind: 'non-file', reason: 'non-file', rel: rawRel, display: rawRel };
  }

  return { ok: true, rel: rawRel, full, size: st.size };
}

function hasNullBytePrefix(fullPath, size) {
  if (size === 0) return false;
  let fd;
  try {
    fd = fs.openSync(fullPath, 'r');
    const len = Math.min(size, BINARY_PEEK_BYTES);
    const buf = Buffer.alloc(len);
    const n = fs.readSync(fd, buf, 0, len, 0);
    for (let i = 0; i < n; i++) {
      if (buf[i] === 0x00) return true;
    }
    return false;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
  }
}

function vendoredRootOf(rel) {
  const m = VENDORED_RE.exec(rel);
  if (!m) return rel;
  if (!m[2]) return rel;
  const idx = m.index + (m[1] ? m[1].length : 0);
  return `${rel.slice(0, idx)}${m[2]}/`;
}

function classifyFile(rel, full, size) {
  if (VENDORED_RE.test(rel)) {
    return { category: 'vendored', vendoredRoot: vendoredRootOf(rel) };
  }
  const base = path.posix.basename(rel);
  const ext = path.posix.extname(base).toLowerCase();
  if (BINARY_EXTS.has(ext)) {
    return { category: 'binary', ext: ext || '(binary)' };
  }
  if (TEXT_EXTS.has(ext) || TEXT_BASENAMES.has(base)) {
    return { category: 'in-scope' };
  }
  if (hasNullBytePrefix(full, size)) {
    return { category: 'binary', ext: ext || '(binary)' };
  }
  return { category: 'in-scope' };
}

function enumerateTrackedPaths(rootReal, scope, opts = {}) {
  const { cap, uncapped } = resolveFileCap(opts);
  const gitArgs = ['ls-files', '-z'];
  if (scope) gitArgs.push('--', scope);
  try {
    const out = execFileSync('git', gitArgs, {
      cwd: rootReal,
      encoding: 'utf8',
      timeout: uncapped ? 15000 : 5000,
      maxBuffer: 128 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return { source: 'git', paths: out.split('\0').filter(Boolean), walkBounded: false };
  } catch { /* fallback for non-git workspace */ }

  const out = [];
  const startDir = scope ? path.join(rootReal, scope) : rootReal;
  const walkLimit = Number.isFinite(cap) ? Math.max(cap * 4, 80000) : Infinity;
  let walkBounded = false;

  (function walk(dir, depth) {
    if (depth > 20 || out.length >= walkLimit) {
      if (out.length >= walkLimit) walkBounded = true;
      return;
    }
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => cmpAscii(a.name, b.name));
    for (const e of entries) {
      if (out.length >= walkLimit) { walkBounded = true; return; }
      if (e.name === '.git') continue;
      const full = path.join(dir, e.name);
      const rel = path.relative(rootReal, full).split(path.sep).join('/');
      if (e.isSymbolicLink && e.isSymbolicLink()) {
        out.push(rel); // let validateRepoRelPath classify/reject symlinks explicitly
        continue;
      }
      if (e.isDirectory()) walk(full, depth + 1);
      else out.push(rel);
    }
  })(startDir, 0);

  return { source: 'walk', paths: out, walkBounded };
}

function collectRiskSignals(rootReal, env = process.env) {
  const extFiles = new Set();
  const intFiles = new Set();
  const extSinks = new Map();
  const intSinks = new Map();
  const bridgeFiles = new Set();

  const cfg = readProjectConfig(rootReal, env);
  if (cfg && cfg.boundaries) {
    const ext = cfg.boundaries.external || {};
    const int = cfg.boundaries.internal || {};
    const record = (list, set, sinkMap) => {
      if (!Array.isArray(list)) return;
      for (const entry of list) {
        const [f, sinks] = String(entry || '').split('->');
        if (!f) continue;
        set.add(f);
        if (!sinkMap.has(f)) sinkMap.set(f, new Set());
        if (sinks) {
          for (const s of sinks.split(',')) {
            const clean = s.trim();
            if (clean) sinkMap.get(f).add(clean);
          }
        }
      }
    };
    for (const k of ['ingress', 'egress', 'supply']) record(ext[k], extFiles, extSinks);
    for (const k of ['auth', 'data', 'exec', 'ai']) record(int[k], intFiles, intSinks);
    for (const f of extFiles) {
      if (intFiles.has(f)) bridgeFiles.add(f);
    }
  }

  // Scan .ai-audit/annotations.jsonl for all PRISM risk_score >= 0.60 hits (bounded read, no symlink follow).
  const prismHighFiles = new Map();
  const annFile = path.join(rootReal, '.ai-audit', 'annotations.jsonl');
  try {
    const lst = fs.lstatSync(annFile);
    if (lst.isFile() && !lst.isSymbolicLink()) {
      const realAnn = fs.realpathSync(annFile);
      if (realAnn.startsWith(rootReal + path.sep)) {
        const fd = fs.openSync(realAnn, 'r');
        try {
          const size = Math.min(lst.size, MAX_PRISM_READ_BYTES);
          const offset = Math.max(0, lst.size - size);
          const buf = Buffer.alloc(size);
          const read = fs.readSync(fd, buf, 0, size, offset);
          const lines = buf.toString('utf8', 0, read).split('\n');
          if (offset > 0) lines.shift();
          for (const line of lines) {
            const t = line.trim();
            if (!t.startsWith('{')) continue;
            let row;
            try { row = JSON.parse(t); } catch { continue; }
            if (!row || typeof row !== 'object') continue;
            const risk = typeof row.risk_score === 'number'
              ? row.risk_score
              : (row.prism && typeof row.prism.risk_score === 'number' ? row.prism.risk_score : null);
            if (risk === null || !Number.isFinite(risk) || risk < PRISM_HIGH_THRESHOLD) continue;
            const rawFile = row.file_path || row.file || row.path || '';
            const norm = String(rawFile).replace(/\\/g, '/').replace(/^\.\//, '');
            if (!norm) continue;
            const prev = prismHighFiles.get(norm) || 0;
            if (risk > prev) prismHighFiles.set(norm, Number(risk.toFixed(2)));
          }
        } finally {
          fs.closeSync(fd);
        }
      }
    }
  } catch { /* no .ai-audit/annotations.jsonl */ }

  return { extFiles, intFiles, extSinks, intSinks, bridgeFiles, prismHighFiles };
}

function scoreFile(rel, signals) {
  const isBridge = signals.bridgeFiles.has(rel);
  const prismRisk = signals.prismHighFiles.get(rel) || 0;
  const isPrismHigh = prismRisk >= PRISM_HIGH_THRESHOLD;
  const isExt = signals.extFiles.has(rel);
  const isInt = signals.intFiles.has(rel);

  let riskScore = 0;
  const reasons = [];
  if (isBridge) {
    riskScore += 100;
    const extList = [...(signals.extSinks.get(rel) || [])].sort(cmpAscii).join(',');
    const intList = [...(signals.intSinks.get(rel) || [])].sort(cmpAscii).join(',');
    reasons.push(`bridge:[ext:${extList || 'ext'}]->[int:${intList || 'int'}]`);
  } else {
    if (isExt) { riskScore += 30; reasons.push('boundary:ext'); }
    if (isInt) { riskScore += 20; reasons.push('boundary:int'); }
  }
  if (isPrismHigh) {
    riskScore += 80 + Math.round(prismRisk * 20);
    reasons.push(`prism:${prismRisk.toFixed(2)}`);
  }
  if (HIGH_RISK_PATH_RE.test(rel)) riskScore += 10;
  else if (MANIFEST_PATH_RE.test(rel)) riskScore += 5;
  else if (DOC_ROOT_RE.test(rel)) riskScore += 2;

  return {
    riskScore,
    isBridge,
    prismRisk: isPrismHigh ? prismRisk : 0,
    hasHighRisk: isBridge || isPrismHigh,
    reasons,
  };
}

function moduleGroupKey(dir) {
  if (!dir || dir === '.') return '.';
  const parts = dir.split('/');
  if (parts.length >= 2 && GROUP_PREFIXES.has(parts[0])) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
}

function partitionIntoChunks(inScopeFiles, opts = {}) {
  const maxChunkFiles = Math.max(1, Math.floor(Number(opts.maxChunkFiles) || DEFAULT_MAX_CHUNK_FILES));
  const maxChunkBytes = Math.max(1024, Math.floor(Number(opts.maxChunkBytes) || DEFAULT_MAX_CHUNK_BYTES));

  // Group files by directory so related files stay together deterministically.
  const byDir = new Map();
  for (const f of inScopeFiles) {
    if (!byDir.has(f.dir)) byDir.set(f.dir, []);
    byDir.get(f.dir).push(f);
  }
  const sortedDirs = [...byDir.keys()].sort(cmpAscii);

  const units = [];
  for (const dir of sortedDirs) {
    const dirFiles = byDir.get(dir).sort((a, b) => cmpAscii(a.path, b.path));
    let cur = null;
    const flush = () => {
      if (cur && cur.files.length > 0) units.push(cur);
      cur = null;
    };

    for (const file of dirFiles) {
      if (file.size > maxChunkBytes) {
        flush();
        units.push({
          primaryDir: dir,
          dirs: new Set([dir]),
          files: [file],
          bytes: file.size,
          hasHighRisk: file.hasHighRisk,
          oversizedSingleFile: true,
        });
        continue;
      }
      if (!cur || cur.files.length + 1 > maxChunkFiles || cur.bytes + file.size > maxChunkBytes) {
        flush();
        cur = {
          primaryDir: dir,
          dirs: new Set([dir]),
          files: [],
          bytes: 0,
          hasHighRisk: false,
          oversizedSingleFile: false,
        };
      }
      cur.files.push(file);
      cur.bytes += file.size;
      if (file.hasHighRisk) cur.hasHighRisk = true;
    }
    flush();
  }

  // Coalesce small adjacent units within the same module prefix and risk tier without breaking bounds.
  const merged = [];
  for (const unit of units) {
    const prev = merged.length > 0 ? merged[merged.length - 1] : null;
    const canMerge = Boolean(
      prev &&
      !prev.oversizedSingleFile &&
      !unit.oversizedSingleFile &&
      prev.hasHighRisk === unit.hasHighRisk &&
      moduleGroupKey(prev.primaryDir) === moduleGroupKey(unit.primaryDir) &&
      prev.files.length + unit.files.length <= maxChunkFiles &&
      prev.bytes + unit.bytes <= maxChunkBytes
    );
    if (canMerge) {
      prev.files.push(...unit.files);
      prev.bytes += unit.bytes;
      for (const d of unit.dirs) prev.dirs.add(d);
    } else {
      merged.push(unit);
    }
  }

  // Compute risk metrics and sort chunks highest-risk first, then deterministically by directory & first path.
  const scoredChunks = merged.map((u) => {
    const bridgeFiles = [];
    const prismHighFiles = [];
    let maxRiskScore = 0;
    let totalRiskScore = 0;
    for (const f of u.files) {
      if (f.riskScore > maxRiskScore) maxRiskScore = f.riskScore;
      totalRiskScore += f.riskScore;
      if (f.isBridge) bridgeFiles.push(f.path);
      if (f.prismRisk >= PRISM_HIGH_THRESHOLD) prismHighFiles.push({ path: f.path, riskScore: f.prismRisk });
    }
    return {
      primaryDir: u.primaryDir,
      dirs: [...u.dirs].sort(cmpAscii),
      files: u.files,
      fileCount: u.files.length,
      bytes: u.bytes,
      oversizedSingleFile: u.oversizedSingleFile,
      hasHighRisk: bridgeFiles.length > 0 || prismHighFiles.length > 0,
      bridgeCount: bridgeFiles.length,
      prismHighCount: prismHighFiles.length,
      bridgeFiles,
      prismHighFiles,
      maxRiskScore,
      totalRiskScore,
    };
  });

  scoredChunks.sort((a, b) =>
    ((b.hasHighRisk ? 1 : 0) - (a.hasHighRisk ? 1 : 0)) ||
    (b.maxRiskScore - a.maxRiskScore) ||
    (b.bridgeCount - a.bridgeCount) ||
    (b.prismHighCount - a.prismHighCount) ||
    (b.totalRiskScore - a.totalRiskScore) ||
    cmpAscii(a.primaryDir, b.primaryDir) ||
    cmpAscii(a.files[0].path, b.files[0].path)
  );

  const padWidth = Math.max(2, String(scoredChunks.length).length);
  const chunks = scoredChunks.map((c, idx) => ({
    id: `CHUNK-${String(idx + 1).padStart(padWidth, '0')}`,
    index: idx + 1,
    primaryDir: c.primaryDir,
    dirs: c.dirs,
    fileCount: c.fileCount,
    bytes: c.bytes,
    oversizedSingleFile: c.oversizedSingleFile,
    hasHighRisk: c.hasHighRisk,
    bridgeCount: c.bridgeCount,
    prismHighCount: c.prismHighCount,
    bridgeFiles: c.bridgeFiles,
    prismHighFiles: c.prismHighFiles,
    maxRiskScore: c.maxRiskScore,
    totalRiskScore: c.totalRiskScore,
    files: c.files.map((f) => ({
      path: f.path,
      size: f.size,
      riskScore: f.riskScore,
      isBridge: f.isBridge,
      prismRisk: f.prismRisk,
      reasons: f.reasons,
    })),
  }));

  // Internal invariant proof: strictly disjoint and complete partition of inScopeFiles.
  const seen = new Set();
  for (const ch of chunks) {
    if (ch.files.length > maxChunkFiles) {
      throw new Error(`Chunk ${ch.id} exceeded maxChunkFiles (${ch.files.length} > ${maxChunkFiles})`);
    }
    if (ch.bytes > maxChunkBytes && ch.files.length > 1) {
      throw new Error(`Chunk ${ch.id} exceeded maxChunkBytes (${ch.bytes} > ${maxChunkBytes})`);
    }
    for (const f of ch.files) {
      if (seen.has(f.path)) throw new Error(`Duplicate file across chunks: ${f.path}`);
      seen.add(f.path);
    }
  }
  if (seen.size !== inScopeFiles.length) {
    throw new Error(`Chunk partition mismatch: ${seen.size} != ${inScopeFiles.length}`);
  }

  return chunks;
}

function selectTier(inScopeCount, inScopeBytes) {
  if (inScopeCount <= SMALL_MAX_FILES && inScopeBytes <= SMALL_MAX_BYTES) return 'small';
  if (inScopeCount <= MEDIUM_MAX_FILES && inScopeBytes <= MEDIUM_MAX_BYTES) return 'medium';
  return 'massive';
}

function buildAuditPlan(root = process.cwd(), opts = {}) {
  const env = opts.env || process.env;
  const rootReal = canonicalizeExistingDir(root, 'Repository root');
  const scope = validateScopeSubpath(rootReal, opts.scope || '');
  const { cap, uncapped } = resolveFileCap(opts, env);
  const maxChunkFiles = Math.max(1, Math.floor(Number(opts.maxChunkFiles) || DEFAULT_MAX_CHUNK_FILES));
  const maxChunkBytes = Math.max(1024, Math.floor(Number(opts.maxChunkBytes) || DEFAULT_MAX_CHUNK_BYTES));

  const enumRes = enumerateTrackedPaths(rootReal, scope, { ...opts, env });
  const rawPaths = enumRes.paths.slice().sort(cmpAscii);
  const totalEnumerated = rawPaths.length;
  const truncated = !uncapped && (totalEnumerated > cap || enumRes.walkBounded);
  const pathsToInspect = truncated ? rawPaths.slice(0, cap) : rawPaths;
  const capNotice = truncated ? formatCapNotice(totalEnumerated, cap, enumRes.walkBounded) : '';

  const signals = collectRiskSignals(rootReal, env);

  const inScopeFiles = [];
  const binaryAssets = [];
  const binaryByExt = {};
  const vendoredFiles = [];
  const vendoredRoots = new Set();
  const skippedItems = [];
  const rejectedPaths = [];

  let totalTrackedBytes = 0;
  let inScopeBytes = 0;
  let binaryBytes = 0;
  let vendoredBytes = 0;

  for (const rawRel of pathsToInspect) {
    const check = validateRepoRelPath(rootReal, rawRel);
    if (!check.ok) {
      if (check.kind === 'rejected') {
        rejectedPaths.push({ display: check.display, reason: check.reason });
      } else {
        skippedItems.push({ path: check.display, reason: check.reason });
      }
      continue;
    }

    totalTrackedBytes += check.size;
    const cls = classifyFile(check.rel, check.full, check.size);
    if (cls.category === 'vendored') {
      vendoredFiles.push({ path: check.rel, size: check.size });
      vendoredBytes += check.size;
      vendoredRoots.add(cls.vendoredRoot);
      continue;
    }
    if (cls.category === 'binary') {
      binaryAssets.push({ path: check.rel, size: check.size, ext: cls.ext });
      binaryBytes += check.size;
      binaryByExt[cls.ext] = (binaryByExt[cls.ext] || 0) + 1;
      continue;
    }

    const dir = path.posix.dirname(check.rel);
    const risk = scoreFile(check.rel, signals);
    inScopeFiles.push({
      path: check.rel,
      dir,
      size: check.size,
      ...risk,
    });
    inScopeBytes += check.size;
  }

  const chunks = partitionIntoChunks(inScopeFiles, { maxChunkFiles, maxChunkBytes });
  const tier = selectTier(inScopeFiles.length, inScopeBytes);
  const bridgeCount = inScopeFiles.filter((f) => f.isBridge).length;
  const prismHighCount = inScopeFiles.filter((f) => f.prismRisk >= PRISM_HIGH_THRESHOLD).length;

  return {
    root: rootReal,
    scope: scope || '.',
    source: enumRes.source,
    uncapped,
    cap: Number.isFinite(cap) ? cap : null,
    truncated,
    capNotice,
    bounds: {
      maxChunkFiles,
      maxChunkBytes,
    },
    tier,
    totals: {
      trackedFiles: totalEnumerated,
      inspectedFiles: pathsToInspect.length,
      trackedBytes: totalTrackedBytes,
      inScopeFiles: inScopeFiles.length,
      inScopeBytes,
      binaryFiles: binaryAssets.length,
      binaryBytes,
      vendoredFiles: vendoredFiles.length,
      vendoredBytes,
      skippedFiles: skippedItems.length,
      rejectedFiles: rejectedPaths.length,
      chunkCount: chunks.length,
      bridgeFiles: bridgeCount,
      prismHighFiles: prismHighCount,
    },
    notRead: {
      summary: `${binaryAssets.length} binary asset(s) (${formatBytes(binaryBytes)})`,
      byExtension: binaryByExt,
      files: binaryAssets.map((b) => b.path),
    },
    notChecked: {
      summary: `${vendoredFiles.length} vendored file(s) (${formatBytes(vendoredBytes)})` +
        (skippedItems.length ? `, ${skippedItems.length} symlink/non-file(s)` : '') +
        (rejectedPaths.length ? `, ${rejectedPaths.length} rejected hostile path(s)` : ''),
      vendoredRoots: [...vendoredRoots].sort(cmpAscii),
      vendoredFiles: vendoredFiles.map((v) => v.path),
      skipped: skippedItems,
      rejected: rejectedPaths,
    },
    chunks,
  };
}

function normalizeCandidatePath(raw) {
  let s = String(raw || '').trim();
  if (!s) return '';
  s = s.replace(/^[`"'([<]+/, '').replace(/[`"')\]>,;]+$/, '');
  s = s.replace(/^\.\//, '');
  s = s.replace(/:(\d+)(?:[:-](\d+))?$/, '');
  s = s.replace(/[.,;]+$/, '');
  return s;
}

function extractCoveredPathsFromText(text, expectedSet, coveredSet) {
  const tryCand = (raw) => {
    const norm = normalizeCandidatePath(raw);
    if (norm && expectedSet.has(norm)) coveredSet.add(norm);
  };

  // 1. Backticked spans (handles paths containing spaces)
  for (const m of text.matchAll(/`([^`\r\n]{1,512})`/g)) {
    tryCand(m[1]);
  }
  // 2. Quoted strings (handles JSON arrays and paths containing spaces)
  for (const m of text.matchAll(/"([^"\r\n]{1,512})"/g)) {
    tryCand(m[1]);
  }
  // 3. Markdown bullet lines and table cells (handles unbackticked paths with spaces)
  for (const line of text.split('\n')) {
    const bullet = /^\s*(?:[-*+]\s+|\d+\.\s+)(.{1,512})$/.exec(line);
    if (bullet) {
      const rest = bullet[1].trim();
      tryCand(rest);
      const beforeColon = rest.split(/\s+[-—:]\s+/)[0];
      if (beforeColon && beforeColon !== rest) tryCand(beforeColon);
    }
    if (line.includes('|')) {
      for (const cell of line.split('|')) {
        const trimmed = cell.trim();
        if (trimmed) tryCand(trimmed);
      }
    }
  }
  // 4. Plain whitespace-delimited tokens (linear time)
  for (const m of text.matchAll(/[^\s"'`<>|()[\],]+/g)) {
    tryCand(m[0]);
  }
}

function checkCoverage(plan, reportsDir) {
  const reportsReal = canonicalizeExistingDir(reportsDir, 'Reports directory');
  const expectedSet = new Set();
  for (const ch of plan.chunks) {
    for (const f of ch.files) expectedSet.add(f.path);
  }

  const coveredSet = new Set();
  const reportFiles = [];
  const rejectedReportSymlinks = [];

  (function walkReports(dir, depth) {
    if (depth > 4 || reportFiles.length >= MAX_REPORT_FILES) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => cmpAscii(a.name, b.name));
    for (const e of entries) {
      if (reportFiles.length >= MAX_REPORT_FILES) return;
      if (e.name.startsWith('.')) continue;
      const full = path.join(dir, e.name);
      let lst;
      try { lst = fs.lstatSync(full); } catch { continue; }
      if (lst.isSymbolicLink()) {
        rejectedReportSymlinks.push(path.relative(reportsReal, full).split(path.sep).join('/'));
        continue;
      }
      if (lst.isDirectory()) {
        walkReports(full, depth + 1);
        continue;
      }
      if (!lst.isFile()) continue;
      const ext = path.extname(e.name).toLowerCase();
      if (!['.md', '.txt', '.json', '.jsonl'].includes(ext)) continue;
      // Do not treat the emitted plan manifest or playbook task docs as completed audit reports
      if (e.name === 'audit-plan.json' || /^AUDIT-\d+(?:-SYNTHESIS)?\.md$/i.test(e.name)) continue;
      if (lst.size > MAX_REPORT_BYTES) continue;
      reportFiles.push(full);
    }
  })(reportsReal, 0);

  if (rejectedReportSymlinks.length > 0) {
    throw new Error(`Refusing symlink(s) inside reports directory: ${rejectedReportSymlinks.slice(0, 5).join(', ')}`);
  }

  let scannedReports = 0;
  for (const rf of reportFiles) {
    let raw;
    try { raw = fs.readFileSync(rf, 'utf8'); } catch { continue; }
    // Skip unexecuted Maestro audit playbook documents so task checklists cannot spoof coverage
    if (/^- \[ \] Audit CHUNK-\d+/m.test(raw)) continue;
    scannedReports += 1;
    if (rf.endsWith('.json')) {
      try {
        const parsed = JSON.parse(raw);
        for (const key of ['auditedFiles', 'coveredFiles', 'filesAudited', 'files']) {
          if (Array.isArray(parsed && parsed[key])) {
            for (const item of parsed[key]) {
              const p = typeof item === 'string' ? item : (item && typeof item.path === 'string' ? item.path : '');
              const norm = normalizeCandidatePath(p);
              if (norm && expectedSet.has(norm)) coveredSet.add(norm);
            }
          }
        }
      } catch { /* fallback to text extraction */ }
    }
    extractCoveredPathsFromText(raw, expectedSet, coveredSet);
  }

  const missingFiles = [];
  const missingByChunk = [];
  for (const ch of plan.chunks) {
    const chunkMissing = [];
    for (const f of ch.files) {
      if (!coveredSet.has(f.path)) {
        missingFiles.push(f.path);
        chunkMissing.push(f.path);
      }
    }
    if (chunkMissing.length > 0) {
      missingByChunk.push({ chunkId: ch.id, missingCount: chunkMissing.length, missingFiles: chunkMissing });
    }
  }
  missingFiles.sort(cmpAscii);

  return {
    reportsDir: reportsReal,
    reportFilesScanned: scannedReports,
    expectedCount: expectedSet.size,
    coveredCount: coveredSet.size,
    missingCount: missingFiles.length,
    missingFiles,
    missingByChunk,
    truncated: plan.truncated,
    capNotice: plan.capNotice,
    pass: !plan.truncated && missingFiles.length === 0,
  };
}

function assertSafeOutputDir(targetDir, label) {
  const abs = path.resolve(String(targetDir || ''));
  const parts = abs.split(path.sep);
  if (parts.includes('.git') || parts.includes('.ai-audit')) {
    throw new Error(`Refusing ${label} inside protected directory (.git or .ai-audit)`);
  }
  // Find nearest existing path; refuse symlink on target itself or any non-root ancestor symlink.
  let cur = abs;
  while (cur && cur !== path.dirname(cur)) {
    try {
      const st = fs.lstatSync(cur);
      if (st.isSymbolicLink()) {
        const isTopLevelOsAlias = cur !== abs && path.dirname(cur) === path.parse(cur).root;
        if (!isTopLevelOsAlias) {
          throw new Error(`Refusing symlink in ${label} path`);
        }
      }
      break;
    } catch (err) {
      if (err && /Refusing symlink/.test(err.message)) throw err;
      cur = path.dirname(cur);
    }
  }
  fs.mkdirSync(abs, { recursive: true });
  const lst = fs.lstatSync(abs);
  if (lst.isSymbolicLink() || !lst.isDirectory()) {
    throw new Error(`${label} must be a real directory`);
  }
  return fs.realpathSync(abs);
}

function safeWriteFileNoSymlink(filePath, content) {
  try {
    const st = fs.lstatSync(filePath);
    if (st.isSymbolicLink()) {
      throw new Error(`Refusing to overwrite symlink: ${path.basename(filePath)}`);
    }
  } catch (err) {
    if (err && /Refusing to overwrite symlink/.test(err.message)) throw err;
  }
  fs.writeFileSync(filePath, content, 'utf8');
}

function displayRelOrBase(rootReal, targetReal) {
  if (targetReal === rootReal) return '.';
  if (targetReal.startsWith(rootReal + path.sep)) {
    return path.relative(rootReal, targetReal).split(path.sep).join('/');
  }
  return path.basename(targetReal);
}

function emitPlaybook(plan, outDir, opts = {}) {
  const defaultOut = path.join(plan.root, '.maestro', 'playbooks', 'neckbeard-audit');
  const outReal = assertSafeOutputDir(outDir || defaultOut, 'playbook output directory');
  const reportsReal = assertSafeOutputDir(opts.reportsDir || path.join(outReal, 'reports'), 'reports directory');

  const outLabel = displayRelOrBase(plan.root, outReal);
  const reportsLabel = displayRelOrBase(plan.root, reportsReal);
  const planFilePath = path.join(outReal, 'audit-plan.json');

  // Persist sanitized plan (omit host absolute root path)
  const sanitizedPlan = { ...plan, root: '.' };
  safeWriteFileNoSymlink(planFilePath, JSON.stringify(sanitizedPlan, null, 2) + '\n');

  const chunkGroups = [];
  for (let i = 0; i < plan.chunks.length; i += CHUNKS_PER_PLAYBOOK_DOC) {
    chunkGroups.push(plan.chunks.slice(i, i + CHUNKS_PER_PLAYBOOK_DOC));
  }
  const totalPhaseDocs = chunkGroups.length + 1; // N chunk docs + 1 synthesis doc
  const pad = Math.max(2, String(totalPhaseDocs).length);
  const emittedDocs = [];

  for (let g = 0; g < chunkGroups.length; g++) {
    const phaseNum = String(g + 1).padStart(pad, '0');
    const docName = `AUDIT-${phaseNum}.md`;
    const group = chunkGroups[g];
    const lines = [
      `# NeckBeard Complete Audit — Phase ${phaseNum} (${group[0].id}..${group[group.length - 1].id})`,
      '',
      `Scope: \`${plan.scope}\` · In-scope total: ${plan.totals.inScopeFiles} files (${formatBytes(plan.totals.inScopeBytes)}) · Tier: \`${plan.tier}\``,
      `Reports directory: \`${reportsLabel}\` · Manifest: \`${outLabel}/audit-plan.json\``,
      '',
      'Chunk guardrail: Audit ONLY the files listed under each task against Safe, Fast at the named load, and Done with concrete failure proof. Skip repo-wide README, lockfile, and Refactor-vs-Rewrite boilerplate (handled once in the final synthesis phase).',
      '',
    ];

    for (const ch of group) {
      const riskBits = [];
      if (ch.bridgeCount > 0) riskBits.push(`${ch.bridgeCount} [ext]->[int] bridge(s)`);
      if (ch.prismHighCount > 0) riskBits.push(`${ch.prismHighCount} PRISM >= 0.60 hit(s)`);
      const riskLabel = riskBits.length ? ` [HIGH-RISK: ${riskBits.join(', ')}]` : '';
      const reportTarget = `${reportsLabel}/${ch.id}.md`;
      lines.push(
        `- [ ] Audit ${ch.id} (${ch.fileCount} files, ${formatBytes(ch.bytes)}, primary dir \`${ch.primaryDir}\`)${riskLabel} and write the chunk report to \`${reportTarget}\`. Include concrete Must-fix / Should-fix / Nice-to-have findings (no artificial cap) and a \`## Files audited\` section listing every audited file path verbatim in backticks:`
      );
      for (const f of ch.files) {
        const tag = f.reasons.length ? ` (${f.reasons.join(', ')})` : '';
        lines.push(`  - \`${f.path}\`${tag}`);
      }
      lines.push('');
    }

    const docPath = path.join(outReal, docName);
    safeWriteFileNoSymlink(docPath, lines.join('\n').trimEnd() + '\n');
    emittedDocs.push(docPath);
  }

  const synthNum = String(totalPhaseDocs).padStart(pad, '0');
  const synthName = `AUDIT-${synthNum}-SYNTHESIS.md`;
  const uncappedArg = plan.uncapped ? ' --uncapped' : '';
  const scopeArg = plan.scope && plan.scope !== '.' ? ` --scope ${plan.scope}` : '';
  const synthLines = [
    `# NeckBeard Complete Audit — Phase ${synthNum}: Coverage Proof & Final Synthesis`,
    '',
    `Manifest: \`${outLabel}/audit-plan.json\` · Chunk reports: \`${reportsLabel}\``,
    `Excluded — Not read: ${plan.notRead.summary} · Not checked: ${plan.notChecked.summary}`,
    ...(plan.truncated && plan.capNotice ? ['', `WARNING: ${plan.capNotice}`] : []),
    '',
    `- [ ] Verify 100% file coverage across all ${plan.totals.inScopeFiles} in-scope files by running \`node <neckbeard-root>/hooks/audit-plan.js .${scopeArg}${uncappedArg} --check-coverage ${reportsLabel}\` and confirming exit code 0 (0 missing files). If any files are missing, audit them into \`${reportsLabel}/CHUNK-MISSING.md\` and re-run \`--check-coverage\` until exit code 0.`,
    '',
    `- [ ] Perform one repo-wide verification pass over top-level docs (\`README.md\`, \`AGENTS.md\`, \`CLAUDE.md\`, Copilot instructions), dependency manifests/lockfiles, CI workflows, \`.neckbeard.json\`, and \`.ai-audit/\` provenance integrity; run cross-file \`architecture.flows\` variant search for every confirmed Must-fix and Should-fix finding across all reports in \`${reportsLabel}\`; compute explicit \`E_patch\` vs. \`E_rewrite\` effort math; and write the consolidated final report to \`${outLabel}/REPORT.md\` (including exact \`Not read:\` binary and \`Not checked:\` vendored summaries).`,
    '',
  ];
  const synthPath = path.join(outReal, synthName);
  safeWriteFileNoSymlink(synthPath, synthLines.join('\n').trimEnd() + '\n');
  emittedDocs.push(synthPath);

  return {
    playbookType: 'task-based',
    outDir: outReal,
    reportsDir: reportsReal,
    planFile: planFilePath,
    documents: emittedDocs,
    documentCount: emittedDocs.length,
  };
}

function formatPlanText(plan) {
  const t = plan.totals;
  const lines = [
    `NeckBeard Audit Plan (${plan.scope}, source: ${plan.source}, tier: ${plan.tier})`,
    `Tracked: ${t.trackedFiles} files (${formatBytes(t.trackedBytes)}) | In-scope: ${t.inScopeFiles} files (${formatBytes(t.inScopeBytes)}) | Chunks: ${t.chunkCount} (bounds: <= ${plan.bounds.maxChunkFiles} files, <= ${formatBytes(plan.bounds.maxChunkBytes)})`,
    `Priority risk hits: ${t.bridgeFiles} [ext]->[int] bridge file(s), ${t.prismHighFiles} PRISM >= 0.60 file(s)`,
    `Not read: ${plan.notRead.summary}`,
    `Not checked: ${plan.notChecked.summary}`,
  ];
  if (plan.truncated && plan.capNotice) {
    lines.push(`WARNING: ${plan.capNotice}`);
  }
  lines.push('Chunks (risk-ordered):');
  for (const ch of plan.chunks) {
    const flags = [];
    if (ch.bridgeCount > 0) flags.push(`bridges=${ch.bridgeCount}`);
    if (ch.prismHighCount > 0) flags.push(`prism=${ch.prismHighCount}`);
    if (ch.oversizedSingleFile) flags.push('single-large-file');
    const tag = flags.length ? ` [${flags.join(', ')}]` : '';
    lines.push(`  - ${ch.id}: ${ch.fileCount} files, ${formatBytes(ch.bytes)}, dir=${ch.primaryDir}${tag}`);
  }
  return lines.join('\n');
}

function formatCoverageText(cov) {
  const status = cov.pass ? 'PASS (0 missing files)' : 'FAIL';
  const lines = [
    `NeckBeard Audit Coverage: ${status}`,
    `Covered: ${cov.coveredCount} / ${cov.expectedCount} in-scope files (${cov.missingCount} missing) across ${cov.reportFilesScanned} report file(s)`,
  ];
  if (cov.truncated && cov.capNotice) {
    lines.push(`WARNING: ${cov.capNotice}`);
  }
  if (cov.missingByChunk.length > 0) {
    lines.push('Missing by chunk:');
    for (const mc of cov.missingByChunk.slice(0, 20)) {
      lines.push(`  - ${mc.chunkId}: ${mc.missingCount} missing (${mc.missingFiles.slice(0, 5).join(', ')}${mc.missingFiles.length > 5 ? ', ...' : ''})`);
    }
  }
  return lines.join('\n');
}

function parsePositiveIntFlag(flag, rawVal, minVal) {
  if (rawVal === undefined || rawVal === '' || rawVal.startsWith('-')) {
    throw new Error(`Missing value for ${flag}`);
  }
  const n = Number(rawVal);
  if (!Number.isInteger(n) || n < minVal) {
    throw new Error(`Invalid value for ${flag}: must be an integer >= ${minVal}`);
  }
  return n;
}

function parseCliArgs(argv) {
  const opts = {
    root: process.cwd(),
    rootSet: false,
    json: false,
    uncapped: false,
    scope: '',
    maxChunkFiles: DEFAULT_MAX_CHUNK_FILES,
    maxChunkBytes: DEFAULT_MAX_CHUNK_BYTES,
    checkCoverageDir: '',
    emitPlaybook: false,
    emitPlaybookDir: '',
    reportsDir: '',
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { opts.help = true; continue; }
    if (a === '--json') { opts.json = true; continue; }
    if (a === '--uncapped') { opts.uncapped = true; continue; }
    if (a === '--scope') {
      const next = argv[++i];
      if (!next || next.startsWith('-')) throw new Error('Missing value for --scope');
      opts.scope = next;
      continue;
    }
    if (a === '--max-files') {
      opts.maxChunkFiles = parsePositiveIntFlag('--max-files', argv[++i], 1);
      continue;
    }
    if (a === '--max-bytes') {
      opts.maxChunkBytes = parsePositiveIntFlag('--max-bytes', argv[++i], 1024);
      continue;
    }
    if (a === '--check-coverage') {
      const next = argv[++i];
      if (!next || next.startsWith('-')) throw new Error('Missing value for --check-coverage <reports-dir>');
      opts.checkCoverageDir = next;
      continue;
    }
    if (a === '--reports-dir') {
      const next = argv[++i];
      if (!next || next.startsWith('-')) throw new Error('Missing value for --reports-dir <dir>');
      opts.reportsDir = next;
      continue;
    }
    if (a === '--emit-playbook') {
      opts.emitPlaybook = true;
      if (argv[i + 1] && !argv[i + 1].startsWith('-')) {
        opts.emitPlaybookDir = argv[++i];
      }
      continue;
    }
    if (a.startsWith('-')) {
      throw new Error(`Unknown option: ${a}`);
    }
    if (!opts.rootSet) {
      opts.root = a;
      opts.rootSet = true;
    } else {
      throw new Error(`Unexpected extra positional argument: ${a}`);
    }
  }
  return opts;
}

module.exports = {
  DEFAULT_MAX_CHUNK_FILES,
  DEFAULT_MAX_CHUNK_BYTES,
  SMALL_MAX_FILES,
  SMALL_MAX_BYTES,
  MEDIUM_MAX_FILES,
  MEDIUM_MAX_BYTES,
  PRISM_HIGH_THRESHOLD,
  MAX_FILES,
  VENDORED_RE,
  BINARY_EXTS,
  validateScopeSubpath,
  validateRepoRelPath,
  classifyFile,
  collectRiskSignals,
  partitionIntoChunks,
  selectTier,
  buildAuditPlan,
  checkCoverage,
  emitPlaybook,
  formatPlanText,
  formatCoverageText,
  parseCliArgs,
};

if (require.main === module) {
  try {
    const cli = parseCliArgs(process.argv.slice(2));
    if (cli.help) {
      process.stdout.write(
        'Usage: node hooks/audit-plan.js [repo-root] [--scope <rel>] [--max-files N] [--max-bytes N] [--uncapped] [--json] [--check-coverage <reports-dir>] [--emit-playbook [out-dir]] [--reports-dir <dir>]\n'
      );
      process.exit(0);
    }
    const plan = buildAuditPlan(cli.root, {
      scope: cli.scope,
      maxChunkFiles: cli.maxChunkFiles,
      maxChunkBytes: cli.maxChunkBytes,
      uncapped: cli.uncapped ? true : undefined,
      env: process.env,
    });
    if (plan.truncated && plan.capNotice) {
      process.stderr.write(`[neckbeard] WARNING: ${plan.capNotice}\n`);
    }
    if (cli.checkCoverageDir) {
      const cov = checkCoverage(plan, cli.checkCoverageDir);
      process.stdout.write((cli.json ? JSON.stringify(cov, null, 2) : formatCoverageText(cov)) + '\n');
      process.exit(cov.pass ? 0 : 1);
    }
    if (cli.emitPlaybook) {
      const emitted = emitPlaybook(plan, cli.emitPlaybookDir, { reportsDir: cli.reportsDir });
      const payload = { plan: { ...plan, root: '.' }, playbook: emitted };
      if (cli.json) {
        process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
      } else {
        process.stdout.write(
          formatPlanText(plan) +
          `\n\nCreated a task-based playbook (${emitted.documentCount} docs) in ${emitted.outDir} (reports: ${emitted.reportsDir}).\n`
        );
      }
      process.exit(0);
    }
    process.stdout.write((cli.json ? JSON.stringify(plan, null, 2) : formatPlanText(plan)) + '\n');
  } catch (err) {
    process.stderr.write(`audit-plan error: ${err && err.message ? err.message : 'failed'}\n`);
    process.exit(2);
  }
}
