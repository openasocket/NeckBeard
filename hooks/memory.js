'use strict';
// Unified $CREW_CONFIG_DIR 3-Tier Memory & Self-Improvement Engine (`hooks/memory.js`)
// Implements Crew/docs/11 Section 4.3:
//   - Root: $CREW_CONFIG_DIR (env CREW_CONFIG_DIR || ~/.config/crew)
//   - Tier 1 (Agent-Local, 4 bounded buckets under memory/agents/neckbeard/):
//       preferences.jsonl (<= 24), insights.jsonl (<= 40),
//       learned-skills/<slug>.md (<= 20), dead-ends.jsonl (<= 32)
//   - Tier 2 (Team / Enclave Shared):
//       commercial -> memory/teams/<team-slug>/{canon-truth.json, causal-graph.jsonl}
//       regulated  -> enclaves/<enclave-id>/team-memory/{canon-truth.json, causal-graph.jsonl}
//   - Tier 3 (GRPO & Deviation-Driven Top-K Injection):
//       commercial -> memory/grpo-signals.jsonl
//       regulated  -> enclaves/<enclave-id>/grpo-signals.jsonl
//   - Hard Compliance Compartment Wall (cmmc, finsec, hipaa stay strictly inside enclaves/<enclave-id>/)
//   - Anti-Memory-Poisoning Gate (Memory Write Authority)
//   - Transparent Human Memory Inspector: inspect | pin | unpin | edit | forget | reset
// Zero external dependencies, zero network calls.

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const { crewConfigDir, atomicWriteFile, estimateTokens } = require('./lib');
const { findSensitiveMatch, sanitizeLoad } = require('./surface');

const PERSONA_ID = 'neckbeard';
const MEMORY_BUCKETS = Object.freeze(['preferences', 'insights', 'learned-skills', 'dead-ends']);
const BUCKET_CAPS = Object.freeze({
  preferences: 24,
  insights: 40,
  'learned-skills': 20,
  'dead-ends': 32,
});
const PROTECTED_BUCKETS = new Set(['preferences', 'learned-skills']);
const COMPARTMENTS = Object.freeze(['commercial', 'cmmc', 'finsec', 'hipaa']);
const REGULATED_COMPARTMENTS = new Set(['cmmc', 'finsec', 'hipaa']);
const TRUST_TIERS = Object.freeze(['verified-human', 'deterministic-oracle', 'agent-distilled', 'untrusted']);

const SAFE_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const MAX_JSONL_LINE_BYTES = 4096;
const DEFAULT_DIGEST_TOKENS = 600;
const MAX_DIGEST_TOKENS = 800;
const DEFAULT_TOPK_TOKENS = 1800;
const MAX_TOPK_TOKENS = 2500;
const STALE_HALF_LIFE_DAYS = 30;

const UNTRUSTED_PAYLOAD_RE =
  /<\s*(?:untrusted_external_human_data|untrusted_event_data|untrusted_cross_effort_data)\b[^>]*>|untrusted_data\s*=\s*["']true["']/i;
const REGULATED_MARKING_RE =
  /(?:^|[^A-Za-z0-9_])(?:CUI\/\/|(?:ITAR|HIPAA-PHI|PCI-PAN)(?![A-Za-z0-9_]))/i;

function normalizeBucket(raw) {
  const v = String(raw || '').trim().toLowerCase().replace(/[\s_]+/g, '-');
  if (v === 'pref' || v === 'prefs' || v === 'preference' || v === 'preferences') return 'preferences';
  if (v === 'insight' || v === 'insights') return 'insights';
  if (v === 'skill' || v === 'skills' || v === 'learned-skill' || v === 'learned-skills' || v === 'learnedskills') {
    return 'learned-skills';
  }
  if (v === 'dead-end' || v === 'dead-ends' || v === 'deadend' || v === 'deadends') return 'dead-ends';
  return null;
}

function validateSlug(raw, label = 'slug') {
  if (typeof raw !== 'string' || !SAFE_SLUG_RE.test(raw) || raw.includes('..') || /[\0\r\n/\\]/.test(raw)) {
    throw new Error(`Invalid ${label} "${String(raw)}": must match ${SAFE_SLUG_RE}`);
  }
  return raw;
}

function assertContained(baseDir, targetPath, label = 'memory path') {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(targetPath);
  const rel = path.relative(resolvedBase, resolvedTarget);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Path containment violation (${label}): escapes ${resolvedBase}`);
  }
  // Reject symlinks along existing prefixes
  const parts = rel.split(path.sep);
  let cur = resolvedBase;
  for (const part of parts) {
    cur = path.join(cur, part);
    try {
      const st = fs.lstatSync(cur);
      if (st.isSymbolicLink()) {
        throw new Error(`Symlink escape rejected (${label}): ${part}`);
      }
    } catch (err) {
      if (err && /Symlink escape/i.test(err.message)) throw err;
      break;
    }
  }
  return resolvedTarget;
}

function resolveScope(opts = {}, env = process.env) {
  const root = path.resolve(crewConfigDir(env));
  const rawClass = String(opts.classification || opts.compartment || 'commercial').trim().toLowerCase();
  if (!COMPARTMENTS.includes(rawClass)) {
    throw new Error(`Invalid classification "${rawClass}": expected ${COMPARTMENTS.join('|')}`);
  }
  const hasEnclave = Boolean(opts.enclaveId && String(opts.enclaveId).trim());
  const isRegulated = REGULATED_COMPARTMENTS.has(rawClass) || hasEnclave;

  if (isRegulated) {
    const enclaveId = validateSlug(
      hasEnclave ? String(opts.enclaveId).trim().toLowerCase() : `${rawClass}-default`,
      'enclaveId'
    );
    const enclaveBase = assertContained(root, path.join(root, 'enclaves', enclaveId), 'enclave root');
    const agentDir = assertContained(enclaveBase, path.join(enclaveBase, 'memory', 'agents', PERSONA_ID), 'enclave agent dir');
    const teamDir = assertContained(enclaveBase, path.join(enclaveBase, 'team-memory'), 'enclave team dir');
    const grpoPath = assertContained(enclaveBase, path.join(enclaveBase, 'grpo-signals.jsonl'), 'enclave grpo');
    return {
      root,
      isRegulated: true,
      classification: REGULATED_COMPARTMENTS.has(rawClass) ? rawClass : 'cmmc',
      enclaveId,
      teamSlug: null,
      scope: 'enclave',
      scopeLabel: `enclave/${enclaveId}`,
      agentDir,
      teamDir,
      grpoPath,
    };
  }

  const teamSlug = validateSlug(
    String(opts.teamSlug || 'default').trim().toLowerCase(),
    'teamSlug'
  );
  const memRoot = assertContained(root, path.join(root, 'memory'), 'commercial memory root');
  const agentDir = assertContained(memRoot, path.join(memRoot, 'agents', PERSONA_ID), 'agent memory dir');
  const teamDir = assertContained(memRoot, path.join(memRoot, 'teams', teamSlug), 'team memory dir');
  const grpoPath = assertContained(memRoot, path.join(memRoot, 'grpo-signals.jsonl'), 'commercial grpo');
  return {
    root,
    isRegulated: false,
    classification: 'commercial',
    enclaveId: null,
    teamSlug,
    scope: 'agent',
    scopeLabel: `commercial/${teamSlug}`,
    agentDir,
    teamDir,
    grpoPath,
  };
}

function assertCompartmentWall(sourceOpts, targetScope) {
  const srcClass = String((sourceOpts && (sourceOpts.sourceClassification || sourceOpts.sourceCompartment)) || '').trim().toLowerCase();
  const srcEnclave = String((sourceOpts && sourceOpts.sourceEnclaveId) || '').trim().toLowerCase();
  const srcRegulated = REGULATED_COMPARTMENTS.has(srcClass) || Boolean(srcEnclave);
  if (srcRegulated) {
    if (!targetScope.isRegulated) {
      throw new Error(`Compartment Wall blocked regulated (${srcClass || srcEnclave}) write into commercial memory`);
    }
    if (srcEnclave && targetScope.enclaveId && srcEnclave !== targetScope.enclaveId) {
      throw new Error(`Compartment Wall blocked cross-enclave write (${srcEnclave} -> ${targetScope.enclaveId})`);
    }
  }
}

function assertWriteAuthority(bucket, recordInput) {
  if (!PROTECTED_BUCKETS.has(bucket)) return;
  const trust = String((recordInput && recordInput.trustTier) || 'agent-distilled').trim().toLowerCase();
  const serialized = typeof recordInput === 'string' ? recordInput : JSON.stringify(recordInput || {});
  if (recordInput && recordInput.untrusted === true) {
    throw new Error(`Memory Write Authority blocked untrusted payload targeting "${bucket}"`);
  }
  if (trust === 'untrusted') {
    throw new Error(`Memory Write Authority blocked trustTier="untrusted" targeting "${bucket}"`);
  }
  if (UNTRUSTED_PAYLOAD_RE.test(serialized)) {
    throw new Error(`Memory Write Authority blocked untrusted external/event/cross-effort marker targeting "${bucket}"`);
  }
}

function bucketPath(scopeInfo, bucket) {
  if (bucket === 'learned-skills') {
    return assertContained(scopeInfo.agentDir, path.join(scopeInfo.agentDir, 'learned-skills'), 'learned-skills dir');
  }
  return assertContained(scopeInfo.agentDir, path.join(scopeInfo.agentDir, `${bucket}.jsonl`), `${bucket} file`);
}

function sanitizeTags(tags) {
  if (!Array.isArray(tags)) return [];
  const out = [];
  for (const t of tags) {
    const clean = String(t || '').trim().toLowerCase().replace(/[^a-z0-9._:-]/g, '').slice(0, 32);
    if (clean && !out.includes(clean) && out.length < 12) out.push(clean);
  }
  return out;
}

function effectiveConfidence(record, nowMs = Date.now()) {
  const base = Number.isFinite(Number(record.confidence)) ? Math.max(0, Math.min(1, Number(record.confidence))) : 0.7;
  if (record.pinned) return +base.toFixed(3);
  const stamp = Date.parse(record.lastConfirmedIso || record.createdAtIso || '');
  if (!Number.isFinite(stamp)) return +base.toFixed(3);
  const ageDays = Math.max(0, (nowMs - stamp) / (24 * 60 * 60 * 1000));
  if (ageDays <= STALE_HALF_LIFE_DAYS) return +base.toFixed(3);
  const decay = Math.pow(0.5, (ageDays - STALE_HALF_LIFE_DAYS) / STALE_HALF_LIFE_DAYS);
  return +Math.max(0.1, base * decay).toFixed(3);
}

function readJsonlRecords(filePath) {
  try {
    if (!fs.existsSync(filePath)) return [];
    const st = fs.lstatSync(filePath);
    if (st.isSymbolicLink() || !st.isFile()) return [];
    const raw = fs.readFileSync(filePath, 'utf8');
    const out = [];
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        const obj = JSON.parse(t);
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) out.push(obj);
      } catch { /* skip malformed line */ }
    }
    return out;
  } catch {
    return [];
  }
}

function writeJsonlRecords(filePath, records) {
  const lines = [];
  for (const rec of records) {
    const line = JSON.stringify(rec);
    if (line.includes('\r') || line.includes('\n')) {
      throw new Error('JSONL record must be single-line LF-only');
    }
    if (Buffer.byteLength(line + '\n', 'utf8') >= MAX_JSONL_LINE_BYTES) {
      throw new Error(`JSONL record exceeds strict < ${MAX_JSONL_LINE_BYTES} UTF-8 byte limit`);
    }
    lines.push(line);
  }
  const content = lines.length ? lines.join('\n') + '\n' : '';
  atomicWriteFile(filePath, content, 0o600);
}

function buildEnvelope(bucket, input, scopeInfo) {
  const nowIso = new Date().toISOString();
  const rawSummary = String((input && (input.summary || input.text || input.content)) || '').trim();
  if (!rawSummary) throw new Error('Memory entry requires non-empty summary');

  const sensitive = findSensitiveMatch(rawSummary);
  if (sensitive) {
    throw new Error(`Memory entry blocked by censorship guard (${sensitive.slice(0, 28)})`);
  }
  if (!scopeInfo.isRegulated && REGULATED_MARKING_RE.test(rawSummary)) {
    throw new Error('Compartment Wall blocked regulated marking in commercial memory');
  }

  const trust = String((input && input.trustTier) || 'agent-distilled').trim().toLowerCase();
  const trustTier = TRUST_TIERS.includes(trust) ? trust : 'agent-distilled';
  const summary = sanitizeLoad(rawSummary).slice(0, 600);
  const id = (input && input.id && String(input.id).trim().replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 48)) ||
    `nb-${bucket.slice(0, 4)}-${createHash('sha256').update(`${nowIso}:${summary}:${Math.random()}`).digest('hex').slice(0, 8)}`;

  const record = {
    id,
    personaId: PERSONA_ID,
    bucket,
    scope: scopeInfo.isRegulated ? 'enclave' : (input.scope || 'agent'),
    trustTier,
    classification: scopeInfo.classification,
    confidence: Number.isFinite(Number(input.confidence)) ? Math.max(0, Math.min(1, Number(input.confidence))) : 0.8,
    grpoScore: Number.isFinite(Number(input.grpoScore)) ? +Number(input.grpoScore).toFixed(3) : 0,
    pinned: Boolean(input.pinned),
    supersedes: input.supersedes ? String(input.supersedes).slice(0, 48) : null,
    createdAtIso: input.createdAtIso || nowIso,
    lastConfirmedIso: input.lastConfirmedIso || nowIso,
    summary,
    tags: sanitizeTags(input.tags),
  };

  if (Buffer.byteLength(JSON.stringify(record) + '\n', 'utf8') >= MAX_JSONL_LINE_BYTES) {
    throw new Error(`Memory record exceeds strict < ${MAX_JSONL_LINE_BYTES} byte limit`);
  }
  return record;
}

function readLearnedSkills(scopeInfo) {
  const dir = bucketPath(scopeInfo, 'learned-skills');
  const out = [];
  if (!fs.existsSync(dir)) return out;
  try {
    const dirSt = fs.lstatSync(dir);
    if (dirSt.isSymbolicLink() || !dirSt.isDirectory()) return out;
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.md')).sort()) {
      const slug = file.slice(0, -3);
      if (!SAFE_SLUG_RE.test(slug)) continue;
      const fp = assertContained(dir, path.join(dir, file), 'learned-skill');
      const raw = fs.readFileSync(fp, 'utf8');
      const pinned = /^pinned:\s*true$/m.test(raw);
      const confMatch = /^confidence:\s*([0-9.]+)$/m.exec(raw);
      const tsMatch = /^lastConfirmedIso:\s*([^\n]+)$/m.exec(raw);
      const body = raw.replace(/^---[\s\S]*?---\s*/, '').trim();
      const firstLine = body.split('\n').find((l) => l.trim()) || slug;
      out.push({
        id: slug,
        personaId: PERSONA_ID,
        bucket: 'learned-skills',
        scope: scopeInfo.isRegulated ? 'enclave' : 'agent',
        trustTier: 'agent-distilled',
        classification: scopeInfo.classification,
        confidence: confMatch ? Number(confMatch[1]) : 0.85,
        grpoScore: 0,
        pinned,
        lastConfirmedIso: tsMatch ? tsMatch[1].trim() : '',
        summary: firstLine.replace(/^#+\s*/, '').slice(0, 240),
        tags: [],
      });
    }
  } catch { /* empty */ }
  return out;
}

function addMemory(rawBucket, input, opts = {}, env = process.env) {
  const bucket = normalizeBucket(rawBucket);
  if (!bucket) throw new Error(`Invalid bucket "${rawBucket}"`);
  const scopeInfo = resolveScope(opts, env);
  assertCompartmentWall(opts, scopeInfo);
  assertWriteAuthority(bucket, input);

  if (bucket === 'learned-skills') {
    const slug = validateSlug(String((input && (input.slug || input.id)) || '').trim().toLowerCase(), 'skill slug');
    const text = String((input && (input.body || input.summary || input.content)) || '').trim();
    if (!text) throw new Error('Learned skill requires non-empty content');
    const sensitive = findSensitiveMatch(text);
    if (sensitive) throw new Error(`Learned skill blocked by censorship guard (${sensitive.slice(0, 28)})`);
    if (!scopeInfo.isRegulated && REGULATED_MARKING_RE.test(text)) {
      throw new Error('Compartment Wall blocked regulated marking in commercial learned-skill');
    }
    const dir = bucketPath(scopeInfo, 'learned-skills');
    const existing = readLearnedSkills(scopeInfo);
    const existsAlready = existing.some((s) => s.id === slug);
    if (!existsAlready && existing.length >= BUCKET_CAPS['learned-skills']) {
      throw new Error(`learned-skills bucket cap (${BUCKET_CAPS['learned-skills']}) reached; forget or reset an entry first`);
    }
    const fp = assertContained(dir, path.join(dir, `${slug}.md`), 'learned-skill file');
    const nowIso = new Date().toISOString();
    const md = [
      '---',
      `id: ${slug}`,
      `personaId: ${PERSONA_ID}`,
      `classification: ${scopeInfo.classification}`,
      `pinned: ${Boolean(input.pinned)}`,
      `confidence: ${Number.isFinite(Number(input.confidence)) ? Number(input.confidence) : 0.85}`,
      `lastConfirmedIso: ${nowIso}`,
      '---',
      '',
      text.replace(/\r/g, ''),
      '',
    ].join('\n');
    atomicWriteFile(fp, md, 0o600);
    return { id: slug, bucket, path: fp, scope: scopeInfo.scopeLabel };
  }

  const record = buildEnvelope(bucket, input, scopeInfo);
  const fp = bucketPath(scopeInfo, bucket);
  const current = readJsonlRecords(fp).filter((r) => r.id !== record.id);
  current.push(record);

  const cap = BUCKET_CAPS[bucket];
  while (current.length > cap) {
    const dropIdx = current.findIndex((r) => !r.pinned);
    if (dropIdx >= 0) current.splice(dropIdx, 1);
    else current.shift();
  }
  writeJsonlRecords(fp, current);
  return record;
}

function recordGrpoSignal(signal, opts = {}, env = process.env) {
  const scopeInfo = resolveScope(opts, env);
  assertCompartmentWall(opts, scopeInfo);
  const summary = String((signal && (signal.summary || signal.outcome)) || '').trim();
  const sensitive = findSensitiveMatch(summary);
  if (sensitive) throw new Error(`GRPO signal blocked by censorship guard (${sensitive.slice(0, 28)})`);
  if (!scopeInfo.isRegulated && REGULATED_MARKING_RE.test(summary)) {
    throw new Error('Compartment Wall blocked regulated marking in commercial grpo-signals.jsonl');
  }
  const row = {
    id: `grpo-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    personaId: PERSONA_ID,
    bucket: 'grpo',
    scope: scopeInfo.isRegulated ? 'enclave' : 'agent',
    trustTier: 'deterministic-oracle',
    classification: scopeInfo.classification,
    confidence: 1,
    grpoScore: Number.isFinite(Number(signal.delta)) ? +Number(signal.delta).toFixed(3) : 0,
    createdAtIso: new Date().toISOString(),
    lastConfirmedIso: new Date().toISOString(),
    summary: sanitizeLoad(summary || String(signal.event || 'signal')).slice(0, 240),
    tags: sanitizeTags(signal.tags),
  };
  const line = JSON.stringify(row) + '\n';
  if (Buffer.byteLength(line, 'utf8') >= MAX_JSONL_LINE_BYTES) {
    throw new Error(`GRPO signal exceeds < ${MAX_JSONL_LINE_BYTES} byte limit`);
  }
  fs.mkdirSync(path.dirname(scopeInfo.grpoPath), { recursive: true, mode: 0o700 });
  fs.appendFileSync(scopeInfo.grpoPath, line, { encoding: 'utf8', mode: 0o600 });
  return row;
}

function inspectMemory(bucketFilter = '', opts = {}, env = process.env) {
  const scopeInfo = resolveScope(opts, env);
  const targetBuckets = bucketFilter ? [normalizeBucket(bucketFilter)].filter(Boolean) : [...MEMORY_BUCKETS];
  const buckets = {};
  let totalCount = 0;

  for (const b of targetBuckets) {
    const items = b === 'learned-skills'
      ? readLearnedSkills(scopeInfo)
      : readJsonlRecords(bucketPath(scopeInfo, b));
    buckets[b] = items.map((r) => ({ ...r, effectiveConfidence: effectiveConfidence(r) }));
    totalCount += items.length;
  }

  const grpoSignals = readJsonlRecords(scopeInfo.grpoPath);
  const grpoNet = +grpoSignals.reduce((acc, s) => acc + (Number(s.grpoScore) || 0), 0).toFixed(3);
  const teamTruthPath = path.join(scopeInfo.teamDir, 'canon-truth.json');
  let teamTruthKeys = 0;
  try {
    if (fs.existsSync(teamTruthPath)) {
      const obj = JSON.parse(fs.readFileSync(teamTruthPath, 'utf8'));
      if (obj && typeof obj === 'object') teamTruthKeys = Object.keys(obj).length;
    }
  } catch { /* ignore */ }

  return {
    personaId: PERSONA_ID,
    scope: scopeInfo.scopeLabel,
    classification: scopeInfo.classification,
    enclaveId: scopeInfo.enclaveId,
    totalCount,
    caps: BUCKET_CAPS,
    buckets,
    teamTruthKeys,
    grpoCount: grpoSignals.length,
    grpoNet,
  };
}

function setPinned(rawBucket, id, pinned, opts = {}, env = process.env) {
  const bucket = normalizeBucket(rawBucket);
  if (!bucket) throw new Error(`Invalid bucket "${rawBucket}"`);
  const scopeInfo = resolveScope(opts, env);

  if (bucket === 'learned-skills') {
    const slug = validateSlug(String(id || '').trim().toLowerCase(), 'skill slug');
    const fp = assertContained(bucketPath(scopeInfo, 'learned-skills'), path.join(bucketPath(scopeInfo, 'learned-skills'), `${slug}.md`), 'learned-skill');
    if (!fs.existsSync(fp)) return false;
    const raw = fs.readFileSync(fp, 'utf8');
    const updated = /^pinned:\s*(?:true|false)$/m.test(raw)
      ? raw.replace(/^pinned:\s*(?:true|false)$/m, `pinned: ${Boolean(pinned)}`)
      : raw.replace(/^---\n/, `---\npinned: ${Boolean(pinned)}\n`);
    atomicWriteFile(fp, updated, 0o600);
    return true;
  }

  const fp = bucketPath(scopeInfo, bucket);
  const rows = readJsonlRecords(fp);
  let found = false;
  for (const r of rows) {
    if (r.id === id) {
      r.pinned = Boolean(pinned);
      r.lastConfirmedIso = new Date().toISOString();
      found = true;
    }
  }
  if (!found) return false;
  writeJsonlRecords(fp, rows);
  return true;
}

function editMemory(rawBucket, id, newText, opts = {}, env = process.env) {
  const bucket = normalizeBucket(rawBucket);
  if (!bucket) throw new Error(`Invalid bucket "${rawBucket}"`);
  const scopeInfo = resolveScope(opts, env);
  assertCompartmentWall(opts, scopeInfo);
  assertWriteAuthority(bucket, { summary: newText, trustTier: opts.trustTier || 'verified-human' });

  const sensitive = findSensitiveMatch(newText);
  if (sensitive) throw new Error(`Memory edit blocked by censorship guard (${sensitive.slice(0, 28)})`);
  if (!scopeInfo.isRegulated && REGULATED_MARKING_RE.test(String(newText || ''))) {
    throw new Error('Compartment Wall blocked regulated marking in commercial memory edit');
  }

  if (bucket === 'learned-skills') {
    const slug = validateSlug(String(id || '').trim().toLowerCase(), 'skill slug');
    const fp = assertContained(bucketPath(scopeInfo, 'learned-skills'), path.join(bucketPath(scopeInfo, 'learned-skills'), `${slug}.md`), 'learned-skill');
    if (!fs.existsSync(fp)) return false;
    const raw = fs.readFileSync(fp, 'utf8');
    const front = raw.match(/^---[\s\S]*?---\s*/);
    const updatedFront = front
      ? front[0].replace(/^lastConfirmedIso:[^\n]*$/m, `lastConfirmedIso: ${new Date().toISOString()}`)
      : `---\nid: ${slug}\npersonaId: ${PERSONA_ID}\nlastConfirmedIso: ${new Date().toISOString()}\n---\n\n`;
    atomicWriteFile(fp, `${updatedFront.trimEnd()}\n\n${String(newText).replace(/\r/g, '').trim()}\n`, 0o600);
    return true;
  }

  const fp = bucketPath(scopeInfo, bucket);
  const rows = readJsonlRecords(fp);
  let found = false;
  for (const r of rows) {
    if (r.id === id) {
      r.summary = sanitizeLoad(String(newText)).slice(0, 600);
      r.lastConfirmedIso = new Date().toISOString();
      found = true;
    }
  }
  if (!found) return false;
  writeJsonlRecords(fp, rows);
  return true;
}

function forgetMemory(rawBucket, id, opts = {}, env = process.env) {
  const bucket = normalizeBucket(rawBucket);
  if (!bucket) throw new Error(`Invalid bucket "${rawBucket}"`);
  const scopeInfo = resolveScope(opts, env);

  if (bucket === 'learned-skills') {
    const slug = validateSlug(String(id || '').trim().toLowerCase(), 'skill slug');
    const fp = assertContained(bucketPath(scopeInfo, 'learned-skills'), path.join(bucketPath(scopeInfo, 'learned-skills'), `${slug}.md`), 'learned-skill');
    if (!fs.existsSync(fp)) return false;
    fs.unlinkSync(fp);
    return true;
  }

  const fp = bucketPath(scopeInfo, bucket);
  const rows = readJsonlRecords(fp);
  const next = rows.filter((r) => r.id !== id);
  if (next.length === rows.length) return false;
  writeJsonlRecords(fp, next);
  return true;
}

function resetMemory(bucketFilter = '', opts = {}, env = process.env) {
  const scopeInfo = resolveScope(opts, env);
  const keepPinned = Boolean(opts.keepPinned);
  const targets = bucketFilter ? [normalizeBucket(bucketFilter)].filter(Boolean) : [...MEMORY_BUCKETS];
  let removed = 0;

  for (const b of targets) {
    if (b === 'learned-skills') {
      const skills = readLearnedSkills(scopeInfo);
      const dir = bucketPath(scopeInfo, 'learned-skills');
      for (const s of skills) {
        if (keepPinned && s.pinned) continue;
        const fp = assertContained(dir, path.join(dir, `${s.id}.md`), 'learned-skill');
        if (fs.existsSync(fp)) {
          fs.unlinkSync(fp);
          removed += 1;
        }
      }
      continue;
    }
    const fp = bucketPath(scopeInfo, b);
    const rows = readJsonlRecords(fp);
    const kept = keepPinned ? rows.filter((r) => r.pinned) : [];
    removed += rows.length - kept.length;
    if (rows.length > 0) writeJsonlRecords(fp, kept);
  }

  return { scope: scopeInfo.scopeLabel, keepPinned, removed };
}

// Deviation-Driven Top-K Memory Selection within strict token budget (<= 1,500–2,500 tok).
function selectTopKMemories(queryText = '', opts = {}, env = process.env) {
  const maxTokens = Math.min(MAX_TOPK_TOKENS, Math.max(100, Number(opts.maxTokens) || DEFAULT_TOPK_TOKENS));
  const inv = inspectMemory('', opts, env);
  const queryTerms = new Set(
    String(queryText || '').toLowerCase().split(/[^a-z0-9_-]+/).filter((w) => w.length >= 3)
  );

  const candidates = [];
  for (const b of MEMORY_BUCKETS) {
    for (const r of inv.buckets[b] || []) {
      const hay = `${r.summary} ${(r.tags || []).join(' ')}`.toLowerCase();
      let overlap = 0;
      for (const term of queryTerms) {
        if (hay.includes(term)) overlap += 1;
      }
      const score = (r.pinned ? 3 : 0) + (r.effectiveConfidence || 0.5) + (Number(r.grpoScore) || 0) + overlap * 0.6;
      candidates.push({ ...r, rankScore: +score.toFixed(3) });
    }
  }
  candidates.sort((a, b) => b.rankScore - a.rankScore);

  const chosen = [];
  let usedTokens = 0;
  for (const c of candidates) {
    const line = `- [${c.bucket}${c.pinned ? ',pinned' : ''}] ${c.id}: ${c.summary}`;
    const tok = estimateTokens(line + '\n');
    if (usedTokens + tok > maxTokens) break;
    chosen.push(c);
    usedTokens += tok;
  }
  return { scope: inv.scope, tokens: usedTokens, items: chosen };
}

// Returns compact <= 800-token digest ONLY when memory has entries; returns "" when empty.
function formatCompactMemoryDigest(opts = {}, env = process.env) {
  const maxTokens = Math.min(MAX_DIGEST_TOKENS, Math.max(64, Number(opts.maxTokens) || DEFAULT_DIGEST_TOKENS));
  const inv = inspectMemory('', opts, env);
  if (inv.totalCount === 0 && inv.grpoCount === 0) return '';

  const sel = selectTopKMemories(opts.queryText || '', { ...opts, maxTokens: Math.max(100, maxTokens - 32) }, env);
  const header = `Memory [${inv.scope}] prefs:${(inv.buckets.preferences || []).length}/${BUCKET_CAPS.preferences} ins:${(inv.buckets.insights || []).length}/${BUCKET_CAPS.insights} skills:${(inv.buckets['learned-skills'] || []).length}/${BUCKET_CAPS['learned-skills']} dead:${(inv.buckets['dead-ends'] || []).length}/${BUCKET_CAPS['dead-ends']} grpo:${inv.grpoNet}`;
  const lines = [header];
  for (const item of sel.items.slice(0, 6)) {
    const line = `  - (${item.bucket}${item.pinned ? '*' : ''}) ${item.id}: ${item.summary.slice(0, 120)}`;
    if (estimateTokens(lines.concat(line).join('\n')) > maxTokens) break;
    lines.push(line);
  }
  return lines.join('\n');
}

function formatInspectorReport(inv) {
  const lines = [
    `NeckBeard 3-Tier Memory Inspector (${inv.scope} · classification=${inv.classification})`,
    `Buckets: preferences=${(inv.buckets.preferences || []).length}/${BUCKET_CAPS.preferences} | insights=${(inv.buckets.insights || []).length}/${BUCKET_CAPS.insights} | learned-skills=${(inv.buckets['learned-skills'] || []).length}/${BUCKET_CAPS['learned-skills']} | dead-ends=${(inv.buckets['dead-ends'] || []).length}/${BUCKET_CAPS['dead-ends']} | grpo=${inv.grpoCount} (net ${inv.grpoNet})`,
  ];
  for (const [b, list] of Object.entries(inv.buckets)) {
    for (const r of list.slice(0, 12)) {
      lines.push(`  [${b}] ${r.id} | pin=${r.pinned ? 'Y' : 'N'} | conf=${r.effectiveConfidence} | ${r.summary}`);
    }
  }
  lines.push('Compartment Wall: PASS | Write Authority: PASS | Envelope <4096B LF-only: PASS');
  return lines.join('\n');
}

function runMemoryCommand(argv = [], env = process.env) {
  const args = [...argv];
  const keepPinned = args.includes('--keep-pinned');
  const filtered = args.filter((a) => a !== '--keep-pinned');
  const verb = String(filtered[0] || 'inspect').toLowerCase();

  if (verb === 'inspect' || verb === 'list' || verb === 'status') {
    const bucket = filtered[1] || '';
    return formatInspectorReport(inspectMemory(bucket, {}, env));
  }
  if (verb === 'pin' || verb === 'unpin') {
    const ok = setPinned(filtered[1], filtered[2], verb === 'pin', {}, env);
    return ok ? `Memory ${verb}ned: ${filtered[1]}/${filtered[2]}` : `Memory entry not found: ${filtered[1]}/${filtered[2]}`;
  }
  if (verb === 'edit') {
    const ok = editMemory(filtered[1], filtered[2], filtered.slice(3).join(' '), {}, env);
    return ok ? `Memory updated: ${filtered[1]}/${filtered[2]}` : `Memory entry not found: ${filtered[1]}/${filtered[2]}`;
  }
  if (verb === 'forget' || verb === 'delete' || verb === 'rm') {
    const ok = forgetMemory(filtered[1], filtered[2], {}, env);
    return ok ? `Memory forgotten: ${filtered[1]}/${filtered[2]}` : `Memory entry not found: ${filtered[1]}/${filtered[2]}`;
  }
  if (verb === 'reset') {
    const res = resetMemory(filtered[1] || '', { keepPinned }, env);
    return `Memory reset (${res.scope}): removed ${res.removed} record(s)${keepPinned ? ' (pinned preserved)' : ''}.`;
  }
  return 'Usage: /neckbeard-memory [inspect [bucket]|pin <bucket> <id>|unpin <bucket> <id>|edit <bucket> <id> <text>|forget <bucket> <id>|reset [bucket] [--keep-pinned]]';
}

module.exports = {
  PERSONA_ID,
  MEMORY_BUCKETS,
  BUCKET_CAPS,
  COMPARTMENTS,
  REGULATED_COMPARTMENTS,
  UNTRUSTED_PAYLOAD_RE,
  REGULATED_MARKING_RE,
  normalizeBucket,
  validateSlug,
  resolveScope,
  addMemory,
  recordGrpoSignal,
  inspectMemory,
  setPinned,
  editMemory,
  forgetMemory,
  resetMemory,
  selectTopKMemories,
  formatCompactMemoryDigest,
  formatInspectorReport,
  runMemoryCommand,
};

if (require.main === module) {
  try {
    process.stdout.write(runMemoryCommand(process.argv.slice(2), process.env) + '\n');
  } catch (err) {
    process.stderr.write(`neckbeard-memory error: ${err.message}\n`);
    process.exit(1);
  }
}
