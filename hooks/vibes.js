'use strict';
// VIBES Protocol (.ai-audit/) telemetry reader.
// When .ai-audit/manifest.json or .ai-audit/annotations.jsonl is present, NeckBeard
// defaults to using VIBES provenance, PRISM risk scores, EVOLVE decisions, and TRACE
// incident records for session/project instrumentation instead of duplicating scans.

const fs = require('fs');
const path = require('path');

const MAX_READ_BYTES = 16 * 1024 * 1024;

function hasVibes(root = process.cwd()) {
  const dir = path.join(root, '.ai-audit');
  return fs.existsSync(path.join(dir, 'manifest.json')) || fs.existsSync(path.join(dir, 'annotations.jsonl'));
}

function readJsonSafe(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function readJsonlSafe(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return [];
    const fd = fs.openSync(file, 'r');
    const size = Math.min(st.size, MAX_READ_BYTES);
    const buf = Buffer.alloc(size);
    const offset = Math.max(0, st.size - size);
    const read = fs.readSync(fd, buf, 0, size, offset);
    fs.closeSync(fd);
    const lines = buf.toString('utf8', 0, read).split('\n');
    if (offset > 0) lines.shift();
    const out = [];
    for (const line of lines) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try { out.push(JSON.parse(t)); } catch { /* skip malformed line */ }
    }
    return out;
  } catch {
    return [];
  }
}

function countRangeLines(ranges) {
  if (!Array.isArray(ranges)) return 0;
  let total = 0;
  for (const r of ranges) {
    if (Array.isArray(r) && r.length >= 2) {
      total += Math.max(1, Number(r[1]) - Number(r[0]) + 1);
    } else if (r && typeof r === 'object' && r.start_line != null && r.end_line != null) {
      total += Math.max(1, Number(r.end_line) - Number(r.start_line) + 1);
    } else if (typeof r === 'number' && Number.isFinite(r)) {
      total += 1;
    }
  }
  return total;
}

// Extracts project-level and per-session metrics from .ai-audit/manifest.json and annotations.jsonl.
function readVibesTelemetry(root = process.cwd()) {
  if (!hasVibes(root)) return null;
  const dir = path.join(root, '.ai-audit');
  const manifest = readJsonSafe(path.join(dir, 'manifest.json')) || {};
  const annotations = readJsonlSafe(path.join(dir, 'annotations.jsonl'));

  const sessions = new Map();
  let maxPrismRisk = 0;
  let highRiskCount = 0;
  let traceIncidents = 0;
  let traceResolved = 0;
  let decisions = Array.isArray(manifest.decisions) ? manifest.decisions.length : 0;
  let linesAdded = 0;
  let linesRemoved = 0;
  const filesTouched = new Set();

  const ensureSession = (id, ts, model) => {
    const sid = String(id || 'vibes-session');
    if (!sessions.has(sid)) {
      sessions.set(sid, {
        sessionId: sid,
        startedMs: ts || Date.now(),
        lastMs: ts || Date.now(),
        model: model || '',
        name: '',
        turns: 0,
        agentMs: 0,
        tokens: 0,
        outputTokens: 0,
        costUsd: null,
        linesAdded: 0,
        linesRemoved: 0,
        maxRisk: 0,
        secFound: 0,
        secFixed: 0,
        files: new Set(),
      });
    }
    const s = sessions.get(sid);
    if (ts && ts < s.startedMs) s.startedMs = ts;
    if (ts && ts > s.lastMs) {
      const delta = ts - s.lastMs;
      if (delta > 0 && delta <= 30 * 60000) s.agentMs += delta;
      s.lastMs = ts;
    }
    if (model && !s.model) s.model = model;
    return s;
  };

  if (manifest.sessions && typeof manifest.sessions === 'object') {
    for (const [sid, meta] of Object.entries(manifest.sessions)) {
      if (!meta || typeof meta !== 'object') continue;
      const ts = meta.started_at ? Date.parse(meta.started_at) : (meta.timestamp ? Date.parse(meta.timestamp) : NaN);
      const s = ensureSession(sid, Number.isFinite(ts) ? ts : Date.now(), meta.model || meta.agent_model || '');
      if (meta.title || meta.summary || meta.prompt) {
        s.name = String(meta.title || meta.summary || meta.prompt).split('\n')[0].slice(0, 60);
      }
      if (typeof meta.turns === 'number') s.turns = Math.max(s.turns, meta.turns);
      if (typeof meta.tokens_total === 'number') s.tokens = Math.max(s.tokens, meta.tokens_total);
      if (typeof meta.cost_usd === 'number') s.costUsd = meta.cost_usd;
    }
  }

  for (const a of annotations) {
    if (!a || typeof a !== 'object') continue;
    const tsRaw = a.timestamp || a.created_at || a.started_at;
    const ts = tsRaw ? Date.parse(tsRaw) : NaN;
    const sid = a.session_id || a.sessionId || (manifest.session_id) || 'vibes-default';
    const model = a.model || a.agent_model || (a.agent && a.agent.model) || '';
    const s = ensureSession(sid, Number.isFinite(ts) ? ts : undefined, model);
    s.turns += 1;

    if (!s.name && (a.prompt || a.intent || a.summary || a.description)) {
      s.name = String(a.prompt || a.intent || a.summary || a.description).split('\n')[0].slice(0, 60);
    }

    const file = a.file_path || a.file || a.path;
    if (file) {
      filesTouched.add(file);
      s.files.add(file);
    }

    const added = (typeof a.lines_added === 'number' ? a.lines_added : 0) ||
      countRangeLines(a.created_lines || a.added_lines || (a.changes && a.changes.created)) +
      countRangeLines(a.modified_lines || (a.changes && a.changes.modified));
    const removed = (typeof a.lines_removed === 'number' ? a.lines_removed : 0) ||
      countRangeLines(a.deleted_lines || a.removed_lines || (a.changes && a.changes.deleted));
    linesAdded += added;
    linesRemoved += removed;
    s.linesAdded += added;
    s.linesRemoved += removed;

    if (typeof a.tokens_total === 'number') s.tokens += a.tokens_total;
    else if (a.usage && typeof a.usage === 'object') {
      const inTok = Number(a.usage.input_tokens || 0);
      const outTok = Number(a.usage.output_tokens || 0);
      s.tokens += inTok + outTok;
      s.outputTokens += outTok;
    }
    if (typeof a.cost_usd === 'number') s.costUsd = (s.costUsd || 0) + a.cost_usd;

    const risk = typeof a.risk_score === 'number' ? a.risk_score : (a.prism && typeof a.prism.risk_score === 'number' ? a.prism.risk_score : null);
    if (risk !== null && Number.isFinite(risk)) {
      if (risk > maxPrismRisk) maxPrismRisk = risk;
      if (risk > s.maxRisk) s.maxRisk = risk;
      if (risk >= 0.6) {
        highRiskCount += 1;
        s.secFound += 1;
        if (a.verified === true || a.resolved === true || a.status === 'resolved' || a.status === 'verified') {
          s.secFixed += 1;
        }
      }
    }

    if (a.type === 'decision' || a.record_type === 'decision') decisions += 1;
    if (a.type === 'incident' || a.record_type === 'incident' || a.ioc_id || a.trace_incident) {
      traceIncidents += 1;
      s.secFound += 1;
      if (a.resolved === true || a.status === 'resolved' || a.status === 'mitigated' || a.status === 'closed') {
        traceResolved += 1;
        s.secFixed += 1;
      }
    }
  }

  // Also check .ai-audit/incidents/ directory if present
  try {
    const incDir = path.join(dir, 'incidents');
    if (fs.existsSync(incDir)) {
      const entries = fs.readdirSync(incDir);
      traceIncidents = Math.max(traceIncidents, entries.filter((e) => !e.startsWith('.')).length);
    }
  } catch { /* ignore */ }

  return {
    present: true,
    annotationsCount: annotations.length,
    sessions: [...sessions.values()].map((s) => ({ ...s, filesCount: s.files.size, files: undefined })),
    maxPrismRisk: +maxPrismRisk.toFixed(2),
    highRiskCount,
    traceIncidents,
    traceResolved,
    decisions,
    linesAdded,
    linesRemoved,
    filesTouchedCount: filesTouched.size,
  };
}

function formatVibesContext(root = process.cwd()) {
  const v = readVibesTelemetry(root);
  if (!v) return '';
  return `VIBES (.ai-audit/): active · ${v.annotationsCount} annotations · PRISM max risk ${v.maxPrismRisk.toFixed(2)} (${v.highRiskCount} high) · TRACE incidents ${v.traceIncidents} (${v.traceResolved} resolved) · EVOLVE decisions ${v.decisions}`;
}

module.exports = { hasVibes, readVibesTelemetry, formatVibesContext };
