'use strict';
// VIBES Protocol (.ai-audit/) telemetry reader & 5-pillar visualizer data extractor.
// Supports the complete canonical VIBES v1.0/v1.1, VERIFY v1.0, PRISM v1.0, EVOLVE v1.0, and TRACE v1.0 schemas
// across VibeCheck, ClaudeCode-VIBES, Codex-VIBES, AntigravityCLI-VIBES, and VibeTrace:
// - manifest.json `entries` content-addressed hash map:
//   * environment: tool_name, tool_version, model_name, model_version, model_parameters, tool_extensions, created_at
//   * prompt: prompt_text, prompt_type, prompt_context_files, created_at
//   * command: command_text, command_type, command_exit_code, command_output_summary, working_directory, created_at
//   * reasoning: reasoning_text, reasoning_token_count, reasoning_model, compressed, external, blob_path, created_at
//   * decision: decision_point, options, selected, rationale, confidence, created_at
// - annotations.jsonl records:
//   * line: file_path, line_start, line_end, action, assurance_level, *_hash, risk_score, risk_band, risk_factors
//   * function: file_path, function_name, function_signature, action, assurance_level, *_hash, risk_score
//   * session: session_id, event, timestamp, environment_hash, assurance_level, description, agent_name, agent_type
//   * delegation: parent_session_id, child_session_id, task_description, delegated_files, delegation_type
//   * edge: edge_type, source_ref, source_type, target_ref, target_type, session_id
//   * incident: incident_id, ioc_id, rule_id, severity, status, quarantined, risk_score, risk_factors

const fs = require('fs');
const path = require('path');

const MAX_READ_BYTES = 16 * 1024 * 1024;
const GENERIC_HEADING_RE = /^(?:#{1,6}\s*(?:Context|Instructions|Overview|Task|Tasks|Prior Conversation|Context Summarization|Context Transfer|Background|System|CRITICAL|Structured Output|YAML Front Matter|Folder Organization).*|---|\*\*\*)$/i;

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

function countDirEntriesSafe(dirPath) {
  try {
    if (!fs.existsSync(dirPath)) return 0;
    let total = 0;
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      if (e.isDirectory()) {
        try {
          total += fs.readdirSync(path.join(dirPath, e.name)).filter((x) => !x.startsWith('.')).length;
        } catch {
          total += 1;
        }
      } else {
        total += 1;
      }
    }
    return total;
  } catch {
    return 0;
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

function extractCleanTextSummary(rawText) {
  if (!rawText || typeof rawText !== 'string') return '';
  const trimmed = rawText.trim();
  const playbookMatch = /Process tasks from this document:\s+([^\s\n]+)/i.exec(trimmed);
  if (playbookMatch) {
    const docBase = path.basename(playbookMatch[1], '.md');
    const dirBase = path.basename(path.dirname(playbookMatch[1]));
    return `Playbook: ${docBase}${dirBase && dirBase !== 'playbooks' ? ` (${dirBase})` : ''}`.slice(0, 76);
  }
  const lines = trimmed.split('\n');
  for (const rawLine of lines) {
    const line = rawLine.replace(/[*#`]/g, '').trim();
    if (!line || line.length < 4) continue;
    if (GENERIC_HEADING_RE.test(rawLine.trim())) continue;
    if (/^Your name is\b/i.test(line) || /^- (?:Agent Path|Git Branch|Auto Run Folder|Loop Iteration|Working Folder):/i.test(rawLine.trim())) continue;
    return line.slice(0, 76);
  }
  return lines[0].replace(/[*#`]/g, '').trim().slice(0, 76);
}

// Extracts project-level, per-session, and 5-pillar visualization telemetry from .ai-audit/.
function readVibesTelemetry(root = process.cwd()) {
  if (!hasVibes(root)) return null;
  const dir = path.join(root, '.ai-audit');
  const manifest = readJsonSafe(path.join(dir, 'manifest.json')) || {};
  const annotations = readJsonlSafe(path.join(dir, 'annotations.jsonl'));

  const sessions = new Map();
  let maxPrismRisk = 0;
  let highRiskCount = 0;
  let verifiedCount = 0;
  let traceIncidents = 0;
  let traceResolved = 0;
  let decisions = Array.isArray(manifest.decisions) ? manifest.decisions.length : 0;
  let linesAdded = 0;
  let linesRemoved = 0;
  const filesTouched = new Set();
  const fileStatsMap = new Map();
  const prismBuckets = { low: 0, moderate: 0, high: 0, critical: 0 };
  const assuranceBreakdown = { high: 0, medium: 0, low: 0 };
  const manifestCounts = { environment: 0, reasoning: 0, command: 0, prompt: 0, decision: 0, total: 0 };
  const envModels = new Map();
  const manifestSummaries = new Map();
  const manifestInspectorRows = [];
  const decisionRecords = [];
  const incidentRecords = [];
  const recentAnnotations = [];

  // Parse content-addressed manifest.entries hash table (canonical VIBES v1.0 / v1.1 schema)
  if (manifest.entries && typeof manifest.entries === 'object') {
    for (const [hash, entry] of Object.entries(manifest.entries)) {
      if (!entry || typeof entry !== 'object') continue;
      manifestCounts.total += 1;
      const eType = String(entry.type || '');
      if (eType in manifestCounts) manifestCounts[eType] += 1;
      const createdStamp = String(entry.created_at || '').replace('T', ' ').slice(0, 19);

      if (eType === 'environment') {
        const modelLabel = (entry.model_name && entry.model_name !== 'unknown' ? entry.model_name : '') ||
          entry.tool_name || '';
        if (modelLabel) envModels.set(hash, modelLabel);
      } else if (eType === 'prompt') {
        const promptSum = extractCleanTextSummary(entry.prompt_text || '');
        if (promptSum) {
          manifestSummaries.set(hash, promptSum);
          const ctxFiles = Array.isArray(entry.prompt_context_files) && entry.prompt_context_files.length
            ? entry.prompt_context_files[0]
            : '[prompt]';
          manifestInspectorRows.push({
            sessionId: hash.slice(0, 10),
            timestamp: createdStamp,
            model: String(entry.prompt_type || 'prompt'),
            file: String(ctxFiles),
            linesAdded: 0,
            linesRemoved: 0,
            riskScore: null,
            verified: true,
            summary: promptSum,
          });
        }
      } else if (eType === 'reasoning') {
        const reasonSum = extractCleanTextSummary(entry.reasoning_text || '');
        if (reasonSum) {
          manifestSummaries.set(hash, reasonSum);
          manifestInspectorRows.push({
            sessionId: hash.slice(0, 10),
            timestamp: createdStamp,
            model: String(entry.reasoning_model || 'reasoning'),
            file: entry.blob_path ? `blob:${path.basename(entry.blob_path).slice(0, 12)}` : '[reasoning]',
            linesAdded: Number(entry.reasoning_token_count || 0),
            linesRemoved: 0,
            riskScore: null,
            verified: true,
            summary: `Reasoning: ${reasonSum}`,
          });
        }
      } else if (eType === 'command') {
        const cmdSummary = entry.command_output_summary || entry.command_text || entry.command_type || '';
        const cleanCmd = extractCleanTextSummary(String(cmdSummary));
        if (cleanCmd) {
          manifestSummaries.set(hash, cleanCmd);
          manifestInspectorRows.push({
            sessionId: hash.slice(0, 10),
            timestamp: createdStamp,
            model: String(entry.command_type || 'command'),
            file: `[cmd exit:${entry.command_exit_code ?? 0}]`,
            linesAdded: 0,
            linesRemoved: 0,
            riskScore: null,
            verified: entry.command_exit_code === 0 || entry.command_exit_code == null,
            summary: cleanCmd,
          });
        }
      } else if (eType === 'decision') {
        decisions += 1;
        if (decisionRecords.length < 15) {
          // Canonical VibeCheck decision fields: decision_point, options, selected, rationale, confidence
          const dp = entry.decision_point || entry.title || entry.summary || '';
          const sel = entry.selected ? ` → ${entry.selected}` : '';
          const rat = entry.rationale ? ` (${entry.rationale})` : '';
          const fullTitle = `${dp}${sel}${rat}`.trim() || 'Manifest decision record';
          decisionRecords.push({
            id: hash.slice(0, 10),
            title: fullTitle.slice(0, 110),
            status: String(entry.confidence || entry.status || 'attested'),
            timestamp: createdStamp,
          });
        }
      }
    }
  }

  if (Array.isArray(manifest.decisions)) {
    for (const d of manifest.decisions.slice(0, 15)) {
      if (d && typeof d === 'object') {
        const dp = d.decision_point || d.title || d.summary || '';
        const sel = d.selected ? ` → ${d.selected}` : '';
        const rat = d.rationale && !dp.includes(d.rationale) ? ` (${d.rationale})` : '';
        decisionRecords.push({
          id: String(d.id || d.decision_id || d.hash || `DEC-${decisionRecords.length + 1}`).slice(0, 12),
          title: (`${dp}${sel}${rat}`.trim() || 'Recorded architectural decision').slice(0, 110),
          status: String(d.confidence || d.status || 'accepted'),
          timestamp: String(d.timestamp || d.created_at || ''),
        });
      }
    }
  }

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
    if (model && (!s.model || s.model === 'unknown')) s.model = model;
    return s;
  };

  if (manifest.sessions && typeof manifest.sessions === 'object') {
    for (const [sid, meta] of Object.entries(manifest.sessions)) {
      if (!meta || typeof meta !== 'object') continue;
      const ts = meta.started_at ? Date.parse(meta.started_at) : (meta.timestamp ? Date.parse(meta.timestamp) : NaN);
      const s = ensureSession(sid, Number.isFinite(ts) ? ts : Date.now(), meta.model || meta.agent_model || '');
      if (meta.title || meta.summary || meta.prompt) {
        s.name = extractCleanTextSummary(String(meta.title || meta.summary || meta.prompt)).slice(0, 60);
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
    const sid = a.session_id || a.sessionId || a.parent_session_id || manifest.session_id || 'vibes-default';
    const resolvedEnvModel = (a.environment_hash && envModels.get(a.environment_hash)) || '';
    const model = (a.model && a.model !== 'unknown' ? a.model : '') ||
      a.agent_model || (a.agent && a.agent.model) || resolvedEnvModel || a.agent_name || '';
    const s = ensureSession(sid, Number.isFinite(ts) ? ts : undefined, model);
    s.turns += 1;

    const linkedPrompt = (a.prompt_hash && manifestSummaries.get(a.prompt_hash)) || '';
    const linkedReason = (a.reasoning_hash && manifestSummaries.get(a.reasoning_hash)) || '';
    const linkedCmd = (a.command_hash && manifestSummaries.get(a.command_hash)) || '';

    const rawFile = a.file_path || a.file || a.path || '';
    const fileLabel = rawFile
      ? (a.function_name ? `${rawFile} :: ${a.function_name}()` : rawFile)
      : '';

    const summaryText = extractCleanTextSummary(
      a.prompt || a.intent || a.summary || a.task_description || linkedPrompt || linkedReason || linkedCmd ||
      (a.description && !String(a.description).endsWith('session ended') ? a.description : '') ||
      (a.action && fileLabel ? `${a.action} ${fileLabel}` : a.action || a.type || '')
    );
    if (!s.name && summaryText && !/agent session/i.test(summaryText)) {
      s.name = summaryText.slice(0, 60);
    }

    const assurance = String(a.assurance_level || '').toLowerCase();
    if (assurance === 'high') assuranceBreakdown.high += 1;
    else if (assurance === 'medium') assuranceBreakdown.medium += 1;
    else if (assurance === 'low') assuranceBreakdown.low += 1;

    const isVerified = Boolean(
      a.verified === true ||
      a.status === 'verified' ||
      a.action === 'attest' ||
      a.action === 'verify' ||
      assurance === 'high' ||
      a.attestation_id ||
      a.dsse_hash ||
      (a.command_hash && a.environment_hash)
    );
    if (isVerified) verifiedCount += 1;

    const lineRangeCount = (a.line_start != null && a.line_end != null)
      ? Math.max(1, Number(a.line_end) - Number(a.line_start) + 1)
      : (a.type === 'function' ? 1 : 0);

    let added = (typeof a.lines_added === 'number' ? a.lines_added : 0) ||
      countRangeLines(a.created_lines || a.added_lines || (a.changes && a.changes.created)) +
      countRangeLines(a.modified_lines || (a.changes && a.changes.modified));
    let removed = (typeof a.lines_removed === 'number' ? a.lines_removed : 0) ||
      countRangeLines(a.deleted_lines || a.removed_lines || (a.changes && a.changes.deleted));

    if (added === 0 && removed === 0 && lineRangeCount > 0) {
      if (a.action === 'delete') removed = lineRangeCount;
      else added = lineRangeCount;
    }

    linesAdded += added;
    linesRemoved += removed;
    s.linesAdded += added;
    s.linesRemoved += removed;

    const risk = typeof a.risk_score === 'number' ? a.risk_score : (a.prism && typeof a.prism.risk_score === 'number' ? a.prism.risk_score : null);
    if (risk !== null && Number.isFinite(risk)) {
      if (risk > maxPrismRisk) maxPrismRisk = risk;
      if (risk > s.maxRisk) s.maxRisk = risk;
      if (risk >= 0.8) prismBuckets.critical += 1;
      else if (risk >= 0.6) prismBuckets.high += 1;
      else if (risk >= 0.3) prismBuckets.moderate += 1;
      else prismBuckets.low += 1;

      if (risk >= 0.6) {
        highRiskCount += 1;
        s.secFound += 1;
        if (isVerified || a.resolved === true || a.status === 'resolved') {
          s.secFixed += 1;
        }
      }
    }

    if (rawFile) {
      filesTouched.add(rawFile);
      s.files.add(rawFile);
      const prev = fileStatsMap.get(rawFile) || { file: rawFile, annotations: 0, linesAdded: 0, linesRemoved: 0, maxRisk: 0, verified: true };
      prev.annotations += 1;
      prev.linesAdded += added;
      prev.linesRemoved += removed;
      if (risk !== null && Number.isFinite(risk) && risk > prev.maxRisk) prev.maxRisk = +risk.toFixed(2);
      prev.verified = prev.verified && isVerified;
      fileStatsMap.set(rawFile, prev);
    }

    if (typeof a.tokens_total === 'number') s.tokens += a.tokens_total;
    else if (a.usage && typeof a.usage === 'object') {
      const inTok = Number(a.usage.input_tokens || 0);
      const outTok = Number(a.usage.output_tokens || 0);
      s.tokens += inTok + outTok;
      s.outputTokens += outTok;
    }
    if (typeof a.cost_usd === 'number') s.costUsd = (s.costUsd || 0) + a.cost_usd;

    if (a.type === 'decision' || a.record_type === 'decision' || a.decision_hash || a.type === 'delegation') {
      decisions += 1;
      if (decisionRecords.length < 15) {
        const dp = a.decision_point || a.task_description || summaryText || 'Agent decision record';
        const sel = a.selected ? ` → ${a.selected}` : '';
        decisionRecords.push({
          id: String(a.id || a.decision_id || (a.decision_hash && a.decision_hash.slice(0, 10)) || (a.type === 'delegation' ? 'DELEGATE' : `DEC-${decisions}`)),
          title: `${dp}${sel}`.slice(0, 110),
          status: String(a.confidence || a.status || (isVerified ? 'attested' : 'recorded')),
          timestamp: String(tsRaw || ''),
        });
      }
    }

    if (a.type === 'incident' || a.record_type === 'incident' || a.ioc_id || a.trace_incident || a.action === 'block' || a.quarantined === true) {
      traceIncidents += 1;
      s.secFound += 1;
      const isResolved = Boolean(a.resolved === true || a.status === 'resolved' || a.status === 'mitigated' || a.status === 'closed' || a.action === 'block' || a.quarantined === true);
      if (isResolved) {
        traceResolved += 1;
        s.secFixed += 1;
      }
      if (incidentRecords.length < 15) {
        const factorSignal = Array.isArray(a.risk_factors) && a.risk_factors[0] && a.risk_factors[0].signal;
        incidentRecords.push({
          id: String(a.id || a.incident_id || (a.annotation_id && String(a.annotation_id).slice(0, 10)) || `INC-${traceIncidents}`),
          iocId: String(a.ioc_id || a.rule_id || factorSignal || (a.action === 'block' ? 'VIBES-BLOCK' : 'TRACE-IOC')),
          severity: String(a.severity || (risk && risk >= 0.8 ? 'critical' : 'high')),
          status: isResolved ? 'resolved' : String(a.status || 'open'),
          summary: summaryText || String(a.ioc_id || 'TRACE security incident'),
          timestamp: String(tsRaw || ''),
        });
      }
    }

    if (fileLabel || risk !== null || a.type !== 'session') {
      recentAnnotations.push({
        sessionId: String(sid).slice(0, 14),
        timestamp: String(tsRaw || '').replace('T', ' ').slice(0, 19),
        model: String(model || 'agent'),
        file: String(fileLabel || (a.action ? `[${a.action}]` : `[${a.type || 'turn'}]`)),
        linesAdded: added,
        linesRemoved: removed,
        riskScore: risk !== null && Number.isFinite(risk) ? +risk.toFixed(2) : null,
        verified: isVerified,
        summary: summaryText || 'Annotated agent turn',
      });
    }
  }

  // If annotations.jsonl only had session start/end events (like VibeCheck), populate recentAnnotations from manifestInspectorRows
  if (recentAnnotations.length === 0 && manifestInspectorRows.length > 0) {
    recentAnnotations.push(...manifestInspectorRows.slice(-16));
  }

  const incDirCount = countDirEntriesSafe(path.join(dir, 'incidents'));
  traceIncidents = Math.max(traceIncidents, incDirCount);
  const blobsCount = countDirEntriesSafe(path.join(dir, 'blobs')) || manifestCounts.total;
  const attestationsCount = countDirEntriesSafe(path.join(dir, 'attestations')) +
    countDirEntriesSafe(path.join(dir, 'provenance')) +
    countDirEntriesSafe(path.join(dir, 'cosign')) +
    countDirEntriesSafe(path.join(dir, 'evidence')) ||
    assuranceBreakdown.high;
  const iocRulesCount = countDirEntriesSafe(path.join(dir, 'iocs.d'));
  const hasAuditDb = fs.existsSync(path.join(dir, 'audit.db')) || fs.existsSync(path.join(dir, 'wal'));

  if (decisionRecords.length === 0 && manifestCounts.total > 0) {
    if (manifestCounts.reasoning > 0) {
      decisionRecords.push({
        id: 'VIBES-REASON',
        title: `${manifestCounts.reasoning} content-addressed agent reasoning chains hashed in .ai-audit/manifest.json`,
        status: 'attested',
        timestamp: '',
      });
    }
    if (manifestCounts.command > 0) {
      decisionRecords.push({
        id: 'VIBES-CMD',
        title: `${manifestCounts.command} tool/command execution records hashed in .ai-audit/manifest.json`,
        status: 'attested',
        timestamp: '',
      });
    }
    if (manifestCounts.environment > 0) {
      decisionRecords.push({
        id: 'VIBES-ENV',
        title: `${manifestCounts.environment} agent runtime environment snapshots hashed in .ai-audit/manifest.json`,
        status: 'attested',
        timestamp: '',
      });
    }
  }

  const fileHotspots = [...fileStatsMap.values()]
    .sort((a, b) => (b.maxRisk - a.maxRisk) || ((b.linesAdded + b.linesRemoved) - (a.linesAdded + a.linesRemoved)))
    .slice(0, 10);

  return {
    present: true,
    annotationsCount: annotations.length,
    verifiedCount,
    blobsCount,
    attestationsCount,
    iocRulesCount,
    hasAuditDb,
    manifestCounts,
    assuranceBreakdown,
    prismBuckets,
    fileHotspots,
    decisionRecords,
    incidentRecords,
    recentAnnotations: recentAnnotations.slice(-16).reverse(),
    sessions: [...sessions.values()]
      .sort((a, b) => (b.startedMs || 0) - (a.startedMs || 0))
      .slice(0, 250)
      .map((s) => ({ ...s, filesCount: s.files.size, files: undefined })),
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

module.exports = { hasVibes, readVibesTelemetry, formatVibesContext, extractCleanTextSummary };
