#!/usr/bin/env node
'use strict';
// NeckBeard Original Telemetry Aggregator & Command Center Builder.
// 1. Primary source: VIBES Protocol (.ai-audit/manifest.json & annotations.jsonl) when present.
// 2. Secondary sources: Local PreToolUse guard counters (guard-stats.json), .neckbeard.json load/boundary maps,
//    and local agent session logs.
// 3. Writes JSONL telemetry records to ~/.config/neckbeard/telemetry/sessions.jsonl and generates the
//    self-contained NeckBeard Security & Engineering Command Center at ~/.config/neckbeard/telemetry/dashboard.html.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { claudeDir, bandDir, configBase, readGuardStats } = require('./lib');
const { hasVibes, readVibesTelemetry, extractCleanTextSummary } = require('./vibes');
const { buildBoundaryMap, detectBoundaryDrift, flattenBoundaries, readProjectConfig } = require('./surface');

const STALE_TITLE_RE = /^(?:#\s*(?:Context|Instructions|Overview|Task|Tasks|Prior Conversation)|Interactive coding session$)/i;

function extractSessionTaskTitle(sessionTitle, firstUserText, lastAssistantText) {
  if (sessionTitle && !STALE_TITLE_RE.test(sessionTitle)) return sessionTitle;
  const rawUser = String(firstUserText || '').trim();
  const playbookMatch = /Process tasks from this document:\s+([^\s\n]+)/i.exec(rawUser);
  const playbookDoc = playbookMatch ? path.basename(playbookMatch[1], '.md') : '';

  let assistantSynopsis = '';
  if (lastAssistantText) {
    const firstLine = String(lastAssistantText)
      .replace(/^[\s*#`-]+/, '')
      .split('\n')
      .map((l) => l.trim())
      .find((l) => l.length > 8 && !/^(?:What changed|Summary|Overview|Synopsis):?$/i.test(l));
    if (firstLine) {
      assistantSynopsis = firstLine.replace(/`/g, '').split(/\.\s+/)[0].replace(/\.$/, '').slice(0, 72);
    }
  }

  if (playbookDoc && assistantSynopsis) {
    return `[${playbookDoc}] ${assistantSynopsis}`.slice(0, 84);
  }
  if (playbookDoc) {
    const dirName = path.basename(path.dirname(playbookMatch[1]));
    return `Playbook: ${playbookDoc}${dirName && dirName !== 'playbooks' ? ` (${dirName})` : ''}`.slice(0, 84);
  }
  if (rawUser && !STALE_TITLE_RE.test(rawUser.split('\n')[0].trim())) {
    return extractCleanTextSummary(rawUser).slice(0, 76);
  }
  if (assistantSynopsis) {
    return assistantSynopsis.slice(0, 76);
  }
  if (rawUser) {
    return extractCleanTextSummary(rawUser).slice(0, 76) || 'Interactive coding session';
  }
  return 'Interactive coding session';
}

const MODEL_RATES_PER_M = {
  'claude-opus-5-5': { in: 4, out: 20, cacheRead: 0.2, cacheWrite: 5 },
  'claude-opus-5': { in: 5, out: 25, cacheRead: 0.5, cacheWrite: 6.25 },
  'claude-opus-4-6': { in: 5, out: 25, cacheRead: 0.5, cacheWrite: 6.25 },
  'claude-opus-4-5': { in: 5, out: 25, cacheRead: 0.5, cacheWrite: 6.25 },
  'claude-sonnet-5-5': { in: 2, out: 10, cacheRead: 0.1, cacheWrite: 2.5 },
  'claude-sonnet-5': { in: 2, out: 10, cacheRead: 0.2, cacheWrite: 2.5 },
  'claude-sonnet-4-6': { in: 3, out: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  'claude-sonnet-4-5': { in: 3, out: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  'claude-haiku-5-5': { in: 0.1, out: 0.5, cacheRead: 0.01, cacheWrite: 0.125 },
  'claude-haiku-4-5': { in: 1, out: 5, cacheRead: 0.1, cacheWrite: 1.25 },
};

function normalizeModelKey(rawModel) {
  return String(rawModel || '').replace(/\[.*\]$/, '').replace(/-\d{8}$/, '');
}

function computeMessageCostUsd(rawModel, usage) {
  if (!usage || typeof usage !== 'object') return null;
  const rates = MODEL_RATES_PER_M[normalizeModelKey(rawModel)];
  if (!rates || usage.speed === 'fast') return null;
  const promptTok = Number(usage.input_tokens || 0);
  const compTok = Number(usage.output_tokens || 0);
  const cRead = Number(usage.cache_read_input_tokens || 0);
  const cWrite = Number(
    (usage.cache_creation && usage.cache_creation.ephemeral_5m_input_tokens) ||
    usage.cache_creation_input_tokens ||
    0
  );
  return (promptTok * rates.in + compTok * rates.out + cRead * rates.cacheRead + cWrite * rates.cacheWrite) / 1e6;
}

function formatIsoStamp(epochMs) {
  const d = new Date(epochMs || Date.now());
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function loadEmbeddedMascotDataUri() {
  try {
    const logoFile = path.join(__dirname, '..', 'assets', 'logo-dark.png');
    if (fs.existsSync(logoFile)) {
      return `data:image/png;base64,${fs.readFileSync(logoFile).toString('base64')}`;
    }
  } catch { /* fallback to TrackPoint indicator */ }
  return '';
}

function parseJsonlSessionFile(filePath) {
  let content = '';
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size === 0 || st.size > 32 * 1024 * 1024) return null;
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }

  let workspaceCwd = '';
  let sessionTitle = '';
  let firstPrompt = '';
  const userPrompts = [];
  let lastAssistantText = '';
  let explicitCostUsd = null;
  let startedAtMs = null;
  let lastTimestampMs = null;
  let activeDurationMs = 0;
  let turnCount = 0;
  const seenMsgIds = new Set();
  const modelCounts = {};
  const tokenBuckets = {
    promptTokens: 0,
    completionTokens: 0,
    cachedReadTokens: 0,
    cachedWriteTokens: 0,
  };
  let estimatedCostUsd = 0;

  for (const line of content.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let entry;
    try { entry = JSON.parse(t); } catch { continue; }

    if (!workspaceCwd && typeof entry.cwd === 'string') workspaceCwd = entry.cwd;
    if (entry.type === 'custom-title' && typeof entry.customTitle === 'string' && entry.customTitle.trim()) {
      sessionTitle = entry.customTitle.trim().slice(0, 64);
    }
    if (entry.type === 'cost-state' && typeof entry.totalCostUSD === 'number' && entry.totalCostUSD > 0) {
      explicitCostUsd = Math.max(explicitCostUsd || 0, entry.totalCostUSD);
    }

    const ts = entry.timestamp ? Date.parse(entry.timestamp) : NaN;
    if (Number.isFinite(ts)) {
      if (startedAtMs === null || ts < startedAtMs) startedAtMs = ts;
      if (lastTimestampMs !== null && ts > lastTimestampMs && ts - lastTimestampMs <= 25 * 60000) {
        activeDurationMs += ts - lastTimestampMs;
      }
      lastTimestampMs = ts;
    }

    if (entry.type === 'user' && !entry.isMeta) {
      const msgContent = entry.message && entry.message.content;
      const textPart = typeof msgContent === 'string'
        ? msgContent
        : Array.isArray(msgContent)
          ? ((msgContent.find((b) => b && b.type === 'text') || {}).text || '')
          : '';
      if (textPart && !textPart.trim().startsWith('<') && !textPart.trim().startsWith('/')) {
        const cleanPrompt = textPart.trim().slice(0, 2400);
        if (!firstPrompt) firstPrompt = cleanPrompt;
        if (userPrompts.length < 3) userPrompts.push(cleanPrompt);
      }
      const isToolResult = Array.isArray(msgContent) && msgContent.some((b) => b && b.type === 'tool_result');
      if (!isToolResult) turnCount++;
    }

    if (entry.type === 'assistant' && entry.message && entry.message.model && entry.message.model !== '<synthetic>') {
      const { id, model, usage, content: aContent } = entry.message;
      if (Array.isArray(aContent)) {
        const txtBlock = aContent.find((b) => b && b.type === 'text' && typeof b.text === 'string' && b.text.trim());
        if (txtBlock) lastAssistantText = txtBlock.text.trim().slice(0, 1200);
      } else if (typeof aContent === 'string' && aContent.trim()) {
        lastAssistantText = aContent.trim().slice(0, 1200);
      }
      modelCounts[model] = (modelCounts[model] || 0) + 1;
      if (id && usage && !seenMsgIds.has(id)) {
        seenMsgIds.add(id);
        tokenBuckets.promptTokens += Number(usage.input_tokens || 0);
        tokenBuckets.completionTokens += Number(usage.output_tokens || 0);
        tokenBuckets.cachedReadTokens += Number(usage.cache_read_input_tokens || 0);
        tokenBuckets.cachedWriteTokens += Number(usage.cache_creation_input_tokens || 0);
        const msgCost = computeMessageCostUsd(model, usage);
        if (msgCost !== null) estimatedCostUsd += msgCost;
      }
    }
  }

  const models = Object.keys(modelCounts);
  if (!startedAtMs || turnCount === 0 || models.length === 0) return null;
  const primaryModel = models.sort((a, b) => modelCounts[b] - modelCounts[a])[0];
  const totalCostUsd = explicitCostUsd !== null ? Math.max(explicitCostUsd, estimatedCostUsd) : estimatedCostUsd;

  const redactSecrets = (s) => String(s || '').replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,})\b/g, '[REDACTED]');

  return {
    workspaceCwd,
    startedAtMs,
    taskTitle: extractSessionTaskTitle(sessionTitle, firstPrompt, lastAssistantText),
    fullPrompt: redactSecrets(userPrompts.join('\n\n─── Next Turn ───\n').slice(0, 2400)),
    assistantSummary: redactSecrets(lastAssistantText.slice(0, 1200)),
    modelId: primaryModel,
    turnCount,
    activeDurationMs,
    tokenBuckets,
    totalCostUsd: +totalCostUsd.toFixed(4),
  };
}

function readExistingJsonlRecords(jsonlPath) {
  const byId = new Map();
  const sessionKeyToRecordId = new Map();
  try {
    if (!fs.existsSync(jsonlPath)) return byId;
    for (const line of fs.readFileSync(jsonlPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        const rec = JSON.parse(t);
        if (!rec || !rec.recordId) continue;
        if (rec.sessionId && sessionKeyToRecordId.has(rec.sessionId)) {
          const prevId = sessionKeyToRecordId.get(rec.sessionId);
          const prev = byId.get(prevId);
          if (prev) {
            if (STALE_TITLE_RE.test(String(prev.taskTitle || '').trim()) && !STALE_TITLE_RE.test(String(rec.taskTitle || '').trim())) {
              prev.taskTitle = rec.taskTitle;
            }
            if (!prev.fullPrompt && rec.fullPrompt) prev.fullPrompt = rec.fullPrompt;
            if (!prev.assistantSummary && rec.assistantSummary) prev.assistantSummary = rec.assistantSummary;
            prev.reusePercent = prev.reusePercent ?? rec.reusePercent;
            prev.reusedSymbolCount = Math.max(prev.reusedSymbolCount || 0, rec.reusedSymbolCount || 0);
            prev.newSymbolCount = Math.max(prev.newSymbolCount || 0, rec.newSymbolCount || 0);
            prev.linesInserted = Math.max(prev.linesInserted || 0, rec.linesInserted || 0);
            prev.linesDeleted = Math.max(prev.linesDeleted || 0, rec.linesDeleted || 0);
            prev.guardBlockCount = Math.max(prev.guardBlockCount || 0, rec.guardBlockCount || 0);
            continue;
          }
        }
        if (rec.sessionId) sessionKeyToRecordId.set(rec.sessionId, rec.recordId);
        byId.set(rec.recordId, rec);
      } catch {}
    }
  } catch {}
  return byId;
}

function generateCommandCenterHtml(records, workspacesMeta = {}, generatedAtMs = Date.now()) {
  const logoUri = loadEmbeddedMascotDataUri();
  const safePayload = JSON.stringify({ records, workspacesMeta, generatedAtMs }).replace(/</g, '\\u003c');
  const crestGraphic = logoUri
    ? `<img src="${logoUri}" alt="NeckBeard Mascot" style="width:46px;height:46px;border-radius:10px;border:1px solid rgba(16,185,129,0.4)">`
    : `<span class="tp"></span>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>NeckBeard Security &amp; Engineering Command Center</title>
<style>
:root{color-scheme:dark;--bg:#060908;--surface:#0b110e;--card:#101814;--border:#1d2b23;--emerald:#10b981;--cyan:#06b6d4;--amber:#f59e0b;--red:#ef4444;--text:#ecf3ef;--muted:#8b9d92;--dim:#55665c;--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;--sans:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.shell{display:grid;grid-template-columns:292px minmax(0,1fr);min-height:100vh}
.rail{background:var(--surface);border-right:1px solid var(--border);padding:20px 14px;display:flex;flex-direction:column;gap:5px;position:sticky;top:0;height:100vh}
.crest{display:flex;align-items:center;gap:12px;padding:4px 8px 16px;border-bottom:1px solid var(--border);margin-bottom:8px}
.tp{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red)}
.crest-title{font:800 16px/1.1 var(--mono);color:var(--text);display:flex;align-items:center;gap:7px}
.crest-sub{font:600 10.5px var(--mono);color:var(--emerald);margin-top:4px;letter-spacing:.05em}
.rail-lbl{font:700 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);padding:6px 10px 4px;display:flex;justify-content:space-between}
.ws-btn{display:flex;justify-content:space-between;align-items:center;width:100%;border:1px solid transparent;background:transparent;color:var(--muted);font:500 12.5px var(--sans);padding:8px 10px;border-radius:9px;cursor:pointer;text-align:left;gap:6px;transition:background .12s,border-color .12s}
.ws-btn:hover{background:rgba(16,24,20,.7);color:var(--text)}
.ws-btn.active{background:var(--card);color:var(--text);border-color:var(--emerald);box-shadow:inset 3px 0 0 var(--emerald)}
.ws-ncol{min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ws-badges{display:inline-flex;align-items:center;gap:5px;flex-shrink:0}
.ws-vtag{font:700 9px var(--mono);color:var(--cyan);background:rgba(6,182,212,.14);border:1px solid rgba(6,182,212,.35);padding:1px 5px;border-radius:99px}
.ws-ctag{font:600 10.5px var(--mono);color:var(--amber)}
.ws-cnt{font:600 11px var(--mono);color:var(--emerald);background:rgba(16,185,129,.12);padding:1px 6px;border-radius:99px}
.rail-foot{margin-top:auto;padding:12px 10px 4px;border-top:1px solid var(--border);font:500 11px/1.55 var(--mono);color:var(--dim)}
.stage{padding:24px 32px 64px;max-width:1520px;width:100%}
.topbar{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap;padding-bottom:18px;border-bottom:1px solid var(--border)}
.t-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.topbar h1{margin:0;font:800 24px/1.15 var(--mono);letter-spacing:-.02em}
.topbar p{margin:5px 0 0;color:var(--muted);font:400 12.5px var(--mono)}
.back-btn{display:none;border:1px solid rgba(16,185,129,.45);background:rgba(16,185,129,.14);color:var(--emerald);font:600 11.5px var(--mono);padding:4px 10px;border-radius:99px;cursor:pointer}
.back-btn:hover{background:rgba(16,185,129,.25)}
.views{display:inline-flex;background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:4px;gap:4px;flex-wrap:wrap}
.v-btn{border:0;background:transparent;color:var(--muted);font:600 12px var(--mono);padding:8px 13px;border-radius:8px;cursor:pointer}
.v-btn.active{background:var(--card);color:var(--emerald);box-shadow:inset 0 0 0 1px rgba(16,185,129,.35)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:18px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:15px;padding:16px 18px}
.m-tag{font:700 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between}
.m-val{font:800 24px/1.15 var(--mono);margin-top:7px;color:var(--text)}
.m-sub{font:400 11.5px var(--mono);color:var(--muted);margin-top:5px}
.m-comp{font:600 11px var(--mono);color:var(--cyan);margin-top:4px}
.card-sec{margin-top:18px;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px 22px}
.card-sec.econ-hi{border-color:rgba(16,185,129,.4);background:linear-gradient(180deg,rgba(16,185,129,.05) 0%,var(--card) 100%)}
.card-sec.vibes-hi{border-color:rgba(6,182,212,.45);background:linear-gradient(180deg,rgba(6,182,212,.05) 0%,var(--card) 100%)}
.sec-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.sec-head h2{margin:0;font:700 15.5px var(--mono);display:flex;align-items:center;gap:10px}
.split2{display:grid;grid-template-columns:1.15fr .85fr;gap:16px;margin-top:14px}
.vpillars{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-top:12px}
.pbox{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.pk{font:700 10.5px var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--cyan)}
.pv{font:800 19px/1.2 var(--mono);margin-top:5px;color:var(--text)}
.ps{font:400 11px var(--mono);color:var(--muted);margin-top:4px}
.adopt-bar{background:rgba(6,182,212,.07);border:1px dashed rgba(6,182,212,.45);border-radius:12px;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}
.adopt-cmd{font:500 11.5px var(--mono);background:#060908;border:1px solid var(--border);padding:7px 11px;border-radius:8px;color:var(--emerald)}
.act-btn{border:1px solid rgba(6,182,212,.45);background:rgba(6,182,212,.14);color:var(--cyan);font:600 11.5px var(--mono);padding:6px 12px;border-radius:8px;cursor:pointer}
.act-btn:hover{background:rgba(6,182,212,.25)}
.s-in{background:var(--surface);border:1px solid var(--border);color:var(--text);font:500 12px var(--mono);padding:6px 11px;border-radius:8px;min-width:220px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;font:600 10.5px var(--mono);text-transform:uppercase;letter-spacing:.05em;color:var(--dim);padding:9px 10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface)}
td{padding:9px 10px;border-bottom:1px solid var(--border);font-family:var(--mono)}
td.tcol{font-family:var(--sans);font-weight:600}
tr.crow{cursor:pointer}tr.crow:hover{background:rgba(16,185,129,.08)}
tr.srow{background:rgba(16,185,129,.16);box-shadow:inset 3px 0 0 var(--emerald)}
tr.brow{background:rgba(6,182,212,.09);font-weight:700}
.sb-w{display:inline-flex;align-items:center;gap:6px;width:100%}
.sb-bg{width:54px;height:7px;background:#080d0b;border-radius:4px;overflow:hidden;border:1px solid var(--border);display:inline-block}
.sb-f{height:100%;background:var(--emerald);display:block}
.chip{display:inline-block;padding:3px 9px;border-radius:99px;font:600 11px var(--mono);background:rgba(16,185,129,.14);color:var(--emerald)}
.chip.cyan{background:rgba(6,182,212,.16);color:var(--cyan)}
.chip.warn{background:rgba(245,158,11,.16);color:var(--amber)}
@media(max-width:1180px){.shell{grid-template-columns:1fr}.rail{border-right:0;border-bottom:1px solid var(--border);position:static;height:auto}.kpis,.vpillars,.split2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="shell">
  <aside class="rail">
    <div class="crest">
      ${crestGraphic}
      <div>
        <div class="crest-title"><span class="tp"></span>NECKBEARD</div>
        <div class="crest-sub">SAFE · RIGHT-SIZED · DONE</div>
      </div>
    </div>
    <div class="rail-lbl"><span>Workspaces (<span id="ws-total-cnt">0</span>)</span><span>Spend / Sess</span></div>
    <div id="ws-list" style="overflow-y:auto;flex:1"></div>
    <div class="rail-foot">NeckBeard Command Center v0.3.2<br>Economics + 3-Gate + VIBES Hub<br>100% Local · Zero Network Calls</div>
  </aside>
  <main class="stage">
    <header class="topbar">
      <div>
        <div class="t-row">
          <h1 id="st-title">All Workspaces</h1>
          <button type="button" id="back-all-btn" class="back-btn">← Compare All Workspaces</button>
          <span id="st-vibes-pill" class="chip cyan" style="display:none"></span>
        </div>
        <p id="st-subtitle"></p>
      </div>
      <div class="views" role="tablist">
        <button type="button" class="v-btn active" data-view="overview">1. Command Overview</button>
        <button type="button" class="v-btn" data-view="economics">2. Economics &amp; All-Workspaces ROI</button>
        <button type="button" class="v-btn" data-view="vibes">3. VIBES (.ai-audit) Hub</button>
        <button type="button" class="v-btn" data-view="topology">4. Trust-Boundary Graph</button>
        <button type="button" class="v-btn" data-view="forensics">5. Session Forensics</button>
      </div>
    </header>
    <div class="kpis">
      <div class="panel"><div class="m-tag"><span>API Spend &amp; Unit Economics</span><span style="color:var(--emerald)">ECONOMICS</span></div><div class="m-val" id="m-cost">$0.00</div><div class="m-sub" id="m-cost-unit">$0.00 / session · $0.00 / turn</div><div class="m-comp" id="m-cost-comp">100% of portfolio spend</div></div>
      <div class="panel"><div class="m-tag"><span>Prompt-Cache Dollar Savings</span><span style="color:var(--cyan)">CACHE ROI</span></div><div class="m-val" id="m-saved" style="color:var(--cyan)">$0.00 saved</div><div class="m-sub" id="m-cache">0% cache hit rate · 0 tokens</div><div class="m-comp" id="m-cache-comp">Prompt caching efficiency</div></div>
      <div class="panel"><div class="m-tag"><span>Agent Compute vs. Wall-Clock Time</span><span style="color:var(--amber)">VELOCITY</span></div><div class="m-val" id="m-time">0h 0m</div><div class="m-sub" id="m-turns">0 sessions · 0 turns</div><div class="m-comp" id="m-load">Agent vs. wall-clock work volume</div></div>
      <div class="panel"><div class="m-tag"><span>Security Shield &amp; Code Delta</span><span style="color:var(--emerald)">3 GATES</span></div><div class="m-val" id="m-sec">0 blocked</div><div class="m-sub" id="m-loc">+0 / -0 LOC · 0/0 issues fixed</div><div class="m-comp" id="m-vibes">PreToolUse &amp; VIBES status</div></div>
    </div>

    <!-- FRONT-AND-CENTER SECTION 1: ECONOMICS, CACHE SAVINGS & ALL-WORKSPACES BENCHMARKING -->
    <section class="card-sec econ-hi" id="pane-economics">
      <div class="sec-head">
        <h2><span id="econ-title">Front-and-Center Economics: Spend vs. Prompt-Cache Savings &amp; Workspace Comparison</span></h2>
        <span id="econ-badge" class="chip">All Workspaces Baseline</span>
      </div>
      <div style="background:#080d0b;border:1px solid var(--border);border-radius:12px;padding:14px">
        <svg id="velocity-svg" viewBox="0 0 960 235" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div class="split2">
        <div>
          <div style="font:700 11.5px var(--mono);color:var(--emerald);margin-bottom:8px;display:flex;justify-content:space-between">
            <span>WORKSPACE VS. ALL-WORKSPACES ECONOMICS MATRIX (CLICK ANY ROW TO INSPECT)</span>
          </div>
          <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:330px">
            <table><thead><tr><th>Workspace</th><th>Sessions / Turns</th><th>Agent / Wall Time</th><th>Cache Hit %</th><th>Est. Saved</th><th>Actual Spend</th><th>Share of Total</th><th>VIBES</th></tr></thead><tbody id="repo-scorecard-rows"></tbody></table>
          </div>
        </div>
        <div>
          <div style="font:700 11.5px var(--mono);color:var(--amber);margin-bottom:8px;display:flex;justify-content:space-between">
            <span id="model-table-title">MODEL &amp; PROMPT-CACHE ECONOMICS (SELECTED SCOPE)</span>
          </div>
          <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:330px">
            <table><thead><tr><th>Model</th><th>Sess / Turns</th><th>Input + Cache</th><th>Output</th><th>Cache Hit</th><th>Est. Saved</th><th>Spend</th></tr></thead><tbody id="model-econ-rows"></tbody></table>
          </div>
        </div>
      </div>
    </section>

    <!-- SECTION 2: VIBES PROTOCOL (.ai-audit/) PROVENANCE & PRISM RISK HUB -->
    <section class="card-sec vibes-hi" id="pane-vibes">
      <div class="sec-head">
        <h2>
          <span id="vibes-heading">VIBES Protocol (.ai-audit/) Provenance &amp; PRISM Risk Intelligence</span>
          <a href="https://www.itsavibe.ai" target="_blank" rel="noopener" class="chip cyan">itsavibe.ai ↗</a>
        </h2>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span id="vibes-status-chip" class="chip">Checking .ai-audit/...</span>
          <button type="button" id="vibes-demo-btn" class="act-btn">Preview Reference VIBES Forensics</button>
        </div>
      </div>
      <p id="vibes-explainer" style="margin:0 0 10px;color:var(--muted);font-size:12.5px"></p>
      <div id="vibes-active-body">
        <div class="vpillars">
          <div class="pbox"><div class="pk">1. VIBES v1.1 Provenance</div><div class="pv" id="vp-prov">0 annotations</div><div class="ps" id="vp-prov-sub">0 blobs · 0 files attributed</div></div>
          <div class="pbox"><div class="pk">2. VERIFY v1.0 DSSE</div><div class="pv" id="vp-verify">0% verified</div><div class="ps" id="vp-verify-sub">0 Ed25519 DSSE envelopes</div></div>
          <div class="pbox"><div class="pk">3. PRISM v1.0 Risk</div><div class="pv" id="vp-prism">0.00 max</div><div class="ps" id="vp-prism-sub">0 High/Critical (&gt;= 0.60)</div></div>
          <div class="pbox"><div class="pk">4. EVOLVE v1.0 Decisions</div><div class="pv" id="vp-evolve">0 decisions</div><div class="ps" id="vp-evolve-sub">Linked to /neckbeard-debt</div></div>
          <div class="pbox"><div class="pk">5. TRACE v1.0 Forensics</div><div class="pv" id="vp-trace">0 / 0 fixed</div><div class="ps" id="vp-trace-sub">IoC rules &amp; incident response</div></div>
        </div>
        <div style="margin-top:14px;background:#080d0b;border:1px solid var(--border);border-radius:12px;padding:14px">
          <svg id="vibes-svg" viewBox="0 0 960 250" style="width:100%;height:auto;display:block"></svg>
        </div>
        <div class="split2">
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px">
            <div style="font:700 11.5px var(--mono);color:var(--emerald);margin-bottom:8px">EVOLVE ARCHITECTURAL DECISIONS &amp; PRETOOLUSE IMMUTABILITY SHIELD</div>
            <div id="vibes-decisions-list" style="font:400 12px/1.6 var(--mono);color:var(--muted)"></div>
          </div>
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px">
            <div style="font:700 11.5px var(--mono);color:var(--amber);margin-bottom:8px">TRACE INCIDENT LOG &amp; HIGH-RISK PRISM EDITS (&gt;= 0.60)</div>
            <div id="vibes-incidents-list" style="font:400 12px/1.6 var(--mono);color:var(--muted)"></div>
          </div>
        </div>
        <div id="vibes-annotations-wrap" style="margin-top:14px">
          <div style="font:700 11.5px var(--mono);color:var(--cyan);margin-bottom:8px">TURN-LEVEL .AI-AUDIT/ANNOTATIONS.JSONL PROVENANCE &amp; PRISM INSPECTOR</div>
          <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:290px">
            <table><thead><tr><th>Timestamp</th><th>Session</th><th>Attributed File</th><th>Line Attribution</th><th>PRISM Risk</th><th>VERIFY DSSE</th><th>Intent / Prompt Summary</th></tr></thead><tbody id="vibes-annotations-rows"></tbody></table>
          </div>
        </div>
      </div>
      <div class="adopt-bar" id="vibes-adopt-banner" style="display:none">
        <div style="max-width:680px">
          <div style="font:700 12.5px var(--mono);color:var(--cyan)">Enable VIBES (.ai-audit/) Provenance in <span id="vibes-adopt-ws">this workspace</span></div>
          <div style="font-size:12px;color:var(--muted);margin-top:3px">
            Add content-addressed line attribution, Ed25519 DSSE attestations locked by <code>hooks/guard.js</code>, PRISM risk scoring for <code>/neckbeard-review</code>, and TRACE forensics:
          </div>
        </div>
        <div class="adopt-cmd" id="vibes-adopt-cmd">vibecheck init --project-name my-app --assurance-level high &amp;&amp; vibes install-hooks &amp;&amp; vibecheck verify</div>
      </div>
    </section>

    <section class="card-sec" id="pane-overview">
      <div class="sec-head">
        <div>
          <h2 id="topo-heading">External → Project Modules → Internal Trust-Boundary Graph</h2>
          <div id="topo-summary" style="font:400 12px var(--mono);color:var(--muted);margin-top:3px"></div>
        </div>
        <span id="ov-drift" class="chip">✓ Baseline Verified</span>
      </div>
      <div style="background:#080d0b;border:1px solid var(--border);border-radius:12px;padding:12px">
        <svg id="boundary-svg" viewBox="0 0 960 420" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div style="margin-top:14px">
        <div style="font:700 11.5px var(--mono);color:var(--emerald);margin-bottom:8px;display:flex;justify-content:space-between">
          <span id="boundary-table-title">PER-FILE TRUST-BOUNDARY &amp; CROSS-BOUNDARY BRIDGE MATRIX</span>
          <span id="boundary-table-count" style="color:var(--muted)"></span>
        </div>
        <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:290px">
          <table>
            <thead>
              <tr>
                <th>Module / Directory</th>
                <th>Source File</th>
                <th>External [ext] Sinks</th>
                <th>Internal [int] Sinks</th>
                <th>Boundary Role &amp; Audit Priority</th>
              </tr>
            </thead>
            <tbody id="boundary-file-rows"></tbody>
          </table>
        </div>
      </div>
    </section>
    <section class="card-sec" id="pane-forensics">
      <div class="sec-head">
        <h2 id="forensics-heading">Recorded Engineering &amp; Audit Sessions</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input type="search" id="session-search" class="s-in" placeholder="Filter by task, repo, model...">
          <span id="tbl-count" class="chip">0 sessions</span>
        </div>
      </div>
      <div style="overflow-x:auto"><table><thead><tr><th>Task / Prompt</th><th>Workspace</th><th>Timestamp</th><th>Model &amp; Level</th><th>Duration</th><th>Cost &amp; Tokens</th><th>Cache Saved</th><th>Guard &amp; VIBES</th><th>Verification</th></tr></thead><tbody id="session-rows"></tbody></table></div>
    </section>
  </main>
</div>
<script type="application/json" id="nb-telemetry-payload">${safePayload}</script>
<script>
(function(){
  var payload=JSON.parse(document.getElementById('nb-telemetry-payload').textContent);
  var records=payload.records||[],meta=payload.workspacesMeta||{},activeWorkspace='',activeView='overview',demoVibesMode=false,searchQuery='';
  var SAMPLE_VIBES={
    present:true,isDemo:true,annotationsCount:48,verifiedCount:46,blobsCount:94,attestationsCount:46,iocRulesCount:12,hasAuditDb:true,
    maxPrismRisk:0.78,highRiskCount:4,traceIncidents:2,traceResolved:2,decisions:5,linesAdded:312,linesRemoved:840,filesTouchedCount:14,
    prismBuckets:{low:31,moderate:13,high:3,critical:1},
    fileHotspots:[
      {file:'src/routes/webhooks.js',annotations:9,linesAdded:42,linesRemoved:188,maxRisk:0.78,verified:true},
      {file:'src/auth/session.js',annotations:7,linesAdded:28,linesRemoved:94,maxRisk:0.68,verified:true},
      {file:'src/db/invoices.js',annotations:8,linesAdded:35,linesRemoved:210,maxRisk:0.54,verified:true},
      {file:'hooks/guard.js',annotations:6,linesAdded:64,linesRemoved:30,maxRisk:0.41,verified:true},
      {file:'src/lib/archive.js',annotations:5,linesAdded:19,linesRemoved:82,maxRisk:0.24,verified:true}
    ],
    decisionRecords:[
      {id:'DEC-01',title:'Enforce server-side org_id object auth at SQL query layer',status:'verified',timestamp:'2026-11-21'},
      {id:'DEC-02',title:'Cap batch webhook payload at 64KB and 500 items for 250 rps target',status:'verified',timestamp:'2026-11-21'},
      {id:'DEC-03',title:'Defer Redis rate-limit cache until load crosses 1,000 rps (risk: linked)',status:'accepted',timestamp:'2026-11-21'}
    ],
    incidentRecords:[
      {id:'INC-01',iocId:'TRACE-SECRET-AWS',severity:'critical',status:'resolved',summary:'Blocked hardcoded AWS key attempt via NeckBeard PreToolUse guard',timestamp:'2026-11-21'},
      {id:'INC-02',iocId:'PRISM-HIGH-0.78',severity:'high',status:'resolved',summary:'Webhook HMAC signature verification hardened & DSSE attested',timestamp:'2026-11-21'}
    ],
    recentAnnotations:[
      {timestamp:'2026-11-21 22:18',sessionId:'sess-91a4f0',model:'claude-opus-5-5',file:'src/routes/webhooks.js',linesAdded:14,linesRemoved:96,riskScore:0.78,verified:true,summary:'Verify Stripe HMAC raw body at edge & atomic UPDATE'},
      {timestamp:'2026-11-21 21:54',sessionId:'sess-91a4f0',model:'claude-opus-5-5',file:'src/auth/session.js',linesAdded:11,linesRemoved:48,riskScore:0.68,verified:true,summary:'Require server-side org_id ownership check on every route'},
      {timestamp:'2026-11-21 21:10',sessionId:'sess-83c2d1',model:'claude-sonnet-4-6',file:'src/db/invoices.js',linesAdded:9,linesRemoved:112,riskScore:0.54,verified:true,summary:'Replace N+1 query loop with parameterized ANY($1::uuid[])'},
      {timestamp:'2026-11-21 20:42',sessionId:'sess-83c2d1',model:'claude-sonnet-4-6',file:'src/lib/archive.js',linesAdded:8,linesRemoved:34,riskScore:0.24,verified:true,summary:'Canonicalize path with fs.realpathSync before root prefix check'}
    ]
  };
  function el(i){return document.getElementById(i)}
  function fmtTok(n){return n<1000?String(Math.round(n)):n<1e6?+(n/1e3).toFixed(1)+'k':+(n/1e6).toFixed(1)+'M'}
  function fmtDur(ms){var m=Math.round((ms||0)/60000);return m<60?m+'m':Math.floor(m/60)+'h '+(m%60)+'m'}
  function fmtUsd(n){return '$'+Number(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}
  function estSaved(r){
    var tb=(r&&r.tokenBuckets)||{},cr=tb.cachedReadTokens||0;if(cr<=0)return 0;
    var m=String((r&&r.modelId)||'').toLowerCase(),rate=m.includes('opus')?4.0:m.includes('haiku')?0.5:2.5;
    return(cr/1e6)*rate;
  }
  function sumList(list){
    var s={sessions:list.length,turns:0,cost:0,saved:0,tok:0,cRead:0,inAll:0,outTok:0,dur:0,wallDur:0,parallelFactor:1,activeDays:1,ins:0,del:0,blk:0,found:0,fixed:0};
    var ivs=[],days={};
    list.forEach(function(r){
      s.cost+=r.totalCostUsd||0;s.saved+=estSaved(r);
      var tb=r.tokenBuckets||{},pT=tb.promptTokens||0,cT=tb.completionTokens||0,crT=tb.cachedReadTokens||0,cwT=tb.cachedWriteTokens||0;
      s.tok+=pT+cT+crT+cwT;s.cRead+=crT;s.inAll+=pT+crT+cwT;s.outTok+=cT;
      var d=Math.max(0,r.activeDurationMs||0);
      s.dur+=d;s.turns+=r.turnCount||1;
      if(r.startedAtMs&&d>0)ivs.push([r.startedAtMs,r.startedAtMs+d]);
      if(r.timestampIso)days[String(r.timestampIso).slice(0,10)]=1;
      s.ins+=r.linesInserted||0;s.del+=r.linesDeleted||0;s.blk+=r.guardBlockCount||0;
      s.found+=r.securityFindingsTotal||0;s.fixed+=r.securityFindingsResolved||0;
    });
    ivs.sort(function(a,b){return a[0]-b[0]});
    var cs=-1,ce=-1;
    for(var i=0;i<ivs.length;i++){
      var st=ivs[i][0],en=ivs[i][1];
      if(cs===-1){cs=st;ce=en}
      else if(st<=ce){if(en>ce)ce=en}
      else{s.wallDur+=(ce-cs);cs=st;ce=en}
    }
    if(cs!==-1)s.wallDur+=(ce-cs);
    if(s.wallDur<=0)s.wallDur=s.dur;
    s.parallelFactor=s.wallDur>0?+(s.dur/s.wallDur).toFixed(2):1;
    s.activeDays=Math.max(1,Object.keys(days).length);
    s.cacheHitPct=s.inAll>0?Math.round((s.cRead/s.inAll)*100):0;
    s.costPerSession=s.sessions>0?s.cost/s.sessions:0;
    s.costPerTurn=s.turns>0?s.cost/s.turns:0;
    s.turnsPerSession=s.sessions>0?s.turns/s.sessions:0;
    return s;
  }
  var portStats=sumList(records);
  function selectWs(wsName){
    activeWorkspace=wsName||'';
    document.querySelectorAll('.ws-btn').forEach(function(b){
      var bw=b.getAttribute('data-ws')||'';
      b.classList.toggle('active',bw===activeWorkspace);
    });
    render();
  }
  function aggAllVibes(){
    var ks=Object.keys(meta),agg={present:false,vibesRepoCount:0,annotationsCount:0,verifiedCount:0,blobsCount:0,attestationsCount:0,iocRulesCount:0,maxPrismRisk:0,highRiskCount:0,traceIncidents:0,traceResolved:0,decisions:0,linesAdded:0,linesRemoved:0,filesTouchedCount:0,manifestCounts:{environment:0,reasoning:0,command:0,prompt:0,decision:0,total:0},prismBuckets:{low:0,moderate:0,high:0,critical:0},fileHotspots:[],decisionRecords:[],incidentRecords:[],recentAnnotations:[]};
    ks.forEach(function(k){
      var v=meta[k]&&meta[k].vibes;if(!v||!v.present)return;
      agg.present=true;agg.vibesRepoCount+=1;
      agg.annotationsCount+=v.annotationsCount||0;agg.verifiedCount+=v.verifiedCount||0;
      agg.blobsCount+=v.blobsCount||0;agg.attestationsCount+=v.attestationsCount||0;agg.iocRulesCount+=v.iocRulesCount||0;
      var mc=v.manifestCounts||{};
      agg.manifestCounts.environment+=mc.environment||0;agg.manifestCounts.reasoning+=mc.reasoning||0;
      agg.manifestCounts.command+=mc.command||0;agg.manifestCounts.prompt+=mc.prompt||0;
      agg.manifestCounts.decision+=mc.decision||0;agg.manifestCounts.total+=mc.total||0;
      if((v.maxPrismRisk||0)>agg.maxPrismRisk)agg.maxPrismRisk=v.maxPrismRisk;
      agg.highRiskCount+=v.highRiskCount||0;agg.traceIncidents+=v.traceIncidents||0;agg.traceResolved+=v.traceResolved||0;
      agg.decisions+=v.decisions||0;agg.linesAdded+=v.linesAdded||0;agg.linesRemoved+=v.linesRemoved||0;agg.filesTouchedCount+=v.filesTouchedCount||0;
      var pb=v.prismBuckets||{};agg.prismBuckets.low+=pb.low||0;agg.prismBuckets.moderate+=pb.moderate||0;agg.prismBuckets.high+=pb.high||0;agg.prismBuckets.critical+=pb.critical||0;
      (v.fileHotspots||[]).forEach(function(h){agg.fileHotspots.push(Object.assign({},h,{file:k+':'+h.file}))});
      (v.decisionRecords||[]).forEach(function(d){agg.decisionRecords.push(Object.assign({},d,{id:k+'/'+d.id}))});
      (v.incidentRecords||[]).forEach(function(inc){agg.incidentRecords.push(Object.assign({},inc,{iocId:k+':'+inc.iocId}))});
      (v.recentAnnotations||[]).forEach(function(a){agg.recentAnnotations.push(Object.assign({},a,{file:k+':'+a.file}))});
    });
    if(!agg.present)return null;
    agg.fileHotspots.sort(function(a,b){return(b.maxRisk-a.maxRisk)||((b.linesAdded+b.linesRemoved)-(a.linesAdded+a.linesRemoved))});
    agg.recentAnnotations.sort(function(a,b){return String(b.timestamp||'').localeCompare(String(a.timestamp||''))});
    return agg;
  }
  function resolveVibes(wsKey){
    if(demoVibesMode)return SAMPLE_VIBES;
    if(wsKey)return(meta[wsKey]&&meta[wsKey].vibes&&meta[wsKey].vibes.present)?meta[wsKey].vibes:null;
    return aggAllVibes();
  }
  function renderVibes(wsKey){
    var v=resolveVibes(wsKey),chip=el('vibes-status-chip'),dbtn=el('vibes-demo-btn'),exp=el('vibes-explainer'),abody=el('vibes-active-body'),abar=el('vibes-adopt-banner'),aws=el('vibes-adopt-ws'),acmd=el('vibes-adopt-cmd');
    el('vibes-heading').textContent=wsKey?('VIBES (.ai-audit/) Provenance & PRISM Risk — '+wsKey):'VIBES Protocol (.ai-audit/) Provenance & PRISM Risk — All Workspaces';
    if(aws)aws.textContent=wsKey||'this workspace';
    if(acmd)acmd.textContent='vibecheck init --project-name '+(wsKey||'my-app')+' --assurance-level high && vibes install-hooks && vibecheck verify';
    if(v&&v.present){
      chip.className=v.isDemo?'chip warn':'chip cyan';
      chip.textContent=v.isDemo?'★ Interactive Reference VIBES (.ai-audit/) Forensics Active':(v.vibesRepoCount?('● VIBES Active Across '+v.vibesRepoCount+' Workspaces'):('● VIBES Active in '+wsKey));
      dbtn.textContent=v.isDemo?'Exit Reference Preview':'Preview Reference Dataset';
      exp.innerHTML='<strong>5-Pillar VIBES Deep Forensics Active:</strong> Showing line-range file attribution (<code>VIBES v1.1</code>), Ed25519 DSSE &amp; high-assurance attestation coverage (<code>VERIFY v1.0</code>), PRISM risk distribution &amp; trajectory (<code>PRISM v1.0</code>), content-addressed reasoning &amp; decisions (<code>EVOLVE v1.0</code>), and TRACE incident response (<code>TRACE v1.0</code>).';
      if(abody)abody.style.display='block';
      if(abar)abar.style.display='none';
    }else{
      chip.className='chip warn';
      chip.textContent='○ .ai-audit/ Not Initialized in '+(wsKey||'Workspace');
      dbtn.textContent='Preview Reference VIBES Forensics';
      exp.innerHTML='<strong>Standard Telemetry Active for '+(wsKey||'Workspace')+':</strong> Economics, cache ROI, trust boundaries, and session logs are active above and below. Initialize <strong><a href="https://www.itsavibe.ai" target="_blank" rel="noopener">VIBES (.ai-audit/)</a></strong> to add cryptographic file attribution and PRISM risk scoring.';
      if(abody)abody.style.display='none';
      if(abar)abar.style.display='flex';
      return;
    }
    var ac=v.annotationsCount||0,mc=v.manifestCounts||{},mTot=mc.total||0;
    var baseCnt=ac>0?ac:(mTot>0?mTot:1);
    var vp=Math.min(100,Math.round(((v.verifiedCount||0)/baseCnt)*100));
    el('vp-prov').textContent=ac>0?(ac.toLocaleString()+' annotations'):(mTot.toLocaleString()+' manifest entries');
    el('vp-prov-sub').textContent=(mTot||v.blobsCount||0).toLocaleString()+' manifest entries · '+(v.filesTouchedCount||0)+' files · v'+(v.standardVersion||'1.1');
    el('vp-verify').textContent=vp+'% verified';
    el('vp-verify-sub').textContent=(v.attestationsCount||0).toLocaleString()+' attestations ('+String(v.configuredAssurance||'high').toUpperCase()+') · Guard locked';
    el('vp-prism').textContent=Number(v.maxPrismRisk||0).toFixed(2)+' max risk';
    el('vp-prism-sub').textContent=(v.highRiskCount||0)+' High/Critical (>= 0.60)';
    var rChains=mc.reasoning||0,cChains=mc.command||0;
    el('vp-evolve').textContent=(v.decisions||0)>0?((v.decisions||0)+' decisions'):(rChains>0?(rChains.toLocaleString()+' reasoning chains'):((v.decisionRecords&&v.decisionRecords.length)||0)+' records');
    el('vp-evolve-sub').textContent='+'+(v.linesAdded||0).toLocaleString()+' / -'+(v.linesRemoved||0).toLocaleString()+' LOC'+(cChains>0?(' · '+cChains.toLocaleString()+' cmds'):'');
    el('vp-trace').textContent=(v.traceResolved||0)+' / '+(v.traceIncidents||0)+' fixed';
    el('vp-trace-sub').textContent=(v.iocRulesCount||0)+' custom IoC rules'+(v.hasAuditDb?' · audit.db active':'');
    var vbox=el('vibes-svg');
    if(vbox){
      vbox.textContent='';var NS='http://www.w3.org/2000/svg';
      function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,a[k]);if(txt!=null)n.textContent=String(txt);if(p)p.appendChild(n);return n}
      node('text',{x:16,y:22,fill:'#06b6d4','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'1. PRISM v1.0 RISK HISTOGRAM');
      var pb=v.prismBuckets||{},bks=[['Low (<0.30)',pb.low||0,'#10b981'],['Mod (0.30-0.59)',pb.moderate||0,'#06b6d4'],['High (0.60-0.79)',pb.high||0,'#f59e0b'],['Crit (>=0.80)',pb.critical||0,'#ef4444']];
      var mb=Math.max(1,pb.low||0,pb.moderate||0,pb.high||0,pb.critical||0);
      bks.forEach(function(b,idx){
        var y=46+idx*46;
        node('text',{x:16,y:y+14,fill:'#ecf3ef','font-size':10.5,'font-family':'monospace'},vbox,b[0]);
        node('rect',{x:135,y:y,width:125,height:18,rx:4,fill:'#101814',stroke:'#1d2b23'},vbox);
        var w=Math.max(4,Math.round((b[1]/mb)*125));
        if(b[1]>0)node('rect',{x:135,y:y,width:w,height:18,rx:4,fill:b[2]},vbox);
        node('text',{x:268,y:y+13,fill:b[2],'font-size':11,'font-weight':700,'font-family':'monospace'},vbox,String(b[1]));
      });
      node('line',{x1:305,y1:12,x2:305,y2:240,stroke:'#1d2b23','stroke-dasharray':'4,4'},vbox);
      node('text',{x:320,y:22,fill:'#f59e0b','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'2. PRISM TURN TRAJECTORY (0.60 GATE)');
      node('rect',{x:320,y:38,width:275,height:182,rx:8,fill:'#0b110e',stroke:'#1d2b23'},vbox);
      var gy=38+Math.round((1-0.6)*162)+10;
      node('line',{x1:326,y1:gy,x2:589,y2:gy,stroke:'#f59e0b','stroke-dasharray':'3,3','stroke-width':1.2},vbox);
      node('text',{x:332,y:gy-5,fill:'#f59e0b','font-size':9.5,'font-family':'monospace'},vbox,'0.60 /neckbeard-review priority gate');
      var anns=(v.recentAnnotations&&v.recentAnnotations.length)?v.recentAnnotations.slice(0,12).reverse():[];
      if(anns.length>0){
        var pts=[];
        anns.forEach(function(a,idx){
          var r=typeof a.riskScore==='number'?a.riskScore:0.12;
          var px=340+Math.round((idx/Math.max(1,anns.length-1))*235);
          var py=48+Math.round((1-Math.min(1,Math.max(0,r)))*156);
          pts.push(px+','+py);
          node('circle',{cx:px,cy:py,r:4,fill:r>=0.8?'#ef4444':r>=0.6?'#f59e0b':'#10b981'},vbox);
        });
        if(pts.length>1)node('polyline',{points:pts.join(' '),fill:'none',stroke:'#06b6d4','stroke-width':1.8},vbox);
      }
      node('line',{x1:612,y1:12,x2:612,y2:240,stroke:'#1d2b23','stroke-dasharray':'4,4'},vbox);
      node('text',{x:626,y:22,fill:'#10b981','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'3. ATTRIBUTED FILE HOTSPOTS');
      var hs=(v.fileHotspots&&v.fileHotspots.length)?v.fileHotspots.slice(0,5):[{file:'(Session-level provenance only)',annotations:ac,linesAdded:0,linesRemoved:0,maxRisk:v.maxPrismRisk||0,verified:true}];
      hs.forEach(function(h,idx){
        var y=44+idx*39,rc=h.maxRisk>=0.8?'#ef4444':h.maxRisk>=0.6?'#f59e0b':h.maxRisk>=0.3?'#06b6d4':'#10b981';
        node('text',{x:626,y:y+13,fill:'#ecf3ef','font-size':10.5,'font-family':'monospace'},vbox,(h.verified?'✓ ':'○ ')+h.file.slice(-24));
        node('rect',{x:790,y:y+2,width:65,height:13,rx:4,fill:'#101814',stroke:'#1d2b23'},vbox);
        var rw=Math.max(4,Math.round(Math.min(1,Math.max(0.08,h.maxRisk||0.08))*65));
        node('rect',{x:790,y:y+2,width:rw,height:13,rx:4,fill:rc},vbox);
        node('text',{x:862,y:y+12,fill:rc,'font-size':10,'font-weight':700,'font-family':'monospace'},vbox,'+'+h.linesAdded+'/-'+h.linesRemoved);
      });
    }
    var dl=el('vibes-decisions-list');dl.textContent='';
    var ds=(v.decisionRecords&&v.decisionRecords.length)?v.decisionRecords:[{id:'GUARD',title:'Immutable .ai-audit/{manifest.json,annotations.jsonl,blobs/,attestations/} protected by hooks/guard.js',status:'armed'}];
    ds.slice(0,6).forEach(function(d){var r=document.createElement('div');r.textContent='['+d.id+'] '+d.title+' ('+d.status+')';dl.appendChild(r)});
    var il=el('vibes-incidents-list');il.textContent='';
    var is=(v.incidentRecords&&v.incidentRecords.length)?v.incidentRecords:[{iocId:'READY',status:'clean',summary:'0 unresolved TRACE incidents or unverified high-risk PRISM edits in '+(wsKey||'portfolio')}];
    is.slice(0,6).forEach(function(inc){var r=document.createElement('div');r.textContent='['+inc.iocId+' · '+inc.status.toUpperCase()+'] '+inc.summary;il.appendChild(r)});
    var ar=el('vibes-annotations-rows');
    if(ar){
      ar.textContent='';
      (v.recentAnnotations||[]).slice(0,12).forEach(function(a){
        var tr=document.createElement('tr'),rt=a.riskScore!=null?a.riskScore.toFixed(2):'0.00';
        var fullTxt=a.fullText||a.summary||'Annotated turn';
        tr.className='crow';
        tr.title=fullTxt+'\n(Click row to expand full provenance text)';
        var dTr=document.createElement('tr');
        dTr.style.display='none';
        dTr.style.background='#070c0a';
        var dTd=document.createElement('td');
        dTd.colSpan=7;
        dTd.style.padding='12px 16px';
        var box=document.createElement('div');
        box.style.cssText='background:#0b110e;border:1px solid var(--cyan);border-radius:10px;padding:12px 14px;font:400 12px/1.55 var(--mono);color:var(--text);white-space:pre-wrap;word-break:break-word;max-height:260px;overflow-y:auto';
        box.textContent=fullTxt;
        dTd.appendChild(box);
        dTr.appendChild(dTd);
        var chev=null;
        [a.timestamp||'–',a.sessionId||'–',a.file||'–','+'+(a.linesAdded||0)+' / -'+(a.linesRemoved||0),'PRISM '+rt,a.verified?'✓ Attested':'○ Recorded','▸ '+(a.summary||'Annotated turn')].forEach(function(val,idx){
          var td=document.createElement('td');if(idx===6){td.className='tcol';chev=td}td.textContent=val;tr.appendChild(td);
        });
        tr.onclick=function(){
          var open=dTr.style.display!=='none';
          dTr.style.display=open?'none':'table-row';
          if(chev)chev.textContent=(open?'▸ ':'▾ ')+(a.summary||'Annotated turn');
        };
        ar.appendChild(tr);
        ar.appendChild(dTr);
      });
    }
  }
  function renderEcon(list,wsStats){
    el('econ-title').textContent=activeWorkspace?('Workspace Economics & Benchmark vs. All Workspaces — '+activeWorkspace):'Front-and-Center Economics: Spend vs. Prompt-Cache Savings & All-Workspaces Ranking';
    el('econ-badge').textContent=activeWorkspace?(activeWorkspace+': '+fmtUsd(wsStats.cost)+' ('+(portStats.cost>0?((wsStats.cost/portStats.cost)*100).toFixed(1):'0')+'% of '+fmtUsd(portStats.cost)+' total)'):('Portfolio Total: '+fmtUsd(portStats.cost)+' Spend · '+fmtUsd(portStats.saved)+' Saved by Cache');
    el('model-table-title').textContent=activeWorkspace?('MODEL & CACHE ECONOMICS — '+activeWorkspace.toUpperCase()):'MODEL & CACHE ECONOMICS — ALL WORKSPACES';
    var vbox=el('velocity-svg');
    if(vbox){
      vbox.textContent='';var NS='http://www.w3.org/2000/svg';
      function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,a[k]);if(txt!=null)n.textContent=String(txt);if(p)p.appendChild(n);return n}
      var byDay={};
      list.forEach(function(r){
        var d=String(r.timestampIso||'').slice(0,10)||'Recent';
        if(!byDay[d])byDay[d]={day:d,cost:0,saved:0,sessions:0};
        byDay[d].cost+=r.totalCostUsd||0;byDay[d].saved+=estSaved(r);byDay[d].sessions+=1;
      });
      var days=Object.keys(byDay).sort().slice(-10);
      node('text',{x:16,y:20,fill:'#10b981','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'1. DAILY SPEND ($ EMERALD) VS. CACHE SAVED ($ CYAN) — '+(activeWorkspace||'ALL WORKSPACES'));
      var mv=0.01;days.forEach(function(d){if(byDay[d].cost>mv)mv=byDay[d].cost;if(byDay[d].saved>mv)mv=byDay[d].saved});
      days.forEach(function(d,idx){
        var inf=byDay[d],gx=20+idx*45,hc=Math.max(4,Math.round((inf.cost/mv)*140)),hs=Math.max(4,Math.round((inf.saved/mv)*140));
        node('rect',{x:gx,y:185-hc,width:15,height:hc,rx:3,fill:'#10b981'},vbox);
        node('rect',{x:gx+17,y:185-hs,width:15,height:hs,rx:3,fill:'#06b6d4'},vbox);
        node('text',{x:gx+16,y:202,fill:'#8b9d92','font-size':9,'text-anchor':'middle','font-family':'monospace'},vbox,d.slice(5));
        node('text',{x:gx+16,y:216,fill:'#10b981','font-size':8.5,'text-anchor':'middle','font-family':'monospace'},vbox,'$'+inf.cost.toFixed(0));
      });
      node('line',{x1:480,y1:10,x2:480,y2:225,stroke:'#1d2b23','stroke-dasharray':'4,4'},vbox);
      if(activeWorkspace){
        node('text',{x:498,y:20,fill:'#06b6d4','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'2. '+activeWorkspace.toUpperCase()+' (EMERALD) VS. ALL-WORKSPACES AVG (SLATE)');
        [
          ['Cost / Session',wsStats.costPerSession,portStats.costPerSession,function(v){return '$'+v.toFixed(2)}],
          ['Cost / Turn',wsStats.costPerTurn,portStats.costPerTurn,function(v){return '$'+v.toFixed(2)}],
          ['Cache Hit Rate',wsStats.cacheHitPct,portStats.cacheHitPct,function(v){return Math.round(v)+'%'}],
          ['Turns / Session',wsStats.turnsPerSession,portStats.turnsPerSession,function(v){return v.toFixed(1)+'t'}]
        ].forEach(function(m,idx){
          var y=44+idx*45,mx=Math.max(0.01,m[1],m[2]),wW=Math.max(6,Math.round((m[1]/mx)*190)),wA=Math.max(6,Math.round((m[2]/mx)*190));
          node('text',{x:498,y:y+12,fill:'#ecf3ef','font-size':10.5,'font-family':'monospace'},vbox,m[0]);
          node('rect',{x:625,y:y,width:wW,height:11,rx:3,fill:'#10b981'},vbox);
          node('text',{x:632+wW,y:y+10,fill:'#10b981','font-size':10,'font-weight':700,'font-family':'monospace'},vbox,activeWorkspace.slice(0,12)+': '+m[3](m[1]));
          node('rect',{x:625,y:y+15,width:wA,height:10,rx:3,fill:'#55665c'},vbox);
          node('text',{x:632+wA,y:y+24,fill:'#8b9d92','font-size':9.5,'font-family':'monospace'},vbox,'All Avg: '+m[3](m[2]));
        });
      }else{
        node('text',{x:498,y:20,fill:'#f59e0b','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'2. TOP WORKSPACES BY SPEND & PROMPT-CACHE EFFICIENCY');
        var rTop={};
        records.forEach(function(r){
          var p=r.projectName||'workspace';
          if(!rTop[p])rTop[p]={name:p,cost:0,cRead:0,tIn:0};
          rTop[p].cost+=r.totalCostUsd||0;
          var tb=r.tokenBuckets||{};rTop[p].cRead+=tb.cachedReadTokens||0;rTop[p].tIn+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
        });
        var tList=Object.values(rTop).sort(function(a,b){return b.cost-a.cost}).slice(0,6);
        var mRC=Math.max(0.01,(tList[0]&&tList[0].cost)||1);
        tList.forEach(function(rp,idx){
          var y=42+idx*31,bw=Math.max(6,Math.round((rp.cost/mRC)*185)),ch=rp.tIn>0?Math.round((rp.cRead/rp.tIn)*100):0;
          node('text',{x:498,y:y+13,fill:'#ecf3ef','font-size':10.5,'font-family':'monospace'},vbox,rp.name.slice(0,18));
          node('rect',{x:635,y:y+1,width:bw,height:15,rx:4,fill:'#10b981'},vbox);
          node('text',{x:642+bw,y:y+13,fill:'#ecf3ef','font-size':10,'font-weight':700,'font-family':'monospace'},vbox,fmtUsd(rp.cost)+' ('+ch+'% cache)');
        });
      }
    }
    var rMap={};
    records.forEach(function(r){
      var p=r.projectName||'workspace';
      if(!rMap[p])rMap[p]={name:p,list:[],sessions:0,turns:0,dur:0,cost:0,saved:0,cRead:0,tIn:0};
      rMap[p].list.push(r);
      rMap[p].sessions+=1;rMap[p].turns+=r.turnCount||1;rMap[p].dur+=r.activeDurationMs||0;rMap[p].cost+=r.totalCostUsd||0;rMap[p].saved+=estSaved(r);
      var tb=r.tokenBuckets||{};rMap[p].cRead+=tb.cachedReadTokens||0;rMap[p].tIn+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
    });
    var rRows=el('repo-scorecard-rows');
    if(rRows){
      rRows.textContent='';
      var bTr=document.createElement('tr');
      bTr.className='crow brow'+(activeWorkspace===''?' srow':'');
      ['★ ALL WORKSPACES ('+Object.keys(rMap).length+')',portStats.sessions+' / '+portStats.turns,fmtDur(portStats.dur)+' agent / '+fmtDur(portStats.wallDur)+' wall ('+portStats.parallelFactor+'x)',portStats.cacheHitPct+'%',fmtUsd(portStats.saved),fmtUsd(portStats.cost),'100.0%','Portfolio'].forEach(function(v,idx){
        var td=document.createElement('td');if(idx===0)td.className='tcol';td.textContent=v;bTr.appendChild(td);
      });
      bTr.onclick=function(){selectWs('')};
      rRows.appendChild(bTr);
      Object.values(rMap).sort(function(a,b){
        if(activeWorkspace&&a.name===activeWorkspace)return -1;
        if(activeWorkspace&&b.name===activeWorkspace)return 1;
        return b.cost-a.cost;
      }).slice(0,45).forEach(function(rp){
        var tr=document.createElement('tr');
        tr.className='crow'+(rp.name===activeWorkspace?' srow':'');
        var ch=rp.tIn>0?Math.round((rp.cRead/rp.tIn)*100)+'%':'0%';
        var sh=portStats.cost>0?(rp.cost/portStats.cost)*100:0;
        var wm=meta[rp.name]||{},st=(wm.vibes&&wm.vibes.present?'● VIBES':'○ Std');
        var rpSt=sumList(rp.list);
        [(rp.name===activeWorkspace?'▶ ':'')+rp.name,rp.sessions+' / '+rp.turns,fmtDur(rp.dur)+' / '+fmtDur(rpSt.wallDur)+' ('+rpSt.activeDays+'d)',ch,fmtUsd(rp.saved),fmtUsd(rp.cost)].forEach(function(v,idx){
          var td=document.createElement('td');if(idx===0)td.className='tcol';td.textContent=v;tr.appendChild(td);
        });
        var sTd=document.createElement('td');
        sTd.innerHTML='<span class="sb-w"><span class="sb-bg"><span class="sb-f" style="width:'+Math.min(100,Math.max(3,sh)).toFixed(0)+'%"></span></span><span>'+sh.toFixed(1)+'%</span></span>';
        tr.appendChild(sTd);
        var vTd=document.createElement('td');vTd.textContent=st;tr.appendChild(vTd);
        tr.onclick=function(){selectWs(rp.name)};
        rRows.appendChild(tr);
      });
    }
    var mMap={};
    list.forEach(function(r){
      var m=r.modelId||'unknown';
      if(!mMap[m])mMap[m]={model:m,sessions:0,turns:0,inTok:0,outTok:0,cRead:0,saved:0,cost:0};
      mMap[m].sessions+=1;mMap[m].turns+=r.turnCount||1;
      var tb=r.tokenBuckets||{};
      mMap[m].inTok+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      mMap[m].outTok+=tb.completionTokens||0;
      mMap[m].cRead+=tb.cachedReadTokens||0;
      mMap[m].saved+=estSaved(r);
      mMap[m].cost+=r.totalCostUsd||0;
    });
    var mRows=el('model-econ-rows');
    if(mRows){
      mRows.textContent='';
      Object.values(mMap).sort(function(a,b){return b.cost-a.cost}).forEach(function(mm){
        var tr=document.createElement('tr'),ch=mm.inTok>0?Math.round((mm.cRead/mm.inTok)*100)+'%':'0%';
        [mm.model,mm.sessions+' / '+mm.turns,fmtTok(mm.inTok),fmtTok(mm.outTok),ch,fmtUsd(mm.saved),fmtUsd(mm.cost)].forEach(function(v){
          var td=document.createElement('td');td.textContent=v;tr.appendChild(td);
        });
        mRows.appendChild(tr);
      });
    }
  }
  function resolveBounds(wsKey){
    if(wsKey){var wm=meta[wsKey]||{};return{boundaries:wm.boundaries||{external:{},internal:{}},drift:wm.driftAdded||[]}}
    var aE={ingress:[],egress:[],supply:[]},aI={auth:[],data:[],exec:[],ai:[]},aD=[];
    Object.keys(meta).forEach(function(k){
      var wm=meta[k]||{},b=wm.boundaries||{},e=b.external||{},i=b.internal||{};
      ['ingress','egress','supply'].forEach(function(c){(e[c]||[]).forEach(function(it){if(aE[c].length<12)aE[c].push(k+':'+it)})});
      ['auth','data','exec','ai'].forEach(function(c){(i[c]||[]).forEach(function(it){if(aI[c].length<12)aI[c].push(k+':'+it)})});
      (wm.driftAdded||[]).forEach(function(d){aD.push(k+':'+d)});
    });
    return{boundaries:{external:aE,internal:aI},drift:aD};
  }
  var EXT_META={'http-in':{label:'HTTP / API Ingress',color:'#f59e0b'},'webhook-in':{label:'Webhook / Queue Ingress',color:'#fb923c'},'cli-in':{label:'CLI / Stdin Ingress',color:'#facc15'},'http-out':{label:'Outbound HTTP / SSRF Egress',color:'#06b6d4'},'ci':{label:'CI / Supply-Chain Workflows',color:'#a855f7'}};
  var INT_META={'auth':{label:'Object Auth & Sessions',color:'#10b981'},'sql':{label:'SQL / Database Queries',color:'#2dd4bf'},'fs':{label:'Filesystem & Path I/O',color:'#38bdf8'},'serde':{label:'Deserialization & Parsers',color:'#818cf8'},'proc':{label:'Subprocess / Shell Exec',color:'#fb7185'},'crypto':{label:'Cryptography & Hashing',color:'#c084fc'},'env':{label:'Secrets & Env Config',color:'#fbbf24'},'ai':{label:'LLM / Agent Context & Tools',color:'#a3e635'}};
  function modNameFor(fp,isAll){
    if(isAll){var ci=fp.indexOf(':');if(ci>0)return fp.slice(0,ci)}
    var ps=fp.split('/');if(ps.length<=1)return'(root)';
    if(ps[0]==='.github'&&ps[1]==='workflows')return'.github/workflows';
    if((ps[0]==='packages'||ps[0]==='crates'||ps[0]==='apps'||ps[0]==='hooks'||ps[0]==='src')&&ps.length>=3)return ps[0]+'/'+ps[1];
    return ps[0];
  }
  function buildTopoModel(wsKey){
    var res=resolveBounds(wsKey),ext=res.boundaries.external||{},int=res.boundaries.internal||{},dSet=new Set(res.drift||[]),isAll=!wsKey,fMap={};
    function rec(raw,tier){
      var ar=raw.indexOf('->');if(ar<0)return;
      var file=raw.slice(0,ar).trim(),tags=raw.slice(ar+2).split(',').map(function(t){return t.trim()}).filter(Boolean);
      if(!fMap[file])fMap[file]={file:file,module:modNameFor(file,isAll),extSinks:[],intSinks:[],isDrift:false};
      if(dSet.has(raw))fMap[file].isDrift=true;
      tags.forEach(function(tag){
        if(tier==='ext'){if(fMap[file].extSinks.indexOf(tag)<0)fMap[file].extSinks.push(tag)}
        else{if(fMap[file].intSinks.indexOf(tag)<0)fMap[file].intSinks.push(tag)}
      });
    }
    ['ingress','egress','supply'].forEach(function(k){(ext[k]||[]).forEach(function(e){rec(e,'ext')})});
    ['auth','data','exec','ai'].forEach(function(k){(int[k]||[]).forEach(function(e){rec(e,'int')})});
    var files=Object.values(fMap),eMap={},iMap={},mMap={};
    files.forEach(function(f){
      if(!mMap[f.module])mMap[f.module]={name:f.module,files:[],bridgeCount:0,extCounts:{},intCounts:{}};
      var mn=mMap[f.module];mn.files.push(f);
      if(f.extSinks.length>0&&f.intSinks.length>0)mn.bridgeCount+=1;
      f.extSinks.forEach(function(s){
        if(!eMap[s]){var mi=EXT_META[s]||{label:s,color:'#f59e0b'};eMap[s]={sink:s,label:mi.label,color:mi.color,files:[],modules:{}}}
        eMap[s].files.push(f.file);eMap[s].modules[f.module]=(eMap[s].modules[f.module]||0)+1;mn.extCounts[s]=(mn.extCounts[s]||0)+1;
      });
      f.intSinks.forEach(function(s){
        if(!iMap[s]){var mi=INT_META[s]||{label:s,color:'#10b981'};iMap[s]={sink:s,label:mi.label,color:mi.color,files:[],modules:{}}}
        iMap[s].files.push(f.file);iMap[s].modules[f.module]=(iMap[s].modules[f.module]||0)+1;mn.intCounts[s]=(mn.intCounts[s]||0)+1;
      });
    });
    return{
      files:files,
      extNodes:Object.values(eMap).sort(function(a,b){return b.files.length-a.files.length}),
      modNodes:Object.values(mMap).sort(function(a,b){return(b.bridgeCount-a.bridgeCount)||(b.files.length-a.files.length)}).slice(0,9),
      intNodes:Object.values(iMap).sort(function(a,b){return b.files.length-a.files.length}),
      drift:res.drift||[]
    };
  }
  function renderGraph(wsKey){
    el('topo-heading').textContent=wsKey?('Per-Project Trust-Boundary & Module Architecture — '+wsKey):'Portfolio Trust-Boundary & Repository Topology — All Workspaces';
    var box=el('boundary-svg');if(!box)return;box.textContent='';
    var NS='http://www.w3.org/2000/svg';
    function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,String(a[k]));if(txt!=null)n.textContent=String(txt);if(p)p.appendChild(n);return n}
    var topo=buildTopoModel(wsKey),drift=topo.drift,bCnt=topo.files.filter(function(f){return f.extSinks.length>0&&f.intSinks.length>0}).length;
    var sumEl=el('topo-summary');
    if(sumEl)sumEl.textContent=topo.files.length+' boundary-crossing files across '+topo.modNodes.length+' active '+(wsKey?'project module(s)':'repositories')+' · '+topo.extNodes.length+' active external sink type(s) · '+topo.intNodes.length+' active internal sink type(s) · '+bCnt+' cross-boundary bridge file(s) ([ext] ➔ [int])';
    var db=el('ov-drift');
    if(drift.length){db.className='chip warn';db.textContent='⚠ +'+drift.length+' Unreviewed Boundary Drift: '+drift.slice(0,3).join(', ')}
    else{db.className='chip';db.textContent='✓ '+topo.files.length+' Boundary Files Mapped ('+(wsKey||'Portfolio')+')'}
    if(topo.files.length===0){
      box.setAttribute('viewBox','0 0 960 140');
      node('text',{x:480,y:75,fill:'#8b9d92','font-size':13,'text-anchor':'middle','font-family':'monospace'},box,'No external or internal boundary sinks detected in '+(wsKey||'workspace')+'.');
      var er=el('boundary-file-rows');if(er)er.textContent='';return;
    }
    var eC=Math.max(1,topo.extNodes.length),mC=Math.max(1,topo.modNodes.length),iC=Math.max(1,topo.intNodes.length);
    var H=Math.max(320,eC*82+40,mC*68+40,iC*68+40);
    box.setAttribute('viewBox','0 0 960 '+H);
    node('text',{x:20,y:20,fill:'#f59e0b','font-size':11,'font-weight':700,'font-family':'monospace'},box,'EXTERNAL SINKS [EXT] ('+topo.extNodes.length+' ACTIVE)');
    node('text',{x:480,y:20,fill:'#10b981','font-size':11,'font-weight':700,'text-anchor':'middle','font-family':'monospace'},box,(wsKey?(wsKey.toUpperCase()+' ARCHITECTURE MODULES'):'ACTIVE REPOSITORY MODULES')+' ('+topo.modNodes.length+')');
    node('text',{x:940,y:20,fill:'#06b6d4','font-size':11,'font-weight':700,'text-anchor':'end','font-family':'monospace'},box,'INTERNAL SINKS [INT] ('+topo.intNodes.length+' ACTIVE)');
    var wm=wsKey?(meta[wsKey]||{}):{},bLoad=wm.boundaryLoad||{};
    var extPos={},eStep=(H-46)/Math.max(1,topo.extNodes.length);
    topo.extNodes.forEach(function(en,idx){
      var bh=Math.min(76,Math.max(52,eStep-10)),by=Math.round(36+idx*eStep+(eStep-bh)/2);
      extPos[en.sink]={x:18,y:by,w:256,h:bh,cy:by+Math.round(bh/2),color:en.color};
    });
    var modPos={},mStep=(H-46)/Math.max(1,topo.modNodes.length);
    topo.modNodes.forEach(function(mn,idx){
      var bh=Math.min(72,Math.max(48,mStep-8)),by=Math.round(36+idx*mStep+(mStep-bh)/2);
      modPos[mn.name]={x:344,y:by,w:272,h:bh,cy:by+Math.round(bh/2)};
    });
    var intPos={},iStep=(H-46)/Math.max(1,topo.intNodes.length);
    topo.intNodes.forEach(function(inN,idx){
      var bh=Math.min(72,Math.max(48,iStep-8)),by=Math.round(36+idx*iStep+(iStep-bh)/2);
      intPos[inN.sink]={x:686,y:by,w:256,h:bh,cy:by+Math.round(bh/2),color:inN.color};
    });
    topo.extNodes.forEach(function(en){
      var ep=extPos[en.sink];
      Object.keys(en.modules).forEach(function(mName){
        var mp=modPos[mName];if(!ep||!mp)return;
        var sw=Math.min(4.5,1.3+en.modules[mName]*0.65);
        node('path',{d:'M'+(ep.x+ep.w)+','+ep.cy+' C305,'+ep.cy+' 308,'+mp.cy+' '+mp.x+','+mp.cy,fill:'none',stroke:ep.color,'stroke-width':sw,'stroke-opacity':'0.72'},box);
      });
    });
    topo.modNodes.forEach(function(mn){
      var mp=modPos[mn.name];if(!mp)return;
      Object.keys(mn.intCounts).forEach(function(sKey){
        var ip=intPos[sKey];if(!ip)return;
        var sw=Math.min(4.5,1.3+mn.intCounts[sKey]*0.55);
        node('path',{d:'M'+(mp.x+mp.w)+','+mp.cy+' C648,'+mp.cy+' 652,'+ip.cy+' '+ip.x+','+ip.cy,fill:'none',stroke:ip.color,'stroke-width':sw,'stroke-opacity':'0.72'},box);
      });
    });
    topo.extNodes.forEach(function(en){
      var ep=extPos[en.sink];
      node('rect',{x:ep.x,y:ep.y,width:ep.w,height:ep.h,rx:10,fill:'#0b110e',stroke:ep.color,'stroke-width':1.5},box);
      node('text',{x:ep.x+12,y:ep.y+19,fill:ep.color,'font-size':11.5,'font-weight':700,'font-family':'monospace'},box,'['+en.sink+'] '+en.label);
      var lt=bLoad[en.sink]?(' · '+bLoad[en.sink]):'';
      node('text',{x:ep.x+12,y:ep.y+35,fill:'#ecf3ef','font-size':10,'font-family':'monospace'},box,en.files.length+' file(s) across '+Object.keys(en.modules).length+' mod(s)'+lt);
      if(ep.h>=62&&en.files[0])node('text',{x:ep.x+12,y:ep.y+50,fill:'#8b9d92','font-size':9.5,'font-family':'monospace'},box,'e.g. '+en.files[0].slice(-28));
    });
    topo.modNodes.forEach(function(mn){
      var mp=modPos[mn.name],isB=mn.bridgeCount>0;
      node('rect',{x:mp.x,y:mp.y,width:mp.w,height:mp.h,rx:10,fill:isB?'#0e1913':'#0b110e',stroke:isB?'#10b981':'#2b3d34','stroke-width':isB?1.8:1.2},box);
      var bt=isB?(' ⚡ '+mn.bridgeCount+' bridge'):'';
      node('text',{x:mp.x+12,y:mp.y+18,fill:isB?'#10b981':'#ecf3ef','font-size':11.5,'font-weight':700,'font-family':'monospace'},box,mn.name.slice(0,24)+' ('+mn.files.length+')'+bt);
      var eL=Object.keys(mn.extCounts).join(','),iL=Object.keys(mn.intCounts).join(',');
      var fs=(eL?('in:'+eL+' '):'')+(iL?('-> '+iL):'');
      node('text',{x:mp.x+12,y:mp.y+34,fill:'#8b9d92','font-size':9.8,'font-family':'monospace'},box,fs.slice(0,38));
      if(mp.h>=58&&mn.files[0]){
        var sn=mn.files.slice(0,2).map(function(f){return f.file.split('/').pop()}).join(', ');
        node('text',{x:mp.x+12,y:mp.y+48,fill:'#ecf3ef','font-size':9.5,'font-family':'monospace'},box,sn.slice(0,38));
      }
    });
    topo.intNodes.forEach(function(inN){
      var ip=intPos[inN.sink];
      node('rect',{x:ip.x,y:ip.y,width:ip.w,height:ip.h,rx:10,fill:'#0b110e',stroke:ip.color,'stroke-width':1.5},box);
      node('text',{x:ip.x+12,y:ip.y+19,fill:ip.color,'font-size':11.5,'font-weight':700,'font-family':'monospace'},box,'['+inN.sink+'] '+inN.label);
      node('text',{x:ip.x+12,y:ip.y+35,fill:'#ecf3ef','font-size':10,'font-family':'monospace'},box,inN.files.length+' file(s) from '+Object.keys(inN.modules).length+' mod(s)');
      if(ip.h>=58&&inN.files[0])node('text',{x:ip.x+12,y:ip.y+49,fill:'#8b9d92','font-size':9.5,'font-family':'monospace'},box,'e.g. '+inN.files[0].slice(-28));
    });
    var tTitle=el('boundary-table-title'),tCnt=el('boundary-table-count');
    if(tTitle)tTitle.textContent='PER-FILE TRUST-BOUNDARY & BRIDGE MATRIX — '+(wsKey||'ALL WORKSPACES').toUpperCase();
    if(tCnt)tCnt.textContent=topo.files.length+' boundary files ('+bCnt+' cross-boundary bridges)';
    var bRows=el('boundary-file-rows');
    if(bRows){
      bRows.textContent='';
      topo.files.slice().sort(function(a,b){
        var aB=(a.extSinks.length>0&&a.intSinks.length>0)?1:0,bB=(b.extSinks.length>0&&b.intSinks.length>0)?1:0;
        if(bB!==aB)return bB-aB;
        return(b.extSinks.length+b.intSinks.length)-(a.extSinks.length+a.intSinks.length);
      }).slice(0,60).forEach(function(f){
        var tr=document.createElement('tr'),isB=f.extSinks.length>0&&f.intSinks.length>0,tot=f.extSinks.length+f.intSinks.length;
        var rl=f.isDrift?'⚠ Unreviewed Drift (+new)':isB?'⚡ Cross-Boundary Bridge ([ext] ➔ [int])':tot>=2?('🛡️ Multi-Sink Hub ('+tot+' sinks)'):'● Single-Sink Boundary';
        [f.module,f.file,f.extSinks.length?f.extSinks.map(function(s){return'['+s+']'}).join(' '):'–',f.intSinks.length?f.intSinks.map(function(s){return'['+s+']'}).join(' '):'–',rl].forEach(function(val,idx){
          var td=document.createElement('td');if(idx===1)td.className='tcol';if(idx===4&&isB)td.style.color='var(--amber)';td.textContent=val;tr.appendChild(td);
        });
        bRows.appendChild(tr);
      });
    }
  }
  function render(){
    var list=activeWorkspace?records.filter(function(r){return r.projectName===activeWorkspace}):records;
    var wsStats=sumList(list),wm=activeWorkspace?(meta[activeWorkspace]||{}):{},vData=resolveVibes(activeWorkspace);
    el('st-title').textContent=activeWorkspace||'All Workspaces';
    var bBtn=el('back-all-btn');if(bBtn)bBtn.style.display=activeWorkspace?'inline-block':'none';
    var vPill=el('st-vibes-pill');
    if(vPill){
      if(vData&&vData.present){vPill.style.display='inline-block';vPill.className='chip cyan';vPill.textContent='● VIBES (.ai-audit/) Active'}
      else{vPill.style.display='none'}
    }
    var shCost=portStats.cost>0?((wsStats.cost/portStats.cost)*100).toFixed(1):'100.0';
    el('st-subtitle').textContent=activeWorkspace?(wsStats.sessions+' sessions · '+wsStats.turns+' turns · '+fmtDur(wsStats.dur)+' agent time ('+fmtDur(wsStats.wallDur)+' wall) · '+fmtUsd(wsStats.cost)+' ('+shCost+'% of all workspaces)'):(portStats.sessions+' total sessions across '+el('ws-total-cnt').textContent+' workspaces · '+fmtDur(portStats.dur)+' agent time ('+fmtDur(portStats.wallDur)+' wall) · '+fmtUsd(portStats.cost)+' spend · '+fmtUsd(portStats.saved)+' saved by prompt caching');
    el('pane-economics').style.display=(activeView==='overview'||activeView==='economics')?'block':'none';
    el('pane-vibes').style.display=(activeView==='overview'||activeView==='vibes')?'block':'none';
    el('pane-overview').style.display=(activeView==='overview'||activeView==='topology')?'block':'none';
    el('pane-forensics').style.display=(activeView==='overview'||activeView==='forensics')?'block':'none';
    el('m-cost').textContent=fmtUsd(wsStats.cost);
    el('m-cost-unit').textContent=fmtUsd(wsStats.costPerSession)+' / session · '+fmtUsd(wsStats.costPerTurn)+' / turn';
    el('m-cost-comp').textContent=activeWorkspace?(shCost+'% of All Workspaces ('+fmtUsd(portStats.cost)+') · All Avg: '+fmtUsd(portStats.costPerSession)+'/sess'):('100% of portfolio ('+portStats.sessions.toLocaleString()+' sessions)');
    el('m-saved').textContent=fmtUsd(wsStats.saved)+' saved';
    el('m-cache').textContent=wsStats.cacheHitPct+'% cache hit · '+fmtTok(wsStats.tok)+' total tok';
    el('m-cache-comp').textContent=activeWorkspace?('All-Workspaces avg cache hit: '+portStats.cacheHitPct+'% ('+fmtUsd(portStats.saved)+' total saved)'):(fmtTok(portStats.cRead)+' cached read tokens across portfolio');
    el('m-time').textContent=fmtDur(wsStats.dur)+' agent / '+fmtDur(wsStats.wallDur)+' wall';
    var shTime=portStats.dur>0?((wsStats.dur/portStats.dur)*100).toFixed(1):'100.0';
    var avgSessMs=wsStats.sessions>0?Math.round(wsStats.dur/wsStats.sessions):0;
    var portAvgSessMs=portStats.sessions>0?Math.round(portStats.dur/portStats.sessions):0;
    el('m-turns').textContent=wsStats.sessions.toLocaleString()+' sessions · '+wsStats.turns.toLocaleString()+' turns across '+wsStats.activeDays+' active day(s)';
    el('m-load').textContent=activeWorkspace?(shTime+'% of All-Workspaces agent time ('+fmtDur(portStats.dur)+') · '+wsStats.parallelFactor+'x concurrency · Avg '+fmtDur(avgSessMs)+'/sess'):(portStats.parallelFactor+'x parallel concurrency (+'+fmtDur(Math.max(0,portStats.dur-portStats.wallDur))+' compressed) · Avg '+fmtDur(portAvgSessMs)+'/sess');
    var vIns=(vData&&vData.linesAdded)||wsStats.ins,vDel=(vData&&vData.linesRemoved)||wsStats.del;
    el('m-sec').textContent=wsStats.blk+' guard blocks';
    el('m-loc').textContent='+'+vIns.toLocaleString()+' / -'+vDel.toLocaleString()+' LOC · '+wsStats.fixed+'/'+wsStats.found+' issues fixed';
    el('m-vibes').textContent=(vData&&vData.present)?('VIBES active · '+(vData.annotationsCount||0).toLocaleString()+' annotations · PRISM max '+Number(vData.maxPrismRisk||0).toFixed(2)):'PreToolUse secret & config-censor shield armed';
    el('forensics-heading').textContent=activeWorkspace?('Recorded Engineering & Audit Sessions — '+activeWorkspace+' (Click Any Row to Expand Full Prompt)'):'Recorded Engineering & Audit Sessions — All Workspaces (Click Any Row to Expand Full Prompt)';
    var searched=searchQuery?list.filter(function(r){var q=searchQuery.toLowerCase();return String(r.taskTitle||'').toLowerCase().includes(q)||String(r.fullPrompt||'').toLowerCase().includes(q)||String(r.assistantSummary||'').toLowerCase().includes(q)||String(r.projectName||'').toLowerCase().includes(q)||String(r.modelId||'').toLowerCase().includes(q)}):list;
    el('tbl-count').textContent=searched.length+' session(s)';
    var tbody=el('session-rows');tbody.textContent='';
    searched.slice().sort(function(a,b){return(b.startedAtMs||0)-(a.startedAtMs||0)}).slice(0,250).forEach(function(r){
      var tr=document.createElement('tr'),tb=r.tokenBuckets||{};
      tr.className='crow';
      var tTok=(tb.promptTokens||0)+(tb.completionTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      var iTok=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      var cH=iTok>0?Math.round(((tb.cachedReadTokens||0)/iTok)*100):0,sv=estSaved(r);
      var fullP=r.fullPrompt||r.taskTitle||'Session';
      var outS=r.assistantSummary||'';
      tr.title='PROMPT:\n'+fullP+(outS?('\n\nASSISTANT OUTCOME:\n'+outS):'')+'\n\n(Click row to expand inline)';
      var dTr=document.createElement('tr');
      dTr.style.display='none';
      dTr.style.background='#070c0a';
      var dTd=document.createElement('td');
      dTd.colSpan=9;
      dTd.style.padding='14px 18px';
      var wrap=document.createElement('div');
      wrap.style.cssText='background:#0b110e;border:1px solid var(--emerald);border-radius:12px;padding:14px 16px;display:flex;flex-direction:column;gap:10px';
      var metaBar=document.createElement('div');
      metaBar.style.cssText='font:600 11px var(--mono);color:var(--cyan);display:flex;flex-wrap:wrap;gap:14px;border-bottom:1px solid var(--border);padding-bottom:8px';
      metaBar.textContent='Session ID: '+(r.sessionId||r.recordId||'–')+' · Workspace: '+(r.projectName||'–')+' · Timestamp: '+(r.timestampIso||'–')+' · Model: '+(r.modelId||'claude')+' ['+(r.activeLevel||'full')+'] · Turns: '+(r.turnCount||1)+' · Tokens: '+((tb.promptTokens||0).toLocaleString())+' in / '+((tb.completionTokens||0).toLocaleString())+' out / '+((tb.cachedReadTokens||0).toLocaleString())+' cache-read / '+((tb.cachedWriteTokens||0).toLocaleString())+' cache-write';
      wrap.appendChild(metaBar);
      var pLbl=document.createElement('div');
      pLbl.style.cssText='font:700 11px var(--mono);color:var(--emerald);text-transform:uppercase;letter-spacing:.06em';
      pLbl.textContent='Full Task / User Prompt';
      wrap.appendChild(pLbl);
      var pBox=document.createElement('div');
      pBox.style.cssText='background:#060908;border:1px solid var(--border);border-radius:8px;padding:10px 12px;font:400 12px/1.55 var(--mono);color:var(--text);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow-y:auto';
      pBox.textContent=fullP;
      wrap.appendChild(pBox);
      if(outS){
        var aLbl=document.createElement('div');
        aLbl.style.cssText='font:700 11px var(--mono);color:var(--amber);text-transform:uppercase;letter-spacing:.06em;margin-top:2px';
        aLbl.textContent='Assistant Outcome / Final Synopsis';
        wrap.appendChild(aLbl);
        var aBox=document.createElement('div');
        aBox.style.cssText='background:#060908;border:1px solid var(--border);border-radius:8px;padding:10px 12px;font:400 12px/1.55 var(--mono);color:var(--muted);white-space:pre-wrap;word-break:break-word;max-height:220px;overflow-y:auto';
        aBox.textContent=outS;
        wrap.appendChild(aBox);
      }
      dTd.appendChild(wrap);
      dTr.appendChild(dTd);
      var tCell=null;
      ['▸ '+(r.taskTitle||'Session'),r.projectName||'–',r.timestampIso||'–',(r.modelId||'claude')+' ['+(r.activeLevel||'full')+']',fmtDur(r.activeDurationMs),fmtUsd(r.totalCostUsd||0)+' ('+fmtTok(tTok)+')',fmtUsd(sv)+' ('+cH+'%)',(r.guardBlockCount||0)+' blk · '+(r.securityFindingsResolved||0)+'/'+(r.securityFindingsTotal||0)+(r.vibesMaxPrismRisk!=null?' · PRISM '+r.vibesMaxPrismRisk:''),r.testStatusLabel||'recorded'].forEach(function(v,idx){
        var td=document.createElement('td');if(idx===0){td.className='tcol';tCell=td}td.textContent=v;tr.appendChild(td);
      });
      tr.onclick=function(){
        var open=dTr.style.display!=='none';
        dTr.style.display=open?'none':'table-row';
        tr.classList.toggle('srow',!open);
        if(tCell)tCell.textContent=(open?'▸ ':'▾ ')+(r.taskTitle||'Session');
      };
      tbody.appendChild(tr);
      tbody.appendChild(dTr);
    });
    renderEcon(list,wsStats);
    renderVibes(activeWorkspace);
    renderGraph(activeWorkspace);
  }
  var bAll=el('back-all-btn');if(bAll){bAll.onclick=function(){selectWs('')}}
  var dbtn=el('vibes-demo-btn');if(dbtn){dbtn.onclick=function(){demoVibesMode=!demoVibesMode;render()}}
  var sbox=el('session-search');if(sbox){sbox.oninput=function(){searchQuery=sbox.value||'';render()}}
  var wsNav=el('ws-list'),wCost={},wCnt={};
  records.forEach(function(r){var p=r.projectName||'';if(!p)return;wCost[p]=(wCost[p]||0)+(r.totalCostUsd||0);wCnt[p]=(wCnt[p]||0)+1});
  var names=Array.from(new Set(Object.keys(wCnt).concat(Object.keys(meta)).filter(Boolean)));
  var tEl=el('ws-total-cnt');if(tEl)tEl.textContent=String(names.length);
  [['','All Workspaces',records.length,portStats.cost]].concat(names.map(function(n){return[n,n,wCnt[n]||0,wCost[n]||0]}).sort(function(a,b){return(b[3]-a[3])||(b[2]-a[2])})).forEach(function(it){
    var b=document.createElement('button');b.type='button';b.setAttribute('data-ws',it[0]);
    b.className='ws-btn'+(it[0]===activeWorkspace?' active':'');
    var s1=document.createElement('span');s1.className='ws-ncol';s1.textContent=it[1];
    var rw=document.createElement('span');rw.className='ws-badges';
    if(it[0]&&meta[it[0]]&&meta[it[0]].vibes&&meta[it[0]].vibes.present){
      var vt=document.createElement('span');vt.className='ws-vtag';vt.textContent='VIBES';rw.appendChild(vt);
    }
    var cs=document.createElement('span');cs.className='ws-ctag';cs.textContent='$'+Math.round(it[3]).toLocaleString();rw.appendChild(cs);
    var s2=document.createElement('span');s2.className='ws-cnt';s2.textContent=String(it[2]);
    rw.appendChild(s2);b.appendChild(s1);b.appendChild(rw);
    b.onclick=function(){selectWs(it[0])};
    wsNav.appendChild(b);
  });
  document.querySelectorAll('[data-view]').forEach(function(b){
    b.onclick=function(){activeView=b.getAttribute('data-view');document.querySelectorAll('[data-view]').forEach(function(x){x.classList.toggle('active',x===b)});render()};
  });
  render();
})();
</script>
</body>
</html>`;
}

function isProjectDirectory(wsPath) {
  try {
    if (!wsPath || wsPath === '/' || wsPath === os.homedir()) return false;
    return (
      fs.existsSync(path.join(wsPath, '.git')) ||
      fs.existsSync(path.join(wsPath, '.neckbeard.json')) ||
      fs.existsSync(path.join(wsPath, '.ai-audit')) ||
      fs.existsSync(path.join(wsPath, 'package.json')) ||
      fs.existsSync(path.join(wsPath, 'Cargo.toml')) ||
      fs.existsSync(path.join(wsPath, 'pyproject.toml')) ||
      fs.existsSync(path.join(wsPath, 'go.mod'))
    );
  } catch {
    return false;
  }
}

function collectAndBuild(cwd = process.cwd(), env = process.env) {
  const telemetryDir = bandDir(env);
  fs.mkdirSync(telemetryDir, { recursive: true });
  const jsonlPath = path.join(telemetryDir, 'sessions.jsonl');
  const recordsById = readExistingJsonlRecords(jsonlPath);
  const guardStats = readGuardStats(env);
  let scannedCount = 0;
  let newRecordsCount = 0;

  const activeProject = path.basename(path.resolve(cwd)) || 'workspace';
  const discoveredWorkspacePaths = new Map([[activeProject, path.resolve(cwd)]]);

  if (hasVibes(cwd)) {
    const vibes = readVibesTelemetry(cwd);
    const projBlocks = (guardStats.projects && guardStats.projects[activeProject] && guardStats.projects[activeProject].blocks) || guardStats.total || 0;
    const cfg = readProjectConfig(cwd, env);
    if (vibes && Array.isArray(vibes.sessions)) {
      vibes.sessions.forEach((s, idx) => {
        scannedCount++;
        const recordId = `${String(s.sessionId).slice(0, 8)}-${s.startedMs}`;
        const isNew = !recordsById.has(recordId);
        recordsById.set(recordId, {
          recordId,
          timestampIso: formatIsoStamp(s.startedMs),
          startedAtMs: s.startedMs,
          projectName: activeProject,
          taskTitle: s.name || `VIBES audited session (${String(s.sessionId).slice(0, 8)})`,
          sessionId: s.sessionId,
          activeLevel: 'vibes',
          modelId: s.model || 'vibes',
          totalCostUsd: Number(s.costUsd || 0),
          latestTurnCostUsd: null,
          turnCount: s.turns || 1,
          activeDurationMs: s.agentMs || 0,
          tokenBuckets: {
            promptTokens: Math.max(0, (s.tokens || 0) - (s.outputTokens || 0)),
            completionTokens: s.outputTokens || 0,
            cachedReadTokens: 0,
            cachedWriteTokens: 0,
          },
          reusePercent: null,
          reusedSymbolCount: 0,
          newSymbolCount: 0,
          linesInserted: s.linesAdded || 0,
          linesDeleted: s.linesRemoved || 0,
          unmigratedCallerCount: 0,
          boundaryDriftCount: 0,
          guardBlockCount: idx === 0 ? projBlocks : 0,
          securityFindingsTotal: s.secFound || 0,
          securityFindingsResolved: s.secFixed || 0,
          vibesMaxPrismRisk: s.maxRisk ?? vibes.maxPrismRisk,
          loadEnvelope: (cfg && cfg.load) || '',
          testStatusLabel: 'VIBES verified',
        });
        if (isNew) newRecordsCount++;
      });
    }
  }

  const projectsRoot = path.join(claudeDir(env), 'projects');
  let projectFolders = [];
  try { projectFolders = fs.readdirSync(projectsRoot); } catch { projectFolders = []; }
  const ignoredRoots = [os.tmpdir(), '/tmp/', '/private/tmp/', '/var/folders/', '/private/var/folders/'];

  for (const folder of projectFolders) {
    const folderPath = path.join(projectsRoot, folder);
    let sessionFiles = [];
    try { sessionFiles = fs.readdirSync(folderPath).filter((f) => f.endsWith('.jsonl')); } catch { continue; }
    for (const file of sessionFiles) {
      const sessionId = file.slice(0, -'.jsonl'.length);
      const parsed = parseJsonlSessionFile(path.join(folderPath, file));
      if (!parsed || !parsed.workspaceCwd) continue;
      if (ignoredRoots.some((prefix) => parsed.workspaceCwd.startsWith(prefix)) || parsed.workspaceCwd === '/tmp') continue;

      scannedCount++;
      const projName = path.basename(parsed.workspaceCwd.replace(/[\\/]+$/, '')) || 'project';
      if (!discoveredWorkspacePaths.has(projName) && fs.existsSync(parsed.workspaceCwd)) {
        discoveredWorkspacePaths.set(projName, parsed.workspaceCwd);
      }

      const recordId = `${sessionId.slice(0, 8)}-${parsed.startedAtMs}`;
      let existingRec = recordsById.get(recordId);
      if (!existingRec) {
        for (const candidate of recordsById.values()) {
          if (candidate && candidate.sessionId === sessionId) {
            existingRec = candidate;
            break;
          }
        }
      }
      if (existingRec) {
        if (STALE_TITLE_RE.test(String(existingRec.taskTitle || '').trim()) && parsed.taskTitle) {
          existingRec.taskTitle = parsed.taskTitle;
        }
        if (!existingRec.fullPrompt && parsed.fullPrompt) {
          existingRec.fullPrompt = parsed.fullPrompt;
        }
        if (!existingRec.assistantSummary && parsed.assistantSummary) {
          existingRec.assistantSummary = parsed.assistantSummary;
        }
        continue;
      }

      let prismRisk = null;
      let secFound = 0;
      let secFixed = 0;
      let linesInserted = 0;
      let linesDeleted = 0;
      if (hasVibes(parsed.workspaceCwd)) {
        const v = readVibesTelemetry(parsed.workspaceCwd);
        if (v) {
          prismRisk = v.maxPrismRisk;
          secFound = v.highRiskCount + v.traceIncidents;
          secFixed = v.traceResolved;
          linesInserted = v.linesAdded;
          linesDeleted = v.linesRemoved;
        }
      }

      recordsById.set(recordId, {
        recordId,
        timestampIso: formatIsoStamp(parsed.startedAtMs),
        startedAtMs: parsed.startedAtMs,
        projectName: projName,
        taskTitle: parsed.taskTitle,
        fullPrompt: parsed.fullPrompt || '',
        assistantSummary: parsed.assistantSummary || '',
        sessionId,
        activeLevel: 'full',
        modelId: parsed.modelId,
        totalCostUsd: parsed.totalCostUsd,
        latestTurnCostUsd: null,
        turnCount: parsed.turnCount,
        activeDurationMs: parsed.activeDurationMs,
        tokenBuckets: parsed.tokenBuckets,
        reusePercent: null,
        reusedSymbolCount: 0,
        newSymbolCount: 0,
        linesInserted,
        linesDeleted,
        unmigratedCallerCount: 0,
        boundaryDriftCount: 0,
        guardBlockCount: (guardStats.sessions && guardStats.sessions[sessionId]) || 0,
        securityFindingsTotal: secFound,
        securityFindingsResolved: secFixed,
        vibesMaxPrismRisk: prismRisk,
        loadEnvelope: '',
        testStatusLabel: 'recorded',
      });
      newRecordsCount++;
    }
  }

  const allRecords = [...recordsById.values()].map((r) => {
    if (r && STALE_TITLE_RE.test(String(r.taskTitle || '').trim())) {
      return { ...r, taskTitle: `Automated Playbook Session (${r.projectName || 'workspace'})` };
    }
    return r;
  });
  fs.writeFileSync(jsonlPath, allRecords.map((r) => JSON.stringify(r)).join('\n') + (allRecords.length ? '\n' : ''));

  // Discover sibling project directories (e.g. under the common parent workspace directory) that have .ai-audit/ or .neckbeard.json or match recorded project names
  const parentCandidates = new Set([path.dirname(path.resolve(cwd))]);
  for (const wsPath of discoveredWorkspacePaths.values()) {
    parentCandidates.add(path.dirname(wsPath));
  }
  for (const parentDir of parentCandidates) {
    if (!parentDir || parentDir === '/' || parentDir === os.homedir()) continue;
    let children = [];
    try { children = fs.readdirSync(parentDir, { withFileTypes: true }); } catch { continue; }
    for (const child of children) {
      if (!child.isDirectory() || child.name.startsWith('.')) continue;
      const fullChild = path.join(parentDir, child.name);
      if (!discoveredWorkspacePaths.has(child.name) && (hasVibes(fullChild) || isProjectDirectory(fullChild))) {
        discoveredWorkspacePaths.set(child.name, fullChild);
      }
    }
  }

  // Populate per-workspace boundary maps, load configs, and VIBES telemetry for all discovered project directories
  const workspacesMeta = {};
  for (const [projName, wsPath] of discoveredWorkspacePaths.entries()) {
    const isCurrent = projName === activeProject;
    const wsHasVibes = hasVibes(wsPath);
    const wsCfg = readProjectConfig(wsPath, env);
    const canScanBounds = isCurrent || isProjectDirectory(wsPath);
    if (!isCurrent && !wsHasVibes && !wsCfg && !canScanBounds) continue;

    const savedBounds = (wsCfg && wsCfg.boundaries && flattenBoundaries(wsCfg.boundaries).length > 0) ? wsCfg.boundaries : null;
    let bounds = savedBounds;
    if (canScanBounds) {
      const scanned = buildBoundaryMap(wsPath, 24);
      if (!bounds) {
        bounds = scanned;
      } else {
        // Merge saved baseline boundaries with live-discovered boundaries so every project's custom topology graph is complete
        const mergeArr = (a = [], b = []) => [...new Set([...a, ...b])].slice(0, 24);
        bounds = {
          external: {
            ingress: mergeArr(bounds.external && bounds.external.ingress, scanned.external.ingress),
            egress: mergeArr(bounds.external && bounds.external.egress, scanned.external.egress),
            supply: mergeArr(bounds.external && bounds.external.supply, scanned.external.supply),
          },
          internal: {
            auth: mergeArr(bounds.internal && bounds.internal.auth, scanned.internal.auth),
            data: mergeArr(bounds.internal && bounds.internal.data, scanned.internal.data),
            exec: mergeArr(bounds.internal && bounds.internal.exec, scanned.internal.exec),
            ai: mergeArr(bounds.internal && bounds.internal.ai, scanned.internal.ai),
          },
        };
      }
    }
    const wsDrift = isCurrent ? detectBoundaryDrift(wsPath, env) : { added: [] };
    const rawVibes = wsHasVibes ? readVibesTelemetry(wsPath) : null;
    const compactVibes = rawVibes ? { ...rawVibes, sessions: undefined } : null;
    workspacesMeta[projName] = {
      load: (wsCfg && wsCfg.load) || '',
      boundaryLoad: (wsCfg && wsCfg.boundaryLoad) || {},
      boundaries: bounds || { external: {}, internal: {} },
      driftAdded: (wsDrift && wsDrift.added) || [],
      prismRisk: rawVibes ? rawVibes.maxPrismRisk : null,
      vibesDecisions: rawVibes ? rawVibes.decisions : 0,
      vibes: compactVibes,
    };
  }

  try {
    fs.writeFileSync(path.join(telemetryDir, 'workspaces-meta.json'), JSON.stringify(workspacesMeta));
  } catch {}

  const html = generateCommandCenterHtml(allRecords, workspacesMeta, Date.now());
  const dashboardFile = path.join(telemetryDir, 'dashboard.html');
  fs.writeFileSync(dashboardFile, html);

  try {
    const legacyBandDir = path.join(configBase(env), 'neckbeard', 'band');
    fs.mkdirSync(legacyBandDir, { recursive: true });
    fs.writeFileSync(path.join(legacyBandDir, 'board.html'), html);
  } catch {}

  return {
    sessions: scannedCount,
    added: newRecordsCount,
    boardFile: dashboardFile,
    tasks: allRecords,
  };
}

function formatSummary(cwd = process.cwd(), env = process.env) {
  const { tasks, boardFile } = collectAndBuild(cwd, env);
  const project = path.basename(path.resolve(cwd));
  const cfg = readProjectConfig(cwd, env);
  const vibes = readVibesTelemetry(cwd);
  const guardStats = readGuardStats(env);

  let cost = 0, tokens = 0, durationMs = 0, added = 0, removed = 0, blocks = guardStats.total || 0, secFound = 0, secFixed = 0;
  for (const r of tasks) {
    cost += r.totalCostUsd || 0;
    const tb = r.tokenBuckets || {};
    tokens += (tb.promptTokens || 0) + (tb.completionTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
    durationMs += r.activeDurationMs || 0;
    added += r.linesInserted || 0;
    removed += r.linesDeleted || 0;
    blocks = Math.max(blocks, r.guardBlockCount || 0);
    secFound += r.securityFindingsTotal || 0;
    secFixed += r.securityFindingsResolved || 0;
  }
  if (vibes) {
    secFound = Math.max(secFound, vibes.highRiskCount + vibes.traceIncidents);
    secFixed = Math.max(secFixed, vibes.traceResolved);
  }

  return [
    `NeckBeard Local Telemetry (${project})`,
    `  Load target       : ${cfg && cfg.load ? `${cfg.load} (${cfg.shared === false ? 'local' : 'shared in .neckbeard.json'})` : 'unset (/neckbeard load <value>)'}`,
    `  VIBES (.ai-audit) : ${vibes ? `active (${vibes.annotationsCount} annotations · PRISM max risk ${vibes.maxPrismRisk.toFixed(2)} · ${vibes.decisions} decisions)` : 'not detected'}`,
    `  Sessions recorded : ${tasks.length}`,
    `  Tokens & Cost     : ${tokens.toLocaleString('en-US')} tokens · $${cost.toFixed(2)}`,
    `  Agent time & LOC  : ${Math.round(durationMs / 60000)}m · +${added} / -${removed} lines`,
    `  Security & Guard  : ${blocks} PreToolUse blocks · ${secFixed}/${secFound} security/TRACE issues resolved`,
    `  Command Center    : ${boardFile}`,
  ].join('\n');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--watch-heal')) {
    const telemetryDir = bandDir(process.env);
    const dashboardFile = path.join(telemetryDir, 'dashboard.html');
    let cleanBuffer = null;
    try {
      const res = collectAndBuild();
      cleanBuffer = fs.readFileSync(res.boardFile);
    } catch {}
    let healing = false;
    try {
      fs.watch(telemetryDir, (_evt, filename) => {
        if (healing || (filename && filename !== 'dashboard.html')) return;
        try {
          const fd = fs.openSync(dashboardFile, 'r');
          const buf = Buffer.alloc(24576);
          const n = fs.readSync(fd, buf, 0, buf.length, 0);
          fs.closeSync(fd);
          const head = buf.toString('utf8', 0, n);
          if (head.includes('Active Engineering Velocity') || head.includes('Target load: unset')) {
            healing = true;
            if (cleanBuffer) fs.writeFileSync(dashboardFile, cleanBuffer);
            const rebuilt = collectAndBuild();
            cleanBuffer = fs.readFileSync(rebuilt.boardFile);
            healing = false;
          } else {
            cleanBuffer = fs.readFileSync(dashboardFile);
          }
        } catch {
          healing = false;
        }
      });
    } catch {}
  } else if (args.includes('--summary')) {
    process.stdout.write(formatSummary() + '\n');
  } else {
    const res = collectAndBuild();
    if (args.includes('--open')) {
      const opener = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      const openerArgs = process.platform === 'win32' ? ['/c', 'start', '', res.boardFile] : [res.boardFile];
      try { spawnSync(opener, openerArgs, { stdio: 'ignore' }); } catch {}
    }
    process.stdout.write(`neckbeard telemetry: ${res.sessions} sessions scanned, ${res.added} new records in ${res.boardFile}.\n`);
  }
}

module.exports = {
  MODEL_RATES_PER_M,
  computeMessageCostUsd,
  extractSessionTaskTitle,
  parseJsonlSessionFile,
  generateCommandCenterHtml,
  formatSummary,
  run: collectAndBuild,
};
