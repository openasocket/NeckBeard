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
const { hasVibes, readVibesTelemetry } = require('./vibes');
const { buildBoundaryMap, detectBoundaryDrift, readProjectConfig } = require('./surface');

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
      if (textPart && !firstPrompt && !textPart.trim().startsWith('<') && !textPart.trim().startsWith('/')) {
        firstPrompt = textPart.trim().split('\n')[0].slice(0, 64);
      }
      const isToolResult = Array.isArray(msgContent) && msgContent.some((b) => b && b.type === 'tool_result');
      if (!isToolResult) turnCount++;
    }

    if (entry.type === 'assistant' && entry.message && entry.message.model && entry.message.model !== '<synthetic>') {
      const { id, model, usage } = entry.message;
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

  return {
    workspaceCwd,
    startedAtMs,
    taskTitle: sessionTitle || firstPrompt || 'Interactive coding session',
    modelId: primaryModel,
    turnCount,
    activeDurationMs,
    tokenBuckets,
    totalCostUsd: +totalCostUsd.toFixed(4),
  };
}

function readExistingJsonlRecords(jsonlPath) {
  const byId = new Map();
  try {
    if (!fs.existsSync(jsonlPath)) return byId;
    for (const line of fs.readFileSync(jsonlPath, 'utf8').split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        const rec = JSON.parse(t);
        if (rec && rec.recordId) byId.set(rec.recordId, rec);
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
.shell{display:grid;grid-template-columns:284px minmax(0,1fr);min-height:100vh}
.rail{background:var(--surface);border-right:1px solid var(--border);padding:22px 16px;display:flex;flex-direction:column;gap:6px}
.crest{display:flex;align-items:center;gap:12px;padding:4px 8px 18px;border-bottom:1px solid var(--border);margin-bottom:10px}
.tp{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red)}
.crest-title{font:800 16px/1.1 var(--mono);color:var(--text);display:flex;align-items:center;gap:7px}
.crest-sub{font:600 10.5px var(--mono);color:var(--emerald);margin-top:4px;letter-spacing:.05em}
.rail-lbl{font:700 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);padding:8px 10px 4px}
.ws-btn{display:flex;justify-content:space-between;align-items:center;width:100%;border:1px solid transparent;background:transparent;color:var(--muted);font:500 13px var(--sans);padding:8px 12px;border-radius:10px;cursor:pointer;text-align:left;gap:6px}
.ws-btn:hover,.ws-btn.active{background:var(--card);color:var(--text);border-color:var(--border)}
.ws-badges{display:inline-flex;align-items:center;gap:5px}
.ws-vtag{font:700 9.5px var(--mono);color:var(--cyan);background:rgba(6,182,212,.14);border:1px solid rgba(6,182,212,.35);padding:1px 6px;border-radius:99px}
.ws-cnt{font:600 11.5px var(--mono);color:var(--emerald);background:rgba(16,185,129,.12);padding:2px 7px;border-radius:99px}
.rail-foot{margin-top:auto;padding:14px 10px 4px;border-top:1px solid var(--border);font:500 11.5px/1.6 var(--mono);color:var(--dim)}
.stage{padding:26px 34px 64px;max-width:1480px;width:100%}
.topbar{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid var(--border)}
.topbar h1{margin:0;font:800 24px/1.15 var(--mono);letter-spacing:-.02em}
.topbar p{margin:5px 0 0;color:var(--muted);font:400 13px var(--mono)}
.views{display:inline-flex;background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:4px;gap:4px;flex-wrap:wrap}
.v-btn{border:0;background:transparent;color:var(--muted);font:600 12px var(--mono);padding:8px 13px;border-radius:8px;cursor:pointer}
.v-btn.active{background:var(--card);color:var(--emerald);box-shadow:inset 0 0 0 1px rgba(16,185,129,.35)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:20px}
.vpillars{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-top:14px}
.pbox{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:13px 14px}
.pk{font:700 10.5px var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--cyan)}
.pv{font:800 20px/1.2 var(--mono);margin-top:6px;color:var(--text)}
.ps{font:400 11px var(--mono);color:var(--muted);margin-top:4px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:18px 20px}
.m-tag{font:700 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between}
.m-val{font:800 25px/1.15 var(--mono);margin-top:8px;color:var(--text)}
.m-sub{font:400 11.5px var(--mono);color:var(--dim);margin-top:6px}
.card-sec{margin-top:20px;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:22px}
.card-sec.vibes-hi{border-color:rgba(6,182,212,.45);background:linear-gradient(180deg,rgba(6,182,212,.06) 0%,var(--card) 100%)}
.sec-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.sec-head h2{margin:0;font:700 16px var(--mono);display:flex;align-items:center;gap:10px}
.split2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
.adopt-bar{margin-top:14px;background:rgba(6,182,212,.07);border:1px dashed rgba(6,182,212,.45);border-radius:12px;padding:16px 18px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.adopt-cmd{font:500 12px var(--mono);background:#060908;border:1px solid var(--border);padding:8px 12px;border-radius:8px;color:var(--emerald)}
.act-btn{border:1px solid rgba(6,182,212,.45);background:rgba(6,182,212,.14);color:var(--cyan);font:600 12px var(--mono);padding:7px 13px;border-radius:8px;cursor:pointer}
.act-btn:hover{background:rgba(6,182,212,.25)}
.s-in{background:var(--surface);border:1px solid var(--border);color:var(--text);font:500 12px var(--mono);padding:6px 11px;border-radius:8px;min-width:210px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;font:600 11px var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--dim);padding:10px 12px;border-bottom:1px solid var(--border)}
td{padding:11px 12px;border-bottom:1px solid var(--border);font-family:var(--mono)}
td.tcol{font-family:var(--sans);font-weight:500}
tr.crow{cursor:pointer}tr.crow:hover{background:rgba(16,185,129,.06)}
.chip{display:inline-block;padding:3px 9px;border-radius:99px;font:600 11px var(--mono);background:rgba(16,185,129,.14);color:var(--emerald)}
.chip.cyan{background:rgba(6,182,212,.16);color:var(--cyan)}
.chip.warn{background:rgba(245,158,11,.16);color:var(--amber)}
@media(max-width:1180px){.shell{grid-template-columns:1fr}.rail{border-right:0;border-bottom:1px solid var(--border)}.kpis,.vpillars,.split2{grid-template-columns:1fr}}
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
    <div class="rail-lbl">Workspaces (<span id="ws-total-cnt">0</span>)</div>
    <div id="ws-list" style="overflow-y:auto;max-height:70vh"></div>
    <div class="rail-foot">NeckBeard Command Center v0.2<br>3-Gate Engine + VIBES Hub<br>100% Local · Zero Network Calls</div>
  </aside>
  <main class="stage">
    <header class="topbar">
      <div><h1 id="st-title">All Workspaces</h1><p id="st-subtitle"></p></div>
      <div class="views" role="tablist">
        <button type="button" class="v-btn active" data-view="overview">1. Command Overview</button>
        <button type="button" class="v-btn" data-view="vibes">2. VIBES (.ai-audit) Hub</button>
        <button type="button" class="v-btn" data-view="economics">3. Repo &amp; Model Economics</button>
        <button type="button" class="v-btn" data-view="topology">4. Trust-Boundary Graph</button>
        <button type="button" class="v-btn" data-view="forensics">5. Session Forensics</button>
      </div>
    </header>
    <div class="kpis">
      <div class="panel"><div class="m-tag"><span>Code Minimalism &amp; Reuse</span><span style="color:var(--emerald)">6-RUNG LADDER</span></div><div class="m-val" id="m-loc">+0 / -0 LOC</div><div class="m-sub" id="m-reuse">Symbol reuse ratio across edits</div></div>
      <div class="panel"><div class="m-tag"><span>PreToolUse Shield &amp; Safety</span><span style="color:var(--cyan)">GATE 1: SAFE</span></div><div class="m-val" id="m-sec">0 blocked</div><div class="m-sub" id="m-vibes">Secrets, config censor &amp; VIBES lock</div></div>
      <div class="panel"><div class="m-tag"><span>Token Cache &amp; Cost Efficiency</span><span style="color:var(--amber)">GATE 2: SCALE</span></div><div class="m-val" id="m-cost">$0.00</div><div class="m-sub" id="m-cache">0% prompt cache hit rate</div></div>
      <div class="panel"><div class="m-tag"><span>Active Engineering Velocity</span><span style="color:var(--emerald)">GATE 3: DONE</span></div><div class="m-val" id="m-time">0h 0m</div><div class="m-sub" id="m-load">Load target from .neckbeard.json</div></div>
    </div>

    <!-- FRONT-AND-CENTER VIBES PROTOCOL (.ai-audit/) DATA VISUALIZATION & ADOPTION HUB -->
    <section class="card-sec vibes-hi" id="pane-vibes">
      <div class="sec-head">
        <h2>
          <span>VIBES Protocol (.ai-audit/) Provenance &amp; PRISM Risk Intelligence</span>
          <a href="https://www.itsavibe.ai" target="_blank" rel="noopener" class="chip cyan">itsavibe.ai ↗</a>
        </h2>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span id="vibes-status-chip" class="chip">Checking .ai-audit/...</span>
          <button type="button" id="vibes-demo-btn" class="act-btn">Preview Full VIBES (.ai-audit/) Forensics</button>
        </div>
      </div>
      <p id="vibes-explainer" style="margin:0 0 12px;color:var(--muted);font-size:13px"></p>
      <div class="vpillars">
        <div class="pbox"><div class="pk">1. VIBES v1.1 Provenance</div><div class="pv" id="vp-prov">0 annotations</div><div class="ps" id="vp-prov-sub">0 blobs · 0 files attributed</div></div>
        <div class="pbox"><div class="pk">2. VERIFY v1.0 DSSE</div><div class="pv" id="vp-verify">0% verified</div><div class="ps" id="vp-verify-sub">0 Ed25519 DSSE envelopes</div></div>
        <div class="pbox"><div class="pk">3. PRISM v1.0 Risk</div><div class="pv" id="vp-prism">0.00 max</div><div class="ps" id="vp-prism-sub">0 High/Critical (&gt;= 0.60)</div></div>
        <div class="pbox"><div class="pk">4. EVOLVE v1.0 Decisions</div><div class="pv" id="vp-evolve">0 decisions</div><div class="ps" id="vp-evolve-sub">Linked to /neckbeard-debt</div></div>
        <div class="pbox"><div class="pk">5. TRACE v1.0 Forensics</div><div class="pv" id="vp-trace">0 / 0 fixed</div><div class="ps" id="vp-trace-sub">IoC rules &amp; incident response</div></div>
      </div>
      <div style="margin-top:16px;background:#080d0b;border:1px solid var(--border);border-radius:12px;padding:14px">
        <svg id="vibes-svg" viewBox="0 0 960 255" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div class="split2">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px">
          <div style="font:700 12px var(--mono);color:var(--emerald);margin-bottom:8px">EVOLVE ARCHITECTURAL DECISIONS &amp; PRETOOLUSE IMMUTABILITY SHIELD</div>
          <div id="vibes-decisions-list" style="font:400 12px/1.65 var(--mono);color:var(--muted)"></div>
        </div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px">
          <div style="font:700 12px var(--mono);color:var(--amber);margin-bottom:8px">TRACE INCIDENT LOG &amp; HIGH-RISK PRISM EDITS (&gt;= 0.60)</div>
          <div id="vibes-incidents-list" style="font:400 12px/1.65 var(--mono);color:var(--muted)"></div>
        </div>
      </div>
      <div id="vibes-annotations-wrap" style="margin-top:16px;display:none">
        <div style="font:700 12px var(--mono);color:var(--cyan);margin-bottom:8px">TURN-LEVEL .AI-AUDIT/ANNOTATIONS.JSONL PROVENANCE &amp; PRISM INSPECTOR</div>
        <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px">
          <table><thead><tr><th>Timestamp</th><th>Session</th><th>Attributed File</th><th>Line Attribution</th><th>PRISM Risk</th><th>VERIFY DSSE</th><th>Intent / Prompt Summary</th></tr></thead><tbody id="vibes-annotations-rows"></tbody></table>
        </div>
      </div>
      <div class="adopt-bar">
        <div style="max-width:700px">
          <div style="font:700 13px var(--mono);color:var(--cyan)">🚀 Unlock 5-Pillar VIBES (.ai-audit/) Provenance in Every Project</div>
          <div style="font-size:12.5px;color:var(--muted);margin-top:4px">
            Without VIBES, NeckBeard tracks session cost, token cache efficiency, guard blocks, and <code>.neckbeard.json</code> trust boundaries. Enabling <strong><a href="https://www.itsavibe.ai" target="_blank" rel="noopener">VIBES (.ai-audit/)</a></strong> adds line-range file attribution, Ed25519 DSSE attestations locked by <code>hooks/guard.js</code>, per-turn PRISM risk scores for <code>/neckbeard-review</code>, EVOLVE decision records for <code>/neckbeard-debt</code>, and TRACE incident forensics.
          </div>
        </div>
        <div class="adopt-cmd">npx vibecheck init &amp;&amp; vibecheck validate</div>
      </div>
    </section>

    <!-- BASELINE ENGINEERING VALUE: 14-DAY COST/CACHE VELOCITY CHART + PER-REPO & PER-MODEL ECONOMICS -->
    <section class="card-sec" id="pane-economics">
      <div class="sec-head">
        <h2>Engineering Velocity, Per-Repository Scorecard &amp; Model Cache Economics</h2>
        <span class="chip">100% Local Telemetry</span>
      </div>
      <div style="background:#080d0b;border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:18px">
        <svg id="velocity-svg" viewBox="0 0 960 210" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div class="split2">
        <div>
          <div style="font:700 12px var(--mono);color:var(--emerald);margin-bottom:8px">PER-REPOSITORY ENGINEERING SCORECARD (CLICK TO FILTER)</div>
          <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:320px">
            <table><thead><tr><th>Repository</th><th>Sessions</th><th>Active Time</th><th>Cache Hit</th><th>Cost</th><th>VIBES / Load</th></tr></thead><tbody id="repo-scorecard-rows"></tbody></table>
          </div>
        </div>
        <div>
          <div style="font:700 12px var(--mono);color:var(--amber);margin-bottom:8px">MODEL &amp; PROMPT-CACHE ECONOMICS BREAKDOWN</div>
          <div style="overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;max-height:320px">
            <table><thead><tr><th>Model</th><th>Sessions / Turns</th><th>Prompt + Cache</th><th>Output Tok</th><th>Cache Hit %</th><th>Total Cost</th></tr></thead><tbody id="model-econ-rows"></tbody></table>
          </div>
        </div>
      </div>
    </section>

    <section class="card-sec" id="pane-overview">
      <div class="sec-head"><h2>External → Internal Trust-Boundary Graph</h2><span id="ov-drift" class="chip">✓ Baseline Verified</span></div>
      <svg id="boundary-svg" viewBox="0 0 960 360" style="width:100%;height:auto;display:block"></svg>
    </section>
    <section class="card-sec" id="pane-forensics">
      <div class="sec-head">
        <h2>Recorded Engineering &amp; Audit Sessions</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input type="search" id="session-search" class="s-in" placeholder="Filter by task, repo, model...">
          <span id="tbl-count" class="chip">0 sessions</span>
        </div>
      </div>
      <div style="overflow-x:auto"><table><thead><tr><th>Task / Prompt</th><th>Workspace</th><th>Timestamp</th><th>Model &amp; Level</th><th>Duration</th><th>Cost &amp; Tokens</th><th>Reuse &amp; Net LOC</th><th>Guard &amp; VIBES</th><th>Verification</th></tr></thead><tbody id="session-rows"></tbody></table></div>
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
  function resolveVibes(wsKey){
    if(demoVibesMode)return SAMPLE_VIBES;
    if(wsKey&&meta[wsKey]&&meta[wsKey].vibes&&meta[wsKey].vibes.present)return meta[wsKey].vibes;
    if(!wsKey){
      var ks=Object.keys(meta);
      for(var i=0;i<ks.length;i++){var v=meta[ks[i]]&&meta[ks[i]].vibes;if(v&&v.present)return v}
    }
    return null;
  }
  function renderVibes(wsKey){
    var v=resolveVibes(wsKey),chip=el('vibes-status-chip'),dbtn=el('vibes-demo-btn'),exp=el('vibes-explainer'),awrap=el('vibes-annotations-wrap');
    if(v&&v.present){
      chip.className=v.isDemo?'chip warn':'chip cyan';
      chip.textContent=v.isDemo?'★ Interactive Reference VIBES (.ai-audit/) Forensics Active':'● VIBES (.ai-audit/) Active · 5-Pillar Deep Forensics Unlocked';
      dbtn.textContent=v.isDemo?'Exit Reference Preview':'Toggle Reference Preview';
      exp.innerHTML='<strong>VIBES Deep Forensics Active:</strong> Showing line-range file attribution (<code>VIBES v1.1</code>), Ed25519 DSSE attestation coverage (<code>VERIFY v1.0</code>), per-turn risk distribution &amp; sparkline (<code>PRISM v1.0</code>), architectural decision records (<code>EVOLVE v1.0</code>), and IoC incident response (<code>TRACE v1.0</code>).';
      awrap.style.display='block';
    }else{
      chip.className='chip warn';
      chip.textContent='○ Standard Telemetry Mode (.ai-audit/ Not Detected in Workspace)';
      dbtn.textContent='Preview Full VIBES (.ai-audit/) Forensics';
      exp.innerHTML='<strong>Standard NeckBeard Telemetry Active:</strong> You have full access to session cost, prompt-cache economics, guard blocks, and <code>.neckbeard.json</code> trust boundaries below. Initialize <strong><a href="https://www.itsavibe.ai" target="_blank" rel="noopener">VIBES (.ai-audit/)</a></strong> (or click <em>Preview Full VIBES Forensics</em>) to unlock cryptographic file attribution, PRISM risk trajectories, EVOLVE decision ledgers, and TRACE incident forensics.';
      awrap.style.display='none';
    }
    var av=v||{annotationsCount:0,verifiedCount:0,blobsCount:0,attestationsCount:0,iocRulesCount:0,maxPrismRisk:0,highRiskCount:0,traceIncidents:0,traceResolved:0,decisions:0,filesTouchedCount:0,prismBuckets:{low:0,moderate:0,high:0,critical:0},fileHotspots:[],decisionRecords:[],incidentRecords:[],recentAnnotations:[]};
    var ac=av.annotationsCount||0,vp=ac>0?Math.round(((av.verifiedCount||0)/ac)*100):0;
    el('vp-prov').textContent=ac+' annotations';
    el('vp-prov-sub').textContent=(av.blobsCount||0)+' SHA-256 blobs · '+(av.filesTouchedCount||0)+' files';
    el('vp-verify').textContent=vp+'% verified';
    el('vp-verify-sub').textContent=(av.attestationsCount||0)+' DSSE attestations · Guard locked';
    el('vp-prism').textContent=Number(av.maxPrismRisk||0).toFixed(2)+' max risk';
    el('vp-prism-sub').textContent=(av.highRiskCount||0)+' High/Critical (>= 0.60)';
    el('vp-evolve').textContent=(av.decisions||0)+' decisions';
    el('vp-evolve-sub').textContent='Cross-checked by /neckbeard-debt';
    el('vp-trace').textContent=(av.traceResolved||0)+' / '+(av.traceIncidents||0)+' fixed';
    el('vp-trace-sub').textContent=(av.iocRulesCount||0)+' custom IoC rules in iocs.d/';
    var vbox=el('vibes-svg');
    if(vbox){
      vbox.textContent='';var NS='http://www.w3.org/2000/svg';
      function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,a[k]);if(txt!=null)n.textContent=String(txt);if(p)p.appendChild(n);return n}
      node('text',{x:16,y:22,fill:'#06b6d4','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'1. PRISM v1.0 RISK HISTOGRAM');
      var pb=av.prismBuckets||{},bks=[['Low (<0.30)',pb.low||0,'#10b981'],['Mod (0.30-0.59)',pb.moderate||0,'#06b6d4'],['High (0.60-0.79)',pb.high||0,'#f59e0b'],['Crit (>=0.80)',pb.critical||0,'#ef4444']];
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
      var anns=(av.recentAnnotations&&av.recentAnnotations.length)?av.recentAnnotations.slice(0,10).reverse():[];
      if(anns.length>0){
        var pts=[];
        anns.forEach(function(a,idx){
          var r=typeof a.riskScore==='number'?a.riskScore:0.18;
          var px=342+Math.round((idx/Math.max(1,anns.length-1))*230);
          var py=48+Math.round((1-Math.min(1,Math.max(0,r)))*156);
          pts.push(px+','+py);
          node('circle',{cx:px,cy:py,r:4,fill:r>=0.8?'#ef4444':r>=0.6?'#f59e0b':'#10b981'},vbox);
        });
        if(pts.length>1)node('polyline',{points:pts.join(' '),fill:'none',stroke:'#06b6d4','stroke-width':1.8},vbox);
      }else{
        node('text',{x:338,y:140,fill:'#55665c','font-size':10.5,'font-family':'monospace'},vbox,'(Click Preview above to plot PRISM curve)');
      }
      node('line',{x1:612,y1:12,x2:612,y2:240,stroke:'#1d2b23','stroke-dasharray':'4,4'},vbox);
      node('text',{x:626,y:22,fill:'#10b981','font-size':11.5,'font-weight':700,'font-family':'monospace'},vbox,'3. ATTRIBUTED FILE HOTSPOTS');
      var hs=(av.fileHotspots&&av.fileHotspots.length)?av.fileHotspots.slice(0,5):[{file:'(No .ai-audit/ in workspace)',annotations:0,linesAdded:0,linesRemoved:0,maxRisk:0,verified:false}];
      hs.forEach(function(h,idx){
        var y=44+idx*39,rc=h.maxRisk>=0.8?'#ef4444':h.maxRisk>=0.6?'#f59e0b':h.maxRisk>=0.3?'#06b6d4':'#10b981';
        node('text',{x:626,y:y+13,fill:'#ecf3ef','font-size':10.5,'font-family':'monospace'},vbox,(h.verified?'✓ ':'○ ')+h.file.slice(0,22));
        node('rect',{x:785,y:y+2,width:70,height:13,rx:4,fill:'#101814',stroke:'#1d2b23'},vbox);
        var rw=Math.max(3,Math.round(Math.min(1,h.maxRisk||0)*70));
        if(h.maxRisk>0)node('rect',{x:785,y:y+2,width:rw,height:13,rx:4,fill:rc},vbox);
        node('text',{x:862,y:y+12,fill:rc,'font-size':10,'font-weight':700,'font-family':'monospace'},vbox,Number(h.maxRisk||0).toFixed(2)+' (+'+h.linesAdded+'/-'+h.linesRemoved+')');
      });
    }
    var dl=el('vibes-decisions-list');dl.textContent='';
    var ds=(av.decisionRecords&&av.decisionRecords.length)?av.decisionRecords:[{id:'GUARD',title:'Immutable .ai-audit/{manifest.json,annotations.jsonl,blobs/,attestations/} protected by hooks/guard.js',status:'armed'}];
    ds.slice(0,6).forEach(function(d){var r=document.createElement('div');r.textContent='['+d.id+'] '+d.title+' ('+d.status+')';dl.appendChild(r)});
    var il=el('vibes-incidents-list');il.textContent='';
    var is=(av.incidentRecords&&av.incidentRecords.length)?av.incidentRecords:[{iocId:'READY',status:'clean',summary:'0 unresolved TRACE incidents or unverified high-risk PRISM edits'}];
    is.slice(0,6).forEach(function(inc){var r=document.createElement('div');r.textContent='['+inc.iocId+' · '+inc.status.toUpperCase()+'] '+inc.summary;il.appendChild(r)});
    var ar=el('vibes-annotations-rows');
    if(ar){
      ar.textContent='';
      (av.recentAnnotations||[]).slice(0,10).forEach(function(a){
        var tr=document.createElement('tr'),rt=a.riskScore!=null?a.riskScore.toFixed(2):'–';
        [a.timestamp||'–',a.sessionId||'–',a.file||'–','+'+(a.linesAdded||0)+' / -'+(a.linesRemoved||0),'PRISM '+rt,a.verified?'✓ DSSE Verified':'○ Unattested',a.summary||'Annotated turn'].forEach(function(val,idx){
          var td=document.createElement('td');if(idx===6)td.className='tcol';td.textContent=val;tr.appendChild(td);
        });
        ar.appendChild(tr);
      });
    }
  }
  function renderEcon(list){
    var vbox=el('velocity-svg');
    if(vbox){
      vbox.textContent='';var NS='http://www.w3.org/2000/svg';
      function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,a[k]);if(txt!=null)n.textContent=String(txt);if(p)p.appendChild(n);return n}
      var byDay={};
      list.forEach(function(r){
        var d=String(r.timestampIso||'').slice(0,10)||'Recent';
        if(!byDay[d])byDay[d]={day:d,cost:0,sessions:0,cRead:0,tIn:0};
        byDay[d].cost+=r.totalCostUsd||0;byDay[d].sessions+=1;
        var tb=r.tokenBuckets||{};
        byDay[d].cRead+=tb.cachedReadTokens||0;
        byDay[d].tIn+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      });
      var days=Object.keys(byDay).sort().slice(-14);
      node('text',{x:18,y:22,fill:'#10b981','font-size':12,'font-weight':700,'font-family':'monospace'},vbox,'14-DAY API SPEND ($), SESSION ACTIVITY & PROMPT CACHE EFFICIENCY');
      var mc=0.01;days.forEach(function(d){if(byDay[d].cost>mc)mc=byDay[d].cost});
      days.forEach(function(d,idx){
        var inf=byDay[d],x=28+idx*65,bh=Math.max(6,Math.round((inf.cost/mc)*118)),y=166-bh;
        node('rect',{x:x,y:y,width:38,height:bh,rx:5,fill:'#10b981'},vbox);
        node('text',{x:x+19,y:y-6,fill:'#ecf3ef','font-size':9.5,'text-anchor':'middle','font-family':'monospace'},vbox,'$'+inf.cost.toFixed(0));
        node('text',{x:x+19,y:184,fill:'#8b9d92','font-size':9.5,'text-anchor':'middle','font-family':'monospace'},vbox,d.slice(5));
        var ch=inf.tIn>0?Math.round((inf.cRead/inf.tIn)*100):0;
        node('text',{x:x+19,y:198,fill:'#06b6d4','font-size':9,'text-anchor':'middle','font-family':'monospace'},vbox,ch+'% cache');
      });
    }
    var rMap={};
    records.forEach(function(r){
      var p=r.projectName||'workspace';
      if(!rMap[p])rMap[p]={name:p,sessions:0,dur:0,cost:0,cRead:0,tIn:0};
      rMap[p].sessions+=1;rMap[p].dur+=r.activeDurationMs||0;rMap[p].cost+=r.totalCostUsd||0;
      var tb=r.tokenBuckets||{};
      rMap[p].cRead+=tb.cachedReadTokens||0;
      rMap[p].tIn+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
    });
    var rRows=el('repo-scorecard-rows');
    if(rRows){
      rRows.textContent='';
      Object.values(rMap).sort(function(a,b){return b.cost-a.cost}).slice(0,25).forEach(function(rp){
        var tr=document.createElement('tr');tr.className='crow';
        var ch=rp.tIn>0?Math.round((rp.cRead/rp.tIn)*100)+'%':'0%',wm=meta[rp.name]||{};
        var st=(wm.vibes&&wm.vibes.present?'● VIBES':'○ Std')+(wm.load?' · '+wm.load.slice(0,14):'');
        [rp.name,String(rp.sessions),fmtDur(rp.dur),ch,'$'+rp.cost.toFixed(2),st].forEach(function(v,idx){
          var td=document.createElement('td');if(idx===0)td.className='tcol';td.textContent=v;tr.appendChild(td);
        });
        tr.onclick=function(){activeWorkspace=rp.name;render()};
        rRows.appendChild(tr);
      });
    }
    var mMap={};
    list.forEach(function(r){
      var m=r.modelId||'unknown';
      if(!mMap[m])mMap[m]={model:m,sessions:0,turns:0,inTok:0,outTok:0,cRead:0,cost:0};
      mMap[m].sessions+=1;mMap[m].turns+=r.turnCount||1;
      var tb=r.tokenBuckets||{};
      mMap[m].inTok+=(tb.promptTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      mMap[m].outTok+=tb.completionTokens||0;
      mMap[m].cRead+=tb.cachedReadTokens||0;
      mMap[m].cost+=r.totalCostUsd||0;
    });
    var mRows=el('model-econ-rows');
    if(mRows){
      mRows.textContent='';
      Object.values(mMap).sort(function(a,b){return b.cost-a.cost}).forEach(function(mm){
        var tr=document.createElement('tr'),ch=mm.inTok>0?Math.round((mm.cRead/mm.inTok)*100)+'%':'0%';
        [mm.model,mm.sessions+' / '+mm.turns,fmtTok(mm.inTok),fmtTok(mm.outTok),ch,'$'+mm.cost.toFixed(2)].forEach(function(v){
          var td=document.createElement('td');td.textContent=v;tr.appendChild(td);
        });
        mRows.appendChild(tr);
      });
    }
  }
  function renderGraph(wsKey){
    var box=el('boundary-svg');if(!box)return;box.textContent='';
    var NS='http://www.w3.org/2000/svg';
    function node(t,a,p,txt){var n=document.createElementNS(NS,t);for(var k in a)n.setAttribute(k,a[k]);if(txt!=null)n.textContent=txt;if(p)p.appendChild(n);return n}
    var key=wsKey||Object.keys(meta)[0]||'',wm=meta[key]||{},b=wm.boundaries||{external:{},internal:{}},ext=b.external||{},int=b.internal||{},drift=wm.driftAdded||[];
    var db=el('ov-drift');
    if(drift.length){db.className='chip warn';db.textContent='⚠ +'+drift.length+' Unreviewed Boundary Drift: '+drift.join(', ')}
    else{db.className='chip';db.textContent='✓ Trust Boundaries Match Saved .neckbeard.json'}
    node('rect',{x:420,y:12,width:120,height:336,rx:14,fill:'#0e1913',stroke:'#10b981','stroke-dasharray':'6,4'},box);
    node('text',{x:480,y:162,fill:'#10b981','font-size':12,'font-weight':800,'text-anchor':'middle','font-family':'monospace'},box,'TRUST');
    node('text',{x:480,y:180,fill:'#10b981','font-size':12,'font-weight':800,'text-anchor':'middle','font-family':'monospace'},box,'BOUNDARY');
    node('text',{x:480,y:202,fill:'#8b9d92','font-size':10,'text-anchor':'middle','font-family':'monospace'},box,'Fail Closed · Object Auth');
    [['External Ingress (HTTP/CLI/Webhook)',ext.ingress||[],'#f59e0b'],['External Egress (Outbound / SSRF)',ext.egress||[],'#06b6d4'],['Supply Chain & CI Workflows',ext.supply||[],'#a855f7']].forEach(function(g,i){
      var y=20+i*112;
      node('rect',{x:16,y:y,width:340,height:92,rx:12,fill:'#0b110e',stroke:g[2]},box);
      node('text',{x:30,y:y+24,fill:g[2],'font-size':12.5,'font-weight':700,'font-family':'monospace'},box,g[0]+' ('+g[1].length+')');
      (g[1].length?g[1].slice(0,3):['(no sinks matched)']).forEach(function(it,j){node('text',{x:30,y:y+45+j*15,fill:'#ecf3ef','font-size':11,'font-family':'monospace'},box,it)});
      node('path',{d:'M356,'+(y+46)+' C390,'+(y+46)+' 390,180 420,180',fill:'none',stroke:g[2],'stroke-width':1.6},box);
    });
    [['Internal Auth & Object Ownership',int.auth||[],'#10b981'],['Internal Data & Storage (SQL/FS)',int.data||[],'#2dd4bf'],['Internal Execution & Crypto',int.exec||[],'#fb7185'],['Internal AI & Prompt Context',int.ai||[],'#facc15']].forEach(function(g,i){
      var y=14+i*84;
      node('rect',{x:604,y:y,width:340,height:72,rx:12,fill:'#0b110e',stroke:g[2]},box);
      node('text',{x:618,y:y+21,fill:g[2],'font-size':12,'font-weight':700,'font-family':'monospace'},box,g[0]+' ('+g[1].length+')');
      (g[1].length?g[1].slice(0,2):['(no sinks matched)']).forEach(function(it,j){node('text',{x:618,y:y+40+j*15,fill:'#ecf3ef','font-size':11,'font-family':'monospace'},box,it)});
      node('path',{d:'M540,180 C572,180 572,'+(y+36)+' 604,'+(y+36),fill:'none',stroke:g[2],'stroke-width':1.6},box);
    });
  }
  function render(){
    var list=activeWorkspace?records.filter(function(r){return r.projectName===activeWorkspace}):records;
    var key=activeWorkspace||Object.keys(meta)[0]||'',wm=meta[key]||{};
    el('st-title').textContent=activeWorkspace||'All Workspaces';
    el('st-subtitle').textContent=list.length+' recorded session(s) · Load envelope: '+(wm.load||'unset (/neckbeard load <params>)');
    el('pane-vibes').style.display=(activeView==='overview'||activeView==='vibes')?'block':'none';
    el('pane-economics').style.display=(activeView==='overview'||activeView==='economics')?'block':'none';
    el('pane-overview').style.display=(activeView==='overview'||activeView==='topology')?'block':'none';
    el('pane-forensics').style.display=(activeView==='overview'||activeView==='forensics')?'block':'none';
    var cost=0,tok=0,cRead=0,inAll=0,dur=0,turns=0,ins=0,del=0,blk=0,found=0,fixed=0,reused=0,created=0;
    list.forEach(function(r){
      cost+=r.totalCostUsd||0;var tb=r.tokenBuckets||{};
      var pT=tb.promptTokens||0,cT=tb.completionTokens||0,crT=tb.cachedReadTokens||0,cwT=tb.cachedWriteTokens||0;
      tok+=pT+cT+crT+cwT;cRead+=crT;inAll+=pT+crT+cwT;dur+=r.activeDurationMs||0;turns+=r.turnCount||1;
      ins+=r.linesInserted||0;del+=r.linesDeleted||0;blk+=r.guardBlockCount||0;
      found+=r.securityFindingsTotal||0;fixed+=r.securityFindingsResolved||0;
      reused+=r.reusedSymbolCount||0;created+=r.newSymbolCount||0;
    });
    el('m-loc').textContent='+'+ins+' / -'+del+' LOC';
    var rPct=(reused+created)>0?Math.round((reused/(reused+created))*100)+'% symbol reuse':'Net code delta across '+list.length+' sessions';
    el('m-reuse').textContent=rPct;
    el('m-sec').textContent=blk+' guard blocks · '+fixed+'/'+found+' fixed';
    el('m-vibes').textContent=wm.prismRisk!=null?('VIBES active · PRISM max risk '+wm.prismRisk+' · '+(wm.vibesDecisions||0)+' decisions'):'PreToolUse secret & VIBES provenance shield';
    el('m-cost').textContent='$'+cost.toFixed(2)+' · '+fmtTok(tok)+' tok';
    var cPct=inAll>0?Math.round((cRead/inAll)*100):0;
    el('m-cache').textContent=cPct+'% prompt cache hit rate · '+turns.toLocaleString()+' turns';
    el('m-time').textContent=fmtDur(dur);
    el('m-load').textContent='Target load: '+(wm.load||'unset (/neckbeard load <value>)');
    var searched=searchQuery?list.filter(function(r){var q=searchQuery.toLowerCase();return String(r.taskTitle||'').toLowerCase().includes(q)||String(r.projectName||'').toLowerCase().includes(q)||String(r.modelId||'').toLowerCase().includes(q)}):list;
    el('tbl-count').textContent=searched.length+' session(s)';
    var tbody=el('session-rows');tbody.textContent='';
    searched.slice().sort(function(a,b){return(b.startedAtMs||0)-(a.startedAtMs||0)}).slice(0,250).forEach(function(r){
      var tr=document.createElement('tr'),tb=r.tokenBuckets||{};
      var tTok=(tb.promptTokens||0)+(tb.completionTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      [r.taskTitle||'Session',r.projectName||'–',r.timestampIso||'–',(r.modelId||'claude')+' ['+(r.activeLevel||'full')+']',fmtDur(r.activeDurationMs),'$'+(r.totalCostUsd||0).toFixed(2)+' ('+fmtTok(tTok)+')',(r.reusePercent==null?'–':r.reusePercent+'%')+' (+'+(r.linesInserted||0)+'/-'+(r.linesDeleted||0)+')',(r.guardBlockCount||0)+' blk · '+(r.securityFindingsResolved||0)+'/'+(r.securityFindingsTotal||0)+(r.vibesMaxPrismRisk!=null?' · PRISM '+r.vibesMaxPrismRisk:''),r.testStatusLabel||'recorded'].forEach(function(v,idx){
        var td=document.createElement('td');if(idx===0)td.className='tcol';td.textContent=v;tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    renderVibes(activeWorkspace);
    renderEcon(list);
    renderGraph(activeWorkspace);
  }
  var dbtn=el('vibes-demo-btn');
  if(dbtn){dbtn.onclick=function(){demoVibesMode=!demoVibesMode;render()}}
  var sbox=el('session-search');
  if(sbox){sbox.oninput=function(){searchQuery=sbox.value||'';render()}}
  var wsNav=el('ws-list');
  var names=Array.from(new Set(records.map(function(r){return r.projectName}).concat(Object.keys(meta)).filter(Boolean)));
  var tEl=el('ws-total-cnt');if(tEl)tEl.textContent=String(names.length);
  [['','All Workspaces',records.length]].concat(names.map(function(n){return[n,n,records.filter(function(r){return r.projectName===n}).length]}).sort(function(a,b){return b[2]-a[2]})).forEach(function(it){
    var b=document.createElement('button');b.type='button';b.className='ws-btn'+(it[0]===activeWorkspace?' active':'');
    var s1=document.createElement('span');s1.textContent=it[1];
    var rw=document.createElement('span');rw.className='ws-badges';
    if(it[0]&&meta[it[0]]&&meta[it[0]].vibes&&meta[it[0]].vibes.present){
      var vt=document.createElement('span');vt.className='ws-vtag';vt.textContent='VIBES';rw.appendChild(vt);
    }
    var s2=document.createElement('span');s2.className='ws-cnt';s2.textContent=String(it[2]);
    rw.appendChild(s2);b.appendChild(s1);b.appendChild(rw);
    b.onclick=function(){activeWorkspace=it[0];document.querySelectorAll('.ws-btn').forEach(function(x){x.classList.toggle('active',x===b)});render()};
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
      if (recordsById.has(recordId)) continue;

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

  const allRecords = [...recordsById.values()];
  fs.writeFileSync(jsonlPath, allRecords.map((r) => JSON.stringify(r)).join('\n') + (allRecords.length ? '\n' : ''));

  const workspacesMeta = {};
  for (const [projName, wsPath] of discoveredWorkspacePaths.entries()) {
    const isCurrent = projName === activeProject;
    const wsHasVibes = hasVibes(wsPath);
    const wsCfg = readProjectConfig(wsPath, env);
    if (!isCurrent && !wsHasVibes && !wsCfg) continue;
    const wsDrift = isCurrent ? detectBoundaryDrift(wsPath, env) : { added: [] };
    const rawVibes = wsHasVibes ? readVibesTelemetry(wsPath) : null;
    const compactVibes = rawVibes ? { ...rawVibes, sessions: undefined } : null;
    workspacesMeta[projName] = {
      load: (wsCfg && wsCfg.load) || '',
      boundaryLoad: (wsCfg && wsCfg.boundaryLoad) || {},
      boundaries: (wsCfg && wsCfg.boundaries) || (isCurrent ? buildBoundaryMap(wsPath) : { external: {}, internal: {} }),
      driftAdded: (wsDrift && wsDrift.added) || [],
      prismRisk: rawVibes ? rawVibes.maxPrismRisk : null,
      vibesDecisions: rawVibes ? rawVibes.decisions : 0,
      vibes: compactVibes,
    };
  }

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
  if (args.includes('--summary')) {
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
  parseJsonlSessionFile,
  generateCommandCenterHtml,
  formatSummary,
  run: collectAndBuild,
};
