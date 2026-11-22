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

// Per-million token USD pricing table for local session cost calculation when transcript lacks an explicit cost total.
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
.shell{display:grid;grid-template-columns:276px minmax(0,1fr);min-height:100vh}
.rail{background:var(--surface);border-right:1px solid var(--border);padding:22px 16px;display:flex;flex-direction:column;gap:6px}
.crest{display:flex;align-items:center;gap:12px;padding:4px 8px 18px;border-bottom:1px solid var(--border);margin-bottom:10px}
.tp{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red)}
.crest-title{font:800 16px/1.1 var(--mono);color:var(--text);display:flex;align-items:center;gap:7px}
.crest-sub{font:600 10.5px var(--mono);color:var(--emerald);margin-top:4px;letter-spacing:.05em}
.rail-lbl{font:700 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);padding:8px 10px 4px}
.ws-btn{display:flex;justify-content:space-between;align-items:center;width:100%;border:1px solid transparent;background:transparent;color:var(--muted);font:500 13px var(--sans);padding:9px 12px;border-radius:10px;cursor:pointer;text-align:left}
.ws-btn:hover,.ws-btn.active{background:var(--card);color:var(--text);border-color:var(--border)}
.ws-cnt{font:600 11.5px var(--mono);color:var(--emerald);background:rgba(16,185,129,.12);padding:2px 7px;border-radius:99px}
.rail-foot{margin-top:auto;padding:14px 10px 4px;border-top:1px solid var(--border);font:500 11.5px/1.6 var(--mono);color:var(--dim)}
.stage{padding:28px 36px 64px;max-width:1440px;width:100%}
.topbar{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid var(--border)}
.topbar h1{margin:0;font:800 24px/1.15 var(--mono);letter-spacing:-.02em}
.topbar p{margin:5px 0 0;color:var(--muted);font:400 13px var(--mono)}
.views{display:inline-flex;background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:4px;gap:4px}
.v-btn{border:0;background:transparent;color:var(--muted);font:600 12.5px var(--mono);padding:8px 14px;border-radius:8px;cursor:pointer}
.v-btn.active{background:var(--card);color:var(--emerald);box-shadow:inset 0 0 0 1px rgba(16,185,129,.35)}
.kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:22px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px}
.m-tag{font:700 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between}
.m-val{font:800 28px/1.15 var(--mono);margin-top:8px;color:var(--text)}
.m-sub{font:400 12px var(--mono);color:var(--dim);margin-top:6px}
.card-sec{margin-top:20px;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:22px}
.sec-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.sec-head h2{margin:0;font:700 16px var(--mono)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font:600 11.5px var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--dim);padding:10px 12px;border-bottom:1px solid var(--border)}
td{padding:12px;border-bottom:1px solid var(--border);font-family:var(--mono)}
td.tcol{font-family:var(--sans);font-weight:500}
.chip{display:inline-block;padding:3px 9px;border-radius:99px;font:600 11px var(--mono);background:rgba(16,185,129,.14);color:var(--emerald)}
.chip.warn{background:rgba(245,158,11,.16);color:var(--amber)}
@media(max-width:1024px){.shell{grid-template-columns:1fr}.rail{border-right:0;border-bottom:1px solid var(--border)}.kpis{grid-template-columns:1fr}}
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
    <div class="rail-lbl">Workspaces</div>
    <div id="ws-list"></div>
    <div class="rail-foot">NeckBeard Command Center v0.2<br>100% Local JSONL Store<br>Zero Network Telemetry</div>
  </aside>
  <main class="stage">
    <header class="topbar">
      <div><h1 id="st-title">All Workspaces</h1><p id="st-subtitle"></p></div>
      <div class="views" role="tablist">
        <button type="button" class="v-btn active" data-view="overview">1. Command Overview</button>
        <button type="button" class="v-btn" data-view="topology">2. Trust-Boundary Graph</button>
        <button type="button" class="v-btn" data-view="forensics">3. Session Forensics</button>
      </div>
    </header>
    <div class="kpis">
      <div class="panel"><div class="m-tag"><span>Code Minimalism &amp; Reuse</span><span style="color:var(--emerald)">LADDER</span></div><div class="m-val" id="m-loc">+0 / -0 LOC</div><div class="m-sub" id="m-reuse">Symbol reuse ratio across edits</div></div>
      <div class="panel"><div class="m-tag"><span>Security &amp; PreToolUse Shield</span><span style="color:var(--cyan)">SAFE GATE</span></div><div class="m-val" id="m-sec">0 blocked</div><div class="m-sub" id="m-vibes">VIBES PRISM &amp; TRACE status</div></div>
      <div class="panel"><div class="m-tag"><span>Targeted Scalability &amp; Cost</span><span style="color:var(--amber)">FAST GATE</span></div><div class="m-val" id="m-cost">$0.00</div><div class="m-sub" id="m-load">Load target from .neckbeard.json</div></div>
    </div>
    <section class="card-sec" id="pane-overview">
      <div class="sec-head"><h2>External → Internal Trust-Boundary Graph</h2><span id="ov-drift" class="chip">✓ Baseline Verified</span></div>
      <svg id="boundary-svg" viewBox="0 0 960 360" style="width:100%;height:auto;display:block"></svg>
    </section>
    <section class="card-sec" id="pane-forensics">
      <div class="sec-head"><h2>Recorded Engineering &amp; Audit Sessions</h2><span id="tbl-count" class="chip">0 sessions</span></div>
      <div style="overflow-x:auto"><table><thead><tr><th>Task / Prompt</th><th>Workspace</th><th>Timestamp</th><th>Level</th><th>Duration</th><th>Cost &amp; Tokens</th><th>Reuse &amp; Net LOC</th><th>Guard &amp; VIBES</th><th>Verification</th></tr></thead><tbody id="session-rows"></tbody></table></div>
    </section>
  </main>
</div>
<script type="application/json" id="nb-telemetry-payload">${safePayload}</script>
<script>
(function(){
  var payload=JSON.parse(document.getElementById('nb-telemetry-payload').textContent);
  var records=payload.records||[],meta=payload.workspacesMeta||{},activeWorkspace='',activeView='overview';
  function el(i){return document.getElementById(i)}
  function fmtTok(n){return n<1000?String(Math.round(n)):n<1e6?+(n/1e3).toFixed(1)+'k':+(n/1e6).toFixed(1)+'M'}
  function fmtDur(ms){var m=Math.round((ms||0)/60000);return m<60?m+'m':Math.floor(m/60)+'h '+(m%60)+'m'}
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
    el('pane-overview').style.display=(activeView==='overview'||activeView==='topology')?'block':'none';
    el('pane-forensics').style.display=(activeView==='overview'||activeView==='forensics')?'block':'none';
    var cost=0,tok=0,ins=0,del=0,blk=0,found=0,fixed=0,reused=0,created=0;
    list.forEach(function(r){
      cost+=r.totalCostUsd||0;var tb=r.tokenBuckets||{};
      tok+=(tb.promptTokens||0)+(tb.completionTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      ins+=r.linesInserted||0;del+=r.linesDeleted||0;blk+=r.guardBlockCount||0;
      found+=r.securityFindingsTotal||0;fixed+=r.securityFindingsResolved||0;
      reused+=r.reusedSymbolCount||0;created+=r.newSymbolCount||0;
    });
    el('m-loc').textContent='+'+ins+' / -'+del+' LOC';
    var rPct=(reused+created)>0?Math.round((reused/(reused+created))*100)+'% symbol reuse':'Net code delta across sessions';
    el('m-reuse').textContent=rPct+' ('+reused+' reused, '+created+' new)';
    el('m-sec').textContent=blk+' guard blocks · '+fixed+'/'+found+' fixed';
    el('m-vibes').textContent=wm.prismRisk!=null?('VIBES active · PRISM max risk '+wm.prismRisk+' · '+(wm.vibesDecisions||0)+' decisions'):'PreToolUse secret & VIBES provenance shield';
    el('m-cost').textContent='$'+cost.toFixed(2)+' · '+fmtTok(tok)+' tok';
    el('m-load').textContent='Target load: '+(wm.load||'unset');
    el('tbl-count').textContent=list.length+' session(s)';
    var tbody=el('session-rows');tbody.textContent='';
    list.slice().sort(function(a,b){return(b.startedAtMs||0)-(a.startedAtMs||0)}).forEach(function(r){
      var tr=document.createElement('tr'),tb=r.tokenBuckets||{};
      var tTok=(tb.promptTokens||0)+(tb.completionTokens||0)+(tb.cachedReadTokens||0)+(tb.cachedWriteTokens||0);
      [r.taskTitle||'Session',r.projectName||'–',r.timestampIso||'–',r.activeLevel||'full',fmtDur(r.activeDurationMs),'$'+(r.totalCostUsd||0).toFixed(2)+' ('+fmtTok(tTok)+')',(r.reusePercent==null?'–':r.reusePercent+'%')+' (+'+(r.linesInserted||0)+'/-'+(r.linesDeleted||0)+')',(r.guardBlockCount||0)+' blk · '+(r.securityFindingsResolved||0)+'/'+(r.securityFindingsTotal||0)+(r.vibesMaxPrismRisk!=null?' · PRISM '+r.vibesMaxPrismRisk:''),r.testStatusLabel||'untested'].forEach(function(v,idx){
        var td=document.createElement('td');if(idx===0)td.className='tcol';td.textContent=v;tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    renderGraph(activeWorkspace);
  }
  var wsNav=el('ws-list');
  var names=Array.from(new Set(records.map(function(r){return r.projectName}).concat(Object.keys(meta)).filter(Boolean)));
  [['','All Workspaces',records.length]].concat(names.map(function(n){return[n,n,records.filter(function(r){return r.projectName===n}).length]})).forEach(function(it){
    var b=document.createElement('button');b.type='button';b.className='ws-btn'+(it[0]===activeWorkspace?' active':'');
    var s1=document.createElement('span');s1.textContent=it[1];
    var s2=document.createElement('span');s2.className='ws-cnt';s2.textContent=String(it[2]);
    b.appendChild(s1);b.appendChild(s2);
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

  // 1. Primary source: VIBES (.ai-audit/) in the current workspace
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

  // 2. Secondary source: Local Claude Code project transcripts (~/.claude/projects/**/*.jsonl)
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

  const cfg = readProjectConfig(cwd, env);
  const drift = detectBoundaryDrift(cwd, env);
  const vibes = readVibesTelemetry(cwd);
  const workspacesMeta = {
    [activeProject]: {
      load: (cfg && cfg.load) || '',
      boundaryLoad: (cfg && cfg.boundaryLoad) || {},
      boundaries: (cfg && cfg.boundaries) || buildBoundaryMap(cwd),
      driftAdded: (drift && drift.added) || [],
      prismRisk: vibes ? vibes.maxPrismRisk : null,
      vibesDecisions: vibes ? vibes.decisions : 0,
    },
  };

  const html = generateCommandCenterHtml(allRecords, workspacesMeta, Date.now());
  const dashboardFile = path.join(telemetryDir, 'dashboard.html');
  fs.writeFileSync(dashboardFile, html);

  // Also write to ~/.config/neckbeard/band/board.html so any bookmark or legacy path opens NeckBeard's Command Center
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
