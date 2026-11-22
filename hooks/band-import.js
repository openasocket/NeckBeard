#!/usr/bin/env node
'use strict';
// NeckBeard local telemetry importer & HTML board generator.
// 1. Defaults to reading VIBES (.ai-audit/manifest.json & annotations.jsonl) when present in a workspace.
// 2. Also scans past Claude Code transcripts (~/.claude/projects/**/*.jsonl) and local PreToolUse guard counters.
// 3. Writes per-project CSV ledgers and a self-contained ~/.config/neckbeard/band/board.html.
// Zero network calls, zero external dependencies.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { StringDecoder } = require('string_decoder');
const { claudeDir, bandDir, readGuardStats } = require('./lib');
const { hasVibes, readVibesTelemetry } = require('./vibes');
const { buildBoundaryMap, detectBoundaryDrift, readProjectConfig } = require('./surface');

const CSV_HEADER = 'key,started,project,name,cost_usd,turns,agent_minutes,tokens_total,tokens_output,reuse_pct,reused,new,lines_added,lines_removed,callers_open,guard_blocks,sec_found,sec_fixed,prism_risk,tests,level,model';

const OPUS = [5, 6.25, 10, 0.5, 25];
const PRICES = {
  'claude-fable-5-1': [10, 12.5, 20, 0.25, 50],
  'claude-fable-5': [10, 12.5, 20, 1, 50],
  'claude-opus-5-5': [4, 5, 8, 0.2, 20],
  'claude-opus-5': OPUS,
  'claude-opus-4-8': OPUS,
  'claude-opus-4-7': OPUS,
  'claude-opus-4-6': OPUS,
  'claude-opus-4-5': OPUS,
  'claude-sonnet-5-5': [2, 2.5, 4, 0.1, 10],
  'claude-sonnet-5': [2, 2.5, 4, 0.2, 10],
  'claude-sonnet-4-6': [3, 3.75, 6, 0.3, 15],
  'claude-sonnet-4-5': [3, 3.75, 6, 0.3, 15],
  'claude-haiku-5-5': [0.1, 0.125, 0.2, 0.01, 0.5],
  'claude-haiku-4-5': [1, 1.25, 2, 0.1, 5],
};
const HAIKU_55_LONG = [0.5, 0.625, 1, 0.05, 2.5];
const WEB_SEARCH = 10 / 1000;
const IDLE_MS = 30 * 60000;
const modelId = (m) => String(m || '').replace(/\[.*\]$/, '').replace(/-\d{8}$/, '');

function replyCost(model, u) {
  let p = PRICES[modelId(model)];
  if (!p || !u || u.speed === 'fast') return null;
  const cc = u.cache_creation || {};
  const split = cc.ephemeral_5m_input_tokens !== undefined || cc.ephemeral_1h_input_tokens !== undefined;
  const w5 = split ? cc.ephemeral_5m_input_tokens || 0 : u.cache_creation_input_tokens || 0;
  const w1 = split ? cc.ephemeral_1h_input_tokens || 0 : 0;
  const input = u.input_tokens || 0;
  const read = u.cache_read_input_tokens || 0;
  if (modelId(model) === 'claude-haiku-5-5' && input + read + w5 + w1 > 100000) p = HAIKU_55_LONG;
  const searches = (u.server_tool_use && u.server_tool_use.web_search_requests) || 0;
  return (input * p[0] + w5 * p[1] + w1 * p[2] + read * p[3] + (u.output_tokens || 0) * p[4]) / 1e6 + searches * WEB_SEARCH;
}

const human = (r) => r.type === 'user' && (r.turnOrigin === 'human' || (r.origin && r.origin.kind === 'human'));
const promptText = (r) => {
  const c = r.message && r.message.content;
  const t = typeof c === 'string' ? c : Array.isArray(c) ? (c.find((b) => b && b.type === 'text') || {}).text || '' : '';
  return t.trim();
};
const ms = (r) => (r.timestamp ? Date.parse(r.timestamp) : NaN);
const toolResult = (r) => (r.toolResult !== undefined ? r.toolResult
  : Array.isArray(r.message && r.message.content) && r.message.content.some((b) => b && b.type === 'tool_result'));

function slim(r) {
  const m = r.message || {};
  const c = human(r) ? m.content : undefined;
  const text = typeof c === 'string' ? c.slice(0, 500)
    : Array.isArray(c) ? c.filter((b) => b && b.type === 'text').slice(0, 1).map((b) => ({ type: 'text', text: String(b.text).slice(0, 500) })) : undefined;
  return {
    type: r.type, timestamp: r.timestamp, turnOrigin: r.turnOrigin, origin: r.origin && { kind: r.origin.kind },
    isMeta: r.isMeta, toolResult: toolResult(r),
    sessionId: r.sessionId, customTitle: r.customTitle, totalCostUSD: r.totalCostUSD,
    message: { id: m.id, model: m.model, usage: m.usage, content: text },
  };
}

function readRecords(file) {
  const out = [];
  const take = (l) => { if (l.startsWith('{')) try { out.push(slim(JSON.parse(l))); } catch {} };
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(1 << 20);
  const dec = new StringDecoder('utf8');
  let rest = '';
  try {
    for (let n; (n = fs.readSync(fd, buf, 0, buf.length, null)) > 0;) {
      const parts = (rest + dec.write(buf.subarray(0, n))).split('\n');
      rest = parts.pop();
      parts.forEach(take);
    }
    take(rest + dec.end());
  } finally {
    fs.closeSync(fd);
  }
  return out;
}

function sessionStats(records, subagentRecords = [], sessionId = '') {
  const prompts = records.filter(human);
  if (prompts.length === 0) return null;

  const seen = new Set();
  const replies = {};
  let tokens = 0;
  let output = 0;
  let estimate = 0;
  const reply = (r) => r.type === 'assistant' && r.message && r.message.model && r.message.model !== '<synthetic>';
  for (const r of records) if (reply(r)) replies[r.message.model] = (replies[r.message.model] || 0) + 1;
  for (const r of [...records, ...subagentRecords]) {
    if (!reply(r)) continue;
    const { id, model, usage } = r.message;
    if (!usage || !id || seen.has(id)) continue;
    seen.add(id);
    tokens += (usage.input_tokens || 0) + (usage.output_tokens || 0) + (usage.cache_read_input_tokens || 0) + (usage.cache_creation_input_tokens || 0);
    output += usage.output_tokens || 0;
    const c = replyCost(model, usage);
    estimate = estimate === null || c === null ? null : estimate + c;
  }
  const models = Object.keys(replies);
  if (models.length === 0) return null;

  let turns = 0;
  let agentMs = 0;
  const starts = (r) => r.type === 'user' && !toolResult(r) && !r.isMeta;
  const at = records.map((r, i) => (starts(r) ? i : -1)).filter((i) => i >= 0);
  for (let k = 0; k < at.length; k++) {
    const work = records.slice(at[k] + 1, k + 1 < at.length ? at[k + 1] : records.length)
      .filter((r) => r.type === 'assistant' || (r.type === 'user' && toolResult(r)));
    if (!work.some((r) => r.type === 'assistant')) continue;
    turns++;
    let prev = ms(records[at[k]]);
    for (const t of work.map(ms).filter(Number.isFinite)) {
      if (Number.isFinite(prev) && t > prev && t - prev <= IDLE_MS) agentMs += t - prev;
      prev = Math.max(Number.isFinite(prev) ? prev : t, t);
    }
  }
  if (turns === 0) return null;

  const last = (a, f) => { for (let i = a.length - 1; i >= 0; i--) if (f(a[i])) return i; return -1; };
  const costAt = last(records, (r) => r.type === 'cost-state' && (!sessionId || r.sessionId === sessionId));
  const own = costAt >= 0 && last(records, (r) => r.type === 'assistant') < costAt ? records[costAt].totalCostUSD : null;
  const known = [own, estimate].filter((v) => typeof v === 'number' && Number.isFinite(v) && v > 0);
  const cost = known.length ? Math.max(...known) : null;
  const titled = records.filter((r) => r.type === 'custom-title' && typeof r.customTitle === 'string' && r.customTitle.trim());
  const first = prompts.map(promptText).find((t) => t && !t.startsWith('<') && !t.startsWith('/')) || '';
  const started = records.map(ms).find(Number.isFinite);
  return {
    startedMs: started,
    name: (titled.length ? titled[titled.length - 1].customTitle.trim() : first.split('\n')[0]).slice(0, 60),
    model: models.sort((a, b) => replies[b] - replies[a])[0],
    cost,
    own,
    estimate,
    turns,
    agentMs,
    tokens,
    output,
    linesAdded: 0,
    linesRemoved: 0,
    guardBlocks: 0,
    secFound: 0,
    secFixed: 0,
    prismRisk: '',
    level: 'import',
  };
}

const two = (n) => String(n).padStart(2, '0');
const stamp = (t) => { const d = new Date(t); return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())} ${two(d.getHours())}:${two(d.getMinutes())}`; };
const field = (v) => { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

function csvRow(sessionId, project, s) {
  return [
    `${String(sessionId).slice(0, 8)}-${s.startedMs}`,
    stamp(s.startedMs),
    project,
    s.name,
    s.cost === null || s.cost === undefined ? '' : Number(s.cost).toFixed(2),
    s.turns || 0,
    ((s.agentMs || 0) / 60000).toFixed(1),
    s.tokens || 0,
    s.output || 0,
    s.reuse ?? '',
    s.reused ?? '',
    s.created ?? '',
    s.linesAdded || 0,
    s.linesRemoved || 0,
    s.callersOpen || 0,
    s.guardBlocks || 0,
    s.secFound || 0,
    s.secFixed || 0,
    s.prismRisk ?? '',
    s.tests || '',
    s.level || 'import',
    s.model || '',
  ].map(field).join(',');
}

const sessionOf = (row) => row.slice(0, 9);
function mergeRows(existing, rows, have = new Set()) {
  const kept = existing.split('\n').filter((l) => l !== '' && !l.startsWith('key,'));
  const added = rows.filter((r) => !have.has(sessionOf(r)) && !kept.some((l) => sessionOf(l) === sessionOf(r)));
  return { text: [CSV_HEADER, ...kept, ...added].join('\n') + '\n', added: added.length };
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let f = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { f += '"'; i++; }
      else if (c === '"') q = false;
      else f += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(f);
      if (row.some((x) => x !== '')) rows.push(row);
      row = []; f = '';
    } else f += c;
  }
  row.push(f);
  if (row.some((x) => x !== '')) rows.push(row);
  return rows;
}

function tasksFromCsv(text) {
  const [head, ...rows] = parseCsv(text);
  if (!head || !head.includes('key')) return [];
  const at = (r, col) => r[head.indexOf(col)] ?? '';
  const num = (r, col) => Number(at(r, col)) || 0;
  return rows.map((r) => ({
    started: at(r, 'started'),
    project: at(r, 'project'),
    name: at(r, 'name'),
    cost: num(r, 'cost_usd'),
    turns: num(r, 'turns'),
    agentMinutes: num(r, 'agent_minutes'),
    tokens: num(r, 'tokens_total'),
    reuse: at(r, 'reuse_pct') === '' ? null : num(r, 'reuse_pct'),
    linesAdded: num(r, 'lines_added'),
    linesRemoved: num(r, 'lines_removed'),
    guardBlocks: num(r, 'guard_blocks'),
    secFound: num(r, 'sec_found'),
    secFixed: num(r, 'sec_fixed'),
    prismRisk: at(r, 'prism_risk') === '' ? null : num(r, 'prism_risk'),
    tests: at(r, 'tests'),
    level: at(r, 'level'),
    model: at(r, 'model'),
  }));
}

function buildBoardHtml(dir, now = Date.now(), projectsMeta = {}) {
  let files = [];
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.csv')); } catch {}
  const tasks = files.flatMap((f) => {
    try { return tasksFromCsv(fs.readFileSync(path.join(dir, f), 'utf8')); } catch { return []; }
  });
  const d = new Date(now);
  const dayStr = `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`;
  const safeJson = JSON.stringify({ now, tasks, projectsMeta }).replace(/</g, '\\u003c');
  const html = `<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NeckBeard Telemetry Board</title>
<style>:root{color-scheme:dark;--bg:#070908;--card:#101512;--line:#1d2621;--text:#eef2ef;--muted:#8e9a92;--faint:#5b675f;--ok:#22c55e}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.app{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}.side{border-right:1px solid var(--line);padding:22px 14px;display:flex;flex-direction:column;gap:4px}.brand{font:700 16px/1 ui-monospace,Menlo,monospace;padding:0 10px 20px;color:var(--ok)}.nav-item{display:flex;justify-content:space-between;width:100%;border:0;background:transparent;color:var(--muted);font:inherit;padding:8px 10px;border-radius:8px;cursor:pointer;text-align:left}.nav-item:hover{background:#151d18;color:var(--text)}main{padding:24px 32px;max-width:1360px;width:100%}.head{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.tabs{display:inline-flex;background:#111714;border:1px solid var(--line);border-radius:10px;padding:3px;gap:4px}.tab{border:0;background:transparent;color:var(--muted);font:600 13px/1 inherit;padding:8px 14px;border-radius:7px;cursor:pointer}.tab.on{background:#19241e;color:var(--ok)}.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}.kpi-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.kpi-value{font:700 26px/1.2 ui-monospace,Menlo,monospace;margin-top:6px}.kpi-note{color:var(--faint);font-size:12px;margin-top:4px}table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}th{text-align:left;color:var(--faint);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--line)}td{padding:10px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace}td.name{font-family:inherit}#boundary-svg{width:100%;height:auto;display:block;margin-top:12px}footer{color:var(--faint);font-size:12px;margin-top:20px}</style></head>
<body><div class="app"><aside class="side"><div class="brand">NeckBeard Board</div><nav id="projects"></nav><div style="margin-top:auto;font-size:12px;color:var(--faint);padding:10px">100% Local Board<br>${dayStr}</div></aside>
<main><div class="head"><div><h1 id="title" style="margin:0">All projects</h1><p id="subtitle" style="margin:4px 0 0;color:var(--muted)"></p></div><div class="tabs"><button type="button" class="tab on" id="tab-sessions">Sessions &amp; Telemetry</button><button type="button" class="tab" id="tab-graph">Trust-Boundary Graph</button></div></div>
<section class="kpis">
  <div class="card"><div class="kpi-label">Cost</div><div class="kpi-value" id="k-cost">$0.00</div><div class="kpi-note">API-priced session total</div></div>
  <div class="card"><div class="kpi-label">Tokens</div><div class="kpi-value" id="k-tokens">0</div><div class="kpi-note">Input + output + cache</div></div>
  <div class="card"><div class="kpi-label">Time &amp; Refactor Delta</div><div class="kpi-value" id="k-time">0m</div><div class="kpi-note">Active agent time &amp; LOC delta</div></div>
  <div class="card"><div class="kpi-label">Security &amp; Guard</div><div class="kpi-value" id="k-sec">0 blocked</div><div class="kpi-note">PreToolUse blocks &amp; issues fixed</div></div>
</section>
<section class="card" id="view-sessions"><h3 style="margin:0 0 8px">Sessions</h3><table><thead><tr><th>Task</th><th>Project</th><th>Started</th><th>Time</th><th>Cost</th><th>Tokens</th><th>Reuse &amp; LOC</th><th>Security &amp; VIBES</th><th>Tests</th></tr></thead><tbody id="rows"></tbody></table></section>
<section class="card" id="view-graph" style="display:none"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><div><h3 style="margin:0">External &amp; Internal Trust-Boundary Graph</h3><div id="g-load" style="font-size:12px;color:var(--muted);margin-top:4px"></div></div><div id="g-drift" style="font-size:12px;color:var(--ok)"></div></div><svg id="boundary-svg" viewBox="0 0 960 420" role="img" aria-label="External and internal trust-boundary graph"></svg></section>
<footer>Measured locally by NeckBeard (defaulting to .ai-audit/ VIBES data when present). Zero network calls.</footer></main></div>
<script type="application/json" id="board-data">${safeJson}</script>
<script>(function(){var D=JSON.parse(document.getElementById('board-data').textContent),tasks=D.tasks||[],meta=D.projectsMeta||{},project='',activeTab='sessions';function byId(i){return document.getElementById(i)}function money(n){return '$'+(Number(n)||0).toFixed(2)}function tok(n){return n<1000?String(Math.round(n)):n<1e6?+(n/1e3).toFixed(1)+'k':+(n/1e6).toFixed(1)+'M'}function renderGraph(){var box=byId('boundary-svg');if(!box)return;box.textContent='';var NS='http://www.w3.org/2000/svg';function svg(t,a,p,txt){var e=document.createElementNS(NS,t);for(var k in a)e.setAttribute(k,a[k]);if(txt!=null)e.textContent=txt;if(p)p.appendChild(e);return e}var pName=project||Object.keys(meta)[0]||'',pm=meta[pName]||{},b=pm.boundaries||{external:{},internal:{}},ext=b.external||{},int=b.internal||{},loadText=pm.load||'unset (/neckbeard load <val>)',bLoads=pm.boundaryLoad||{},drift=pm.driftAdded||[];byId('g-load').textContent='Load envelope: '+loadText+(Object.keys(bLoads).length?' · Per-boundary: '+Object.keys(bLoads).map(function(k){return k+'='+bLoads[k]}).join(', '):'');byId('g-drift').textContent=drift.length?('⚠ +'+drift.length+' unreviewed boundary expansion: '+drift.join(', ')):'✓ Trust boundaries match saved .neckbeard.json baseline';svg('rect',{x:425,y:16,width:110,height:388,rx:12,fill:'#131c16',stroke:'#22c55e','stroke-dasharray':'5,4'},box);svg('text',{x:480,y:196,fill:'#22c55e','font-size':12,'font-weight':700,'text-anchor':'middle'},box,'TRUST');svg('text',{x:480,y:214,fill:'#22c55e','font-size':12,'font-weight':700,'text-anchor':'middle'},box,'BOUNDARY');svg('text',{x:480,y:236,fill:'#8e9a92','font-size':10,'text-anchor':'middle'},box,'Fail Closed');[['External Ingress',ext.ingress||[],'#f59e0b'],['External Egress (SSRF)',ext.egress||[],'#38bdf8'],['Supply Chain & CI',ext.supply||[],'#a855f7']].forEach(function(g,i){var y=30+i*124;svg('rect',{x:20,y:y,width:330,height:100,rx:12,fill:'#111714',stroke:g[2]},box);svg('text',{x:36,y:y+26,fill:g[2],'font-size':13,'font-weight':700},box,g[0]+' ('+g[1].length+')');(g[1].length?g[1].slice(0,3):['(none detected)']).forEach(function(it,j){svg('text',{x:36,y:y+48+j*16,fill:'#eef2ef','font-size':11,'font-family':'ui-monospace,Menlo,monospace'},box,it)});svg('path',{d:'M350,'+(y+50)+' C385,'+(y+50)+' 390,210 425,210',fill:'none',stroke:g[2],'stroke-width':1.6,'stroke-opacity':0.7},box)});[['Internal Auth & Sessions',int.auth||[],'#22c55e'],['Internal Data & Storage',int.data||[],'#2dd4bf'],['Internal Exec & Crypto',int.exec||[],'#fb7185'],['Internal AI & Prompt Context',int.ai||[],'#facc15']].forEach(function(g,i){var y=20+i*96;svg('rect',{x:610,y:y,width:330,height:82,rx:12,fill:'#111714',stroke:g[2]},box);svg('text',{x:626,y:y+22,fill:g[2],'font-size':13,'font-weight':700},box,g[0]+' ('+g[1].length+')');(g[1].length?g[1].slice(0,3):['(none detected)']).forEach(function(it,j){svg('text',{x:626,y:y+42+j*15,fill:'#eef2ef','font-size':11,'font-family':'ui-monospace,Menlo,monospace'},box,it)});svg('path',{d:'M535,210 C570,210 575,'+(y+41)+' 610,'+(y+41),fill:'none',stroke:g[2],'stroke-width':1.6,'stroke-opacity':0.7},box)})}function render(){var list=project?tasks.filter(function(t){return t.project===project}):tasks;byId('title').textContent=project||'All projects';byId('subtitle').textContent=list.length+' recorded session'+(list.length===1?'':'s');byId('view-sessions').style.display=activeTab==='sessions'?'block':'none';byId('view-graph').style.display=activeTab==='graph'?'block':'none';byId('tab-sessions').className='tab'+(activeTab==='sessions'?' on':'');byId('tab-graph').className='tab'+(activeTab==='graph'?' on':'');var cost=0,tokens=0,mins=0,blocks=0,secFixed=0,secFound=0,added=0,removed=0;list.forEach(function(t){cost+=t.cost||0;tokens+=t.tokens||0;mins+=t.agentMinutes||0;blocks+=t.guardBlocks||0;secFixed+=t.secFixed||0;secFound+=t.secFound||0;added+=t.linesAdded||0;removed+=t.linesRemoved||0});byId('k-cost').textContent=money(cost);byId('k-tokens').textContent=tok(tokens);byId('k-time').textContent=Math.round(mins)+'m (+'+added+'/-'+removed+' LOC)';byId('k-sec').textContent=blocks+' blocked · '+secFixed+'/'+secFound+' fixed';var tbody=byId('rows');tbody.textContent='';list.slice().sort(function(a,b){return(b.started||'').localeCompare(a.started||'')}).forEach(function(t){var tr=document.createElement('tr');[t.name||'Session',t.project||'–',t.started||'–',Math.round(t.agentMinutes||0)+'m',money(t.cost),tok(t.tokens),(t.reuse==null?'–':t.reuse+'%')+' (+'+(t.linesAdded||0)+'/-'+(t.linesRemoved||0)+')',(t.guardBlocks||0)+' blk · '+(t.secFixed||0)+'/'+(t.secFound||0)+(t.prismRisk!=null?' · PRISM '+t.prismRisk:''),t.tests||'–'].forEach(function(v,idx){var td=document.createElement('td');if(idx===0)td.className='name';td.textContent=v;tr.appendChild(td)});tbody.appendChild(tr)});renderGraph()}byId('tab-sessions').onclick=function(){activeTab='sessions';render()};byId('tab-graph').onclick=function(){activeTab='graph';render()};var nav=byId('projects'),names=Array.from(new Set(tasks.map(function(t){return t.project}).concat(Object.keys(meta)).filter(Boolean)));[['','All projects',tasks.length]].concat(names.map(function(n){return[n,n,tasks.filter(function(t){return t.project===n}).length]})).forEach(function(p){var b=document.createElement('button');b.className='nav-item';b.textContent=p[1]+' ('+p[2]+')';b.onclick=function(){project=p[0];render()};nav.appendChild(b)});render()})();</script></body></html>`;
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, 'board.html');
  fs.writeFileSync(out, html);
  return { file: out, tasks };
}

const TEMP = [os.tmpdir(), '/tmp/', '/private/tmp/', '/var/folders/', '/private/var/folders/'];

function projectOf(cwd, cache) {
  if (!cache.has(cwd)) {
    let root = cwd.split(/[\\/]\.claude[\\/]worktrees[\\/]/)[0];
    if (fs.existsSync(root)) {
      const git = spawnSync('git', ['-C', root, 'rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8' });
      if (git.status === 0 && /[\\/]\.git$/.test(git.stdout.trim())) root = path.dirname(git.stdout.trim());
    }
    cache.set(cwd, path.basename(root.replace(/[\\/]+$/, '')));
  }
  return cache.get(cwd);
}

// Imports VIBES (.ai-audit/) first when present in cwd, then past Claude Code transcripts.
function run(cwd = process.cwd(), env = process.env) {
  const byProject = new Map();
  const guardStats = readGuardStats(env);
  let sessions = 0;

  // 1. Default to VIBES (.ai-audit/) in the active workspace when present.
  if (hasVibes(cwd)) {
    const v = readVibesTelemetry(cwd);
    const project = path.basename(path.resolve(cwd)) || 'project';
    const projBlocks = (guardStats.projects && guardStats.projects[project] && guardStats.projects[project].blocks) || 0;
    if (v && v.sessions.length) {
      if (!byProject.has(project)) byProject.set(project, []);
      v.sessions.forEach((s, idx) => {
        sessions++;
        byProject.get(project).push(csvRow(s.sessionId, project, {
          startedMs: s.startedMs,
          name: s.name || `VIBES session ${s.sessionId.slice(0, 8)}`,
          model: s.model || 'vibes',
          cost: s.costUsd,
          turns: s.turns,
          agentMs: s.agentMs,
          tokens: s.tokens,
          output: s.outputTokens,
          linesAdded: s.linesAdded,
          linesRemoved: s.linesRemoved,
          guardBlocks: idx === 0 ? projBlocks : 0,
          secFound: s.secFound,
          secFixed: s.secFixed,
          prismRisk: s.maxRisk,
          level: 'vibes',
        }));
      });
    }
  }

  // 2. Scan Claude Code transcripts (~/.claude/projects/**/*.jsonl)
  const root = path.join(claudeDir(env), 'projects');
  const roots = new Map();
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch { dirs = []; }
  for (const dir of dirs) {
    let files = [];
    try { files = fs.readdirSync(path.join(root, dir)).filter((f) => f.endsWith('.jsonl')); } catch { continue; }
    for (const file of files) {
      const p = path.join(root, dir, file);
      let head = '';
      try { const fd = fs.openSync(p, 'r'); const b = Buffer.alloc(65536); head = b.toString('utf8', 0, fs.readSync(fd, b, 0, b.length, 0)); fs.closeSync(fd); } catch { continue; }
      const m = /"cwd":"((?:[^"\\]|\\.)*)"/.exec(head);
      if (!m) continue;
      const sessCwd = JSON.parse(`"${m[1]}"`);
      if (TEMP.some((t) => sessCwd.startsWith(t)) || sessCwd === '/tmp') continue;
      if (head.includes('"type":"user"') && !/"turnOrigin":"human"|"origin":\{"kind":"human"/.test(head)) continue;
      const id = file.slice(0, -'.jsonl'.length);
      let records;
      try { records = readRecords(p); } catch { continue; }
      const sub = path.join(root, dir, id, 'subagents');
      let subRecords = [];
      try { subRecords = fs.readdirSync(sub).filter((f) => /^agent-.*\.jsonl$/.test(f)).flatMap((f) => readRecords(path.join(sub, f))); } catch {}
      const stats = sessionStats(records, subRecords, id);
      if (!stats || !Number.isFinite(stats.startedMs)) continue;

      // Enrich with VIBES if that workspace has .ai-audit/
      if (hasVibes(sessCwd)) {
        const v = readVibesTelemetry(sessCwd);
        if (v) {
          stats.prismRisk = v.maxPrismRisk;
          stats.secFound = v.highRiskCount + v.traceIncidents;
          stats.secFixed = v.traceResolved;
          stats.linesAdded = v.linesAdded;
          stats.linesRemoved = v.linesRemoved;
        }
      }
      stats.guardBlocks = (guardStats.sessions && guardStats.sessions[id]) || 0;
      sessions++;
      const project = projectOf(sessCwd, roots);
      if (!byProject.has(project)) byProject.set(project, []);
      byProject.get(project).push(csvRow(id, project, stats));
    }
  }

  const dir = bandDir(env);
  fs.mkdirSync(dir, { recursive: true });
  const have = new Set();
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.csv'))) {
    try { fs.readFileSync(path.join(dir, f), 'utf8').split('\n').forEach((l) => l && !l.startsWith('key,') && have.add(sessionOf(l))); } catch {}
  }
  let added = 0;
  for (const [project, rows] of byProject) {
    const file = path.join(dir, `${project.replace(/[^\w.-]/g, '_')}.csv`);
    let existing = '';
    try { existing = fs.readFileSync(file, 'utf8'); } catch {}
    const merged = mergeRows(existing, rows, have);
    if (merged.added > 0) fs.writeFileSync(file, merged.text);
    added += merged.added;
  }
  const activeProj = path.basename(path.resolve(cwd)) || 'project';
  const cfg = readProjectConfig(cwd, env);
  const drift = detectBoundaryDrift(cwd, env);
  const vibes = readVibesTelemetry(cwd);
  const projectsMeta = {
    [activeProj]: {
      load: (cfg && cfg.load) || '',
      boundaryLoad: (cfg && cfg.boundaryLoad) || {},
      boundaries: (cfg && cfg.boundaries) || buildBoundaryMap(cwd),
      driftAdded: (drift && drift.added) || [],
      prismRisk: vibes ? vibes.maxPrismRisk : null,
    },
  };
  const board = buildBoardHtml(dir, Date.now(), projectsMeta);
  return { sessions, added, boardFile: board.file, tasks: board.tasks };
}

function formatSummary(cwd = process.cwd(), env = process.env) {
  const { tasks, boardFile } = run(cwd, env);
  const project = path.basename(path.resolve(cwd));
  const cfg = readProjectConfig(cwd, env);
  const vibes = readVibesTelemetry(cwd);
  const guardStats = readGuardStats(env);

  let cost = 0, tokens = 0, mins = 0, added = 0, removed = 0, blocks = guardStats.total || 0, secFound = 0, secFixed = 0;
  for (const t of tasks) {
    cost += t.cost || 0;
    tokens += t.tokens || 0;
    mins += t.agentMinutes || 0;
    added += t.linesAdded || 0;
    removed += t.linesRemoved || 0;
    blocks = Math.max(blocks, t.guardBlocks || 0);
    secFound += t.secFound || 0;
    secFixed += t.secFixed || 0;
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
    `  Agent time & LOC  : ${Math.round(mins)}m · +${added} / -${removed} lines`,
    `  Security & Guard  : ${blocks} PreToolUse blocks · ${secFixed}/${secFound} security/TRACE issues resolved`,
    `  Local HTML Board  : ${boardFile}`,
  ].join('\n');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--summary')) {
    process.stdout.write(formatSummary() + '\n');
  } else {
    const res = run();
    if (args.includes('--open')) {
      const cmd = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      const cmdArgs = process.platform === 'win32' ? ['/c', 'start', '', res.boardFile] : [res.boardFile];
      try { spawnSync(cmd, cmdArgs, { stdio: 'ignore' }); } catch {}
    }
    process.stdout.write(`neckbeard band import: ${res.sessions} sessions scanned, ${res.added} new rows in ${res.boardFile}.\n`);
  }
}

module.exports = { CSV_HEADER, PRICES, replyCost, sessionStats, csvRow, mergeRows, parseCsv, tasksFromCsv, buildBoardHtml, formatSummary, run };
