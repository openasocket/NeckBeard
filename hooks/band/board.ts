// The NeckBeard local telemetry board: one self-contained HTML page built from the band's CSV ledgers,
// .neckbeard.json trust-boundary maps, and VIBES (.ai-audit/) data. Includes an interactive
// SVG Trust-Boundary Architecture Graph tab alongside the Sessions & Telemetry dashboard.

import { LOGO_PATHS, LOGO_VIEWBOX } from './logo'

export const duration = (minutes: number) =>
  minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`

export const elapsed = (ms: number) => {
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return duration(Math.round(s / 60))
}

export const fmtTokens = (n: number) =>
  n < 1000 ? `${n}` : n < 1e6 ? `${+(n / 1e3).toFixed(1)}k` : `${+(n / 1e6).toFixed(1)}M`

export type Task = {
  started: string
  project: string
  name: string
  cost: number
  turns: number
  agentMinutes: number
  tokens: number
  reuse: number | null
  linesAdded: number
  linesRemoved: number
  guardBlocks: number
  secFound: number
  secFixed: number
  prismRisk: number | null
  tests: string
  level: string
  model: string
}

export type ProjectBoundaryMeta = {
  load?: string
  boundaryLoad?: Record<string, string>
  boundaries?: {
    external?: { ingress?: string[]; egress?: string[]; supply?: string[] }
    internal?: { auth?: string[]; data?: string[]; exec?: string[]; ai?: string[] }
  }
  driftAdded?: string[]
  prismRisk?: number | null
}

export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let quoted = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"'
        i++
      } else if (c === '"') quoted = false
      else field += c
    } else if (c === '"') quoted = true
    else if (c === ',') {
      row.push(field)
      field = ''
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++
      row.push(field)
      if (row.some(f => f !== '')) rows.push(row)
      row = []
      field = ''
    } else field += c
  }
  row.push(field)
  if (row.some(f => f !== '')) rows.push(row)
  return rows
}

export function tasksFrom(text: string): Task[] {
  const [head, ...rows] = parseCsv(text)
  if (!head?.includes('key')) return []
  const at = (row: string[], col: string) => row[head.indexOf(col)] ?? ''
  const num = (row: string[], col: string) => Number(at(row, col)) || 0
  return rows.map(row => ({
    started: at(row, 'started'),
    project: at(row, 'project'),
    name: at(row, 'name'),
    cost: num(row, 'cost_usd'),
    turns: num(row, 'turns'),
    agentMinutes: num(row, 'agent_minutes'),
    tokens: num(row, 'tokens_total'),
    reuse: at(row, 'reuse_pct') === '' ? null : num(row, 'reuse_pct'),
    linesAdded: num(row, 'lines_added'),
    linesRemoved: num(row, 'lines_removed'),
    guardBlocks: num(row, 'guard_blocks'),
    secFound: num(row, 'sec_found'),
    secFixed: num(row, 'sec_fixed'),
    prismRisk: at(row, 'prism_risk') === '' ? null : num(row, 'prism_risk'),
    tests: at(row, 'tests'),
    level: at(row, 'level'),
    model: at(row, 'model'),
  }))
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
const day = (ms: number) => {
  const d = new Date(ms)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

const MONO_CSS = '"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace'

const CSS = `:root{color-scheme:dark;--bg:#070908;--panel:#0d110f;--card:#101512;--line:#1d2621;--text:#eef2ef;--muted:#8e9a92;--faint:#5b675f;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.app{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}
.side{border-right:1px solid var(--line);padding:22px 14px;display:flex;flex-direction:column;gap:4px}
.brand{display:flex;align-items:center;gap:10px;font:700 16px/1 ${MONO_CSS};padding:0 10px 20px;color:var(--ok)}
.logo{width:28px;height:28px;flex:none}.logo svg{width:100%;height:100%}
.nav-item{display:flex;justify-content:space-between;width:100%;border:0;background:transparent;color:var(--muted);font:inherit;padding:8px 10px;border-radius:8px;cursor:pointer;text-align:left}
.nav-item.on,.nav-item:hover{background:#151d18;color:var(--text)}
main{padding:24px 32px;max-width:1360px;width:100%}
.head{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.tabs{display:inline-flex;background:#111714;border:1px solid var(--line);border-radius:10px;padding:3px;gap:4px}
.tab{border:0;background:transparent;color:var(--muted);font:600 13px/1 inherit;padding:8px 14px;border-radius:7px;cursor:pointer}
.tab.on{background:#19241e;color:var(--ok)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}
.kpi-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kpi-value{font:700 28px/1.2 ${MONO_CSS};margin-top:6px}
.kpi-note{color:var(--faint);font-size:12px;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th{text-align:left;color:var(--faint);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:10px;border-bottom:1px solid var(--line);font-family:${MONO_CSS}}
td.name{font-family:inherit}
#boundary-svg{width:100%;height:auto;display:block;margin-top:12px}
footer{color:var(--faint);font-size:12px;margin-top:20px}`

const json = (value: unknown) => JSON.stringify(value).replace(/</g, '\\u003c')

const APP = `(function(){
  var D = JSON.parse(document.getElementById('board-data').textContent);
  var tasks = D.tasks || [], meta = D.projectsMeta || {}, project = '', activeTab = 'sessions';
  function byId(id){ return document.getElementById(id); }
  function money(n){ return '$' + (Number(n)||0).toFixed(2); }
  function tok(n){ return n < 1000 ? String(Math.round(n)) : n < 1e6 ? +(n/1e3).toFixed(1)+'k' : +(n/1e6).toFixed(1)+'M'; }
  function renderGraph(){
    var box = byId('boundary-svg'); if (!box) return;
    box.textContent = '';
    var NS = 'http://www.w3.org/2000/svg';
    function svg(tag, attrs, parent, text){
      var e = document.createElementNS(NS, tag);
      for (var k in attrs) e.setAttribute(k, attrs[k]);
      if (text != null) e.textContent = text;
      if (parent) parent.appendChild(e);
      return e;
    }
    var pName = project || Object.keys(meta)[0] || '';
    var pm = meta[pName] || {};
    var b = pm.boundaries || { external: {}, internal: {} };
    var ext = b.external || {}, int = b.internal || {};
    var loadText = pm.load || 'unset (/neckbeard load <val>)';
    var bLoads = pm.boundaryLoad || {};
    var drift = pm.driftAdded || [];

    byId('g-load').textContent = 'Load envelope: ' + loadText + (Object.keys(bLoads).length ? ' · Per-boundary: ' + Object.keys(bLoads).map(function(k){ return k + '=' + bLoads[k]; }).join(', ') : '');
    byId('g-drift').textContent = drift.length ? ('⚠ +' + drift.length + ' unreviewed boundary expansion: ' + drift.join(', ')) : '✓ Trust boundaries match saved .neckbeard.json baseline';

    var extGroups = [
      ['External Ingress', ext.ingress || [], '#f59e0b'],
      ['External Egress (SSRF)', ext.egress || [], '#38bdf8'],
      ['Supply Chain & CI', ext.supply || [], '#a855f7']
    ];
    var intGroups = [
      ['Internal Auth & Sessions', int.auth || [], '#22c55e'],
      ['Internal Data & Storage', int.data || [], '#2dd4bf'],
      ['Internal Exec & Crypto', int.exec || [], '#fb7185'],
      ['Internal AI & Prompt Context', int.ai || [], '#facc15']
    ];

    // Draw Trust Boundary center barrier
    svg('rect', { x: 425, y: 16, width: 110, height: 388, rx: 12, fill: '#131c16', stroke: '#22c55e', 'stroke-dasharray': '5,4' }, box);
    svg('text', { x: 480, y: 196, fill: '#22c55e', 'font-size': 12, 'font-weight': 700, 'text-anchor': 'middle' }, box, 'TRUST');
    svg('text', { x: 480, y: 214, fill: '#22c55e', 'font-size': 12, 'font-weight': 700, 'text-anchor': 'middle' }, box, 'BOUNDARY');
    svg('text', { x: 480, y: 236, fill: '#8e9a92', 'font-size': 10, 'text-anchor': 'middle' }, box, 'Fail Closed');

    extGroups.forEach(function(g, i){
      var y = 30 + i * 124;
      svg('rect', { x: 20, y: y, width: 330, height: 100, rx: 12, fill: '#111714', stroke: g[2] }, box);
      svg('text', { x: 36, y: y + 26, fill: g[2], 'font-size': 13, 'font-weight': 700 }, box, g[0] + ' (' + g[1].length + ')');
      var items = g[1].length ? g[1].slice(0, 3) : ['(none detected)'];
      items.forEach(function(it, j){
        svg('text', { x: 36, y: y + 48 + j * 16, fill: '#eef2ef', 'font-size': 11, 'font-family': 'ui-monospace,Menlo,monospace' }, box, it);
      });
      svg('path', { d: 'M350,' + (y + 50) + ' C385,' + (y + 50) + ' 390,210 425,210', fill: 'none', stroke: g[2], 'stroke-width': 1.6, 'stroke-opacity': 0.7 }, box);
    });

    intGroups.forEach(function(g, i){
      var y = 20 + i * 96;
      svg('rect', { x: 610, y: y, width: 330, height: 82, rx: 12, fill: '#111714', stroke: g[2] }, box);
      svg('text', { x: 626, y: y + 22, fill: g[2], 'font-size': 13, 'font-weight': 700 }, box, g[0] + ' (' + g[1].length + ')');
      var items = g[1].length ? g[1].slice(0, 3) : ['(none detected)'];
      items.forEach(function(it, j){
        svg('text', { x: 626, y: y + 42 + j * 15, fill: '#eef2ef', 'font-size': 11, 'font-family': 'ui-monospace,Menlo,monospace' }, box, it);
      });
      svg('path', { d: 'M535,210 C570,210 575,' + (y + 41) + ' 610,' + (y + 41), fill: 'none', stroke: g[2], 'stroke-width': 1.6, 'stroke-opacity': 0.7 }, box);
    });
  }
  function render(){
    var list = project ? tasks.filter(function(t){ return t.project === project; }) : tasks;
    byId('title').textContent = project || 'All projects';
    byId('subtitle').textContent = list.length + ' recorded session' + (list.length === 1 ? '' : 's');
    byId('view-sessions').style.display = activeTab === 'sessions' ? 'block' : 'none';
    byId('view-graph').style.display = activeTab === 'graph' ? 'block' : 'none';
    byId('tab-sessions').className = 'tab' + (activeTab === 'sessions' ? ' on' : '');
    byId('tab-graph').className = 'tab' + (activeTab === 'graph' ? ' on' : '');

    var cost = 0, tokens = 0, mins = 0, blocks = 0, secFixed = 0, secFound = 0, added = 0, removed = 0;
    list.forEach(function(t){
      cost += t.cost || 0; tokens += t.tokens || 0; mins += t.agentMinutes || 0;
      blocks += t.guardBlocks || 0; secFixed += t.secFixed || 0; secFound += t.secFound || 0;
      added += t.linesAdded || 0; removed += t.linesRemoved || 0;
    });
    byId('k-cost').textContent = money(cost);
    byId('k-tokens').textContent = tok(tokens);
    byId('k-time').textContent = Math.round(mins) + 'm (+' + added + '/-' + removed + ' LOC)';
    byId('k-sec').textContent = blocks + ' blocked · ' + secFixed + '/' + secFound + ' fixed';
    var tbody = byId('rows'); tbody.textContent = '';
    list.slice().sort(function(a,b){ return (b.started||'').localeCompare(a.started||''); }).forEach(function(t){
      var tr = document.createElement('tr');
      var vals = [
        t.name || 'Session',
        t.project || '–',
        t.started || '–',
        Math.round(t.agentMinutes || 0) + 'm',
        money(t.cost),
        tok(t.tokens),
        (t.reuse == null ? '–' : t.reuse + '%') + ' (+' + (t.linesAdded||0) + '/-' + (t.linesRemoved||0) + ')',
        (t.guardBlocks||0) + ' blk · ' + (t.secFixed||0) + '/' + (t.secFound||0) + (t.prismRisk != null ? ' · PRISM ' + t.prismRisk : ''),
        t.tests || '–'
      ];
      vals.forEach(function(v, idx){
        var td = document.createElement('td');
        if (idx === 0) td.className = 'name';
        td.textContent = v;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    renderGraph();
  }
  byId('tab-sessions').onclick = function(){ activeTab = 'sessions'; render(); };
  byId('tab-graph').onclick = function(){ activeTab = 'graph'; render(); };
  var nav = byId('projects');
  var names = Array.from(new Set(tasks.map(function(t){ return t.project; }).concat(Object.keys(meta)).filter(Boolean)));
  [['', 'All projects', tasks.length]].concat(names.map(function(n){
    return [n, n, tasks.filter(function(t){ return t.project === n; }).length];
  })).forEach(function(p){
    var b = document.createElement('button');
    b.className = 'nav-item';
    b.textContent = p[1] + ' (' + p[2] + ')';
    b.onclick = function(){ project = p[0]; render(); };
    nav.appendChild(b);
  });
  render();
})()`

export function boardHtml(tasks: Task[], now: number, projectsMeta: Record<string, ProjectBoundaryMeta> = {}): string {
  return `<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NeckBeard Telemetry Board</title><style>${CSS}</style></head>
<body><svg style="display:none"><symbol id="nb-logo" viewBox="${LOGO_VIEWBOX}">${LOGO_PATHS}</symbol></svg>
<div class="app">
<aside class="side"><div class="brand"><span class="logo"><svg viewBox="${LOGO_VIEWBOX}"><use href="#nb-logo"/></svg></span>NeckBeard</div><nav id="projects"></nav><div style="margin-top:auto;font-size:12px;color:var(--faint);padding:10px">100% Local Board<br>${esc(day(now))}</div></aside>
<main>
<div class="head">
  <div><h1 id="title" style="margin:0">All projects</h1><p id="subtitle" style="margin:4px 0 0;color:var(--muted)"></p></div>
  <div class="tabs"><button type="button" class="tab on" id="tab-sessions">Sessions &amp; Telemetry</button><button type="button" class="tab" id="tab-graph">Trust-Boundary Graph</button></div>
</div>
<section class="kpis">
  <div class="card"><div class="kpi-label">Cost</div><div class="kpi-value" id="k-cost">$0.00</div><div class="kpi-note">API-priced session total</div></div>
  <div class="card"><div class="kpi-label">Tokens</div><div class="kpi-value" id="k-tokens">0</div><div class="kpi-note">Input + output + cache</div></div>
  <div class="card"><div class="kpi-label">Time &amp; Refactor Delta</div><div class="kpi-value" id="k-time">0m</div><div class="kpi-note">Active agent time &amp; LOC delta</div></div>
  <div class="card"><div class="kpi-label">Security &amp; Guard</div><div class="kpi-value" id="k-sec">0 blocked</div><div class="kpi-note">PreToolUse blocks &amp; issues fixed</div></div>
</section>
<section class="card" id="view-sessions">
  <h3 style="margin:0 0 8px">Sessions</h3>
  <table><thead><tr><th>Task</th><th>Project</th><th>Started</th><th>Time</th><th>Cost</th><th>Tokens</th><th>Reuse &amp; LOC</th><th>Security &amp; VIBES</th><th>Tests</th></tr></thead><tbody id="rows"></tbody></table>
</section>
<section class="card" id="view-graph" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
    <div><h3 style="margin:0">External &amp; Internal Trust-Boundary Graph</h3><div id="g-load" style="font-size:12px;color:var(--muted);margin-top:4px"></div></div>
    <div id="g-drift" style="font-size:12px;color:var(--ok)"></div>
  </div>
  <svg id="boundary-svg" viewBox="0 0 960 420" role="img" aria-label="External and internal trust-boundary graph"></svg>
</section>
<footer>Measured locally by NeckBeard (and enriched by .ai-audit/ VIBES when present). Zero network calls or external telemetry.</footer>
</main></div>
<script type="application/json" id="board-data">${json({ now, tasks, projectsMeta })}</script>
<script>${APP}</script></body></html>`
}
