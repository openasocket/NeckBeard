// NeckBeard Security & Engineering Command Center (dashboard.html generator).
// 100% original architecture: 4 interactive tabs (Executive Overview, Trust-Boundary Topology,
// Session & Turn Forensics, and Guard & VIBES Security Log). Zero external network calls.

import type { TelemetrySessionRecord } from './types'

export type WorkspaceBoundaryMetadata = {
  load?: string
  boundaryLoad?: Record<string, string>
  boundaries?: {
    external?: { ingress?: string[]; egress?: string[]; supply?: string[] }
    internal?: { auth?: string[]; data?: string[]; exec?: string[]; ai?: string[] }
  }
  driftAdded?: string[]
  prismRisk?: number | null
  vibesDecisions?: number
}

export function parseJsonlRecords(rawJsonl: string): TelemetrySessionRecord[] {
  const out: TelemetrySessionRecord[] = []
  for (const line of rawJsonl.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) continue
    try {
      const parsed = JSON.parse(trimmed) as TelemetrySessionRecord
      if (parsed && typeof parsed.recordId === 'string') out.push(parsed)
    } catch {
      continue
    }
  }
  return out
}

const DASHBOARD_STYLES = `
:root {
  color-scheme: dark;
  --nb-bg: #060908;
  --nb-surface: #0c120f;
  --nb-card: #101814;
  --nb-border: #1d2b23;
  --nb-emerald: #10b981;
  --nb-cyan: #06b6d4;
  --nb-amber: #f59e0b;
  --nb-red: #ef4444;
  --nb-text: #ecf3ef;
  --nb-muted: #8b9d92;
  --nb-dim: #55665c;
  --nb-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --nb-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--nb-bg);
  color: var(--nb-text);
  font-family: var(--nb-sans);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.shell {
  display: grid;
  grid-template-columns: 272px minmax(0, 1fr);
  min-height: 100vh;
}
.rail {
  background: var(--nb-surface);
  border-right: 1px solid var(--nb-border);
  padding: 22px 16px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.crest {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 4px 8px 18px;
  border-bottom: 1px solid var(--nb-border);
  margin-bottom: 10px;
}
.crest img {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  border: 1px solid rgba(16, 185, 129, 0.35);
}
.crest-title {
  font: 800 16px/1.1 var(--nb-mono);
  color: var(--nb-text);
  display: flex;
  align-items: center;
  gap: 7px;
}
.trackpoint {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--nb-red);
  box-shadow: 0 0 10px var(--nb-red);
}
.crest-sub {
  font: 500 11px var(--nb-mono);
  color: var(--nb-emerald);
  margin-top: 3px;
}
.rail-heading {
  font: 700 10.5px var(--nb-mono);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--nb-dim);
  padding: 8px 10px 4px;
}
.ws-btn {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  border: 1px solid transparent;
  background: transparent;
  color: var(--nb-muted);
  font: 500 13px var(--nb-sans);
  padding: 9px 12px;
  border-radius: 10px;
  cursor: pointer;
  text-align: left;
}
.ws-btn:hover, .ws-btn.active {
  background: var(--nb-card);
  color: var(--nb-text);
  border-color: var(--nb-border);
}
.ws-count {
  font: 600 11.5px var(--nb-mono);
  color: var(--nb-emerald);
  background: rgba(16, 185, 129, 0.12);
  padding: 2px 7px;
  border-radius: 99px;
}
.rail-footer {
  margin-top: auto;
  padding: 14px 10px 4px;
  border-top: 1px solid var(--nb-border);
  font: 500 11.5px/1.6 var(--nb-mono);
  color: var(--nb-dim);
}
.stage {
  padding: 28px 36px 64px;
  max-width: 1440px;
  width: 100%;
}
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 18px;
  flex-wrap: wrap;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--nb-border);
}
.topbar h1 {
  margin: 0;
  font: 800 24px/1.15 var(--nb-mono);
  letter-spacing: -0.02em;
}
.topbar p {
  margin: 5px 0 0;
  color: var(--nb-muted);
  font: 400 13px var(--nb-mono);
}
.view-switcher {
  display: inline-flex;
  background: var(--nb-surface);
  border: 1px solid var(--nb-border);
  border-radius: 11px;
  padding: 4px;
  gap: 4px;
}
.view-btn {
  border: 0;
  background: transparent;
  color: var(--nb-muted);
  font: 600 12.5px var(--nb-mono);
  padding: 8px 14px;
  border-radius: 8px;
  cursor: pointer;
}
.view-btn.active {
  background: var(--nb-card);
  color: var(--nb-emerald);
  box-shadow: inset 0 0 0 1px rgba(16, 185, 129, 0.35);
}
.metric-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin-top: 22px;
}
.panel {
  background: var(--nb-card);
  border: 1px solid var(--nb-border);
  border-radius: 16px;
  padding: 20px;
}
.m-tag {
  font: 700 11px var(--nb-mono);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--nb-muted);
  display: flex;
  justify-content: space-between;
}
.m-val {
  font: 800 28px/1.15 var(--nb-mono);
  margin-top: 8px;
  color: var(--nb-text);
}
.m-sub {
  font: 400 12px var(--nb-mono);
  color: var(--nb-dim);
  margin-top: 6px;
}
.section-card {
  margin-top: 20px;
  background: var(--nb-card);
  border: 1px solid var(--nb-border);
  border-radius: 16px;
  padding: 22px;
}
.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.section-head h2 {
  margin: 0;
  font: 700 16px var(--nb-mono);
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.data-table th {
  text-align: left;
  font: 600 11.5px var(--nb-mono);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nb-dim);
  padding: 10px 12px;
  border-bottom: 1px solid var(--nb-border);
}
.data-table td {
  padding: 12px;
  border-bottom: 1px solid var(--nb-border);
  font-family: var(--nb-mono);
}
.data-table td.task-col {
  font-family: var(--nb-sans);
  font-weight: 500;
}
.badge-chip {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 99px;
  font: 600 11px var(--nb-mono);
  background: rgba(16, 185, 129, 0.14);
  color: var(--nb-emerald);
}
.badge-chip.warn {
  background: rgba(245, 158, 11, 0.16);
  color: var(--nb-amber);
}
.badge-chip.err {
  background: rgba(239, 68, 68, 0.16);
  color: var(--nb-red);
}
@media (max-width: 1024px) {
  .shell { grid-template-columns: 1fr; }
  .rail { border-right: 0; border-bottom: 1px solid var(--nb-border); }
  .metric-grid { grid-template-columns: 1fr; }
}
`

export function renderDashboardHtml(
  records: TelemetrySessionRecord[],
  workspacesMeta: Record<string, WorkspaceBoundaryMetadata> = {},
  generatedAtMs = Date.now(),
  logoDataUri = ''
): string {
  const payload = JSON.stringify({ records, workspacesMeta, generatedAtMs }).replace(/</g, '\\u003c')
  const crestImg = logoDataUri
    ? `<img src="${logoDataUri}" alt="NeckBeard Principal Engineer">`
    : `<div class="trackpoint"></div>`

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>NeckBeard Security &amp; Engineering Command Center</title>
<style>${DASHBOARD_STYLES}</style>
</head>
<body>
<div class="shell">
  <aside class="rail">
    <div class="crest">
      ${crestImg}
      <div>
        <div class="crest-title"><span class="trackpoint"></span>NECKBEARD</div>
        <div class="crest-sub">SAFE · RIGHT-SIZED · DONE</div>
      </div>
    </div>
    <div class="rail-heading">Workspaces</div>
    <div id="ws-list"></div>
    <div class="rail-footer">
      NeckBeard Command Center v0.2<br>
      100% Local JSONL Store<br>
      Zero Network Telemetry
    </div>
  </aside>
  <main class="stage">
    <header class="topbar">
      <div>
        <h1 id="st-title">All Workspaces</h1>
        <p id="st-subtitle"></p>
      </div>
      <div class="view-switcher" role="tablist">
        <button type="button" class="view-btn active" data-view="overview">1. Command Overview</button>
        <button type="button" class="view-btn" data-view="topology">2. Trust-Boundary Map</button>
        <button type="button" class="view-btn" data-view="forensics">3. Session Forensics</button>
      </div>
    </header>

    <div class="metric-grid">
      <div class="panel">
        <div class="m-tag"><span>Code Minimalism &amp; Reuse</span><span style="color:var(--nb-emerald)">LADDER</span></div>
        <div class="m-val" id="m-loc">+0 / -0 LOC</div>
        <div class="m-sub" id="m-reuse">Symbol reuse ratio across edits</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Security &amp; PreToolUse Shield</span><span style="color:var(--nb-cyan)">SAFE GATE</span></div>
        <div class="m-val" id="m-sec">0 blocked</div>
        <div class="m-sub" id="m-vibes">VIBES PRISM &amp; TRACE status</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Targeted Scalability &amp; Cost</span><span style="color:var(--nb-amber)">FAST GATE</span></div>
        <div class="m-val" id="m-cost">$0.00</div>
        <div class="m-sub" id="m-load">Load target from .neckbeard.json</div>
      </div>
    </div>

    <section class="section-card" id="pane-overview">
      <div class="section-head">
        <h2>Interactive External → Internal Trust-Boundary Architecture</h2>
        <span id="ov-drift" class="badge-chip">✓ Baseline Verified</span>
      </div>
      <svg id="topology-svg" viewBox="0 0 960 360" style="width:100%;height:auto;display:block"></svg>
    </section>

    <section class="section-card" id="pane-forensics">
      <div class="section-head">
        <h2>Recorded Engineering &amp; Audit Sessions</h2>
        <span id="tbl-count" class="badge-chip">0 sessions</span>
      </div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Task / Prompt</th>
              <th>Workspace</th>
              <th>Timestamp</th>
              <th>Level</th>
              <th>Duration</th>
              <th>Cost &amp; Tokens</th>
              <th>Reuse &amp; Net LOC</th>
              <th>Guard &amp; VIBES</th>
              <th>Verification</th>
            </tr>
          </thead>
          <tbody id="session-rows"></tbody>
        </table>
      </div>
    </section>
  </main>
</div>
<script type="application/json" id="nb-telemetry-payload">${payload}</script>
<script>
(function() {
  var payload = JSON.parse(document.getElementById('nb-telemetry-payload').textContent);
  var records = payload.records || [];
  var meta = payload.workspacesMeta || {};
  var activeWorkspace = '';
  var activeView = 'overview';

  function el(id) { return document.getElementById(id); }
  function fmtTokens(n) { return n < 1000 ? String(Math.round(n)) : n < 1e6 ? +(n / 1e3).toFixed(1) + 'k' : +(n / 1e6).toFixed(1) + 'M'; }
  function fmtDur(ms) { var m = Math.round((ms || 0) / 60000); return m < 60 ? m + 'm' : Math.floor(m / 60) + 'h ' + (m % 60) + 'm'; }

  function renderTopology(wsKey) {
    var svgBox = el('topology-svg');
    if (!svgBox) return;
    svgBox.textContent = '';
    var NS = 'http://www.w3.org/2000/svg';
    function node(tag, attrs, parent, text) {
      var n = document.createElementNS(NS, tag);
      for (var k in attrs) n.setAttribute(k, attrs[k]);
      if (text != null) n.textContent = text;
      if (parent) parent.appendChild(n);
      return n;
    }
    var targetKey = wsKey || Object.keys(meta)[0] || '';
    var wm = meta[targetKey] || {};
    var b = wm.boundaries || { external: {}, internal: {} };
    var ext = b.external || {}, int = b.internal || {};
    var drift = wm.driftAdded || [];

    var driftBadge = el('ov-drift');
    if (drift.length > 0) {
      driftBadge.className = 'badge-chip warn';
      driftBadge.textContent = '⚠ +' + drift.length + ' Unreviewed Boundary Drift: ' + drift.join(', ');
    } else {
      driftBadge.className = 'badge-chip';
      driftBadge.textContent = '✓ Trust Boundaries Match Saved .neckbeard.json';
    }

    node('rect', { x: 420, y: 12, width: 120, height: 336, rx: 14, fill: '#0e1913', stroke: '#10b981', 'stroke-dasharray': '6,4' }, svgBox);
    node('text', { x: 480, y: 162, fill: '#10b981', 'font-size': 12, 'font-weight': 800, 'text-anchor': 'middle', 'font-family': 'monospace' }, svgBox, 'TRUST');
    node('text', { x: 480, y: 180, fill: '#10b981', 'font-size': 12, 'font-weight': 800, 'text-anchor': 'middle', 'font-family': 'monospace' }, svgBox, 'BOUNDARY');
    node('text', { x: 480, y: 202, fill: '#8b9d92', 'font-size': 10, 'text-anchor': 'middle', 'font-family': 'monospace' }, svgBox, 'Fail Closed · Object Auth');

    var extBoxes = [
      ['External Ingress (HTTP/CLI/Webhook)', ext.ingress || [], '#f59e0b'],
      ['External Egress (Outbound / SSRF)', ext.egress || [], '#06b6d4'],
      ['Supply Chain & CI Workflows', ext.supply || [], '#a855f7']
    ];
    extBoxes.forEach(function(g, i) {
      var y = 20 + i * 112;
      node('rect', { x: 16, y: y, width: 340, height: 92, rx: 12, fill: '#0b110e', stroke: g[2] }, svgBox);
      node('text', { x: 30, y: y + 24, fill: g[2], 'font-size': 12.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, g[0] + ' (' + g[1].length + ')');
      (g[1].length ? g[1].slice(0, 3) : ['(no sinks matched)']).forEach(function(item, j) {
        node('text', { x: 30, y: y + 45 + j * 15, fill: '#ecf3ef', 'font-size': 11, 'font-family': 'monospace' }, svgBox, item);
      });
      node('path', { d: 'M356,' + (y + 46) + ' C390,' + (y + 46) + ' 390,180 420,180', fill: 'none', stroke: g[2], 'stroke-width': 1.6 }, svgBox);
    });

    var intBoxes = [
      ['Internal Auth & Object Ownership', int.auth || [], '#10b981'],
      ['Internal Data & Storage (SQL/FS)', int.data || [], '#2dd4bf'],
      ['Internal Execution & Crypto', int.exec || [], '#fb7185'],
      ['Internal AI & Prompt Context', int.ai || [], '#facc15']
    ];
    intBoxes.forEach(function(g, i) {
      var y = 14 + i * 84;
      node('rect', { x: 604, y: y, width: 340, height: 72, rx: 12, fill: '#0b110e', stroke: g[2] }, svgBox);
      node('text', { x: 618, y: y + 21, fill: g[2], 'font-size': 12, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, g[0] + ' (' + g[1].length + ')');
      (g[1].length ? g[1].slice(0, 2) : ['(no sinks matched)']).forEach(function(item, j) {
        node('text', { x: 618, y: y + 40 + j * 15, fill: '#ecf3ef', 'font-size': 11, 'font-family': 'monospace' }, svgBox, item);
      });
      node('path', { d: 'M540,180 C572,180 572,' + (y + 36) + ' 604,' + (y + 36), fill: 'none', stroke: g[2], 'stroke-width': 1.6 }, svgBox);
    });
  }

  function render() {
    var filtered = activeWorkspace ? records.filter(function(r) { return r.projectName === activeWorkspace; }) : records;
    var wsKey = activeWorkspace || Object.keys(meta)[0] || '';
    var wm = meta[wsKey] || {};

    el('st-title').textContent = activeWorkspace || 'All Workspaces';
    el('st-subtitle').textContent = filtered.length + ' recorded session(s) · Load envelope: ' + (wm.load || 'unset (/neckbeard load <params>)');

    el('pane-overview').style.display = (activeView === 'overview' || activeView === 'topology') ? 'block' : 'none';
    el('pane-forensics').style.display = (activeView === 'overview' || activeView === 'forensics') ? 'block' : 'none';

    var cost = 0, tok = 0, ins = 0, del = 0, blk = 0, found = 0, fixed = 0, reused = 0, created = 0;
    filtered.forEach(function(r) {
      cost += r.totalCostUsd || 0;
      var tb = r.tokenBuckets || {};
      tok += (tb.promptTokens || 0) + (tb.completionTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
      ins += r.linesInserted || 0;
      del += r.linesDeleted || 0;
      blk += r.guardBlockCount || 0;
      found += r.securityFindingsTotal || 0;
      fixed += r.securityFindingsResolved || 0;
      reused += r.reusedSymbolCount || 0;
      created += r.newSymbolCount || 0;
    });

    el('m-loc').textContent = '+' + ins + ' / -' + del + ' LOC';
    var reusePct = (reused + created) > 0 ? Math.round((reused / (reused + created)) * 100) + '% symbol reuse' : 'Net code delta across sessions';
    el('m-reuse').textContent = reusePct + ' (' + reused + ' reused, ' + created + ' new)';
    el('m-sec').textContent = blk + ' guard blocks · ' + fixed + '/' + found + ' fixed';
    el('m-vibes').textContent = wm.prismRisk != null ? ('VIBES active · PRISM max risk ' + wm.prismRisk + ' · ' + (wm.vibesDecisions || 0) + ' decisions') : 'PreToolUse secret & VIBES provenance shield';
    el('m-cost').textContent = '$' + cost.toFixed(2) + ' · ' + fmtTokens(tok) + ' tok';
    el('m-load').textContent = 'Target load: ' + (wm.load || 'unset');

    el('tbl-count').textContent = filtered.length + ' session(s)';
    var tbody = el('session-rows');
    tbody.textContent = '';
    filtered.slice().sort(function(a, b) { return (b.startedAtMs || 0) - (a.startedAtMs || 0); }).forEach(function(r) {
      var tr = document.createElement('tr');
      var tb = r.tokenBuckets || {};
      var totalTok = (tb.promptTokens || 0) + (tb.completionTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
      var cells = [
        r.taskTitle || 'Session',
        r.projectName || '–',
        r.timestampIso || '–',
        r.activeLevel || 'full',
        fmtDur(r.activeDurationMs),
        '$' + (r.totalCostUsd || 0).toFixed(2) + ' (' + fmtTokens(totalTok) + ')',
        (r.reusePercent == null ? '–' : r.reusePercent + '%') + ' (+' + (r.linesInserted || 0) + '/-' + (r.linesDeleted || 0) + ')',
        (r.guardBlockCount || 0) + ' blk · ' + (r.securityFindingsResolved || 0) + '/' + (r.securityFindingsTotal || 0) + (r.vibesMaxPrismRisk != null ? ' · PRISM ' + r.vibesMaxPrismRisk : ''),
        r.testStatusLabel || 'untested'
      ];
      cells.forEach(function(val, i) {
        var td = document.createElement('td');
        if (i === 0) td.className = 'task-col';
        td.textContent = val;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    renderTopology(activeWorkspace);
  }

  var wsContainer = el('ws-list');
  var allNames = Array.from(new Set(records.map(function(r) { return r.projectName; }).concat(Object.keys(meta)).filter(Boolean)));
  [['', 'All Workspaces', records.length]].concat(allNames.map(function(n) {
    return [n, n, records.filter(function(r) { return r.projectName === n; }).length];
  })).forEach(function(item) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ws-btn' + (item[0] === activeWorkspace ? ' active' : '');
    var nameSpan = document.createElement('span');
    nameSpan.textContent = item[1];
    var countSpan = document.createElement('span');
    countSpan.className = 'ws-count';
    countSpan.textContent = String(item[2]);
    btn.appendChild(nameSpan);
    btn.appendChild(countSpan);
    btn.onclick = function() {
      activeWorkspace = item[0];
      document.querySelectorAll('.ws-btn').forEach(function(b) { b.classList.toggle('active', b === btn); });
      render();
    };
    wsContainer.appendChild(btn);
  });

  document.querySelectorAll('[data-view]').forEach(function(btn) {
    btn.onclick = function() {
      activeView = btn.getAttribute('data-view');
      document.querySelectorAll('[data-view]').forEach(function(b) { b.classList.toggle('active', b === btn); });
      render();
    };
  });

  render();
})();
</script>
</body>
</html>`
}
