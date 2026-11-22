// NeckBeard Security & Engineering Command Center (dashboard.html generator).
// 100% original architecture built for NeckBeard:
// - Economics-First & Workspace-Reactive: Clicking any workspace in the left sidebar (or in the
//   economics table) dynamically updates 100% of the KPI cards, SVG charts, model breakdowns,
//   VIBES forensics, trust-boundary topology, and session table on the right, while benchmarking
//   the selected workspace directly against the All-Workspaces portfolio baseline.
// - Smart VIBES (.ai-audit/) Hub: Displays the full 5-pillar cryptographic provenance & PRISM risk
//   visualizations when .ai-audit/ is active in the workspace (with zero redundant install banners),
//   and collapses into a clean compact bar when .ai-audit/ is absent so zeros never clutter the screen.

import type { TelemetrySessionRecord } from './types'

export type VibesVisualTelemetry = {
  present?: boolean
  standardVersion?: string
  configuredAssurance?: string
  projectName?: string
  annotationsCount?: number
  verifiedCount?: number
  blobsCount?: number
  attestationsCount?: number
  iocRulesCount?: number
  hasAuditDb?: boolean
  snapshotCount?: number
  manifestCounts?: {
    environment?: number
    reasoning?: number
    command?: number
    prompt?: number
    decision?: number
    total?: number
  }
  maxPrismRisk?: number
  highRiskCount?: number
  traceIncidents?: number
  traceResolved?: number
  decisions?: number
  linesAdded?: number
  linesRemoved?: number
  filesTouchedCount?: number
  prismBuckets?: { low?: number; moderate?: number; high?: number; critical?: number }
  fileHotspots?: Array<{
    file: string
    annotations: number
    linesAdded: number
    linesRemoved: number
    maxRisk: number
    verified: boolean
  }>
  decisionRecords?: Array<{ id: string; title: string; status: string; timestamp: string }>
  incidentRecords?: Array<{ id: string; iocId: string; severity: string; status: string; summary: string; timestamp: string }>
  recentAnnotations?: Array<{
    sessionId: string
    timestamp: string
    model: string
    file: string
    linesAdded: number
    linesRemoved: number
    riskScore: number | null
    verified: boolean
    summary: string
  }>
}

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
  vibes?: VibesVisualTelemetry | null
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
  --nb-surface: #0b110e;
  --nb-card: #101814;
  --nb-card-alt: #131d18;
  --nb-border: #1d2b23;
  --nb-emerald: #10b981;
  --nb-cyan: #06b6d4;
  --nb-amber: #f59e0b;
  --nb-red: #ef4444;
  --nb-purple: #a855f7;
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
a { color: var(--nb-cyan); text-decoration: none; }
a:hover { text-decoration: underline; }
.shell {
  display: grid;
  grid-template-columns: 292px minmax(0, 1fr);
  min-height: 100vh;
}
.rail {
  background: var(--nb-surface);
  border-right: 1px solid var(--nb-border);
  padding: 20px 14px;
  display: flex;
  flex-direction: column;
  gap: 5px;
  position: sticky;
  top: 0;
  height: 100vh;
}
.crest {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 4px 8px 16px;
  border-bottom: 1px solid var(--nb-border);
  margin-bottom: 8px;
}
.crest img {
  width: 46px;
  height: 46px;
  border-radius: 10px;
  border: 1px solid rgba(16, 185, 129, 0.4);
}
.crest-title {
  font: 800 16px/1.1 var(--nb-mono);
  color: var(--nb-text);
  display: flex;
  align-items: center;
  gap: 7px;
}
.trackpoint {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--nb-red);
  box-shadow: 0 0 10px var(--nb-red);
  display: inline-block;
}
.crest-sub {
  font: 600 10.5px var(--nb-mono);
  color: var(--nb-emerald);
  margin-top: 3px;
}
.rail-heading {
  font: 700 10.5px var(--nb-mono);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--nb-dim);
  padding: 6px 10px 4px;
  display: flex;
  justify-content: space-between;
}
.ws-btn {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  border: 1px solid transparent;
  background: transparent;
  color: var(--nb-muted);
  font: 500 12.5px var(--nb-sans);
  padding: 8px 10px;
  border-radius: 9px;
  cursor: pointer;
  text-align: left;
  gap: 6px;
  transition: background 0.12s, border-color 0.12s;
}
.ws-btn:hover {
  background: rgba(16, 24, 20, 0.7);
  color: var(--nb-text);
}
.ws-btn.active {
  background: var(--nb-card);
  color: var(--nb-text);
  border-color: var(--nb-emerald);
  box-shadow: inset 3px 0 0 var(--nb-emerald);
}
.ws-name-col {
  min-width: 0;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ws-badges {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  flex-shrink: 0;
}
.ws-vibes-tag {
  font: 700 9px var(--nb-mono);
  color: var(--nb-cyan);
  background: rgba(6, 182, 212, 0.14);
  border: 1px solid rgba(6, 182, 212, 0.35);
  padding: 1px 5px;
  border-radius: 99px;
}
.ws-cost-tag {
  font: 600 10.5px var(--nb-mono);
  color: var(--nb-amber);
}
.ws-count {
  font: 600 11px var(--nb-mono);
  color: var(--nb-emerald);
  background: rgba(16, 185, 129, 0.12);
  padding: 1px 6px;
  border-radius: 99px;
}
.rail-footer {
  margin-top: auto;
  padding: 12px 10px 4px;
  border-top: 1px solid var(--nb-border);
  font: 500 11px/1.55 var(--nb-mono);
  color: var(--nb-dim);
}
.stage {
  padding: 24px 32px 64px;
  max-width: 1520px;
  width: 100%;
}
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 18px;
  flex-wrap: wrap;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--nb-border);
}
.title-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.topbar h1 {
  margin: 0;
  font: 800 24px/1.15 var(--nb-mono);
  letter-spacing: -0.02em;
}
.topbar p {
  margin: 5px 0 0;
  color: var(--nb-muted);
  font: 400 12.5px var(--nb-mono);
}
.back-all-btn {
  display: none;
  border: 1px solid rgba(16, 185, 129, 0.45);
  background: rgba(16, 185, 129, 0.14);
  color: var(--nb-emerald);
  font: 600 11.5px var(--nb-mono);
  padding: 4px 10px;
  border-radius: 99px;
  cursor: pointer;
}
.back-all-btn:hover {
  background: rgba(16, 185, 129, 0.25);
}
.view-switcher {
  display: inline-flex;
  background: var(--nb-surface);
  border: 1px solid var(--nb-border);
  border-radius: 11px;
  padding: 4px;
  gap: 4px;
  flex-wrap: wrap;
}
.view-btn {
  border: 0;
  background: transparent;
  color: var(--nb-muted);
  font: 600 12px var(--nb-mono);
  padding: 8px 13px;
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
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin-top: 18px;
}
.panel {
  background: var(--nb-card);
  border: 1px solid var(--nb-border);
  border-radius: 15px;
  padding: 16px 18px;
}
.m-tag {
  font: 700 10.5px var(--nb-mono);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--nb-muted);
  display: flex;
  justify-content: space-between;
}
.m-val {
  font: 800 24px/1.15 var(--nb-mono);
  margin-top: 7px;
  color: var(--nb-text);
}
.m-sub {
  font: 400 11.5px var(--nb-mono);
  color: var(--nb-muted);
  margin-top: 5px;
}
.m-comp {
  font: 600 11px var(--nb-mono);
  color: var(--nb-cyan);
  margin-top: 4px;
}
.section-card {
  margin-top: 18px;
  background: var(--nb-card);
  border: 1px solid var(--nb-border);
  border-radius: 16px;
  padding: 20px 22px;
}
.section-card.econ-highlight {
  border-color: rgba(16, 185, 129, 0.4);
  background: linear-gradient(180deg, rgba(16, 185, 129, 0.05) 0%, var(--nb-card) 100%);
}
.section-card.vibes-highlight {
  border-color: rgba(6, 182, 212, 0.45);
  background: linear-gradient(180deg, rgba(6, 182, 212, 0.05) 0%, var(--nb-card) 100%);
}
.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.section-head h2 {
  margin: 0;
  font: 700 15.5px var(--nb-mono);
  display: flex;
  align-items: center;
  gap: 10px;
}
.split-2 {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 16px;
  margin-top: 14px;
}
.vibes-pillars {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  margin-top: 12px;
}
.pillar-box {
  background: var(--nb-surface);
  border: 1px solid var(--nb-border);
  border-radius: 12px;
  padding: 12px 14px;
}
.pillar-k {
  font: 700 10.5px var(--nb-mono);
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--nb-cyan);
}
.pillar-v {
  font: 800 19px/1.2 var(--nb-mono);
  margin-top: 5px;
  color: var(--nb-text);
}
.pillar-s {
  font: 400 11px var(--nb-mono);
  color: var(--nb-muted);
  margin-top: 4px;
}
.adopt-banner {
  background: rgba(6, 182, 212, 0.07);
  border: 1px dashed rgba(6, 182, 212, 0.45);
  border-radius: 12px;
  padding: 14px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.adopt-code {
  font: 500 11.5px var(--nb-mono);
  background: #060908;
  border: 1px solid var(--nb-border);
  padding: 7px 11px;
  border-radius: 8px;
  color: var(--nb-emerald);
}
.act-btn {
  border: 1px solid rgba(6, 182, 212, 0.45);
  background: rgba(6, 182, 212, 0.14);
  color: var(--nb-cyan);
  font: 600 11.5px var(--nb-mono);
  padding: 6px 12px;
  border-radius: 8px;
  cursor: pointer;
}
.act-btn:hover {
  background: rgba(6, 182, 212, 0.25);
}
.filter-bar {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.search-input {
  background: var(--nb-surface);
  border: 1px solid var(--nb-border);
  color: var(--nb-text);
  font: 500 12px var(--nb-mono);
  padding: 6px 11px;
  border-radius: 8px;
  min-width: 220px;
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.data-table th {
  text-align: left;
  font: 600 10.5px var(--nb-mono);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--nb-dim);
  padding: 9px 10px;
  border-bottom: 1px solid var(--nb-border);
  position: sticky;
  top: 0;
  background: var(--nb-surface);
}
.data-table td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--nb-border);
  font-family: var(--nb-mono);
}
.data-table td.task-col {
  font-family: var(--nb-sans);
  font-weight: 600;
}
.data-table tr.clickable-row {
  cursor: pointer;
}
.data-table tr.clickable-row:hover {
  background: rgba(16, 185, 129, 0.08);
}
.data-table tr.selected-row {
  background: rgba(16, 185, 129, 0.16);
  box-shadow: inset 3px 0 0 var(--nb-emerald);
}
.data-table tr.baseline-row {
  background: rgba(6, 182, 212, 0.09);
  font-weight: 700;
}
.share-bar-wrap {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  width: 100%;
}
.share-bar-bg {
  width: 54px;
  height: 7px;
  background: #080d0b;
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid var(--nb-border);
  display: inline-block;
}
.share-bar-fill {
  height: 100%;
  background: var(--nb-emerald);
  display: block;
}
.badge-chip {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 99px;
  font: 600 11px var(--nb-mono);
  background: rgba(16, 185, 129, 0.14);
  color: var(--nb-emerald);
}
.badge-chip.cyan {
  background: rgba(6, 182, 212, 0.16);
  color: var(--nb-cyan);
}
.badge-chip.warn {
  background: rgba(245, 158, 11, 0.16);
  color: var(--nb-amber);
}
.badge-chip.err {
  background: rgba(239, 68, 68, 0.16);
  color: var(--nb-red);
}
@media (max-width: 1180px) {
  .shell { grid-template-columns: 1fr; }
  .rail { border-right: 0; border-bottom: 1px solid var(--nb-border); position: static; height: auto; }
  .metric-grid, .vibes-pillars, .split-2 { grid-template-columns: 1fr; }
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
    : `<span class="trackpoint"></span>`

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
    <div class="rail-heading"><span>Workspaces (<span id="ws-total-cnt">0</span>)</span><span>Spend / Sess</span></div>
    <div id="ws-list" style="overflow-y:auto;flex:1"></div>
    <div class="rail-footer">
      NeckBeard Command Center v0.3.2<br>
      Economics + 3-Gate + VIBES Hub<br>
      100% Local · Zero Network Calls
    </div>
  </aside>
  <main class="stage">
    <header class="topbar">
      <div>
        <div class="title-row">
          <h1 id="st-title">All Workspaces</h1>
          <button type="button" id="back-all-btn" class="back-all-btn">← Compare All Workspaces</button>
          <span id="st-vibes-pill" class="badge-chip cyan" style="display:none"></span>
        </div>
        <p id="st-subtitle"></p>
      </div>
      <div class="view-switcher" role="tablist">
        <button type="button" class="view-btn active" data-view="overview">1. Command Overview</button>
        <button type="button" class="view-btn" data-view="economics">2. Economics &amp; All-Workspaces ROI</button>
        <button type="button" class="view-btn" data-view="vibes">3. VIBES (.ai-audit) Hub</button>
        <button type="button" class="view-btn" data-view="topology">4. Trust-Boundary Graph</button>
        <button type="button" class="view-btn" data-view="forensics">5. Session Forensics</button>
      </div>
    </header>

    <!-- 4 EXECUTIVE ECONOMICS, CACHE ROI & SECURITY KPI CARDS (Always Front & Center, Benchmarked vs All Workspaces) -->
    <div class="metric-grid">
      <div class="panel">
        <div class="m-tag"><span>API Spend &amp; Unit Economics</span><span style="color:var(--nb-emerald)">ECONOMICS</span></div>
        <div class="m-val" id="m-cost">$0.00</div>
        <div class="m-sub" id="m-cost-unit">$0.00 / session · $0.00 / turn</div>
        <div class="m-comp" id="m-cost-comp">100% of portfolio spend</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Prompt-Cache Dollar Savings</span><span style="color:var(--nb-cyan)">CACHE ROI</span></div>
        <div class="m-val" id="m-saved" style="color:var(--nb-cyan)">$0.00 saved</div>
        <div class="m-sub" id="m-cache">0% cache hit rate · 0 tokens</div>
        <div class="m-comp" id="m-cache-comp">Prompt caching efficiency</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Agent Compute vs. Wall-Clock Time</span><span style="color:var(--nb-amber)">VELOCITY</span></div>
        <div class="m-val" id="m-time">0h 0m</div>
        <div class="m-sub" id="m-turns">0 sessions · 0 turns</div>
        <div class="m-comp" id="m-load">Agent vs. wall-clock work volume</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Security Shield &amp; Code Delta</span><span style="color:var(--nb-emerald)">3 GATES</span></div>
        <div class="m-val" id="m-sec">0 blocked</div>
        <div class="m-sub" id="m-loc">+0 / -0 LOC · 0/0 issues fixed</div>
        <div class="m-comp" id="m-vibes">PreToolUse &amp; VIBES status</div>
      </div>
    </div>

    <!-- FRONT-AND-CENTER SECTION 1: ECONOMICS, CACHE SAVINGS & ALL-WORKSPACES BENCHMARKING -->
    <section class="section-card econ-highlight" id="pane-economics">
      <div class="section-head">
        <h2>
          <span id="econ-title">Front-and-Center Economics: Spend vs. Prompt-Cache Savings &amp; Workspace Comparison</span>
        </h2>
        <span id="econ-badge" class="badge-chip">All Workspaces Baseline</span>
      </div>
      <div style="background:#080d0b;border:1px solid var(--nb-border);border-radius:12px;padding:14px">
        <svg id="velocity-svg" viewBox="0 0 960 235" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div class="split-2">
        <div>
          <div style="font:700 11.5px var(--nb-mono);color:var(--nb-emerald);margin-bottom:8px;display:flex;justify-content:space-between">
            <span>WORKSPACE VS. ALL-WORKSPACES ECONOMICS MATRIX (CLICK ANY ROW TO INSPECT)</span>
            <span id="repo-matrix-sub" style="color:var(--nb-muted)"></span>
          </div>
          <div style="overflow-x:auto;background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;max-height:330px">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Workspace</th>
                  <th>Sessions / Turns</th>
                  <th>Agent / Wall Time</th>
                  <th>Cache Hit %</th>
                  <th>Est. Saved</th>
                  <th>Actual Spend</th>
                  <th>Share of Total</th>
                  <th>VIBES</th>
                </tr>
              </thead>
              <tbody id="repo-scorecard-rows"></tbody>
            </table>
          </div>
        </div>
        <div>
          <div style="font:700 11.5px var(--nb-mono);color:var(--nb-amber);margin-bottom:8px;display:flex;justify-content:space-between">
            <span id="model-table-title">MODEL &amp; PROMPT-CACHE ECONOMICS (SELECTED SCOPE)</span>
            <span id="model-table-sub" style="color:var(--nb-muted)"></span>
          </div>
          <div style="overflow-x:auto;background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;max-height:330px">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Sess / Turns</th>
                  <th>Input + Cache</th>
                  <th>Output</th>
                  <th>Cache Hit</th>
                  <th>Est. Saved</th>
                  <th>Spend</th>
                </tr>
              </thead>
              <tbody id="model-econ-rows"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- SECTION 2: VIBES PROTOCOL (.ai-audit/) CRYPTOGRAPHIC PROVENANCE & PRISM RISK HUB -->
    <section class="section-card vibes-highlight" id="pane-vibes">
      <div class="section-head">
        <h2>
          <span id="vibes-heading">VIBES Protocol (.ai-audit/) Cryptographic Provenance &amp; PRISM Risk Hub</span>
          <a href="https://www.itsavibe.ai" target="_blank" rel="noopener" class="badge-chip cyan">itsavibe.ai ↗</a>
        </h2>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span id="vibes-status-chip" class="badge-chip">Checking .ai-audit/...</span>
          <button type="button" id="vibes-demo-btn" class="act-btn">Preview Reference VIBES Forensics</button>
        </div>
      </div>

      <p id="vibes-explainer" style="margin:0 0 10px;color:var(--nb-muted);font-size:12.5px"></p>

      <!-- Rich 5-pillar body: shown automatically when VIBES (.ai-audit/) is present in workspace or in demo mode; collapsed when absent so zeros never clutter the page -->
      <div id="vibes-active-body">
        <div class="vibes-pillars">
          <div class="pillar-box">
            <div class="pillar-k">1. VIBES v1.1 Provenance</div>
            <div class="pillar-v" id="vp-prov">0 annotations</div>
            <div class="pillar-s" id="vp-prov-sub">0 blobs · 0 files attributed</div>
          </div>
          <div class="pillar-box">
            <div class="pillar-k">2. VERIFY v1.0 DSSE</div>
            <div class="pillar-v" id="vp-verify">0% verified</div>
            <div class="pillar-s" id="vp-verify-sub">0 Ed25519 DSSE envelopes</div>
          </div>
          <div class="pillar-box">
            <div class="pillar-k">3. PRISM v1.0 Risk</div>
            <div class="pillar-v" id="vp-prism">0.00 max</div>
            <div class="pillar-s" id="vp-prism-sub">0 High/Critical (&gt;= 0.60)</div>
          </div>
          <div class="pillar-box">
            <div class="pillar-k">4. EVOLVE v1.0 Decisions</div>
            <div class="pillar-v" id="vp-evolve">0 decisions</div>
            <div class="pillar-s" id="vp-evolve-sub">Linked to /neckbeard-debt</div>
          </div>
          <div class="pillar-box">
            <div class="pillar-k">5. TRACE v1.0 Forensics</div>
            <div class="pillar-v" id="vp-trace">0 / 0 fixed</div>
            <div class="pillar-s" id="vp-trace-sub">IoC rules &amp; incident response</div>
          </div>
        </div>

        <div style="margin-top:14px;background:#080d0b;border:1px solid var(--nb-border);border-radius:12px;padding:14px">
          <svg id="vibes-svg" viewBox="0 0 960 250" style="width:100%;height:auto;display:block"></svg>
        </div>

        <div class="split-2">
          <div style="background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;padding:14px">
            <div style="font:700 11.5px var(--nb-mono);color:var(--nb-emerald);margin-bottom:8px">EVOLVE ARCHITECTURAL DECISIONS &amp; PRETOOLUSE IMMUTABILITY SHIELD</div>
            <div id="vibes-decisions-list" style="font:400 12px/1.6 var(--nb-mono);color:var(--nb-muted)"></div>
          </div>
          <div style="background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;padding:14px">
            <div style="font:700 11.5px var(--nb-mono);color:var(--nb-amber);margin-bottom:8px">TRACE INCIDENT LOG &amp; HIGH-RISK PRISM EDITS (&gt;= 0.60)</div>
            <div id="vibes-incidents-list" style="font:400 12px/1.6 var(--nb-mono);color:var(--nb-muted)"></div>
          </div>
        </div>

        <div id="vibes-annotations-wrap" style="margin-top:14px">
          <div style="font:700 11.5px var(--nb-mono);color:var(--nb-cyan);margin-bottom:8px">TURN-LEVEL .AI-AUDIT/ANNOTATIONS.JSONL PROVENANCE &amp; PRISM INSPECTOR</div>
          <div style="overflow-x:auto;background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;max-height:290px">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Session</th>
                  <th>Attributed File</th>
                  <th>Line Attribution</th>
                  <th>PRISM Risk</th>
                  <th>VERIFY DSSE</th>
                  <th>Intent / Prompt Summary</th>
                </tr>
              </thead>
              <tbody id="vibes-annotations-rows"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Shown ONLY when the selected workspace does NOT have .ai-audit/ initialized -->
      <div class="adopt-banner" id="vibes-adopt-banner" style="display:none">
        <div style="max-width:680px">
          <div style="font:700 12.5px var(--nb-mono);color:var(--nb-cyan)">Enable VIBES (.ai-audit/) Provenance in <span id="vibes-adopt-ws">this workspace</span></div>
          <div style="font-size:12px;color:var(--nb-muted);margin-top:3px">
            Add content-addressed line attribution, Ed25519 DSSE attestations locked by <code>hooks/guard.js</code>, PRISM risk scoring for <code>/neckbeard-review</code>, and TRACE forensics:
          </div>
        </div>
        <div class="adopt-code" id="vibes-adopt-cmd">vibecheck init --project-name my-app --assurance-level high &amp;&amp; vibes install-hooks &amp;&amp; vibecheck verify</div>
      </div>
    </section>

    <!-- SECTION 3: TRUST-BOUNDARY TOPOLOGY GRAPH (Dynamically Adapts Per Project Structure) -->
    <section class="section-card" id="pane-overview">
      <div class="section-head">
        <div>
          <h2 id="topo-heading">Per-Project Trust-Boundary &amp; System Architecture Graph</h2>
          <div id="topo-summary" style="font:400 12px var(--nb-mono);color:var(--nb-muted);margin-top:3px"></div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <div class="view-switcher" id="topo-realm-bar" style="padding:3px">
            <button type="button" class="view-btn active" data-realm="security">🛡️ Security Trust Boundaries</button>
            <button type="button" class="view-btn" data-realm="architecture">🏗️ System Architecture &amp; Flow</button>
          </div>
          <span id="ov-drift" class="badge-chip">✓ Baseline Verified</span>
        </div>
      </div>
      <div id="topo-subtype-bar" style="display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 12px;padding:8px 10px;background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:10px;align-items:center"></div>
      <div style="background:#080d0b;border:1px solid var(--nb-border);border-radius:12px;padding:12px">
        <svg id="boundary-svg" viewBox="0 0 960 420" style="width:100%;height:auto;display:block"></svg>
      </div>
      <div style="margin-top:14px">
        <div style="font:700 11.5px var(--nb-mono);color:var(--nb-emerald);margin-bottom:8px;display:flex;justify-content:space-between">
          <span id="boundary-table-title">PER-FILE TRUST-BOUNDARY &amp; CROSS-BOUNDARY BRIDGE MATRIX (CLICK ANY FILE TO EXPAND GUIDANCE)</span>
          <span id="boundary-table-count" style="color:var(--nb-muted)"></span>
        </div>
        <div style="overflow-x:auto;background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;max-height:320px">
          <table class="data-table">
            <thead>
              <tr>
                <th>Module / Subsystem</th>
                <th>Source File</th>
                <th>External [ext] Sinks</th>
                <th>Internal [int] Sinks</th>
                <th>Security / Architecture Role</th>
              </tr>
            </thead>
            <tbody id="boundary-file-rows"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- SECTION 4: SESSION FORENSICS TABLE WITH SEARCH & FILTER -->
    <section class="section-card" id="pane-forensics">
      <div class="section-head">
        <h2 id="forensics-heading">Recorded Engineering &amp; Audit Sessions</h2>
        <div class="filter-bar">
          <input type="search" id="session-search" class="search-input" placeholder="Filter by task, repo, model...">
          <span id="tbl-count" class="badge-chip">0 sessions</span>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Task / Prompt</th>
              <th>Workspace</th>
              <th>Timestamp</th>
              <th>Model &amp; Level</th>
              <th>Duration</th>
              <th>Cost &amp; Tokens</th>
              <th>Cache Saved</th>
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
  var demoVibesMode = false;
  var searchQuery = '';

  var SAMPLE_VIBES = {
    present: true,
    isDemo: true,
    annotationsCount: 48,
    verifiedCount: 46,
    blobsCount: 94,
    attestationsCount: 46,
    iocRulesCount: 12,
    hasAuditDb: true,
    maxPrismRisk: 0.78,
    highRiskCount: 4,
    traceIncidents: 2,
    traceResolved: 2,
    decisions: 5,
    linesAdded: 312,
    linesRemoved: 840,
    filesTouchedCount: 14,
    prismBuckets: { low: 31, moderate: 13, high: 3, critical: 1 },
    fileHotspots: [
      { file: 'src/routes/webhooks.js', annotations: 9, linesAdded: 42, linesRemoved: 188, maxRisk: 0.78, verified: true },
      { file: 'src/auth/session.js', annotations: 7, linesAdded: 28, linesRemoved: 94, maxRisk: 0.68, verified: true },
      { file: 'src/db/invoices.js', annotations: 8, linesAdded: 35, linesRemoved: 210, maxRisk: 0.54, verified: true },
      { file: 'hooks/guard.js', annotations: 6, linesAdded: 64, linesRemoved: 30, maxRisk: 0.41, verified: true },
      { file: 'src/lib/archive.js', annotations: 5, linesAdded: 19, linesRemoved: 82, maxRisk: 0.24, verified: true }
    ],
    decisionRecords: [
      { id: 'DEC-01', title: 'Enforce server-side org_id object auth at SQL query layer', status: 'verified', timestamp: '2026-11-21' },
      { id: 'DEC-02', title: 'Cap batch webhook payload at 64KB and 500 items for 250 rps target', status: 'verified', timestamp: '2026-11-21' },
      { id: 'DEC-03', title: 'Defer Redis rate-limit cache until load crosses 1,000 rps (risk: linked)', status: 'accepted', timestamp: '2026-11-21' }
    ],
    incidentRecords: [
      { id: 'INC-01', iocId: 'TRACE-SECRET-AWS', severity: 'critical', status: 'resolved', summary: 'Blocked hardcoded AWS key attempt via NeckBeard PreToolUse guard', timestamp: '2026-11-21' },
      { id: 'INC-02', iocId: 'PRISM-HIGH-0.78', severity: 'high', status: 'resolved', summary: 'Webhook HMAC signature verification hardened & DSSE attested', timestamp: '2026-11-21' }
    ],
    recentAnnotations: [
      { timestamp: '2026-11-21 22:18', sessionId: 'sess-91a4f0', model: 'claude-opus-5-5', file: 'src/routes/webhooks.js', linesAdded: 14, linesRemoved: 96, riskScore: 0.78, verified: true, summary: 'Verify Stripe HMAC raw body at edge & atomic UPDATE' },
      { timestamp: '2026-11-21 21:54', sessionId: 'sess-91a4f0', model: 'claude-opus-5-5', file: 'src/auth/session.js', linesAdded: 11, linesRemoved: 48, riskScore: 0.68, verified: true, summary: 'Require server-side org_id ownership check on every route' },
      { timestamp: '2026-11-21 21:10', sessionId: 'sess-83c2d1', model: 'claude-sonnet-4-6', file: 'src/db/invoices.js', linesAdded: 9, linesRemoved: 112, riskScore: 0.54, verified: true, summary: 'Replace N+1 query loop with parameterized ANY($1::uuid[])' },
      { timestamp: '2026-11-21 20:42', sessionId: 'sess-83c2d1', model: 'claude-sonnet-4-6', file: 'src/lib/archive.js', linesAdded: 8, linesRemoved: 34, riskScore: 0.24, verified: true, summary: 'Canonicalize path with fs.realpathSync before root prefix check' }
    ]
  };

  function el(id) { return document.getElementById(id); }
  function fmtTokens(n) { return n < 1000 ? String(Math.round(n)) : n < 1e6 ? +(n / 1e3).toFixed(1) + 'k' : +(n / 1e6).toFixed(1) + 'M'; }
  function fmtDur(ms) { var m = Math.round((ms || 0) / 60000); return m < 60 ? m + 'm' : Math.floor(m / 60) + 'h ' + (m % 60) + 'm'; }
  function fmtUsd(n) { return '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

  // Estimates USD saved by prompt caching (cachedReadTokens cost ~90% less than full input rate on Opus/Sonnet/Haiku)
  function estimateCacheSavingsUsd(r) {
    var tb = (r && r.tokenBuckets) || {};
    var cRead = tb.cachedReadTokens || 0;
    if (cRead <= 0) return 0;
    var m = String((r && r.modelId) || '').toLowerCase();
    var savedPerM = m.includes('opus') ? 4.0 : m.includes('haiku') ? 0.5 : 2.5;
    return (cRead / 1e6) * savedPerM;
  }

  function summarizeList(list) {
    var s = { sessions: list.length, turns: 0, cost: 0, saved: 0, tok: 0, cRead: 0, inAll: 0, outTok: 0, dur: 0, wallDur: 0, parallelFactor: 1, activeDays: 1, ins: 0, del: 0, blk: 0, found: 0, fixed: 0 };
    var ivs = [];
    var days = {};
    list.forEach(function(r) {
      s.cost += r.totalCostUsd || 0;
      s.saved += estimateCacheSavingsUsd(r);
      var tb = r.tokenBuckets || {};
      var pT = tb.promptTokens || 0, cT = tb.completionTokens || 0, crT = tb.cachedReadTokens || 0, cwT = tb.cachedWriteTokens || 0;
      s.tok += pT + cT + crT + cwT;
      s.cRead += crT;
      s.inAll += pT + crT + cwT;
      s.outTok += cT;
      var d = Math.max(0, r.activeDurationMs || 0);
      s.dur += d;
      s.turns += r.turnCount || 1;
      if (r.startedAtMs && d > 0) ivs.push([r.startedAtMs, r.startedAtMs + d]);
      if (r.timestampIso) days[String(r.timestampIso).slice(0, 10)] = 1;
      s.ins += r.linesInserted || 0;
      s.del += r.linesDeleted || 0;
      s.blk += r.guardBlockCount || 0;
      s.found += r.securityFindingsTotal || 0;
      s.fixed += r.securityFindingsResolved || 0;
    });
    ivs.sort(function(a, b) { return a[0] - b[0]; });
    var cs = -1, ce = -1;
    for (var i = 0; i < ivs.length; i++) {
      var st = ivs[i][0], en = ivs[i][1];
      if (cs === -1) { cs = st; ce = en; }
      else if (st <= ce) { if (en > ce) ce = en; }
      else { s.wallDur += (ce - cs); cs = st; ce = en; }
    }
    if (cs !== -1) s.wallDur += (ce - cs);
    if (s.wallDur <= 0) s.wallDur = s.dur;
    s.parallelFactor = s.wallDur > 0 ? +(s.dur / s.wallDur).toFixed(2) : 1;
    s.activeDays = Math.max(1, Object.keys(days).length);
    s.cacheHitPct = s.inAll > 0 ? Math.round((s.cRead / s.inAll) * 100) : 0;
    s.costPerSession = s.sessions > 0 ? s.cost / s.sessions : 0;
    s.costPerTurn = s.turns > 0 ? s.cost / s.turns : 0;
    s.turnsPerSession = s.sessions > 0 ? s.turns / s.sessions : 0;
    return s;
  }

  var portfolioStats = summarizeList(records);

  function selectWorkspace(wsName) {
    activeWorkspace = wsName || '';
    document.querySelectorAll('.ws-btn').forEach(function(b) {
      var bWs = b.getAttribute('data-ws') || '';
      b.classList.toggle('active', bWs === activeWorkspace);
    });
    render();
  }

  function aggregateAllVibes() {
    var keys = Object.keys(meta);
    var agg = {
      present: false,
      vibesRepoCount: 0,
      annotationsCount: 0,
      verifiedCount: 0,
      blobsCount: 0,
      attestationsCount: 0,
      iocRulesCount: 0,
      maxPrismRisk: 0,
      highRiskCount: 0,
      traceIncidents: 0,
      traceResolved: 0,
      decisions: 0,
      linesAdded: 0,
      linesRemoved: 0,
      filesTouchedCount: 0,
      manifestCounts: { environment: 0, reasoning: 0, command: 0, prompt: 0, decision: 0, total: 0 },
      prismBuckets: { low: 0, moderate: 0, high: 0, critical: 0 },
      fileHotspots: [],
      decisionRecords: [],
      incidentRecords: [],
      recentAnnotations: []
    };
    keys.forEach(function(k) {
      var v = meta[k] && meta[k].vibes;
      if (!v || !v.present) return;
      agg.present = true;
      agg.vibesRepoCount += 1;
      agg.annotationsCount += v.annotationsCount || 0;
      agg.verifiedCount += v.verifiedCount || 0;
      agg.blobsCount += v.blobsCount || 0;
      agg.attestationsCount += v.attestationsCount || 0;
      agg.iocRulesCount += v.iocRulesCount || 0;
      var mc = v.manifestCounts || {};
      agg.manifestCounts.environment += mc.environment || 0;
      agg.manifestCounts.reasoning += mc.reasoning || 0;
      agg.manifestCounts.command += mc.command || 0;
      agg.manifestCounts.prompt += mc.prompt || 0;
      agg.manifestCounts.decision += mc.decision || 0;
      agg.manifestCounts.total += mc.total || 0;
      if ((v.maxPrismRisk || 0) > agg.maxPrismRisk) agg.maxPrismRisk = v.maxPrismRisk;
      agg.highRiskCount += v.highRiskCount || 0;
      agg.traceIncidents += v.traceIncidents || 0;
      agg.traceResolved += v.traceResolved || 0;
      agg.decisions += v.decisions || 0;
      agg.linesAdded += v.linesAdded || 0;
      agg.linesRemoved += v.linesRemoved || 0;
      agg.filesTouchedCount += v.filesTouchedCount || 0;
      var pb = v.prismBuckets || {};
      agg.prismBuckets.low += pb.low || 0;
      agg.prismBuckets.moderate += pb.moderate || 0;
      agg.prismBuckets.high += pb.high || 0;
      agg.prismBuckets.critical += pb.critical || 0;
      (v.fileHotspots || []).forEach(function(h) {
        agg.fileHotspots.push(Object.assign({}, h, { file: k + ':' + h.file }));
      });
      (v.decisionRecords || []).forEach(function(d) {
        agg.decisionRecords.push(Object.assign({}, d, { id: k + '/' + d.id }));
      });
      (v.incidentRecords || []).forEach(function(inc) {
        agg.incidentRecords.push(Object.assign({}, inc, { iocId: k + ':' + inc.iocId }));
      });
      (v.recentAnnotations || []).forEach(function(a) {
        agg.recentAnnotations.push(Object.assign({}, a, { file: k + ':' + a.file }));
      });
    });
    if (!agg.present) return null;
    agg.fileHotspots.sort(function(a, b) { return (b.maxRisk - a.maxRisk) || ((b.linesAdded + b.linesRemoved) - (a.linesAdded + a.linesRemoved)); });
    agg.recentAnnotations.sort(function(a, b) { return String(b.timestamp || '').localeCompare(String(a.timestamp || '')); });
    return agg;
  }

  function resolveVibesData(wsKey) {
    if (demoVibesMode) return SAMPLE_VIBES;
    if (wsKey) {
      return (meta[wsKey] && meta[wsKey].vibes && meta[wsKey].vibes.present) ? meta[wsKey].vibes : null;
    }
    return aggregateAllVibes();
  }

  function renderVibesSection(wsKey) {
    var v = resolveVibesData(wsKey);
    var chip = el('vibes-status-chip');
    var demoBtn = el('vibes-demo-btn');
    var explainer = el('vibes-explainer');
    var activeBody = el('vibes-active-body');
    var adoptBanner = el('vibes-adopt-banner');
    var adoptWs = el('vibes-adopt-ws');
    var adoptCmd = el('vibes-adopt-cmd');
    var heading = el('vibes-heading');

    heading.textContent = wsKey
      ? ('VIBES (.ai-audit/) Provenance & PRISM Risk — ' + wsKey)
      : 'VIBES Protocol (.ai-audit/) Provenance & PRISM Risk — All Workspaces';

    if (adoptWs) adoptWs.textContent = wsKey || 'this workspace';
    if (adoptCmd) adoptCmd.textContent = 'vibecheck init --project-name ' + (wsKey || 'my-app') + ' --assurance-level high && vibes install-hooks && vibecheck verify';

    if (v && v.present) {
      chip.className = v.isDemo ? 'badge-chip warn' : 'badge-chip cyan';
      chip.textContent = v.isDemo
        ? '★ Interactive Reference VIBES (.ai-audit/) Forensics Active'
        : (v.vibesRepoCount ? ('● VIBES Active Across ' + v.vibesRepoCount + ' Workspaces') : ('● VIBES Active in ' + wsKey));
      demoBtn.textContent = v.isDemo ? 'Exit Reference Preview' : 'Preview Reference Dataset';
      explainer.innerHTML = '<strong>5-Pillar VIBES Deep Forensics Active:</strong> Showing line-range file attribution (<code>VIBES v1.1</code>), Ed25519 DSSE &amp; high-assurance attestation coverage (<code>VERIFY v1.0</code>), PRISM risk distribution &amp; trajectory (<code>PRISM v1.0</code>), content-addressed reasoning &amp; decisions (<code>EVOLVE v1.0</code>), and TRACE incident response (<code>TRACE v1.0</code>).';
      if (activeBody) activeBody.style.display = 'block';
      if (adoptBanner) adoptBanner.style.display = 'none';
    } else {
      chip.className = 'badge-chip warn';
      chip.textContent = '○ .ai-audit/ Not Initialized in ' + (wsKey || 'Workspace');
      demoBtn.textContent = 'Preview Reference VIBES Forensics';
      explainer.innerHTML = '<strong>Standard Telemetry Active for ' + (wsKey || 'Workspace') + ':</strong> Economics, cache ROI, trust boundaries, and session logs are active above and below. Initialize <strong><a href="https://www.itsavibe.ai" target="_blank" rel="noopener">VIBES (.ai-audit/)</a></strong> to add cryptographic file attribution and PRISM risk scoring.';
      if (activeBody) activeBody.style.display = 'none';
      if (adoptBanner) adoptBanner.style.display = 'flex';
      return;
    }

    var annCnt = v.annotationsCount || 0;
    var mc = v.manifestCounts || {};
    var mTot = mc.total || 0;
    var baseCnt = annCnt > 0 ? annCnt : (mTot > 0 ? mTot : 1);
    var verPct = Math.min(100, Math.round(((v.verifiedCount || 0) / baseCnt) * 100));
    el('vp-prov').textContent = annCnt > 0 ? (annCnt.toLocaleString() + ' annotations') : (mTot.toLocaleString() + ' manifest entries');
    el('vp-prov-sub').textContent = (mTot || v.blobsCount || 0).toLocaleString() + ' manifest entries · ' + (v.filesTouchedCount || 0) + ' files · v' + (v.standardVersion || '1.1');
    el('vp-verify').textContent = verPct + '% verified';
    el('vp-verify-sub').textContent = (v.attestationsCount || 0).toLocaleString() + ' attestations (' + String(v.configuredAssurance || 'high').toUpperCase() + ') · Guard locked';
    el('vp-prism').textContent = Number(v.maxPrismRisk || 0).toFixed(2) + ' max risk';
    el('vp-prism-sub').textContent = (v.highRiskCount || 0) + ' High/Critical (>= 0.60)';
    var rChains = mc.reasoning || 0;
    var cChains = mc.command || 0;
    el('vp-evolve').textContent = (v.decisions || 0) > 0 ? ((v.decisions || 0) + ' decisions') : (rChains > 0 ? (rChains.toLocaleString() + ' reasoning chains') : (((v.decisionRecords && v.decisionRecords.length) || 0) + ' records'));
    el('vp-evolve-sub').textContent = '+' + (v.linesAdded || 0).toLocaleString() + ' / -' + (v.linesRemoved || 0).toLocaleString() + ' LOC' + (cChains > 0 ? (' · ' + cChains.toLocaleString() + ' cmds') : '');
    el('vp-trace').textContent = (v.traceResolved || 0) + ' / ' + (v.traceIncidents || 0) + ' fixed';
    el('vp-trace-sub').textContent = (v.iocRulesCount || 0) + ' custom IoC rules' + (v.hasAuditDb ? ' · audit.db active' : '');

    var svgBox = el('vibes-svg');
    if (svgBox) {
      svgBox.textContent = '';
      var NS = 'http://www.w3.org/2000/svg';
      function node(t, a, p, txt) {
        var n = document.createElementNS(NS, t);
        for (var k in a) n.setAttribute(k, a[k]);
        if (txt != null) n.textContent = String(txt);
        if (p) p.appendChild(n);
        return n;
      }

      node('text', { x: 16, y: 22, fill: '#06b6d4', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, '1. PRISM v1.0 RISK HISTOGRAM');
      var pb = v.prismBuckets || {};
      var buckets = [
        ['Low (<0.30)', pb.low || 0, '#10b981'],
        ['Mod (0.30-0.59)', pb.moderate || 0, '#06b6d4'],
        ['High (0.60-0.79)', pb.high || 0, '#f59e0b'],
        ['Crit (>=0.80)', pb.critical || 0, '#ef4444']
      ];
      var maxBucket = Math.max(1, pb.low || 0, pb.moderate || 0, pb.high || 0, pb.critical || 0);
      buckets.forEach(function(b, idx) {
        var y = 46 + idx * 46;
        node('text', { x: 16, y: y + 14, fill: '#ecf3ef', 'font-size': 10.5, 'font-family': 'monospace' }, svgBox, b[0]);
        node('rect', { x: 135, y: y, width: 125, height: 18, rx: 4, fill: '#101814', stroke: '#1d2b23' }, svgBox);
        var w = Math.max(4, Math.round((b[1] / maxBucket) * 125));
        if (b[1] > 0) node('rect', { x: 135, y: y, width: w, height: 18, rx: 4, fill: b[2] }, svgBox);
        node('text', { x: 268, y: y + 13, fill: b[2], 'font-size': 11, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, String(b[1]));
      });

      node('line', { x1: 305, y1: 12, x2: 305, y2: 240, stroke: '#1d2b23', 'stroke-dasharray': '4,4' }, svgBox);
      node('text', { x: 320, y: 22, fill: '#f59e0b', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, '2. PRISM TURN TRAJECTORY (0.60 GATE)');
      node('rect', { x: 320, y: 38, width: 275, height: 182, rx: 8, fill: '#0b110e', stroke: '#1d2b23' }, svgBox);
      var gateY = 38 + Math.round((1 - 0.6) * 162) + 10;
      node('line', { x1: 326, y1: gateY, x2: 589, y2: gateY, stroke: '#f59e0b', 'stroke-dasharray': '3,3', 'stroke-width': 1.2 }, svgBox);
      node('text', { x: 332, y: gateY - 5, fill: '#f59e0b', 'font-size': 9.5, 'font-family': 'monospace' }, svgBox, '0.60 /neckbeard-review priority gate');

      var anns = (v.recentAnnotations && v.recentAnnotations.length) ? v.recentAnnotations.slice(0, 12).reverse() : [];
      if (anns.length > 0) {
        var pts = [];
        anns.forEach(function(a, idx) {
          var r = typeof a.riskScore === 'number' ? a.riskScore : 0.12;
          var px = 340 + Math.round((idx / Math.max(1, anns.length - 1)) * 235);
          var py = 48 + Math.round((1 - Math.min(1, Math.max(0, r))) * 156);
          pts.push(px + ',' + py);
          node('circle', { cx: px, cy: py, r: 4, fill: r >= 0.8 ? '#ef4444' : r >= 0.6 ? '#f59e0b' : '#10b981' }, svgBox);
        });
        if (pts.length > 1) node('polyline', { points: pts.join(' '), fill: 'none', stroke: '#06b6d4', 'stroke-width': 1.8 }, svgBox);
      }

      node('line', { x1: 612, y1: 12, x2: 612, y2: 240, stroke: '#1d2b23', 'stroke-dasharray': '4,4' }, svgBox);
      node('text', { x: 626, y: 22, fill: '#10b981', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, '3. ATTRIBUTED FILE HOTSPOTS');
      var hotspots = (v.fileHotspots && v.fileHotspots.length) ? v.fileHotspots.slice(0, 5) : [{ file: '(Session-level provenance only)', annotations: annCnt, linesAdded: 0, linesRemoved: 0, maxRisk: v.maxPrismRisk || 0, verified: true }];
      hotspots.forEach(function(h, idx) {
        var y = 44 + idx * 39;
        var riskColor = h.maxRisk >= 0.8 ? '#ef4444' : h.maxRisk >= 0.6 ? '#f59e0b' : h.maxRisk >= 0.3 ? '#06b6d4' : '#10b981';
        node('text', { x: 626, y: y + 13, fill: '#ecf3ef', 'font-size': 10.5, 'font-family': 'monospace' }, svgBox, (h.verified ? '✓ ' : '○ ') + h.file.slice(-24));
        node('rect', { x: 790, y: y + 2, width: 65, height: 13, rx: 4, fill: '#101814', stroke: '#1d2b23' }, svgBox);
        var rw = Math.max(4, Math.round(Math.min(1, Math.max(0.08, h.maxRisk || 0.08)) * 65));
        node('rect', { x: 790, y: y + 2, width: rw, height: 13, rx: 4, fill: riskColor }, svgBox);
        node('text', { x: 862, y: y + 12, fill: riskColor, 'font-size': 10, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, '+' + h.linesAdded + '/-' + h.linesRemoved);
      });
    }

    var decList = el('vibes-decisions-list');
    decList.textContent = '';
    var decs = (v.decisionRecords && v.decisionRecords.length) ? v.decisionRecords : [{ id: 'GUARD', title: 'Immutable .ai-audit/{manifest.json,annotations.jsonl,blobs/,attestations/} protected by hooks/guard.js', status: 'armed' }];
    decs.slice(0, 6).forEach(function(d) {
      var row = document.createElement('div');
      row.textContent = '[' + d.id + '] ' + d.title + ' (' + d.status + ')';
      decList.appendChild(row);
    });

    var incList = el('vibes-incidents-list');
    incList.textContent = '';
    var incs = (v.incidentRecords && v.incidentRecords.length) ? v.incidentRecords : [{ iocId: 'READY', status: 'clean', summary: '0 unresolved TRACE incidents or unverified high-risk PRISM edits in ' + (wsKey || 'portfolio') }];
    incs.slice(0, 6).forEach(function(inc) {
      var row = document.createElement('div');
      row.textContent = '[' + inc.iocId + ' · ' + inc.status.toUpperCase() + '] ' + inc.summary;
      incList.appendChild(row);
    });

    var annRows = el('vibes-annotations-rows');
    if (annRows) {
      annRows.textContent = '';
      (v.recentAnnotations || []).slice(0, 12).forEach(function(a) {
        var tr = document.createElement('tr');
        var riskTxt = a.riskScore != null ? a.riskScore.toFixed(2) : '0.00';
        var fullTxt = a.fullText || a.summary || 'Annotated turn';
        tr.className = 'clickable-row';
        tr.title = fullTxt + '\n(Click row to expand full provenance text)';
        var dTr = document.createElement('tr');
        dTr.style.display = 'none';
        dTr.style.background = '#070c0a';
        var dTd = document.createElement('td');
        dTd.colSpan = 7;
        dTd.style.padding = '12px 16px';
        var box = document.createElement('div');
        box.style.cssText = 'background:#0b110e;border:1px solid var(--nb-cyan);border-radius:10px;padding:12px 14px;font:400 12px/1.55 var(--nb-mono);color:var(--nb-text);white-space:pre-wrap;word-break:break-word;max-height:260px;overflow-y:auto';
        box.textContent = fullTxt;
        dTd.appendChild(box);
        dTr.appendChild(dTd);
        var chev = null;
        [a.timestamp || '–', a.sessionId || '–', a.file || '–', '+' + (a.linesAdded || 0) + ' / -' + (a.linesRemoved || 0), 'PRISM ' + riskTxt, a.verified ? '✓ Attested' : '○ Recorded', '▸ ' + (a.summary || 'Annotated turn')].forEach(function(val, idx) {
          var td = document.createElement('td');
          if (idx === 6) { td.className = 'task-col'; chev = td; }
          td.textContent = val;
          tr.appendChild(td);
        });
        tr.onclick = function() {
          var open = dTr.style.display !== 'none';
          dTr.style.display = open ? 'none' : 'table-row';
          if (chev) chev.textContent = (open ? '▸ ' : '▾ ') + (a.summary || 'Annotated turn');
        };
        annRows.appendChild(tr);
        annRows.appendChild(dTr);
      });
    }
  }

  function renderEconomicsAndVelocity(filtered, wsStats) {
    el('econ-title').textContent = activeWorkspace
      ? ('Workspace Economics & Benchmark vs. All Workspaces — ' + activeWorkspace)
      : 'Front-and-Center Economics: Spend vs. Prompt-Cache Savings & All-Workspaces Ranking';
    el('econ-badge').textContent = activeWorkspace
      ? (activeWorkspace + ': ' + fmtUsd(wsStats.cost) + ' (' + (portfolioStats.cost > 0 ? ((wsStats.cost / portfolioStats.cost) * 100).toFixed(1) : '0') + '% of ' + fmtUsd(portfolioStats.cost) + ' total)')
      : ('Portfolio Total: ' + fmtUsd(portfolioStats.cost) + ' Spend · ' + fmtUsd(portfolioStats.saved) + ' Saved by Cache');
    el('model-table-title').textContent = activeWorkspace
      ? ('MODEL & CACHE ECONOMICS — ' + activeWorkspace.toUpperCase())
      : 'MODEL & CACHE ECONOMICS — ALL WORKSPACES';

    var velBox = el('velocity-svg');
    if (velBox) {
      velBox.textContent = '';
      var NS = 'http://www.w3.org/2000/svg';
      function node(t, a, p, txt) {
        var n = document.createElementNS(NS, t);
        for (var k in a) n.setAttribute(k, a[k]);
        if (txt != null) n.textContent = String(txt);
        if (p) p.appendChild(n);
        return n;
      }

      // LEFT HALF (x: 16..470): Timeline of Actual Spend ($ Emerald) vs. Prompt-Cache Savings ($ Cyan)
      var byDay = {};
      filtered.forEach(function(r) {
        var day = String(r.timestampIso || '').slice(0, 10) || 'Recent';
        if (!byDay[day]) byDay[day] = { day: day, cost: 0, saved: 0, sessions: 0 };
        byDay[day].cost += r.totalCostUsd || 0;
        byDay[day].saved += estimateCacheSavingsUsd(r);
        byDay[day].sessions += 1;
      });
      var days = Object.keys(byDay).sort().slice(-10);
      node('text', { x: 16, y: 20, fill: '#10b981', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, velBox, '1. DAILY SPEND ($ EMERALD) VS. CACHE SAVED ($ CYAN) — ' + (activeWorkspace || 'ALL WORKSPACES'));
      var maxVal = 0.01;
      days.forEach(function(d) {
        if (byDay[d].cost > maxVal) maxVal = byDay[d].cost;
        if (byDay[d].saved > maxVal) maxVal = byDay[d].saved;
      });

      days.forEach(function(d, idx) {
        var info = byDay[d];
        var gx = 20 + idx * 45;
        var hCost = Math.max(4, Math.round((info.cost / maxVal) * 140));
        var hSaved = Math.max(4, Math.round((info.saved / maxVal) * 140));
        node('rect', { x: gx, y: 185 - hCost, width: 15, height: hCost, rx: 3, fill: '#10b981' }, velBox);
        node('rect', { x: gx + 17, y: 185 - hSaved, width: 15, height: hSaved, rx: 3, fill: '#06b6d4' }, velBox);
        node('text', { x: gx + 16, y: 202, fill: '#8b9d92', 'font-size': 9, 'text-anchor': 'middle', 'font-family': 'monospace' }, velBox, d.slice(5));
        node('text', { x: gx + 16, y: 216, fill: '#10b981', 'font-size': 8.5, 'text-anchor': 'middle', 'font-family': 'monospace' }, velBox, '$' + info.cost.toFixed(0));
      });

      node('line', { x1: 480, y1: 10, x2: 480, y2: 225, stroke: '#1d2b23', 'stroke-dasharray': '4,4' }, velBox);

      // RIGHT HALF (x: 498..948):
      // - If a workspace is selected: Benchmark Comparison Bars (Selected Workspace vs All-Workspaces Average)
      // - If All Workspaces is selected: Top 6 Workspaces by Spend & Cache Hit %
      if (activeWorkspace) {
        node('text', { x: 498, y: 20, fill: '#06b6d4', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, velBox, '2. ' + activeWorkspace.toUpperCase() + ' (EMERALD) VS. ALL-WORKSPACES AVG (SLATE)');
        var metrics = [
          ['Cost / Session', wsStats.costPerSession, portfolioStats.costPerSession, function(v) { return '$' + v.toFixed(2); }],
          ['Cost / Turn', wsStats.costPerTurn, portfolioStats.costPerTurn, function(v) { return '$' + v.toFixed(2); }],
          ['Cache Hit Rate', wsStats.cacheHitPct, portfolioStats.cacheHitPct, function(v) { return Math.round(v) + '%'; }],
          ['Turns / Session', wsStats.turnsPerSession, portfolioStats.turnsPerSession, function(v) { return v.toFixed(1) + 't'; }]
        ];
        metrics.forEach(function(m, idx) {
          var y = 44 + idx * 45;
          var mx = Math.max(0.01, m[1], m[2]);
          var wWs = Math.max(6, Math.round((m[1] / mx) * 190));
          var wAll = Math.max(6, Math.round((m[2] / mx) * 190));
          node('text', { x: 498, y: y + 12, fill: '#ecf3ef', 'font-size': 10.5, 'font-family': 'monospace' }, velBox, m[0]);
          // Workspace bar
          node('rect', { x: 625, y: y, width: wWs, height: 11, rx: 3, fill: '#10b981' }, velBox);
          node('text', { x: 632 + wWs, y: y + 10, fill: '#10b981', 'font-size': 10, 'font-weight': 700, 'font-family': 'monospace' }, velBox, activeWorkspace.slice(0, 12) + ': ' + m[3](m[1]));
          // All Workspaces Avg bar
          node('rect', { x: 625, y: y + 15, width: wAll, height: 10, rx: 3, fill: '#55665c' }, velBox);
          node('text', { x: 632 + wAll, y: y + 24, fill: '#8b9d92', 'font-size': 9.5, 'font-family': 'monospace' }, velBox, 'All Avg: ' + m[3](m[2]));
        });
      } else {
        node('text', { x: 498, y: 20, fill: '#f59e0b', 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, velBox, '2. TOP WORKSPACES BY SPEND & PROMPT-CACHE EFFICIENCY');
        var rMapTop = {};
        records.forEach(function(r) {
          var p = r.projectName || 'workspace';
          if (!rMapTop[p]) rMapTop[p] = { name: p, cost: 0, saved: 0, cRead: 0, tIn: 0 };
          rMapTop[p].cost += r.totalCostUsd || 0;
          rMapTop[p].saved += estimateCacheSavingsUsd(r);
          var tb = r.tokenBuckets || {};
          rMapTop[p].cRead += tb.cachedReadTokens || 0;
          rMapTop[p].tIn += (tb.promptTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
        });
        var topList = Object.values(rMapTop).sort(function(a, b) { return b.cost - a.cost; }).slice(0, 6);
        var maxRepoCost = Math.max(0.01, (topList[0] && topList[0].cost) || 1);
        topList.forEach(function(rp, idx) {
          var y = 42 + idx * 31;
          var bw = Math.max(6, Math.round((rp.cost / maxRepoCost) * 185));
          var ch = rp.tIn > 0 ? Math.round((rp.cRead / rp.tIn) * 100) : 0;
          node('text', { x: 498, y: y + 13, fill: '#ecf3ef', 'font-size': 10.5, 'font-family': 'monospace' }, velBox, rp.name.slice(0, 18));
          node('rect', { x: 635, y: y + 1, width: bw, height: 15, rx: 4, fill: '#10b981' }, velBox);
          node('text', { x: 642 + bw, y: y + 13, fill: '#ecf3ef', 'font-size': 10, 'font-weight': 700, 'font-family': 'monospace' }, velBox, fmtUsd(rp.cost) + ' (' + ch + '% cache)');
        });
      }
    }

    // 2. Per-Workspace vs All-Workspaces Economics Matrix Table
    var repoMap = {};
    records.forEach(function(r) {
      var p = r.projectName || 'workspace';
      if (!repoMap[p]) repoMap[p] = { name: p, list: [], sessions: 0, turns: 0, dur: 0, cost: 0, saved: 0, cacheRead: 0, totalIn: 0 };
      repoMap[p].list.push(r);
      repoMap[p].sessions += 1;
      repoMap[p].turns += r.turnCount || 1;
      repoMap[p].dur += r.activeDurationMs || 0;
      repoMap[p].cost += r.totalCostUsd || 0;
      repoMap[p].saved += estimateCacheSavingsUsd(r);
      var tb = r.tokenBuckets || {};
      repoMap[p].cacheRead += tb.cachedReadTokens || 0;
      repoMap[p].totalIn += (tb.promptTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
    });

    var repoRows = el('repo-scorecard-rows');
    if (repoRows) {
      repoRows.textContent = '';
      // Always pin All Workspaces Baseline row at the top for instant comparison
      var baseTr = document.createElement('tr');
      baseTr.className = 'clickable-row baseline-row' + (activeWorkspace === '' ? ' selected-row' : '');
      [
        '★ ALL WORKSPACES (' + Object.keys(repoMap).length + ')',
        portfolioStats.sessions + ' / ' + portfolioStats.turns,
        fmtDur(portfolioStats.dur) + ' agent / ' + fmtDur(portfolioStats.wallDur) + ' wall (' + portfolioStats.parallelFactor + 'x)',
        portfolioStats.cacheHitPct + '%',
        fmtUsd(portfolioStats.saved),
        fmtUsd(portfolioStats.cost),
        '100.0%',
        'Portfolio'
      ].forEach(function(v, idx) {
        var td = document.createElement('td');
        if (idx === 0) td.className = 'task-col';
        td.textContent = v;
        baseTr.appendChild(td);
      });
      baseTr.onclick = function() { selectWorkspace(''); };
      repoRows.appendChild(baseTr);

      var sortedRepos = Object.values(repoMap).sort(function(a, b) {
        if (activeWorkspace && a.name === activeWorkspace) return -1;
        if (activeWorkspace && b.name === activeWorkspace) return 1;
        return b.cost - a.cost;
      });

      sortedRepos.slice(0, 45).forEach(function(rp) {
        var tr = document.createElement('tr');
        tr.className = 'clickable-row' + (rp.name === activeWorkspace ? ' selected-row' : '');
        var cHit = rp.totalIn > 0 ? Math.round((rp.cacheRead / rp.totalIn) * 100) + '%' : '0%';
        var sharePct = portfolioStats.cost > 0 ? (rp.cost / portfolioStats.cost) * 100 : 0;
        var wm = meta[rp.name] || {};
        var statusTag = (wm.vibes && wm.vibes.present ? '● VIBES' : '○ Std');
        var rpSt = summarizeList(rp.list);
        [
          (rp.name === activeWorkspace ? '▶ ' : '') + rp.name,
          rp.sessions + ' / ' + rp.turns,
          fmtDur(rp.dur) + ' / ' + fmtDur(rpSt.wallDur) + ' (' + rpSt.activeDays + 'd)',
          cHit,
          fmtUsd(rp.saved),
          fmtUsd(rp.cost)
        ].forEach(function(v, idx) {
          var td = document.createElement('td');
          if (idx === 0) td.className = 'task-col';
          td.textContent = v;
          tr.appendChild(td);
        });

        var shareTd = document.createElement('td');
        shareTd.innerHTML = '<span class="share-bar-wrap"><span class="share-bar-bg"><span class="share-bar-fill" style="width:' + Math.min(100, Math.max(3, sharePct)).toFixed(0) + '%"></span></span><span>' + sharePct.toFixed(1) + '%</span></span>';
        tr.appendChild(shareTd);

        var vTd = document.createElement('td');
        vTd.textContent = statusTag;
        tr.appendChild(vTd);

        tr.onclick = function() { selectWorkspace(rp.name); };
        repoRows.appendChild(tr);
      });
    }

    // 3. Per-Model & Prompt-Cache Economics Table (Dynamically Filtered to Selected Workspace!)
    var modMap = {};
    filtered.forEach(function(r) {
      var m = r.modelId || 'unknown';
      if (!modMap[m]) modMap[m] = { model: m, sessions: 0, turns: 0, inTok: 0, outTok: 0, cacheRead: 0, saved: 0, cost: 0 };
      modMap[m].sessions += 1;
      modMap[m].turns += r.turnCount || 1;
      var tb = r.tokenBuckets || {};
      modMap[m].inTok += (tb.promptTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
      modMap[m].outTok += tb.completionTokens || 0;
      modMap[m].cacheRead += tb.cachedReadTokens || 0;
      modMap[m].saved += estimateCacheSavingsUsd(r);
      modMap[m].cost += r.totalCostUsd || 0;
    });
    var modRows = el('model-econ-rows');
    if (modRows) {
      modRows.textContent = '';
      Object.values(modMap).sort(function(a, b) { return b.cost - a.cost; }).forEach(function(mm) {
        var tr = document.createElement('tr');
        var cHit = mm.inTok > 0 ? Math.round((mm.cacheRead / mm.inTok) * 100) + '%' : '0%';
        [mm.model, mm.sessions + ' / ' + mm.turns, fmtTokens(mm.inTok), fmtTokens(mm.outTok), cHit, fmtUsd(mm.saved), fmtUsd(mm.cost)].forEach(function(v) {
          var td = document.createElement('td');
          td.textContent = v;
          tr.appendChild(td);
        });
        modRows.appendChild(tr);
      });
    }
  }

  function resolveBoundariesForView(wsKey) {
    if (wsKey) {
      var wm = meta[wsKey] || {};
      return {
        boundaries: wm.boundaries || { external: {}, internal: {} },
        drift: wm.driftAdded || []
      };
    }
    var aggExt = { ingress: [], egress: [], supply: [] };
    var aggInt = { auth: [], data: [], exec: [], ai: [] };
    var aggDrift = [];
    Object.keys(meta).forEach(function(k) {
      var wm = meta[k] || {};
      var b = wm.boundaries || {};
      var e = b.external || {}, i = b.internal || {};
      ['ingress', 'egress', 'supply'].forEach(function(cat) {
        (e[cat] || []).forEach(function(item) {
          if (aggExt[cat].length < 12) aggExt[cat].push(k + ':' + item);
        });
      });
      ['auth', 'data', 'exec', 'ai'].forEach(function(cat) {
        (i[cat] || []).forEach(function(item) {
          if (aggInt[cat].length < 12) aggInt[cat].push(k + ':' + item);
        });
      });
      (wm.driftAdded || []).forEach(function(d) { aggDrift.push(k + ':' + d); });
    });
    return { boundaries: { external: aggExt, internal: aggInt }, drift: aggDrift };
  }

  var EXT_SINK_META = {
    'http-in': { label: 'HTTP / API / IPC Ingress', secDomain: 'PERIMETER INGRESS', archLayer: 'API / IPC Transport', color: '#f59e0b' },
    'webhook-in': { label: 'Webhook / Queue Ingress', secDomain: 'PERIMETER INGRESS', archLayer: 'Event / Queue Consumer', color: '#fb923c' },
    'cli-in': { label: 'CLI / Stdin Ingress', secDomain: 'PERIMETER INGRESS', archLayer: 'CLI / Stdin Adapter', color: '#facc15' },
    'http-out': { label: 'Outbound HTTP / SSRF Egress', secDomain: 'NETWORK EGRESS', archLayer: 'External HTTP Client', color: '#06b6d4' },
    'ci': { label: 'CI / Supply-Chain Workflows', secDomain: 'SUPPLY CHAIN', archLayer: 'Build & Release Pipeline', color: '#a855f7' }
  };

  var INT_SINK_META = {
    'auth': { label: 'Object Auth & Identity', secDomain: 'IDENTITY & AUTH', archLayer: 'Auth & Access Control', color: '#10b981' },
    'sql': { label: 'SQL / Database Queries', secDomain: 'DATA & QUERY', archLayer: 'Relational / SQLite Store', color: '#2dd4bf' },
    'fs': { label: 'Filesystem & Path I/O', secDomain: 'OS FILESYSTEM', archLayer: 'Filesystem & Blob Store', color: '#38bdf8' },
    'serde': { label: 'Deserialization & Parsers', secDomain: 'UNTRUSTED PARSER', archLayer: 'Wire & Schema Codec', color: '#818cf8' },
    'proc': { label: 'Subprocess / Thread / Shell', secDomain: 'PROCESS & OS EXEC', archLayer: 'Subprocess & Worker Runtime', color: '#fb7185' },
    'crypto': { label: 'Cryptography & Signing', secDomain: 'CRYPTO & SIGNING', archLayer: 'Cryptographic Engine', color: '#c084fc' },
    'env': { label: 'Secrets & Env Privilege', secDomain: 'SECRET & ENV', archLayer: 'Environment Configuration', color: '#fbbf24' },
    'ai': { label: 'LLM / Agent / MCP Sandbox', secDomain: 'AI / AGENT SANDBOX', archLayer: 'AI / Model / MCP Runtime', color: '#a3e635' }
  };

  var topoRealm = 'security';
  var topoSubtype = 'all';

  var REALM_SUBTYPES = {
    security: [
      { id: 'all', label: 'All Security Boundaries', desc: 'Complete threat-boundary topology across external untrusted entry points, privilege bridges, and internal kernel/system sinks.', match: function() { return true; } },
      { id: 'bridges', label: '⚡ Cross-Boundary Bridges [ext➔int]', desc: 'High-priority files that accept external untrusted input [ext] and directly invoke internal privileged sinks [int].', match: function(f) { return f.extSinks.length > 0 && f.intSinks.length > 0; } },
      { id: 'auth-crypto', label: '🔐 Auth, Identity & Crypto', desc: 'Authentication, server-side object authorization, Ed25519/DSSE/Cosign signature verification, and cryptographic hashing/encryption boundaries.', match: function(f) { return f.intSinks.indexOf('auth') >= 0 || f.intSinks.indexOf('crypto') >= 0; } },
      { id: 'proc-sys', label: '⚙️ Process, Thread & OS System', desc: 'Child process spawning, shell/eval execution, filesystem path/symlink boundaries, and environment secret privilege boundaries.', match: function(f) { return f.intSinks.indexOf('proc') >= 0 || f.intSinks.indexOf('fs') >= 0 || f.intSinks.indexOf('env') >= 0; } },
      { id: 'input-data', label: '🧬 Untrusted Input, Parsers & SQL', desc: 'External ingress (HTTP, CLI, Webhooks) flowing into structured deserialization parsers (JSON, TOML, YAML, Protobuf) and SQL database queries.', match: function(f) { return f.extSinks.indexOf('http-in') >= 0 || f.extSinks.indexOf('cli-in') >= 0 || f.extSinks.indexOf('webhook-in') >= 0 || f.intSinks.indexOf('serde') >= 0 || f.intSinks.indexOf('sql') >= 0; } },
      { id: 'ai-supply', label: '🤖 AI Sandbox, Egress & Supply Chain', desc: 'Prompt-injection / LLM / MCP tool boundaries, outbound HTTP/SSRF network egress, and CI/CD supply-chain workflow boundaries.', match: function(f) { return f.intSinks.indexOf('ai') >= 0 || f.extSinks.indexOf('http-out') >= 0 || f.extSinks.indexOf('ci') >= 0; } }
    ],
    architecture: [
      { id: 'all', label: 'Full Architecture Blueprint', desc: 'End-to-end system architecture showing how interface adapters connect to project modules/crates and storage/runtime backends.', match: function() { return true; } },
      { id: 'interfaces', label: '🔌 Interface & Transport Layer', desc: 'External entry interfaces: HTTP/API controllers, Electron/Tauri IPC handlers, CLI argument parsers, and webhook/queue consumers.', match: function(f) { return f.extSinks.indexOf('http-in') >= 0 || f.extSinks.indexOf('cli-in') >= 0 || f.extSinks.indexOf('webhook-in') >= 0; } },
      { id: 'core-services', label: '📦 Core Subsystems & Orchestrators', desc: 'Multi-capability service modules and cross-layer orchestrators that coordinate 2+ boundary capabilities.', match: function(f) { return (f.extSinks.length + f.intSinks.length) >= 2; } },
      { id: 'persistence', label: '🗄️ Storage, State & Wire Schemas', desc: 'Data persistence and state management modules: SQL/SQLite databases, filesystem/WAL/blob stores, and wire/schema serialization.', match: function(f) { return f.intSinks.indexOf('sql') >= 0 || f.intSinks.indexOf('fs') >= 0 || f.intSinks.indexOf('serde') >= 0; } },
      { id: 'runtime-ext', label: '🚀 Workers, Crypto, AI & External APIs', desc: 'Background subprocess workers, cryptographic engines, AI/LLM/MCP integrations, outbound HTTP clients, and CI build pipelines.', match: function(f) { return f.intSinks.indexOf('proc') >= 0 || f.intSinks.indexOf('crypto') >= 0 || f.intSinks.indexOf('ai') >= 0 || f.extSinks.indexOf('http-out') >= 0 || f.extSinks.indexOf('ci') >= 0; } }
    ]
  };

  function sinkGuidanceForFile(f) {
    var tips = [];
    if (f.extSinks.length > 0 && f.intSinks.length > 0) tips.push('⚡ Cross-Boundary Bridge: Parse and validate untrusted [' + f.extSinks.join(', ') + '] input once at the edge before reaching [' + f.intSinks.join(', ') + ']; fail closed on any error.');
    if (f.intSinks.indexOf('auth') >= 0) tips.push('🔐 Auth Boundary: Authorize object ownership on the server on every request; logged-in session state alone is not sufficient.');
    if (f.intSinks.indexOf('sql') >= 0) tips.push('🗄️ SQL Boundary: Use parameterized queries only and enforce bounded LIMIT clauses sized to the project load target.');
    if (f.intSinks.indexOf('proc') >= 0) tips.push('⚙️ Process Boundary: Invoke child processes with argument arrays (execFileSync / spawnSync / Command::new().args()), never shell-interpolated strings.');
    if (f.intSinks.indexOf('fs') >= 0) tips.push('📂 Filesystem Boundary: Canonicalize paths (realpath) and reject symlink escapes before checking the workspace root prefix.');
    if (f.intSinks.indexOf('serde') >= 0) tips.push('🧬 Deserialization Boundary: Enforce strict schema/type validation and payload byte limits before parsing untrusted input.');
    if (f.intSinks.indexOf('crypto') >= 0) tips.push('🔑 Crypto Boundary: Verify signatures/hashes in constant time and never log or echo secret key material.');
    if (f.extSinks.indexOf('http-out') >= 0) tips.push('🌐 Egress Boundary: Enforce an explicit host allow-list and request timeout on any outbound URL derived from input.');
    if (f.intSinks.indexOf('ai') >= 0) tips.push('🤖 AI / Agent Boundary: Treat model output, retrieved documents, and tool results as untrusted input; never let them choose a shell command, path, or SQL query.');
    if (!tips.length) tips.push('✓ Verify boundary inputs and failure paths stay consistent under retry.');
    return tips;
  }

  function classifyArchModuleRole(mn) {
    var eK = Object.keys(mn.extCounts), iK = Object.keys(mn.intCounts);
    if (eK.indexOf('ci') >= 0 && eK.length === 1 && iK.length === 0) return { tag: 'CI / Build Pipeline', color: '#a855f7' };
    if (mn.bridgeCount > 0) return { tag: 'Gateway / Service Bridge', color: '#10b981' };
    if (eK.length > 0) return { tag: 'Interface / Transport Adapter', color: '#f59e0b' };
    if (iK.indexOf('sql') >= 0 || iK.indexOf('fs') >= 0 || iK.indexOf('serde') >= 0) return { tag: 'Storage & Schema Layer', color: '#38bdf8' };
    if (iK.indexOf('auth') >= 0 || iK.indexOf('crypto') >= 0) return { tag: 'Security & Crypto Core', color: '#c084fc' };
    if (iK.indexOf('proc') >= 0 || iK.indexOf('ai') >= 0) return { tag: 'Runtime / Agent Worker', color: '#fb7185' };
    return { tag: 'Internal Subsystem', color: '#8b9d92' };
  }

  function moduleNameForFile(filePath, isAllWorkspaces) {
    if (isAllWorkspaces) {
      var colonIdx = filePath.indexOf(':');
      if (colonIdx > 0) return filePath.slice(0, colonIdx);
    }
    var parts = filePath.split('/');
    if (parts.length <= 1) return '(root)';
    if (parts[0] === '.github' && parts[1] === 'workflows') return '.github/workflows';
    if ((parts[0] === 'packages' || parts[0] === 'crates' || parts[0] === 'apps' || parts[0] === 'hooks' || parts[0] === 'src') && parts.length >= 3) {
      return parts[0] + '/' + parts[1];
    }
    return parts[0];
  }

  function buildProjectTopologyModel(wsKey, subMatcher) {
    var resolved = resolveBoundariesForView(wsKey);
    var ext = resolved.boundaries.external || {};
    var int = resolved.boundaries.internal || {};
    var driftSet = new Set(resolved.drift || []);
    var isAll = !wsKey;

    var fileMap = {};
    function recordEntry(rawEntry, tier) {
      var arrow = rawEntry.indexOf('->');
      if (arrow < 0) return;
      var file = rawEntry.slice(0, arrow).trim();
      var tags = rawEntry.slice(arrow + 2).split(',').map(function(t) { return t.trim(); }).filter(Boolean);
      if (!fileMap[file]) {
        fileMap[file] = {
          file: file,
          module: moduleNameForFile(file, isAll),
          extSinks: [],
          intSinks: [],
          isDrift: false
        };
      }
      if (driftSet.has(rawEntry)) fileMap[file].isDrift = true;
      tags.forEach(function(tag) {
        if (tier === 'ext') {
          if (fileMap[file].extSinks.indexOf(tag) < 0) fileMap[file].extSinks.push(tag);
        } else {
          if (fileMap[file].intSinks.indexOf(tag) < 0) fileMap[file].intSinks.push(tag);
        }
      });
    }

    ['ingress', 'egress', 'supply'].forEach(function(k) {
      (ext[k] || []).forEach(function(e) { recordEntry(e, 'ext'); });
    });
    ['auth', 'data', 'exec', 'ai'].forEach(function(k) {
      (int[k] || []).forEach(function(e) { recordEntry(e, 'int'); });
    });

    var allFiles = Object.values(fileMap);
    var files = subMatcher ? allFiles.filter(subMatcher) : allFiles;
    var extNodesMap = {};
    var intNodesMap = {};
    var modNodesMap = {};

    files.forEach(function(f) {
      if (!modNodesMap[f.module]) {
        modNodesMap[f.module] = {
          name: f.module,
          files: [],
          bridgeCount: 0,
          extCounts: {},
          intCounts: {},
          extTotal: 0,
          intTotal: 0
        };
      }
      var mNode = modNodesMap[f.module];
      mNode.files.push(f);
      if (f.extSinks.length > 0 && f.intSinks.length > 0) mNode.bridgeCount += 1;

      f.extSinks.forEach(function(s) {
        if (!extNodesMap[s]) {
          var metaInfo = EXT_SINK_META[s] || { label: s, secDomain: 'EXTERNAL', archLayer: 'External Interface', color: '#f59e0b' };
          extNodesMap[s] = { sink: s, label: metaInfo.label, secDomain: metaInfo.secDomain, archLayer: metaInfo.archLayer, color: metaInfo.color, files: [], modules: {} };
        }
        extNodesMap[s].files.push(f.file);
        extNodesMap[s].modules[f.module] = (extNodesMap[s].modules[f.module] || 0) + 1;
        mNode.extCounts[s] = (mNode.extCounts[s] || 0) + 1;
        mNode.extTotal += 1;
      });

      f.intSinks.forEach(function(s) {
        if (!intNodesMap[s]) {
          var metaInfo = INT_SINK_META[s] || { label: s, secDomain: 'INTERNAL', archLayer: 'Internal Capability', color: '#10b981' };
          intNodesMap[s] = { sink: s, label: metaInfo.label, secDomain: metaInfo.secDomain, archLayer: metaInfo.archLayer, color: metaInfo.color, files: [], modules: {} };
        }
        intNodesMap[s].files.push(f.file);
        intNodesMap[s].modules[f.module] = (intNodesMap[s].modules[f.module] || 0) + 1;
        mNode.intCounts[s] = (mNode.intCounts[s] || 0) + 1;
        mNode.intTotal += 1;
      });
    });

    var extNodes = Object.values(extNodesMap).sort(function(a, b) { return b.files.length - a.files.length; });
    var intNodes = Object.values(intNodesMap).sort(function(a, b) { return b.files.length - a.files.length; });
    var modNodes = Object.values(modNodesMap).sort(function(a, b) {
      return (b.bridgeCount - a.bridgeCount) || (b.files.length - a.files.length);
    }).slice(0, 10);

    return {
      allFiles: allFiles,
      files: files,
      extNodes: extNodes,
      modNodes: modNodes,
      intNodes: intNodes,
      drift: resolved.drift || []
    };
  }

  function renderTopology(wsKey) {
    var isSec = topoRealm === 'security';
    var subList = REALM_SUBTYPES[topoRealm] || REALM_SUBTYPES.security;
    var activeSub = subList.find(function(s) { return s.id === topoSubtype; }) || subList[0];
    topoSubtype = activeSub.id;

    var baseTopo = buildProjectTopologyModel(wsKey, null);
    var topo = buildProjectTopologyModel(wsKey, activeSub.match);

    el('topo-heading').textContent = (isSec ? '🛡️ Security Trust-Boundary Isolation' : '🏗️ System Architecture & Module Flow') + ' — ' + (wsKey || 'All Workspaces');

    document.querySelectorAll('#topo-realm-bar [data-realm]').forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-realm') === topoRealm);
      b.onclick = function() {
        topoRealm = b.getAttribute('data-realm');
        topoSubtype = 'all';
        renderTopology(activeWorkspace);
      };
    });

    var sBar = el('topo-subtype-bar');
    if (sBar) {
      sBar.textContent = '';
      var lbl = document.createElement('span');
      lbl.style.cssText = 'font:700 10.5px var(--nb-mono);color:var(--nb-dim);text-transform:uppercase;letter-spacing:.08em;margin-right:4px';
      lbl.textContent = isSec ? 'Security Focus:' : 'Architecture Lens:';
      sBar.appendChild(lbl);
      subList.forEach(function(st) {
        var cnt = baseTopo.allFiles.filter(st.match).length;
        var btn = document.createElement('button');
        btn.type = 'button';
        var isAct = st.id === topoSubtype;
        btn.style.cssText = 'border:1px solid ' + (isAct ? (isSec ? 'var(--nb-emerald)' : 'var(--nb-cyan)') : 'var(--nb-border)') + ';background:' + (isAct ? (isSec ? 'rgba(16,185,129,.18)' : 'rgba(6,182,212,.18)') : 'var(--nb-card)') + ';color:' + (isAct ? 'var(--nb-text)' : cnt > 0 ? 'var(--nb-muted)' : 'var(--nb-dim)') + ';font:600 11px var(--nb-mono);padding:5px 10px;border-radius:99px;cursor:pointer;opacity:' + (cnt === 0 && !isAct ? '0.55' : '1');
        btn.textContent = st.label + ' (' + cnt + ')';
        btn.onclick = function() {
          topoSubtype = st.id;
          renderTopology(activeWorkspace);
        };
        sBar.appendChild(btn);
      });
    }

    var svgBox = el('boundary-svg');
    if (!svgBox) return;
    svgBox.textContent = '';
    var NS = 'http://www.w3.org/2000/svg';
    function node(tag, attrs, parent, text) {
      var n = document.createElementNS(NS, tag);
      for (var k in attrs) n.setAttribute(k, String(attrs[k]));
      if (text != null) n.textContent = String(text);
      if (parent) parent.appendChild(n);
      return n;
    }

    var drift = topo.drift;
    var bridgeFilesCount = topo.files.filter(function(f) { return f.extSinks.length > 0 && f.intSinks.length > 0; }).length;

    var summaryEl = el('topo-summary');
    var archMeta = wsKey && meta[wsKey] && meta[wsKey].architecture;
    var flowSummaryTxt = (archMeta && archMeta.flows && archMeta.flows.length) ? (' · Inter-module flows (' + archMeta.flowCount + '): ' + archMeta.flows.slice(0, 5).join(', ')) : '';
    if (summaryEl) {
      summaryEl.textContent = activeSub.desc + ' Showing ' + topo.files.length + ' of ' + baseTopo.allFiles.length + ' boundary file(s) across ' + topo.modNodes.length + ' ' + (wsKey ? 'module(s)' : 'repositories') + ' (' + bridgeFilesCount + ' cross-boundary bridge files)' + flowSummaryTxt + '.';
    }

    var driftBadge = el('ov-drift');
    if (drift.length > 0) {
      driftBadge.className = 'badge-chip warn';
      driftBadge.textContent = '⚠ +' + drift.length + ' Unreviewed Boundary Drift: ' + drift.slice(0, 3).join(', ');
    } else {
      driftBadge.className = 'badge-chip';
      driftBadge.textContent = '✓ ' + baseTopo.allFiles.length + ' Boundary Files Mapped (' + (wsKey || 'Portfolio') + ')';
    }

    if (topo.files.length === 0) {
      svgBox.setAttribute('viewBox', '0 0 960 140');
      node('text', { x: 480, y: 75, fill: '#8b9d92', 'font-size': 13, 'text-anchor': 'middle', 'font-family': 'monospace' }, svgBox, 'No files match "' + activeSub.label + '" in ' + (wsKey || 'workspace') + '. Click "' + subList[0].label + '" above to view all ' + baseTopo.allFiles.length + ' files.');
      var emptyRows = el('boundary-file-rows');
      if (emptyRows) emptyRows.textContent = '';
      return;
    }

    var extCount = Math.max(1, topo.extNodes.length);
    var modCount = Math.max(1, topo.modNodes.length);
    var intCount = Math.max(1, topo.intNodes.length);
    var H = Math.max(330, extCount * 84 + 44, modCount * 70 + 44, intCount * 70 + 44);
    svgBox.setAttribute('viewBox', '0 0 960 ' + H);

    var col1Hdr = isSec ? ('1. UNTRUSTED PERIMETER [EXT] (' + topo.extNodes.length + ')') : ('1. INTERFACE & TRANSPORT ADAPTERS (' + topo.extNodes.length + ')');
    var col2Hdr = isSec ? ('2. PRIVILEGE & BRIDGE ISOLATION ZONES (' + topo.modNodes.length + ')') : ('2. ' + (wsKey ? wsKey.toUpperCase() : 'REPOSITORY') + ' SUBSYSTEM ARCHITECTURE (' + topo.modNodes.length + ')');
    var col3Hdr = isSec ? ('3. PRIVILEGED KERNEL / SYSTEM SINKS [INT] (' + topo.intNodes.length + ')') : ('3. STORAGE, RUNTIME & CAPABILITY BACKENDS (' + topo.intNodes.length + ')');

    node('text', { x: 20, y: 20, fill: isSec ? '#f59e0b' : '#38bdf8', 'font-size': 11, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, col1Hdr);
    node('text', { x: 480, y: 20, fill: '#10b981', 'font-size': 11, 'font-weight': 700, 'text-anchor': 'middle', 'font-family': 'monospace' }, svgBox, col2Hdr);
    node('text', { x: 940, y: 20, fill: isSec ? '#06b6d4' : '#c084fc', 'font-size': 11, 'font-weight': 700, 'text-anchor': 'end', 'font-family': 'monospace' }, svgBox, col3Hdr);

    var wm = wsKey ? (meta[wsKey] || {}) : {};
    var bLoad = wm.boundaryLoad || {};

    var extPos = {};
    var extStep = (H - 46) / Math.max(1, topo.extNodes.length);
    topo.extNodes.forEach(function(en, idx) {
      var bh = Math.min(78, Math.max(54, extStep - 10));
      var by = Math.round(36 + idx * extStep + (extStep - bh) / 2);
      extPos[en.sink] = { x: 18, y: by, w: 256, h: bh, cy: by + Math.round(bh / 2), color: en.color };
    });

    var modPos = {};
    var modStep = (H - 46) / Math.max(1, topo.modNodes.length);
    topo.modNodes.forEach(function(mn, idx) {
      var bh = Math.min(74, Math.max(50, modStep - 8));
      var by = Math.round(36 + idx * modStep + (modStep - bh) / 2);
      modPos[mn.name] = { x: 344, y: by, w: 272, h: bh, cy: by + Math.round(bh / 2) };
    });

    var intPos = {};
    var intStep = (H - 46) / Math.max(1, topo.intNodes.length);
    topo.intNodes.forEach(function(inNode, idx) {
      var bh = Math.min(74, Math.max(50, intStep - 8));
      var by = Math.round(36 + idx * intStep + (intStep - bh) / 2);
      intPos[inNode.sink] = { x: 686, y: by, w: 256, h: bh, cy: by + Math.round(bh / 2), color: inNode.color };
    });

    topo.extNodes.forEach(function(en) {
      var ep = extPos[en.sink];
      Object.keys(en.modules).forEach(function(mName) {
        var mp = modPos[mName];
        if (!ep || !mp) return;
        var count = en.modules[mName];
        var sw = Math.min(4.5, 1.3 + count * 0.65);
        node('path', {
          d: 'M' + (ep.x + ep.w) + ',' + ep.cy + ' C305,' + ep.cy + ' 308,' + mp.cy + ' ' + mp.x + ',' + mp.cy,
          fill: 'none',
          stroke: ep.color,
          'stroke-width': sw,
          'stroke-opacity': '0.74'
        }, svgBox);
      });
    });

    topo.modNodes.forEach(function(mn) {
      var mp = modPos[mn.name];
      if (!mp) return;
      Object.keys(mn.intCounts).forEach(function(sKey) {
        var ip = intPos[sKey];
        if (!ip) return;
        var count = mn.intCounts[sKey];
        var sw = Math.min(4.5, 1.3 + count * 0.55);
        node('path', {
          d: 'M' + (mp.x + mp.w) + ',' + mp.cy + ' C648,' + mp.cy + ' 652,' + ip.cy + ' ' + ip.x + ',' + ip.cy,
          fill: 'none',
          stroke: ip.color,
          'stroke-width': sw,
          'stroke-opacity': '0.74'
        }, svgBox);
      });
    });

    topo.extNodes.forEach(function(en) {
      var ep = extPos[en.sink];
      node('rect', { x: ep.x, y: ep.y, width: ep.w, height: ep.h, rx: 10, fill: '#0b110e', stroke: ep.color, 'stroke-width': 1.6 }, svgBox);
      var hdrTxt = isSec ? ('[' + en.sink + '] ' + en.secDomain) : ('[' + en.archLayer + ']');
      node('text', { x: ep.x + 12, y: ep.y + 17, fill: ep.color, 'font-size': 10.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, hdrTxt.slice(0, 36));
      node('text', { x: ep.x + 12, y: ep.y + 32, fill: '#ecf3ef', 'font-size': 11, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, en.label + ' (' + en.files.length + ')');
      var loadTag = bLoad[en.sink] ? (' · ' + bLoad[en.sink]) : '';
      var subTxt = Object.keys(en.modules).length + ' mod(s)' + loadTag + (en.files[0] ? (' · ' + en.files[0].split('/').pop()) : '');
      if (ep.h >= 52) {
        node('text', { x: ep.x + 12, y: ep.y + 47, fill: '#8b9d92', 'font-size': 9.5, 'font-family': 'monospace' }, svgBox, subTxt.slice(0, 38));
      }
    });

    topo.modNodes.forEach(function(mn) {
      var mp = modPos[mn.name];
      var isBridgeMod = mn.bridgeCount > 0;
      var archRole = classifyArchModuleRole(mn);
      var borderCol = isSec ? (isBridgeMod ? '#f59e0b' : '#10b981') : archRole.color;
      node('rect', {
        x: mp.x,
        y: mp.y,
        width: mp.w,
        height: mp.h,
        rx: 10,
        fill: isBridgeMod ? '#0e1913' : '#0b110e',
        stroke: borderCol,
        'stroke-width': isBridgeMod ? 1.9 : 1.3
      }, svgBox);

      var topBadge = isSec ? (isBridgeMod ? ('⚡ ' + mn.bridgeCount + ' BRIDGE') : '🛡️ ISOLATED') : archRole.tag;
      node('text', { x: mp.x + 12, y: mp.y + 18, fill: borderCol, 'font-size': 11, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, (mn.name.slice(0, 19) + ' · ' + topBadge).slice(0, 39));

      var extList = Object.keys(mn.extCounts).join(',');
      var intList = Object.keys(mn.intCounts).join(',');
      var flowSummary = isSec
        ? ((extList ? ('ext:[' + extList + '] ') : 'internal-only ') + (intList ? ('➔ int:[' + intList + ']') : ''))
        : (mn.files.length + ' file(s) · ' + (extList ? ('in:' + extList + ' ') : '') + (intList ? ('Uses ' + intList) : ''));
      node('text', { x: mp.x + 12, y: mp.y + 34, fill: '#ecf3ef', 'font-size': 9.8, 'font-family': 'monospace' }, svgBox, flowSummary.slice(0, 40));

      if (mp.h >= 52 && mn.files[0]) {
        var sampleNames = mn.files.slice(0, 2).map(function(f) { return f.file.split('/').pop(); }).join(', ');
        node('text', { x: mp.x + 12, y: mp.y + 48, fill: '#8b9d92', 'font-size': 9.3, 'font-family': 'monospace' }, svgBox, sampleNames.slice(0, 40));
      }
    });

    topo.intNodes.forEach(function(inNode) {
      var ip = intPos[inNode.sink];
      node('rect', { x: ip.x, y: ip.y, width: ip.w, height: ip.h, rx: 10, fill: '#0b110e', stroke: ip.color, 'stroke-width': 1.6 }, svgBox);
      var hdrTxt = isSec ? ('[' + inNode.sink + '] ' + inNode.secDomain) : ('[' + inNode.archLayer + ']');
      node('text', { x: ip.x + 12, y: ip.y + 17, fill: ip.color, 'font-size': 10.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, hdrTxt.slice(0, 36));
      node('text', { x: ip.x + 12, y: ip.y + 32, fill: '#ecf3ef', 'font-size': 11, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, inNode.label + ' (' + inNode.files.length + ')');
      if (ip.h >= 52) {
        node('text', { x: ip.x + 12, y: ip.y + 47, fill: '#8b9d92', 'font-size': 9.5, 'font-family': 'monospace' }, svgBox, Object.keys(inNode.modules).length + ' mod(s)' + (inNode.files[0] ? (' · ' + inNode.files[0].split('/').pop()) : ''));
      }
    });

    var tblTitle = el('boundary-table-title');
    var tblCnt = el('boundary-table-count');
    if (tblTitle) tblTitle.textContent = (isSec ? 'SECURITY TRUST-BOUNDARY' : 'SYSTEM ARCHITECTURE') + ' MATRIX (' + activeSub.label.toUpperCase() + ') — ' + (wsKey || 'ALL WORKSPACES').toUpperCase();
    if (tblCnt) tblCnt.textContent = topo.files.length + ' of ' + baseTopo.allFiles.length + ' boundary files (' + bridgeFilesCount + ' cross-boundary bridges)';

    var bRows = el('boundary-file-rows');
    if (bRows) {
      bRows.textContent = '';
      topo.files.slice().sort(function(a, b) {
        var aBridge = (a.extSinks.length > 0 && a.intSinks.length > 0) ? 1 : 0;
        var bBridge = (b.extSinks.length > 0 && b.intSinks.length > 0) ? 1 : 0;
        if (bBridge !== aBridge) return bBridge - aBridge;
        return (b.extSinks.length + b.intSinks.length) - (a.extSinks.length + a.intSinks.length);
      }).slice(0, 80).forEach(function(f) {
        var tr = document.createElement('tr');
        tr.className = 'clickable-row';
        var isBridge = f.extSinks.length > 0 && f.intSinks.length > 0;
        var totalSinks = f.extSinks.length + f.intSinks.length;
        var tips = sinkGuidanceForFile(f);
        tr.title = f.file + '\n' + tips.join('\n') + '\n(Click row to expand security & architecture guidance)';
        var roleLabel = isSec
          ? (f.isDrift ? '⚠ Unreviewed Drift (+new)' : isBridge ? '⚡ Cross-Boundary Bridge ([ext] ➔ [int])' : totalSinks >= 2 ? ('🛡️ Multi-Sink Isolation (' + totalSinks + ' sinks)') : '● Single-Sink Boundary')
          : (isBridge ? '🔌➔🗄️ Full-Stack Adapter & Bridge' : f.extSinks.length > 0 ? '🔌 External Interface Adapter' : (f.intSinks.indexOf('sql') >= 0 || f.intSinks.indexOf('fs') >= 0 || f.intSinks.indexOf('serde') >= 0) ? '🗄️ Persistence / Schema Module' : (f.intSinks.indexOf('auth') >= 0 || f.intSinks.indexOf('crypto') >= 0) ? '🔐 Security / Crypto Service' : '⚙️ Internal Runtime Module');

        var dTr = document.createElement('tr');
        dTr.style.display = 'none';
        dTr.style.background = '#070c0a';
        var dTd = document.createElement('td');
        dTd.colSpan = 5;
        dTd.style.padding = '12px 16px';
        var gBox = document.createElement('div');
        gBox.style.cssText = 'background:#0b110e;border:1px solid ' + (isBridge ? 'var(--nb-amber)' : 'var(--nb-emerald)') + ';border-radius:10px;padding:12px 14px;font:400 12px/1.6 var(--nb-mono);color:var(--nb-text);white-space:pre-wrap';
        gBox.textContent = 'File: ' + f.file + ' (Subsystem: ' + f.module + ')\nExternal Sinks: ' + (f.extSinks.length ? f.extSinks.map(function(s) { return '[' + s + '] ' + (EXT_SINK_META[s] ? EXT_SINK_META[s].label : s); }).join(' · ') : 'None (internal only)') + '\nInternal Sinks: ' + (f.intSinks.length ? f.intSinks.map(function(s) { return '[' + s + '] ' + (INT_SINK_META[s] ? INT_SINK_META[s].label : s); }).join(' · ') : 'None (perimeter only)') + '\n\nNeckBeard Boundary Guidance:\n• ' + tips.join('\n• ');
        dTd.appendChild(gBox);
        dTr.appendChild(dTd);

        var fCell = null;
        [
          f.module,
          '▸ ' + f.file,
          f.extSinks.length ? f.extSinks.map(function(s) { return '[' + s + ']'; }).join(' ') : '–',
          f.intSinks.length ? f.intSinks.map(function(s) { return '[' + s + ']'; }).join(' ') : '–',
          roleLabel
        ].forEach(function(val, idx) {
          var td = document.createElement('td');
          if (idx === 1) { td.className = 'task-col'; fCell = td; }
          if (idx === 4 && isBridge) td.style.color = 'var(--nb-amber)';
          td.textContent = val;
          tr.appendChild(td);
        });
        tr.onclick = function() {
          var open = dTr.style.display !== 'none';
          dTr.style.display = open ? 'none' : 'table-row';
          tr.classList.toggle('selected-row', !open);
          if (fCell) fCell.textContent = (open ? '▸ ' : '▾ ') + f.file;
        };
        bRows.appendChild(tr);
        bRows.appendChild(dTr);
      });
    }
  }

  function render() {
    var filtered = activeWorkspace ? records.filter(function(r) { return r.projectName === activeWorkspace; }) : records;
    var wsStats = summarizeList(filtered);
    var wm = activeWorkspace ? (meta[activeWorkspace] || {}) : {};
    var vData = resolveVibesData(activeWorkspace);

    el('st-title').textContent = activeWorkspace || 'All Workspaces';
    var backBtn = el('back-all-btn');
    if (backBtn) backBtn.style.display = activeWorkspace ? 'inline-block' : 'none';

    var vPill = el('st-vibes-pill');
    if (vPill) {
      if (vData && vData.present) {
        vPill.style.display = 'inline-block';
        vPill.className = 'badge-chip cyan';
        vPill.textContent = '● VIBES (.ai-audit/) Active';
      } else {
        vPill.style.display = 'none';
      }
    }

    var shareCostPct = portfolioStats.cost > 0 ? ((wsStats.cost / portfolioStats.cost) * 100).toFixed(1) : '100.0';
    el('st-subtitle').textContent = activeWorkspace
      ? (wsStats.sessions + ' sessions · ' + wsStats.turns + ' turns · ' + fmtDur(wsStats.dur) + ' agent time (' + fmtDur(wsStats.wallDur) + ' wall) · ' + fmtUsd(wsStats.cost) + ' (' + shareCostPct + '% of all workspaces)')
      : (portfolioStats.sessions + ' total sessions across ' + el('ws-total-cnt').textContent + ' workspaces · ' + fmtDur(portfolioStats.dur) + ' agent time (' + fmtDur(portfolioStats.wallDur) + ' wall) · ' + fmtUsd(portfolioStats.cost) + ' spend · ' + fmtUsd(portfolioStats.saved) + ' saved by prompt caching');

    el('pane-economics').style.display = (activeView === 'overview' || activeView === 'economics') ? 'block' : 'none';
    el('pane-vibes').style.display = (activeView === 'overview' || activeView === 'vibes') ? 'block' : 'none';
    el('pane-overview').style.display = (activeView === 'overview' || activeView === 'topology') ? 'block' : 'none';
    el('pane-forensics').style.display = (activeView === 'overview' || activeView === 'forensics') ? 'block' : 'none';

    // Top 4 Executive Economics & Security Cards
    el('m-cost').textContent = fmtUsd(wsStats.cost);
    el('m-cost-unit').textContent = fmtUsd(wsStats.costPerSession) + ' / session · ' + fmtUsd(wsStats.costPerTurn) + ' / turn';
    el('m-cost-comp').textContent = activeWorkspace
      ? (shareCostPct + '% of All Workspaces (' + fmtUsd(portfolioStats.cost) + ') · All Avg: ' + fmtUsd(portfolioStats.costPerSession) + '/sess')
      : ('100% of portfolio (' + portfolioStats.sessions.toLocaleString() + ' sessions)');

    el('m-saved').textContent = fmtUsd(wsStats.saved) + ' saved';
    el('m-cache').textContent = wsStats.cacheHitPct + '% cache hit · ' + fmtTokens(wsStats.tok) + ' total tok';
    el('m-cache-comp').textContent = activeWorkspace
      ? ('All-Workspaces avg cache hit: ' + portfolioStats.cacheHitPct + '% (' + fmtUsd(portfolioStats.saved) + ' total saved)')
      : (fmtTokens(portfolioStats.cRead) + ' cached read tokens across portfolio');

    el('m-time').textContent = fmtDur(wsStats.dur) + ' agent / ' + fmtDur(wsStats.wallDur) + ' wall';
    var shareTimePct = portfolioStats.dur > 0 ? ((wsStats.dur / portfolioStats.dur) * 100).toFixed(1) : '100.0';
    var avgSessMs = wsStats.sessions > 0 ? Math.round(wsStats.dur / wsStats.sessions) : 0;
    var portAvgSessMs = portfolioStats.sessions > 0 ? Math.round(portfolioStats.dur / portfolioStats.sessions) : 0;
    el('m-turns').textContent = wsStats.sessions.toLocaleString() + ' sessions · ' + wsStats.turns.toLocaleString() + ' turns across ' + wsStats.activeDays + ' active day(s)';
    el('m-load').textContent = activeWorkspace
      ? (shareTimePct + '% of All-Workspaces agent time (' + fmtDur(portfolioStats.dur) + ') · ' + wsStats.parallelFactor + 'x concurrency · Avg ' + fmtDur(avgSessMs) + '/sess')
      : (portfolioStats.parallelFactor + 'x parallel concurrency (+' + fmtDur(Math.max(0, portfolioStats.dur - portfolioStats.wallDur)) + ' compressed) · Avg ' + fmtDur(portAvgSessMs) + '/sess');

    var vIns = (vData && vData.linesAdded) || wsStats.ins;
    var vDel = (vData && vData.linesRemoved) || wsStats.del;
    el('m-sec').textContent = wsStats.blk + ' guard blocks';
    el('m-loc').textContent = '+' + vIns.toLocaleString() + ' / -' + vDel.toLocaleString() + ' LOC · ' + wsStats.fixed + '/' + wsStats.found + ' issues fixed';
    el('m-vibes').textContent = (vData && vData.present)
      ? ('VIBES active · ' + (vData.annotationsCount || 0).toLocaleString() + ' annotations · PRISM max ' + Number(vData.maxPrismRisk || 0).toFixed(2))
      : 'PreToolUse secret & config-censor shield armed';

    el('forensics-heading').textContent = activeWorkspace
      ? ('Recorded Engineering & Audit Sessions — ' + activeWorkspace + ' (Click Any Row to Expand Full Prompt)')
      : 'Recorded Engineering & Audit Sessions — All Workspaces (Click Any Row to Expand Full Prompt)';

    var searched = searchQuery
      ? filtered.filter(function(r) {
          var q = searchQuery.toLowerCase();
          return String(r.taskTitle || '').toLowerCase().includes(q) ||
                 String(r.fullPrompt || '').toLowerCase().includes(q) ||
                 String(r.assistantSummary || '').toLowerCase().includes(q) ||
                 String(r.projectName || '').toLowerCase().includes(q) ||
                 String(r.modelId || '').toLowerCase().includes(q);
        })
      : filtered;

    el('tbl-count').textContent = searched.length + ' session(s)';
    var tbody = el('session-rows');
    tbody.textContent = '';
    searched.slice().sort(function(a, b) { return (b.startedAtMs || 0) - (a.startedAtMs || 0); }).slice(0, 250).forEach(function(r) {
      var tr = document.createElement('tr');
      tr.className = 'clickable-row';
      var tb = r.tokenBuckets || {};
      var totalTok = (tb.promptTokens || 0) + (tb.completionTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
      var inTok = (tb.promptTokens || 0) + (tb.cachedReadTokens || 0) + (tb.cachedWriteTokens || 0);
      var cHit = inTok > 0 ? Math.round(((tb.cachedReadTokens || 0) / inTok) * 100) : 0;
      var savedUsd = estimateCacheSavingsUsd(r);
      var fullP = r.fullPrompt || r.taskTitle || 'Session';
      var outS = r.assistantSummary || '';
      tr.title = 'PROMPT:\n' + fullP + (outS ? ('\n\nASSISTANT OUTCOME:\n' + outS) : '') + '\n\n(Click row to expand inline)';

      var dTr = document.createElement('tr');
      dTr.style.display = 'none';
      dTr.style.background = '#070c0a';
      var dTd = document.createElement('td');
      dTd.colSpan = 9;
      dTd.style.padding = '14px 18px';
      var wrap = document.createElement('div');
      wrap.style.cssText = 'background:#0b110e;border:1px solid var(--nb-emerald);border-radius:12px;padding:14px 16px;display:flex;flex-direction:column;gap:10px';
      var metaBar = document.createElement('div');
      metaBar.style.cssText = 'font:600 11px var(--nb-mono);color:var(--nb-cyan);display:flex;flex-wrap:wrap;gap:14px;border-bottom:1px solid var(--nb-border);padding-bottom:8px';
      metaBar.textContent = 'Session ID: ' + (r.sessionId || r.recordId || '–') + ' · Workspace: ' + (r.projectName || '–') + ' · Timestamp: ' + (r.timestampIso || '–') + ' · Model: ' + (r.modelId || 'claude') + ' [' + (r.activeLevel || 'full') + '] · Turns: ' + (r.turnCount || 1) + ' · Tokens: ' + ((tb.promptTokens || 0).toLocaleString()) + ' in / ' + ((tb.completionTokens || 0).toLocaleString()) + ' out / ' + ((tb.cachedReadTokens || 0).toLocaleString()) + ' cache-read / ' + ((tb.cachedWriteTokens || 0).toLocaleString()) + ' cache-write';
      wrap.appendChild(metaBar);
      var pLbl = document.createElement('div');
      pLbl.style.cssText = 'font:700 11px var(--nb-mono);color:var(--nb-emerald);text-transform:uppercase;letter-spacing:.06em';
      pLbl.textContent = 'Full Task / User Prompt';
      wrap.appendChild(pLbl);
      var pBox = document.createElement('div');
      pBox.style.cssText = 'background:#060908;border:1px solid var(--nb-border);border-radius:8px;padding:10px 12px;font:400 12px/1.55 var(--nb-mono);color:var(--nb-text);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow-y:auto';
      pBox.textContent = fullP;
      wrap.appendChild(pBox);
      if (outS) {
        var aLbl = document.createElement('div');
        aLbl.style.cssText = 'font:700 11px var(--nb-mono);color:var(--nb-amber);text-transform:uppercase;letter-spacing:.06em;margin-top:2px';
        aLbl.textContent = 'Assistant Outcome / Final Synopsis';
        wrap.appendChild(aLbl);
        var aBox = document.createElement('div');
        aBox.style.cssText = 'background:#060908;border:1px solid var(--nb-border);border-radius:8px;padding:10px 12px;font:400 12px/1.55 var(--nb-mono);color:var(--nb-muted);white-space:pre-wrap;word-break:break-word;max-height:220px;overflow-y:auto';
        aBox.textContent = outS;
        wrap.appendChild(aBox);
      }
      dTd.appendChild(wrap);
      dTr.appendChild(dTd);

      var tCell = null;
      var cells = [
        '▸ ' + (r.taskTitle || 'Session'),
        r.projectName || '–',
        r.timestampIso || '–',
        (r.modelId || 'claude') + ' [' + (r.activeLevel || 'full') + ']',
        fmtDur(r.activeDurationMs),
        fmtUsd(r.totalCostUsd || 0) + ' (' + fmtTokens(totalTok) + ')',
        fmtUsd(savedUsd) + ' (' + cHit + '%)',
        (r.guardBlockCount || 0) + ' blk · ' + (r.securityFindingsResolved || 0) + '/' + (r.securityFindingsTotal || 0) + (r.vibesMaxPrismRisk != null ? ' · PRISM ' + r.vibesMaxPrismRisk : ''),
        r.testStatusLabel || 'recorded'
      ];
      cells.forEach(function(val, i) {
        var td = document.createElement('td');
        if (i === 0) { td.className = 'task-col'; tCell = td; }
        td.textContent = val;
        tr.appendChild(td);
      });
      tr.onclick = function() {
        var open = dTr.style.display !== 'none';
        dTr.style.display = open ? 'none' : 'table-row';
        tr.classList.toggle('selected-row', !open);
        if (tCell) tCell.textContent = (open ? '▸ ' : '▾ ') + (r.taskTitle || 'Session');
      };
      tbody.appendChild(tr);
      tbody.appendChild(dTr);
    });

    renderEconomicsAndVelocity(filtered, wsStats);
    renderVibesSection(activeWorkspace);
    renderTopology(activeWorkspace);
  }

  var backAllBtn = el('back-all-btn');
  if (backAllBtn) {
    backAllBtn.onclick = function() { selectWorkspace(''); };
  }

  var demoBtn = el('vibes-demo-btn');
  if (demoBtn) {
    demoBtn.onclick = function() {
      demoVibesMode = !demoVibesMode;
      render();
    };
  }

  var searchBox = el('session-search');
  if (searchBox) {
    searchBox.oninput = function() {
      searchQuery = searchBox.value || '';
      render();
    };
  }

  var wsContainer = el('ws-list');
  var wsCostMap = {};
  var wsCountMap = {};
  records.forEach(function(r) {
    var p = r.projectName || '';
    if (!p) return;
    wsCostMap[p] = (wsCostMap[p] || 0) + (r.totalCostUsd || 0);
    wsCountMap[p] = (wsCountMap[p] || 0) + 1;
  });
  var allNames = Array.from(new Set(Object.keys(wsCountMap).concat(Object.keys(meta)).filter(Boolean)));
  var totalWsEl = el('ws-total-cnt');
  if (totalWsEl) totalWsEl.textContent = String(allNames.length);

  [['', 'All Workspaces', records.length, portfolioStats.cost]].concat(allNames.map(function(n) {
    return [n, n, wsCountMap[n] || 0, wsCostMap[n] || 0];
  }).sort(function(a, b) { return (b[3] - a[3]) || (b[2] - a[2]); })).forEach(function(item) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute('data-ws', item[0]);
    btn.className = 'ws-btn' + (item[0] === activeWorkspace ? ' active' : '');
    var nameSpan = document.createElement('span');
    nameSpan.className = 'ws-name-col';
    nameSpan.textContent = item[1];
    var rightWrap = document.createElement('span');
    rightWrap.className = 'ws-badges';
    if (item[0] && meta[item[0]] && meta[item[0]].vibes && meta[item[0]].vibes.present) {
      var vTag = document.createElement('span');
      vTag.className = 'ws-vibes-tag';
      vTag.textContent = 'VIBES';
      rightWrap.appendChild(vTag);
    }
    var costSpan = document.createElement('span');
    costSpan.className = 'ws-cost-tag';
    costSpan.textContent = '$' + Math.round(item[3]).toLocaleString();
    rightWrap.appendChild(costSpan);
    var countSpan = document.createElement('span');
    countSpan.className = 'ws-count';
    countSpan.textContent = String(item[2]);
    rightWrap.appendChild(countSpan);
    btn.appendChild(nameSpan);
    btn.appendChild(rightWrap);
    btn.onclick = function() { selectWorkspace(item[0]); };
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
