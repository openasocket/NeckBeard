// NeckBeard Security & Engineering Command Center (dashboard.html generator).
// 100% original architecture with front-and-center VIBES Protocol (.ai-audit/) data visualization
// and standard adoption onboarding (VIBES v1.1, VERIFY v1.0, PRISM v1.0, EVOLVE v1.0, TRACE v1.0).

import type { TelemetrySessionRecord } from './types'

export type VibesVisualTelemetry = {
  present?: boolean
  annotationsCount?: number
  verifiedCount?: number
  blobsCount?: number
  attestationsCount?: number
  iocRulesCount?: number
  hasAuditDb?: boolean
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
  grid-template-columns: 280px minmax(0, 1fr);
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
  font: 600 10.5px var(--nb-mono);
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
  gap: 6px;
}
.ws-btn:hover, .ws-btn.active {
  background: var(--nb-card);
  color: var(--nb-text);
  border-color: var(--nb-border);
}
.ws-badges {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.ws-vibes-tag {
  font: 700 9.5px var(--nb-mono);
  color: var(--nb-cyan);
  background: rgba(6, 182, 212, 0.14);
  border: 1px solid rgba(6, 182, 212, 0.35);
  padding: 1px 6px;
  border-radius: 99px;
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
  max-width: 1460px;
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
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin-top: 22px;
}
.vibes-pillars {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}
.pillar-box {
  background: var(--nb-surface);
  border: 1px solid var(--nb-border);
  border-radius: 12px;
  padding: 13px 14px;
}
.pillar-k {
  font: 700 10.5px var(--nb-mono);
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--nb-cyan);
}
.pillar-v {
  font: 800 21px/1.2 var(--nb-mono);
  margin-top: 6px;
  color: var(--nb-text);
}
.pillar-s {
  font: 400 11px var(--nb-mono);
  color: var(--nb-muted);
  margin-top: 4px;
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
  margin-bottom: 14px;
}
.section-head h2 {
  margin: 0;
  font: 700 16px var(--nb-mono);
  display: flex;
  align-items: center;
  gap: 10px;
}
.split-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-top: 16px;
}
.adopt-banner {
  margin-top: 14px;
  background: rgba(6, 182, 212, 0.07);
  border: 1px dashed rgba(6, 182, 212, 0.45);
  border-radius: 12px;
  padding: 16px 18px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.adopt-code {
  font: 500 12px var(--nb-mono);
  background: #060908;
  border: 1px solid var(--nb-border);
  padding: 8px 12px;
  border-radius: 8px;
  color: var(--nb-emerald);
}
.act-btn {
  border: 1px solid rgba(6, 182, 212, 0.45);
  background: rgba(6, 182, 212, 0.14);
  color: var(--nb-cyan);
  font: 600 12px var(--nb-mono);
  padding: 7px 13px;
  border-radius: 8px;
  cursor: pointer;
}
.act-btn:hover {
  background: rgba(6, 182, 212, 0.25);
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
@media (max-width: 1120px) {
  .shell { grid-template-columns: 1fr; }
  .rail { border-right: 0; border-bottom: 1px solid var(--nb-border); }
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
      VIBES (.ai-audit/) Native Hub<br>
      100% Local · Zero Network Calls
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
        <button type="button" class="view-btn" data-view="vibes">2. VIBES (.ai-audit) Hub</button>
        <button type="button" class="view-btn" data-view="topology">3. Trust-Boundary Graph</button>
        <button type="button" class="view-btn" data-view="forensics">4. Session Forensics</button>
      </div>
    </header>

    <div class="metric-grid">
      <div class="panel">
        <div class="m-tag"><span>Code Minimalism &amp; Reuse</span><span style="color:var(--nb-emerald)">LADDER</span></div>
        <div class="m-val" id="m-loc">+0 / -0 LOC</div>
        <div class="m-sub" id="m-reuse">Symbol reuse ratio across edits</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Security &amp; VIBES Provenance</span><span style="color:var(--nb-cyan)">SAFE GATE</span></div>
        <div class="m-val" id="m-sec">0 blocked</div>
        <div class="m-sub" id="m-vibes">VIBES PRISM &amp; TRACE status</div>
      </div>
      <div class="panel">
        <div class="m-tag"><span>Targeted Scalability &amp; Cost</span><span style="color:var(--nb-amber)">FAST GATE</span></div>
        <div class="m-val" id="m-cost">$0.00</div>
        <div class="m-sub" id="m-load">Load target from .neckbeard.json</div>
      </div>
    </div>

    <!-- FRONT-AND-CENTER VIBES PROTOCOL (.ai-audit/) DATA VISUALIZATION & ADOPTION HUB -->
    <section class="section-card vibes-highlight" id="pane-vibes">
      <div class="section-head">
        <h2>
          <span>VIBES Protocol (.ai-audit/) Provenance &amp; PRISM Risk Intelligence</span>
          <a href="https://www.itsavibe.ai" target="_blank" rel="noopener" class="badge-chip cyan">itsavibe.ai ↗</a>
        </h2>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span id="vibes-status-chip" class="badge-chip">Checking .ai-audit/...</span>
          <button type="button" id="vibes-demo-btn" class="act-btn">Preview Reference VIBES Telemetry</button>
        </div>
      </div>

      <p style="margin:0 0 12px;color:var(--nb-muted);font-size:13px">
        NeckBeard is the <strong>preventive engineering layer</strong> (3 Gates + <code>PreToolUse</code> Guard); the open <strong><a href="https://www.itsavibe.ai" target="_blank" rel="noopener">VIBES Protocol</a></strong> (<code>VIBES v1.1</code> · <code>VERIFY v1.0</code> · <code>PRISM v1.0</code> · <code>EVOLVE v1.0</code> · <code>TRACE v1.0</code>) is the <strong>evidentiary provenance &amp; risk layer</strong> stored in <code>.ai-audit/</code>.
      </p>

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

      <div style="margin-top:16px;background:#080d0b;border:1px solid var(--nb-border);border-radius:12px;padding:14px">
        <svg id="vibes-svg" viewBox="0 0 960 250" style="width:100%;height:auto;display:block"></svg>
      </div>

      <div class="split-2">
        <div style="background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;padding:14px">
          <div style="font:700 12px var(--nb-mono);color:var(--nb-emerald);margin-bottom:8px">EVOLVE DECISION RECORDS &amp; PRETOOLUSE PROVENANCE SHIELD</div>
          <div id="vibes-decisions-list" style="font:400 12px/1.6 var(--nb-mono);color:var(--nb-muted)"></div>
        </div>
        <div style="background:var(--nb-surface);border:1px solid var(--nb-border);border-radius:12px;padding:14px">
          <div style="font:700 12px var(--nb-mono);color:var(--nb-amber);margin-bottom:8px">TRACE INCIDENTS &amp; HIGH-RISK PRISM ANNOTATIONS (&gt;= 0.60)</div>
          <div id="vibes-incidents-list" style="font:400 12px/1.6 var(--nb-mono);color:var(--nb-muted)"></div>
        </div>
      </div>

      <div class="adopt-banner" id="vibes-adopt-banner">
        <div style="max-width:680px">
          <div style="font:700 13px var(--nb-mono);color:var(--nb-cyan)">🚀 Bring Cryptographic AI Provenance (.ai-audit/) to Your Repositories</div>
          <div style="font-size:12.5px;color:var(--nb-muted);margin-top:4px">
            When <code>.ai-audit/</code> is initialized in a project, NeckBeard’s <code>hooks/guard.js</code> automatically protects immutable SHA-256 blobs &amp; DSSE attestations from agent tampering, while <code>/neckbeard-review</code>, <code>/neckbeard-audit</code>, and <code>/neckbeard-debt</code> ingest PRISM risk scores and EVOLVE decisions automatically.
          </div>
        </div>
        <div class="adopt-code">npx vibecheck init &amp;&amp; vibecheck validate</div>
      </div>
    </section>

    <section class="section-card" id="pane-overview">
      <div class="section-head">
        <h2>External → Internal Trust-Boundary Graph</h2>
        <span id="ov-drift" class="badge-chip">✓ Baseline Verified</span>
      </div>
      <svg id="boundary-svg" viewBox="0 0 960 360" style="width:100%;height:auto;display:block"></svg>
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
  var demoVibesMode = false;

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
    ]
  };

  function el(id) { return document.getElementById(id); }
  function fmtTokens(n) { return n < 1000 ? String(Math.round(n)) : n < 1e6 ? +(n / 1e3).toFixed(1) + 'k' : +(n / 1e6).toFixed(1) + 'M'; }
  function fmtDur(ms) { var m = Math.round((ms || 0) / 60000); return m < 60 ? m + 'm' : Math.floor(m / 60) + 'h ' + (m % 60) + 'm'; }

  function resolveVibesData(wsKey) {
    if (demoVibesMode) return SAMPLE_VIBES;
    if (wsKey && meta[wsKey] && meta[wsKey].vibes && meta[wsKey].vibes.present) {
      return meta[wsKey].vibes;
    }
    var keys = Object.keys(meta);
    for (var i = 0; i < keys.length; i++) {
      var v = meta[keys[i]] && meta[keys[i]].vibes;
      if (v && v.present) return v;
    }
    return null;
  }

  function renderVibesSection(wsKey) {
    var v = resolveVibesData(wsKey);
    var chip = el('vibes-status-chip');
    var demoBtn = el('vibes-demo-btn');

    if (v && v.present) {
      chip.className = v.isDemo ? 'badge-chip warn' : 'badge-chip cyan';
      chip.textContent = v.isDemo
        ? '★ Interactive Reference VIBES (.ai-audit/) Preview Active'
        : '● VIBES (.ai-audit/) Active · PreToolUse Immutability Shield Armed';
      demoBtn.textContent = v.isDemo ? 'Exit Reference Preview' : 'Toggle Reference Preview';
    } else {
      chip.className = 'badge-chip warn';
      chip.textContent = '○ .ai-audit/ Not Detected in Workspace · Click Preview or Initialize VIBES';
      demoBtn.textContent = 'Preview Reference VIBES Telemetry';
    }

    var activeV = v || {
      present: false,
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
      filesTouchedCount: 0,
      prismBuckets: { low: 0, moderate: 0, high: 0, critical: 0 },
      fileHotspots: [],
      decisionRecords: [],
      incidentRecords: []
    };

    var annCnt = activeV.annotationsCount || 0;
    var verPct = annCnt > 0 ? Math.round(((activeV.verifiedCount || 0) / annCnt) * 100) : 0;
    el('vp-prov').textContent = annCnt + ' annotations';
    el('vp-prov-sub').textContent = (activeV.blobsCount || 0) + ' SHA-256 blobs · ' + (activeV.filesTouchedCount || 0) + ' files';
    el('vp-verify').textContent = verPct + '% verified';
    el('vp-verify-sub').textContent = (activeV.attestationsCount || 0) + ' DSSE attestations · Guard locked';
    el('vp-prism').textContent = Number(activeV.maxPrismRisk || 0).toFixed(2) + ' max risk';
    el('vp-prism-sub').textContent = (activeV.highRiskCount || 0) + ' High/Critical (>= 0.60)';
    el('vp-evolve').textContent = (activeV.decisions || 0) + ' decisions';
    el('vp-evolve-sub').textContent = 'Cross-checked by /neckbeard-debt';
    el('vp-trace').textContent = (activeV.traceResolved || 0) + ' / ' + (activeV.traceIncidents || 0) + ' fixed';
    el('vp-trace-sub').textContent = (activeV.iocRulesCount || 0) + ' custom IoC rules in iocs.d/';

    var svgBox = el('vibes-svg');
    if (svgBox) {
      svgBox.textContent = '';
      var NS = 'http://www.w3.org/2000/svg';
      function node(t, a, p, txt) {
        var n = document.createElementNS(NS, t);
        for (var k in a) n.setAttribute(k, a[k]);
        if (txt != null) n.textContent = txt;
        if (p) p.appendChild(n);
        return n;
      }

      // Left Chart: PRISM v1.0 Risk Distribution Histogram
      node('text', { x: 20, y: 24, fill: '#06b6d4', 'font-size': 12.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, 'PRISM v1.0 RISK SCORE DISTRIBUTION (.ai-audit/annotations.jsonl)');
      var pb = activeV.prismBuckets || {};
      var buckets = [
        ['Low (< 0.30)', pb.low || 0, '#10b981'],
        ['Moderate (0.30–0.59)', pb.moderate || 0, '#06b6d4'],
        ['High (0.60–0.79) [Review Gate]', pb.high || 0, '#f59e0b'],
        ['Critical (>= 0.80) [Must Fix]', pb.critical || 0, '#ef4444']
      ];
      var maxBucket = Math.max(1, pb.low || 0, pb.moderate || 0, pb.high || 0, pb.critical || 0);
      buckets.forEach(function(b, idx) {
        var y = 48 + idx * 46;
        node('text', { x: 20, y: y + 14, fill: '#ecf3ef', 'font-size': 11, 'font-family': 'monospace' }, svgBox, b[0]);
        node('rect', { x: 235, y: y, width: 170, height: 20, rx: 5, fill: '#101814', stroke: '#1d2b23' }, svgBox);
        var w = Math.max(4, Math.round((b[1] / maxBucket) * 170));
        if (b[1] > 0) node('rect', { x: 235, y: y, width: w, height: 20, rx: 5, fill: b[2] }, svgBox);
        node('text', { x: 415, y: y + 14, fill: b[2], 'font-size': 11.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, String(b[1]));
      });

      // Divider
      node('line', { x1: 465, y1: 14, x2: 465, y2: 235, stroke: '#1d2b23', 'stroke-dasharray': '4,4' }, svgBox);

      // Right Chart: Top Attributed Files & PRISM Risk Hotspots
      node('text', { x: 490, y: 24, fill: '#10b981', 'font-size': 12.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, 'TOP ATTRIBUTED FILES & PRISM RISK HOTSPOTS');
      var hotspots = (activeV.fileHotspots && activeV.fileHotspots.length)
        ? activeV.fileHotspots.slice(0, 5)
        : [{ file: '(No .ai-audit/annotations.jsonl in workspace — click Preview above)', annotations: 0, linesAdded: 0, linesRemoved: 0, maxRisk: 0, verified: false }];

      hotspots.forEach(function(h, idx) {
        var y = 46 + idx * 38;
        var riskColor = h.maxRisk >= 0.8 ? '#ef4444' : h.maxRisk >= 0.6 ? '#f59e0b' : h.maxRisk >= 0.3 ? '#06b6d4' : '#10b981';
        node('text', { x: 490, y: y + 14, fill: '#ecf3ef', 'font-size': 11, 'font-family': 'monospace' }, svgBox, (h.verified ? '✓ ' : '○ ') + h.file.slice(0, 32));
        node('rect', { x: 730, y: y + 2, width: 110, height: 14, rx: 4, fill: '#101814', stroke: '#1d2b23' }, svgBox);
        var rw = Math.max(3, Math.round(Math.min(1, h.maxRisk || 0) * 110));
        if (h.maxRisk > 0) node('rect', { x: 730, y: y + 2, width: rw, height: 14, rx: 4, fill: riskColor }, svgBox);
        node('text', { x: 850, y: y + 13, fill: riskColor, 'font-size': 10.5, 'font-weight': 700, 'font-family': 'monospace' }, svgBox, 'R:' + Number(h.maxRisk || 0).toFixed(2) + ' (+' + h.linesAdded + '/-' + h.linesRemoved + ')');
      });
    }

    var decList = el('vibes-decisions-list');
    decList.textContent = '';
    var decs = (activeV.decisionRecords && activeV.decisionRecords.length)
      ? activeV.decisionRecords
      : [{ id: 'GUARD', title: 'Immutable .ai-audit/{manifest.json,annotations.jsonl,blobs/,attestations/} protected by hooks/guard.js', status: 'armed', timestamp: '' }];
    decs.slice(0, 5).forEach(function(d) {
      var row = document.createElement('div');
      row.textContent = '[' + d.id + '] ' + d.title + ' (' + d.status + ')';
      decList.appendChild(row);
    });

    var incList = el('vibes-incidents-list');
    incList.textContent = '';
    var incs = (activeV.incidentRecords && activeV.incidentRecords.length)
      ? activeV.incidentRecords
      : [{ id: 'TRACE', iocId: 'READY', severity: 'info', status: 'clean', summary: '0 unresolved TRACE incidents or unverified high-risk PRISM edits', timestamp: '' }];
    incs.slice(0, 5).forEach(function(inc) {
      var row = document.createElement('div');
      row.textContent = '[' + inc.iocId + ' · ' + inc.status.toUpperCase() + '] ' + inc.summary;
      incList.appendChild(row);
    });
  }

  function renderTopology(wsKey) {
    var svgBox = el('boundary-svg');
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

    el('pane-vibes').style.display = (activeView === 'overview' || activeView === 'vibes') ? 'block' : 'none';
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

    renderVibesSection(activeWorkspace);
    renderTopology(activeWorkspace);
  }

  var demoBtn = el('vibes-demo-btn');
  if (demoBtn) {
    demoBtn.onclick = function() {
      demoVibesMode = !demoVibesMode;
      render();
    };
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
    var rightWrap = document.createElement('span');
    rightWrap.className = 'ws-badges';
    if (item[0] && meta[item[0]] && meta[item[0]].vibes && meta[item[0]].vibes.present) {
      var vTag = document.createElement('span');
      vTag.className = 'ws-vibes-tag';
      vTag.textContent = 'VIBES';
      rightWrap.appendChild(vTag);
    }
    var countSpan = document.createElement('span');
    countSpan.className = 'ws-count';
    countSpan.textContent = String(item[2]);
    rightWrap.appendChild(countSpan);
    btn.appendChild(nameSpan);
    btn.appendChild(rightWrap);
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
