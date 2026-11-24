# The 5-Character Crew Architecture, Message Protocol & Memory Model

This document defines the inter-agent protocol, single-owner state storage, shared intake queue, message wire envelopes, and cross-session memory/learning architecture for the **5-Character Agent Universe**:

1. 🎯 **`RainMaker`** — **Value Val** (*Value-Based Valentino $\leftrightarrow$ Value-Based Valentina*) — Product Management, Market Analysis, Scope Cutline & Value Gatekeeper
2. 🧢 **`PropellerHead`** — **Decomp Danny** (*Decomp Danny / Daniel $\leftrightarrow$ Decomp Dani / Daniella*) — Forward Systems/Feature Decomposition, Pre-Mortems & Reverse IR / Post-Mortem Forensics
3. 🧔 **`NeckBeard`** — **Ashy Larry** (*Ashy Larry / Lawrence $\leftrightarrow$ Ashy Lari / Lauren*) — Principal Systems, Security & Scale Engineer (`Safe · Fast@Load · Done`)
4. 🎨 **`Hipster`** — **Slick Sammy** (*Slick Sammy: Samuel $\leftrightarrow$ Samantha*) — Human Experience (UX/DX), Design Taste, Visual Polish & Live-Glass E2E Verifier
5. 🧨 **`EdgeLord`** — **Ruckus Ronnie** (*Ruckus Ron / Ronald $\leftrightarrow$ Ruckus Ronica / Veronica*) — Adversarial Red-Team, Hostile Fuzzing, Concurrency Chaos & Boundary-Escape Breaker

---

## 1. Design Principles: Loose Coupling, Single-Owner State & PM Gatekeeping

- **Independent Installation:** Each of the 5 projects is a standalone 8-harness plugin repository (`openasocket/RainMaker`, `openasocket/PropellerHead`, `openasocket/NeckBeard`, `openasocket/Hipster`, `openasocket/EdgeLord`). Any single plugin works on its own with zero errors if the other four are not installed.
- **Automatic Peer Discovery:** When 2 or more Crew plugins are active in a workspace, their `SessionStart` and `SubagentStart` hooks detect each other's repo-local JSON stores and inject a compact `Crew Peers [active]` summary (`<= 240` chars) so every agent and child subagent obeys the active value cutline, root-cause invariants, UX constraints, and security load envelope.
- **Single-Owner State Rule (Zero Write Races):**
  - Each character is the **sole writer** to its own repo-local JSON store (`.rainmaker.json`, `.propellerhead.json`, `.neckbeard.json`, `.hipster.json`, `.edgelord.json`).
  - When running in parallel (e.g., **Claude Agent Teams** with 5 peer instances and child subagents across worktrees), no two characters ever mutate the same JSON file.
- **Shared Lock-Free PM Intake Queue (`.rainmaker-inbox.jsonl`):**
  - Any character or child subagent can **append** newly discovered findings, sibling bug variants, UX friction, or red-team exploits to `.rainmaker-inbox.jsonl`.
  - **Only `RainMaker` (Value Val)** drains, triages, prioritizes, or rejects items from `.rainmaker-inbox.jsonl` into `.rainmaker.json`.
- **Universal Censorship Guard (`PreToolUse`):**
  - Every Crew JSON store and `.rainmaker-inbox.jsonl` is strictly censored against secrets, URLs (`http://`, `https://`), internal hostnames, IPv4/IPv6 addresses, emails, and absolute local filesystem paths (`/Users/...`, `/home/...`, `C:\...`).

---

## 2. Repo-Local State, Memory & Learning Stores (Schemas)

Each character maintains **three tiers of memory**:
1. **Repo-Local Operational State & Learned Invariants (`.<project>.json`)** — Committed to Git by default (`shared: true`; `/<project> share off` moves it to `~/.config/<project>/projects/<repo>-<hash>.json`).
2. **Cryptographic Turn & Incident Provenance (`.ai-audit/` VIBES Protocol)** — Shared content-addressed audit trail (`manifest.json` EVOLVE decisions, `annotations.jsonl` PRISM risk scores, `incidents/<ID>/incident.json` TRACE forensics).
3. **Cross-Workspace Telemetry & Longitudinal Learning (`~/.config/<project>/telemetry/`)** — `sessions.jsonl`, `workspaces-meta.json`, and `dashboard.html`.

### 2.1 `.rainmaker.json` (Sole Owner: `RainMaker` / Value Val)
```json
{
  "shared": true,
  "persona": "valentino",
  "northStar": "1-command multi-harness engineering & security governance with measurable token ROI",
  "activeOutcome": "Ship 2-realm security vs architecture topology switcher with click-to-expand guidance",
  "targetSegment": "Principal engineers, security leads, and AI-native dev teams",
  "cutline": [
    "No cloud SaaS login or external telemetry upload",
    "No custom PDF report builder before v0.4"
  ],
  "budgetCapUsd": 25.0,
  "approvedBacklog": [
    {
      "id": "VAL-01",
      "title": "Add architecture data-flow quantification to .neckbeard.json",
      "userImpact": 9,
      "urgency": 8,
      "ePatchHours": 0.5,
      "valueScore": 144.0,
      "assignedTo": ["propellerhead", "neckbeard", "hipster", "edgelord"],
      "acceptanceProof": "Unit tests + live dashboard.html vm.Script verification",
      "status": "delivered"
    }
  ],
  "valueLearnings": [
    "Cutting external charting libraries kept dashboard.html 100% offline and zero-dependency"
  ]
}
```

### 2.2 `.rainmaker-inbox.jsonl` (Append: Any Crew Agent/Subagent · Drain/Gatekeep: `RainMaker` Only)
Each line is an atomic JSON object appended by `PropellerHead`, `NeckBeard`, `Hipster`, or `EdgeLord`:
```json
{"id":"nb-m3k9a1","timestampIso":"2026-11-22T22:50:00Z","from":"neckbeard","persona":"Ashy Larry","kind":"audit-finding","boundary":"hooks/band-import.js->proc","ePatch":"15m (12 LOC)","summary":"Enforce argument array in background watcher spawn","status":"pending"}
{"id":"ph-a8f2c0","timestampIso":"2026-11-22T22:51:00Z","from":"propellerhead","persona":"Decomp Danny","kind":"variant-cluster","boundary":"hooks/band/dashboard.ts->serde","ePatch":"10m (6 LOC)","summary":"2 sibling template-literal newline escape variants found across dashboard generators","status":"pending"}
{"id":"hp-u4d1e9","timestampIso":"2026-11-22T22:52:00Z","from":"hipster","persona":"Slick Sammy","kind":"ux-friction","boundary":"hooks/band-import.js->cli-in","ePatch":"20m (18 LOC)","summary":"Session Forensics table truncates prompts without hover/click drawer","status":"approved"}
{"id":"el-r9x7b2","timestampIso":"2026-11-22T22:53:00Z","from":"edgelord","persona":"Ruckus Ron","kind":"redteam-breach","boundary":"hooks/surface.js->fs","ePatch":"10m (4 LOC)","summary":"sanitizeArchitecture allowed self-loop flow hooks->hooks and .env module prefix","status":"resolved"}
```

### 2.3 `.propellerhead.json` (Sole Owner: `PropellerHead` / Decomp Danny & Dani)
Stores **both** Forward Decomposition DAGs (`activeSlices`) and Reverse IR / Post-Mortem causal chains & permanent learned invariants (`invariants`, `causalChains`, `premortems`):
```json
{
  "shared": true,
  "persona": "danny",
  "activeInvariant": "Template literals emitting inline <script> blocks must double-escape newlines (\\\\n) and pass vm.Script compilation",
  "activeSlice": "VAL-01: surface.js buildArchitectureMap -> band-import.js workspaces-meta -> test/hooks.test.js",
  "dagSlices": [
    {
      "sliceId": "SLICE-1",
      "parentTaskId": "VAL-01",
      "owner": "neckbeard",
      "module": "hooks",
      "files": ["hooks/surface.js"],
      "dependsOn": [],
      "contract": "Export buildArchitectureMap(root) and sanitizeArchitecture(raw)"
    },
    {
      "sliceId": "SLICE-2",
      "parentTaskId": "VAL-01",
      "owner": "neckbeard",
      "module": "hooks/band",
      "files": ["hooks/band-import.js", "hooks/band/dashboard.ts"],
      "dependsOn": ["SLICE-1"],
      "contract": "Persist ws.architecture in workspaces-meta.json and render inter-module flows"
    }
  ],
  "premortems": [
    {
      "id": "PRE-01",
      "boundary": "hooks/surface.js->fs",
      "hazard": "MAP_BUDGET truncation slicing off Arch Map line when Trust Map is long",
      "mitigation": "Raise MAP_BUDGET to 1200 chars and assert Arch Map presence in unit test"
    }
  ],
  "causalChains": [
    {
      "id": "IR-01",
      "symptom": "dashboard.html rendered blank metrics in browser",
      "trigger": "Added multi-line hover title tooltip to Session Forensics rows",
      "rootMechanism": "Single-escaped \\n inside JS template literal emitted raw newline inside single-quoted JS string in <script>",
      "symptomTrapRejected": "Do not wrap render() in try/catch to hide syntax errors",
      "variantsFound": ["hooks/band-import.js", "hooks/band/dashboard.ts"],
      "invariantId": "INV-01"
    }
  ],
  "invariants": [
    {
      "id": "INV-01",
      "module": "hooks/band",
      "rule": "Every generated dashboard HTML <script> block must compile cleanly via new vm.Script()",
      "testFile": "test/hooks.test.js"
    }
  ]
}
```

### 2.4 `.neckbeard.json` (Sole Owner: `NeckBeard` / Ashy Larry & Lari)
Stores `load`, `boundaryLoad`, `boundaries` (`external` & `internal`), and `architecture` (`fileCount`, `moduleCount`, `bridgeCount`, `flowCount`, `modules`, `flows`).

### 2.5 `.hipster.json` (Sole Owner: `Hipster` / Slick Sammy)
Stores UX/DX taste invariants, 5-second comprehension flows, accessibility/contrast gates, and live-glass E2E verification proofs:
```json
{
  "shared": true,
  "persona": "sammy",
  "activeFlow": "Session Forensics row hover preview + 1-click inline prompt drawer + 2-realm topology pills",
  "glassStatus": "verified-live-dom",
  "designInvariants": [
    "Every KPI card benchmarks the selected workspace against All Workspaces",
    "Every truncated table cell expands inline on click with ▸/▾ affordance",
    "Zero configuration flags required on first install (node scripts/install-all.js)"
  ],
  "frictionRemoved": [
    "Removed confusing 'Target load: unset' from Velocity KPI card in favor of Agent Hours vs Wall-Clock Hours"
  ],
  "liveProofs": [
    {
      "flow": "dashboard.html inline script compilation & 4562-session payload render",
      "surface": "browser-dom + vm.Script",
      "status": "passed"
    }
  ]
}
```

### 2.6 `.edgelord.json` (Sole Owner: `EdgeLord` / Ruckus Ron & Ronica)
Stores red-team attack vectors fired, hostile payloads, concurrency stress tests, and surviving breaches vs. verified blocks:
```json
{
  "shared": true,
  "persona": "ron",
  "vectorsFired": 18,
  "openBreaches": 0,
  "blockedByShield": 18,
  "campaigns": [
    {
      "id": "RT-01",
      "targetBoundary": "hooks/surface.js->fs",
      "vector": "Inject .env:gateway(1f,0b) and self-loop hooks->hooks into sanitizeArchitecture",
      "outcome": "blocked",
      "reproducer": "node --test test/hooks.test.js"
    },
    {
      "id": "RT-02",
      "targetBoundary": "hooks/guard.js->fs",
      "vector": "Attempt path-traversal sed -i against .ai-audit/iocs.d/../manifest.json",
      "outcome": "blocked",
      "reproducer": "node --test test/hooks.test.js"
    }
  ]
}
```

---

## 3. Inter-Agent Wire Message Format (Claude Agent Teams, Swarms & Subagents)

When the 5 characters communicate via **Claude Agent Teams** (`SendMessage` / shared message board), **Antigravity/Codex subagents** (`invoke_subagent` / `send_message`), or **Maestro playbooks**, every message uses a deterministic **Header Tag** + **Body** + **Character Mandatory Footer** so peer agents can parse handoffs with zero ambiguity:

### 3.1 `RainMaker` (Value Val) $\rightarrow$ Crew Assignment Envelope
```text
[RAINMAKER-TASK id=VAL-01 priority=P0 budget=$2.00 assign=propellerhead,neckbeard,hipster,edgelord]
Outcome: Quantify module architecture and inter-module data flows in .neckbeard.json and dashboard.html.
Cutline (Do NOT Build): Do not add external AST parser dependencies or network calls; use zero-dep regex over tracked files.
Acceptance Proof: Unit test in test/hooks.test.js + regenerated dashboard.html passing vm.Script check.

Value targeted: Instant module topology & data-flow visibility at SessionStart and in the Command Center.
Scope cut: External AST dependencies, third-party graph libraries.
Acceptance proof: npm test 21/21 passing + VALID_JS_OK on dashboard.html.
```

### 3.2 `PropellerHead` (Decomp Danny/Dani) $\rightarrow$ Forward Decomp / Reverse IR Envelope
```text
[PROPELLERHEAD-SPEC id=VAL-01 mode=forward|ir slices=2 invariant=INV-01]
Slice 1 (hooks/surface.js): Add ALLOWED_ARCH_ROLES, buildArchitectureMap, sanitizeArchitecture, and Arch Map context line.
Slice 2 (hooks/band-import.js, hooks/band/dashboard.ts): Persist ws.architecture in workspaces-meta.json and display flows.
Pre-Mortem Hazard: MAP_BUDGET=680 will truncate the new Arch Map line; raise MAP_BUDGET to 1200.

Causal chain / DAG: SLICE-1 (surface.js) -> SLICE-2 (band-import.js & dashboard.ts) -> SLICE-3 (test/hooks.test.js).
Symptom traps rejected: Do not compute flows only in browser JS; persist sanitized flows in .neckbeard.json so SessionStart sees them too.
Invariant required: sanitizeArchitecture must reject .env paths, unknown roles, and self-loop flows (mod->mod).
```

### 3.3 `NeckBeard` (Ashy Larry/Lari) $\rightarrow$ Implementation / 3-Gate Review Envelope
`[NECKBEARD-DONE]` and the `Done` gate require **raw verbatim test/command stdout and exit code** from the thread's isolated worktree (prose summaries alone fail). Unattended Autopilot executes strictly inside isolated worktrees with dedicated `CREW_PORT_BASE`, `CREW_DB_PATH`, and `CREW_TMP_DIR` allocations while obeying `[PROPELLERHEAD-SPEC]` `filesOutOfScope` fences (`INV-LLM-06`). Prefer cross-model-family `neckbeard-reviewer` / `EdgeLord` review whenever `>= 2` model families are available, and halt builder↔reviewer loops at max 3 rounds for `[CREW-PUSHBACK]` escalation (`INV-LLM-07`).
```text
[NECKBEARD-DONE id=VAL-01 files=hooks/surface.js,hooks/band-import.js,hooks/band/dashboard.ts,test/hooks.test.js hostile_test=test/hooks.test.js drift=0 exit=0]
Implemented buildArchitectureMap and sanitizeArchitecture using existing listFiles and readHead helpers; added hostile-input test for .env and self-loop flows.
Command: node --test test/hooks.test.js
Stdout (verbatim):
✔ surface map lists file paths by category, never code
ℹ pass 27 | fail 0 (exit 0)

Load assumed: 5,000 local sessions across 60 workspaces, p95 hook latency < 50ms.
Not checked: Python/Go relative package import resolution.
Risk to decide: None.
```

### 3.4 `Hipster` (Slick Sammy) $\rightarrow$ UX/DX & Live-Glass Verification Envelope
```text
[HIPSTER-VERIFIED id=VAL-01 surface=dashboard.html+cli status=PASS]
Verified 2-realm topology switcher pills display live file counts, inter-module flow summary renders cleanly in #topo-summary, and inline script compiles with zero syntax errors.

User flow verified: 1-click toggle between 🛡️ Security Trust Boundaries and 🏗️ System Architecture & Flow + row click drawer.
Friction removed: Surfaced directed inter-module flows directly in the topology subtitle without extra clicks.
Glass/CLI proof: vm.Script compilation + 4,562-session payload verified on ~/.config/neckbeard/telemetry/dashboard.html.
```

### 3.5 `EdgeLord` (Ruckus Ron/Ronica) $\rightarrow$ Adversarial Red-Team & Chaos Envelope
```text
[EDGELORD-REPORT id=VAL-01 vectors=4 breaches=0 status=BULLETPROOF]
Fired hostile module names (.env:gateway(1f,0b)), invalid role enums (bad:unknownrole(1f,0b)), self-loop flows (hooks->hooks), and raw newlines in tooltip strings against surface.js and dashboard.ts. All 4 vectors blocked or sanitized.

Vectors fired: 4 (.env module injection, invalid role enum, self-loop flow, unescaped script newline).
Breaches / survivors: 0 surviving breaches (all caught by sanitizeArchitecture and vm.Script gate).
Reproducer command: node --test test/hooks.test.js
```
