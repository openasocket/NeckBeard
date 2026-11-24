# NeckBeard — Engineering Specification (`SPEC.md`)

## 1. Goal & Scope

Build and maintain **`NeckBeard`** (`openasocket/NeckBeard`), a standalone, zero-dependency, 8-harness AI agent plugin framework starring **`Ashy Larry`** ↔ **`Ashy Lari`** (`Lawrence` ↔ `Lauren`), Principal Systems, Security & Scale Engineer of the Crew Universe Build Squad (`pipelinePriority: 40`).

NeckBeard enforces three non-negotiable engineering gates (**`Safe`**, **`Fast@Load`**, **`Done`**) atop a 6-rung minimalist question ladder while integrating cleanly with the Crew Universe dynamic self-describing persona protocol (§4.5), 3-Tier Memory (`$CREW_CONFIG_DIR`), VIBES `.ai-audit/` provenance, and **Crew Spark (`✦`)** automations.

---

## 2. Repository Layout

```text
NeckBeard/
├── crew-persona.json                # §4.5 self-describing persona manifest (schemaVersion: 1)
├── AGENTS.md                        # <= 110 line core ruleset (byte-identical to skills/neckbeard/SKILL.md body)
├── SPEC.md                          # This engineering specification
├── README.md                        # Product documentation, gates, badges, install guide
├── INSTALL.md                       # Per-harness installation guide
├── package.json                     # Zero-dependency Node >= 18 package ("name": "neckbeard")
├── plugin.json                      # Antigravity CLI root manifest
├── gemini-extension.json            # Gemini CLI extension manifest
├── .neckbeard.json                  # Shared sanitized project load, trust-boundary & architecture map
├── .crew/
│   └── sparks.example.yaml          # Crew Spark (✦) starter automation recipes
├── .claude-plugin/                  # Claude Code plugin & marketplace manifests
├── .codex-plugin/                   # OpenAI Codex plugin manifest
├── .github/                         # Copilot CLI plugin manifest, copilot-instructions.md, CI workflow
├── .grok-plugin/                    # Grok CLI marketplace manifest
├── .opencode/plugins/neckbeard.mjs  # OpenCode & Kilo Code adapter
├── pi-extension/                    # Pi / Oh My Pi TUI status strip & slash commands
├── agents/                          # Subagent definitions (neckbeard.md, neckbeard-reviewer.md)
├── docs/                            # crew-protocol.md & agent-portability.md
├── skills/
│   ├── plugin.json
│   ├── neckbeard/SKILL.md           # Core question ladder & 3 Gates (Safe, Fast@Load, Done)
│   ├── neckbeard-review/SKILL.md    # Diff/PR 3-gate review with concrete exploits & variant search
│   ├── neckbeard-audit/SKILL.md     # Repo audit (lite / complete) with E_patch vs E_rewrite math
│   ├── neckbeard-debt/SKILL.md      # risk: / shortcut: ledger & load-trigger expiry checks
│   ├── neckbeard-map/SKILL.md       # Trust-boundary & inter-module architecture map builder
│   ├── neckbeard-gain/SKILL.md      # Local telemetry & 5-pillar VIBES Command Center
│   └── neckbeard-memory/SKILL.md    # Unified $CREW_CONFIG_DIR 3-Tier Memory Inspector
├── hooks/
│   ├── claude-hooks.json            # SessionStart, SubagentStart, UserPromptSubmit, PreToolUse
│   ├── claude-band.json             # Claude Code AbovePrompt HUD manifest
│   ├── ensemble.js                  # §4.5 dynamic drop-in peer discovery, anti-hijack & leader election
│   ├── lib.js                       # Levels, hashed per-session state, $CREW_CONFIG_DIR & hook I/O
│   ├── surface.js                   # .neckbeard.json, trust/arch maps, multi-view censorship, inbox writer
│   ├── memory.js                    # Unified $CREW_CONFIG_DIR 3-Tier Memory, compartment wall & GRPO
│   ├── guard.js                     # Fail-closed PreToolUse guard (secrets, .ai-audit/**, dynamic siblings, obfuscation)
│   ├── prompt.js                    # UserPromptSubmit command router (/neckbeard, /larry, /lari, memory)
│   ├── session-start.js             # Token-budgeted SessionStart context (<= 1100t solo empty)
│   ├── subagent-start.js            # SubagentStart context propagation
│   ├── vibes.js                     # Read-only .ai-audit/ VIBES 5-pillar reader
│   ├── band-import.js               # Local telemetry aggregator & self-contained HTML Command Center
│   └── band/                        # Claude Code AbovePrompt HUD TypeScript modules
├── scripts/
│   └── install-all.js               # 8-harness installer + atomic §4.5 drop-in presence registration
└── test/
    ├── hooks.test.js                # Hermetic unit & hostile-vector security tests
    └── portable.test.js             # Manifest parity, schema, ruleset, and doc hygiene tests
```

---

## 3. Mandatory Architectural & Security Contracts

### 3.1 Dynamic Self-Describing Persona & Drop-In Registry (§4.5)
- **`crew-persona.json`** declares `schemaVersion: 1`, `id: "neckbeard"`, `handle: "NeckBeard"`, `kind: "universal"`, `squad: "build"`, `pipelinePriority: 40`, `storeFile: ".neckbeard.json"`, `wireEnvelope: "[NECKBEARD-GATE]"`, `themePosture: "dark-only"`, `gates: ["Safe","Fast@Load","Done"]`, `memoryNamespace: "memory/agents/neckbeard"`, `enclaveAware: true`, and `installerScript: "scripts/install-all.js"`.
- **`scripts/install-all.js`** validates `crew-persona.json` and, unless `--dry-run`, atomically writes (tmp + rename) ONLY `$CREW_CONFIG_DIR/registry/personas/neckbeard.json` and appends one `< 4096B` LF-only presence event to `$CREW_CONFIG_DIR/registry/presence.jsonl`. On `--dry-run`, logs the target path without touching disk.
- **`hooks/ensemble.js`** reads valid `*.json` descriptors from `$CREW_CONFIG_DIR/registry/personas/` merged with the built-in 13-persona fallback (`headhoncho:10 .. dealmaker:130`), enforces anti-hijack invariants (rejects symlinks, files `> 32768` bytes, invalid JSON, invalid `id` `!/^[a-z][a-z0-9-]{1,47}$/`, `storeFile !== "." + id + ".json"`, and secrets/URLs/local paths; clamps any non-core/unsigned descriptor `pipelinePriority < 200` to `200`), and sorts deterministically by `(pipelinePriority ASC, id ASC)`.

### 3.2 Fail-Closed `PreToolUse` Guard (`hooks/guard.js`)
At `full` and `paranoid` levels, `hooks/guard.js` enforces:
1. **Immutable VIBES `.ai-audit/**`:** Blocks ALL `Write`/`Edit`/`MultiEdit`/`NotebookEdit` and mutating `Bash` operations targeting any path under `.ai-audit/**`. Read-only inspection and official `vibecheck`/`vibetrace` CLIs remain allowed.
2. **Read-Only `.crew.json`:** Blocks all file and shell mutations targeting `.crew.json`.
3. **Dynamic Sibling Store Protection:** Dynamically collects every OTHER registered persona's `storeFile` from `$CREW_CONFIG_DIR/registry/personas/*.json` merged with the 13-persona fallback and unconditionally blocks writes/edits/shell mutations to every sibling `.<peer>.json` store (Single-Owner Store Rule).
4. **Multi-View Censorship on `.neckbeard.json` & `.rainmaker-inbox.jsonl`:** Inspects raw, NFKC/invisible-stripped, JSON-unicode/hex-unescaped (`\u002fUsers\u002f...`), URL-decoded, and bounded Base64-decoded views (`ghp_...`, `AKIA...`, etc.) to block obfuscated local paths, URLs, IPs, emails, internal hostnames, and secrets across `Write`/`Edit`/`MultiEdit`/`Bash`.
5. **Anti-Memory-Poisoning & Compartment Wall:** Blocks untrusted markers targeting `$CREW_CONFIG_DIR` `preferences.jsonl` or `learned-skills/`, blocks regulated markings (`CUI//`, `ITAR`, `HIPAA-PHI`, `PCI-PAN`) from entering commercial `memory/`, and enforces `< 4096B` LF-only JSONL records.

### 3.3 Unified `$CREW_CONFIG_DIR` 3-Tier Memory (`hooks/memory.js`)
- Tier 1 (`memory/agents/neckbeard/`): bounded `preferences.jsonl` (`<= 24`), `insights.jsonl` (`<= 40`), `learned-skills/<slug>.md` (`<= 20`), `dead-ends.jsonl` (`<= 32`).
- Tier 2 (`memory/teams/<team-slug>/`): `canon-truth.json`, `causal-graph.jsonl`.
- Tier 3 (`memory/grpo-signals.jsonl`): passive outcome scoring & Deviation-Driven top-K injection (`<= 1,500–2,500` tok; compact SessionStart digest `<= 800` tok; `0` tok when empty).
- Regulated compartments (`cmmc`, `finsec`, `hipaa`) stay strictly under `$CREW_CONFIG_DIR/enclaves/<enclave-id>/`.
- Inspector CLI & `/neckbeard-memory` skill expose `inspect`, `pin`, `unpin`, `edit`, `forget`, and `reset`.

### 3.4 Token Budget, Execution Discipline & Interop Envelopes
- `AGENTS.md` `<= 110` lines; solo empty `hooks/session-start.js` stdout `<= 1,100` tokens.
- Supports `[NECKBEARD-GATE]`, `[NECKBEARD-DONE]`, `[CREW-PUSHBACK]`, and `[CREW-SYNC]` wire envelopes and `.crew/sparks.yaml` (`crew spark`) with optional `.maestro/cue.yaml` read-fallback note.
- **Verbatim Output Proof (`Pasted, Not Summarized`):** `[NECKBEARD-DONE]` and the `Done` gate require raw verbatim worktree command stdout and exit code; prose summaries alone fail.
- **Worktree Autopilot & Bounded Cross-Family Review (`INV-LLM-06`, `INV-LLM-07`):** Unattended Autopilot runs strictly inside isolated worktrees with dedicated `CREW_PORT_BASE`, `CREW_DB_PATH`, and `CREW_TMP_DIR` allocations while respecting `[PROPELLERHEAD-SPEC]` `filesOutOfScope` fences. Recommend cross-model-family `neckbeard-reviewer` / `EdgeLord` review whenever `>= 2` model families exist and halt builder↔reviewer loops at max 3 rounds for escalation.

---

## 4. Verification & Acceptance Criteria

1. `npm test` runs `node --test test/*.test.js` with zero external dependencies and 100% pass rate.
2. `node scripts/install-all.js --dry-run` exits `0` without writing to disk.
3. Hermetic tests prove `crew-persona.json` schema parity, atomic registration + `--dry-run`, 14th synthetic persona discovery & sibling-store blocking, anti-hijack priority clamping & `.crew.json` rejection, all 5 hostile guard vectors (`aiM`, `aiU`, `sib`, `uEs`, `b64`), 3-Tier Memory compartment isolation & anti-poisoning, and solo empty `session-start.js` stdout `<= 1,100` tokens.
4. Zero local paths or secrets in any tracked file.
