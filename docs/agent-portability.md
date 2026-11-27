# Agent Portability

<p align="left">
  <a href="https://neckbeard.tech"><img src="../assets/badge.png" width="456" height="28" alt="NeckBeard Audited: Minimal Code · Boundary Safe · Right-Sized Scale"></a>
</p>

NeckBeard is a host-portable principal-engineer skillset. The writing rules and gates live in one place—[`skills/neckbeard/SKILL.md`](../skills/neckbeard/SKILL.md) and [`AGENTS.md`](../AGENTS.md)—and host-specific manifests are thin pointers that never fork or restate those gates.

## Host Matrix

| Host | Manifest / Files | Behavior |
|---|---|---|
| **Claude Code** | [`.claude-plugin/plugin.json`](../.claude-plugin/plugin.json), [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json), [`hooks/claude-hooks.json`](../hooks/claude-hooks.json), [`hooks/claude-band.json`](../hooks/claude-band.json), `skills/` | Loads the five skills, all four lifecycle hooks (`SessionStart`, `SubagentStart`, `UserPromptSubmit`, and the `PreToolUse` secret/VIBES/config-censor guard), and the `AbovePrompt` telemetry HUD + local Command Center (`~/.config/neckbeard/telemetry/dashboard.html`). |
| **Codex** | [`.codex-plugin/plugin.json`](../.codex-plugin/plugin.json), [`hooks/claude-hooks.json`](../hooks/claude-hooks.json), `skills/` | Loads the five skills and `hooks/claude-hooks.json` for session activation and level/load/map/share/band commands (`$neckbeard`, `/neckbeard`, or `@neckbeard`). |
| **GitHub Copilot CLI** | [`.github/plugin/plugin.json`](../.github/plugin/plugin.json), [`AGENTS.md`](../AGENTS.md), [`.github/copilot-instructions.md`](../.github/copilot-instructions.md), `skills/` | Loads the five skills without hooks and reads [`AGENTS.md`](../AGENTS.md) / [`.github/copilot-instructions.md`](../.github/copilot-instructions.md) for always-on coding rules. |
| **GitHub Copilot Editor & Antigravity IDE** | [`AGENTS.md`](../AGENTS.md), [`.github/copilot-instructions.md`](../.github/copilot-instructions.md) | Read [`AGENTS.md`](../AGENTS.md) from the open repository root as always-on workspace instructions. |
| **Antigravity CLI** | [`plugin.json`](../plugin.json), [`skills/plugin.json`](../skills/plugin.json), `skills/` | Loads the five skills without hooks. |
| **Grok Build** | [`.grok-plugin/marketplace.json`](../.grok-plugin/marketplace.json), `skills/` | Loads the five skills from `./skills` without hooks. |
| **Pi (`pi`) & Oh My Pi (`omp`)** | [`package.json`](../package.json) (`"pi"`), [`pi-extension/index.js`](../pi-extension/index.js), `skills/` | Renders a live TUI status bar (`ctx.ui.setStatus`), injects the active ruleset + `.neckbeard.json` load/boundary map + VIBES summary on `before_agent_start`, and registers `/neckbeard*` commands. |
| **OpenCode & Kilo Code** | [`.opencode/plugins/neckbeard.mjs`](../.opencode/plugins/neckbeard.mjs), `skills/` | Server plugin (V1 & V2) injecting the ruleset, `.neckbeard.json` load/boundary map, and VIBES summary on every turn (`context` and `compaction`) and registering the five skills. |
| **Gemini CLI** | [`gemini-extension.json`](../gemini-extension.json), [`AGENTS.md`](../AGENTS.md), `skills/` | Loads [`AGENTS.md`](../AGENTS.md) via `contextFileName` and discovers `skills/`. Because `hooks/hooks.json` does not exist, Gemini CLI never collides with Claude hook event names. |
| **Cursor** | [`.cursor-plugin/plugin.json`](../.cursor-plugin/plugin.json), [`.cursor-plugin/marketplace.json`](../.cursor-plugin/marketplace.json), [`rules/neckbeard.mdc`](../rules/neckbeard.mdc), [`hooks/cursor-hooks.json`](../hooks/cursor-hooks.json), [`hooks/cursor-adapter.js`](../hooks/cursor-adapter.js), `skills/`, `agents/` | Native Cursor plugin: lazy `.mdc` rule (`alwaysApply: false`), skill & subagent discovery, and Cursor v1 lifecycle hooks (`sessionStart`, `subagentStart`, `beforeSubmitPrompt`, `preToolUse` with exit code `2` guard blocking). Keeps `hooks/hooks.json` strictly absent so Claude/Copilot/Gemini never collide. |
| **Windsurf, Kiro** | [`AGENTS.md`](../AGENTS.md) | Do not read `AGENTS.md` unless their own rules file (`.windsurf/rules/`, `.kiro/steering/`) includes it. |
| **Any other agent** | [`AGENTS.md`](../AGENTS.md) | Copy `AGENTS.md` into the root of the project. |

## Cross-Platform Multi-Harness Auto-Discovery & Sync (`scripts/install-all.js`)

Running `node scripts/install-all.js` (or `npm run sync`) on Windows, macOS, or Linux automatically detects all 9 installed agent harnesses from the matrix above, runs their CLI marketplace/update commands (`spawnSync` argument arrays), syncs their local plugin cache directories (`~/.claude/plugins`, `~/.codex/plugins`, `~/.grok/installed-plugins`, `~/.gemini/config/plugins`, `~/.gemini/extensions`, `~/.pi/agent/extensions`, `~/.config/opencode/plugins`, `~/.cursor/{plugins,skills,agents,rules,hooks.json}`) to the current NeckBeard version, disables legacy `ponytail@ponytail` collisions, and rebuilds `~/.config/neckbeard/telemetry/dashboard.html`.

## Adapter Invariants (Enforced by `npm test`)

1. **Single source of truth:** The body of [`skills/neckbeard/SKILL.md`](../skills/neckbeard/SKILL.md) after YAML frontmatter and [`AGENTS.md`](../AGENTS.md) are byte-for-byte identical.
2. **No auto-discovered Claude hook collisions:** `hooks/hooks.json` must never exist; only `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` reference [`hooks/claude-hooks.json`](../hooks/claude-hooks.json), and only `.cursor-plugin/plugin.json` references [`hooks/cursor-hooks.json`](../hooks/cursor-hooks.json).
3. **Report skills reference the gates instead of copying them:** [`skills/neckbeard-review/SKILL.md`](../skills/neckbeard-review/SKILL.md), [`skills/neckbeard-audit/SKILL.md`](../skills/neckbeard-audit/SKILL.md), and [`skills/neckbeard-debt/SKILL.md`](../skills/neckbeard-debt/SKILL.md) point at [`skills/neckbeard/SKILL.md`](../skills/neckbeard/SKILL.md).
