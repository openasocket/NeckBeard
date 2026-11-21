# Install

Pick your agent below. Not listed? Most agents read [`AGENTS.md`](AGENTS.md): copy it into your project root, or point your agent at [`skills/neckbeard/SKILL.md`](skills/neckbeard/SKILL.md). For the full host-to-manifest matrix, see [Agent Portability](docs/agent-portability.md).

The Claude Code and Codex plugins run lightweight Node.js lifecycle hooks (`node >= 18`, zero dependencies), so `node` should be on your non-interactive shell `PATH`.

## Claude Code

From the command line:

```bash
claude plugin marketplace add openasocket/NeckBeard
claude plugin install neckbeard@neckbeard
```

Or inside an interactive Claude Code session, as two separate prompts:

```text
/plugin marketplace add openasocket/NeckBeard
```
```text
/plugin install neckbeard@neckbeard
```

Claude Code loads [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) and [`hooks/claude-hooks.json`](hooks/claude-hooks.json), which activates:
- **`SessionStart` & `SubagentStart`:** injects the active level's ruleset from [`skills/neckbeard/SKILL.md`](skills/neckbeard/SKILL.md) (and when `NECKBEARD_SURFACE=1`, the file-path attack-surface map).
- **`UserPromptSubmit`:** switches the session level when you type `/neckbeard lite|full|paranoid|off` or `"stop neckbeard"`.
- **`PreToolUse` secret & command guard:** at `full` (default), blocks hardcoded secrets in `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, and `Bash`; at `paranoid`, also blocks `curl … | sh`, disabled TLS verification, `chmod 777`, `--no-verify`, and literal credentials.

## Codex

```bash
codex plugin marketplace add openasocket/NeckBeard
codex plugin add neckbeard@neckbeard
```

Codex loads [`.codex-plugin/plugin.json`](.codex-plugin/plugin.json), registers the four skills (`$neckbeard`, `$neckbeard-review`, `$neckbeard-audit`, `$neckbeard-debt`), and loads [`hooks/claude-hooks.json`](hooks/claude-hooks.json) for session activation and `$neckbeard` level switching.

## GitHub Copilot CLI

```bash
copilot plugin marketplace add openasocket/NeckBeard
copilot plugin install neckbeard@neckbeard
```

Copilot CLI loads [`.github/plugin/plugin.json`](.github/plugin/plugin.json) (which registers the four skills in `skills/` without hooks) and reads [`AGENTS.md`](AGENTS.md) / [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## Antigravity CLI & Antigravity IDE

```bash
agy plugin install https://github.com/openasocket/NeckBeard
```

- **Antigravity CLI:** reads the root [`plugin.json`](plugin.json) and loads the four skills (`neckbeard`, `neckbeard-review`, `neckbeard-audit`, `neckbeard-debt`) without hooks.
- **Antigravity IDE & GitHub Copilot Editor:** automatically read [`AGENTS.md`](AGENTS.md) (and [`.github/copilot-instructions.md`](.github/copilot-instructions.md)) from the open project root.

## Grok CLI / Grok Build

```bash
grok plugin install openasocket/NeckBeard --trust
```

Plugins in Grok are disabled by default after installation. Enable `neckbeard` interactively via `/plugins` → **Plugins** → press `Space` on `neckbeard`, or enable it in `~/.grok/config.toml`:

```toml
[plugins]
enabled = ["neckbeard"]
```

Start a new session (or reload plugins) and verify with `grok inspect`. Grok loads [`.grok-plugin/marketplace.json`](.grok-plugin/marketplace.json) (`source: "./skills"`), registering `/neckbeard`, `/neckbeard-review`, `/neckbeard-audit`, and `/neckbeard-debt`. For always-on workspace rules without explicit skill invocation, copy [`AGENTS.md`](AGENTS.md) into your project root.

## Gemini CLI

```bash
gemini extensions install https://github.com/openasocket/NeckBeard
```

Loads [`gemini-extension.json`](gemini-extension.json), which sets `contextFileName` to [`AGENTS.md`](AGENTS.md) and discovers `skills/` without auto-loading Claude/Codex hooks (`hooks/hooks.json` is intentionally absent).

## Any Other Host (Cursor, Windsurf, Kiro, OpenCode, Cline, Zed, Amp, Droid)

Copy `AGENTS.md` into the root of a project whose host does not load this plugin. Cursor, Windsurf, and Kiro do not read `AGENTS.md` unless their own rules file includes it (for example, reference `@AGENTS.md` from `.cursor/rules/`, `.windsurf/rules/`, or `.kiro/steering/`).

## Configuration & Environment Variables

No configuration file is required. Optional environment variables and user config:

| Setting | Default | What it does |
|---|---|---|
| `NECKBEARD_LEVEL` | `full` | Default level for new sessions (`lite`, `full`, `paranoid`, `off`). Overrides `~/.config/neckbeard/config.json`. |
| `~/.config/neckbeard/config.json` | `{"defaultLevel":"full"}` | Persistent default level when `NECKBEARD_LEVEL` is unset. |
| `NECKBEARD_SURFACE=1` | `0` (off) | Opts into the regex attack-surface file map on `SessionStart`. |
| `NECKBEARD_SUBAGENTS=0` | `1` (on) | Disables injecting the ruleset into subagents on `SubagentStart`. |
| `NECKBEARD_GUARD=0` | `1` (on) | Disables the `PreToolUse` secret and unsafe-command guard. |
