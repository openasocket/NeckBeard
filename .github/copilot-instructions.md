# Copilot Instructions

Follow `AGENTS.md` in the repository root for every coding task. All rules, framing questions, the question ladder, and the gates live there—do not maintain a separate copy here.

Skills in `skills/`:
- `neckbeard` — default coding rules and level selection (`lite`, `full`, `paranoid`, `off`).
- `neckbeard-review` — review a change against the rules in `skills/neckbeard/SKILL.md`.
- `neckbeard-audit` — repo audit in `lite` mode (default: targeted execution flows & major data/trust boundaries) or `complete` mode (every code, config, and doc file, with an upfront time/token/tool-call warning).
- `neckbeard-debt` — scan and check `risk:` and `shortcut:` comments.
- `neckbeard-gain` — local telemetry report and HTML board (tokens, cost, reuse %, refactor delta, security blocks, and `.ai-audit/` VIBES metrics).
