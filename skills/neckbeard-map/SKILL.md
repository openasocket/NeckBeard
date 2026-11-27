---
name: neckbeard-map
description: >
  Scan, build, and refresh the project's External/Internal Trust-Boundary Map
  (boundaries) and System Architecture & Inter-Module Data-Flow Map
  (architecture) in .neckbeard.json (or ~/.config/neckbeard/projects/ when
  shared: false) and ~/.config/neckbeard/telemetry/workspaces-meta.json. Use for
  /neckbeard-map, "/neckbeard map", "map this repo", "refresh the boundary map",
  or "generate the architecture map".
argument-hint: "[--uncapped]"
disable-model-invocation: true
---

# Neckbeard Map

Scan the repository's tracked production source files, refresh both `"boundaries"` and `"architecture"` in `.neckbeard.json` (or `~/.config/neckbeard/projects/<repo>.json` when `shared: false`), and sync the workspace topology into `~/.config/neckbeard/telemetry/workspaces-meta.json` and `dashboard.html`.

## Execution

1. Run `node <neckbeard-root>/hooks/surface.js --map` in the target repository root (where `<neckbeard-root>` is the repository root or installed plugin directory such as `~/.claude/plugins/marketplaces/neckbeard` or `~/.gemini/config/plugins/neckbeard`). The default cap is `20,000` source files; if exceeded, `surface.js` emits an explicit cap notice showing the exact file count vs. cap rather than silently truncating—re-run with `--uncapped` (or `NECKBEARD_UNCAPPED=1`, or `/neckbeard-map --uncapped`) for massive repos exceeding `20,000` files.
2. Run `node <neckbeard-root>/hooks/band-import.js --summary` in the target repository root (with `NECKBEARD_UNCAPPED=1` when uncapped) so `~/.config/neckbeard/telemetry/workspaces-meta.json` and `~/.config/neckbeard/telemetry/dashboard.html` immediately reflect the refreshed boundary and architecture maps.

## Report Format

Present the refreshed map concisely:
- **Storage & Load Target:** Whether `.neckbeard.json` is shared in Git (`shared: true`) or local (`shared: false`), plus the active load target and any per-boundary load overrides (`boundaryLoad`).
- **Security Trust Boundaries (`boundaries`):**
  - **External Perimeter (`[ext]`):** `ingress` (`http-in`, `cli-in`, `webhook-in`), `egress` (`http-out`), and `supply` (`ci`).
  - **Internal Privileged Sinks (`[int]`):** `auth` (`auth`), `data` (`sql`, `fs`, `serde`), `exec` (`proc`, `crypto`, `env`), and `ai` (`ai`).
  - **Cross-Boundary Bridges (`[ext] ➔ [int]`):** Source files that accept external input and directly reach internal privileged sinks.
- **System Architecture & Inter-Module Data Flow (`architecture`):**
  - **Subsystems & Roles (`moduleCount` modules, `fileCount` tracked files):** Each module's classified role (`gateway`, `interface`, `service`, `persistence`, `security`, `runtime`, `pipeline`, `core`), file count, and bridge count (`<module>:<role>(<files>f,<bridges>b)`).
  - **Directed Inter-Module Data Flows (`flowCount` edges):** `<fromModule>-><toModule>` dependency and data-flow edges.
