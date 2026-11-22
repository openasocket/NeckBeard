'use strict';
// SessionStart: load the ruleset for this session's level, inject persisted project load +
// concise trust-boundary map when .neckbeard.json (or local project config) exists, inject
// VIBES (.ai-audit/) summary when present, and include the full attack-surface map when NECKBEARD_SURFACE=1.

const path = require('path');
const { execFileSync } = require('child_process');
const { readInput, readLevel, writeLevel, emitContext, rules } = require('./lib');
const { readProjectConfig, formatProjectContext } = require('./surface');
const { hasVibes, formatVibesContext } = require('./vibes');

(async () => {
  const input = await readInput();
  const level = readLevel(input.session_id); // compact and resume keep the session's level
  try { writeLevel(input.session_id, level); } catch { /* state is best-effort */ }
  if (level === 'off') return;

  const cwd = input.cwd || process.cwd();
  let text = rules(level);

  // Inject persisted load default & concise internal/external trust-boundary map when configured or when NECKBEARD_SURFACE=1.
  try {
    if (readProjectConfig(cwd) || process.env.NECKBEARD_SURFACE === '1') {
      const ctx = formatProjectContext(cwd);
      if (ctx) text += '\n\n' + ctx;
    }
  } catch { /* best-effort */ }

  // Default to VIBES (.ai-audit/) telemetry summary when present.
  try {
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
  } catch { /* best-effort */ }

  if (process.env.NECKBEARD_SURFACE === '1') {
    try {
      const map = execFileSync(process.execPath, [path.join(__dirname, 'surface.js'), cwd], {
        encoding: 'utf8', timeout: 3000, maxBuffer: 256 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (map) text += '\n\n' + map;
    } catch { /* a slow or failed map never costs the rules */ }
  }
  emitContext('SessionStart', text);
})().finally(() => setTimeout(() => process.exit(0), 0));
