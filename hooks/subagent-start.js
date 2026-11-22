'use strict';
// SubagentStart: session context never reaches subagents, so hand them the ruleset,
// project load default + trust-boundary map, and VIBES summary too.
// NECKBEARD_SUBAGENTS=0 turns this off.

const { readInput, readLevel, emitContext, rules } = require('./lib');
const { readProjectConfig, formatProjectContext } = require('./surface');
const { hasVibes, formatVibesContext } = require('./vibes');

(async () => {
  if (process.env.NECKBEARD_SUBAGENTS === '0') return;
  const input = await readInput();
  const level = readLevel(input.session_id);
  if (level === 'off') return;

  const cwd = input.cwd || process.cwd();
  let text = rules(level);
  try {
    if (readProjectConfig(cwd) || process.env.NECKBEARD_SURFACE === '1') {
      const ctx = formatProjectContext(cwd);
      if (ctx) text += '\n\n' + ctx;
    }
  } catch { /* best-effort */ }
  try {
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
  } catch { /* best-effort */ }

  emitContext('SubagentStart', text);
})().finally(() => setTimeout(() => process.exit(0), 0));
