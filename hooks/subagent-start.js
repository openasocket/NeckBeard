'use strict';
// SubagentStart: session context never reaches subagents, so hand them the ruleset,
// project load default + trust-boundary map, and VIBES summary too.
// NECKBEARD_SUBAGENTS=0 turns this off.

const { readInput, readLevel, emitContext, rules, detectCrewEnsemble, formatEnsembleRules } = require('./lib');
const { ensureFreshBoundaryMap, formatProjectContext } = require('./surface');
const { hasVibes, formatVibesContext } = require('./vibes');
const { formatCompactMemoryDigest } = require('./memory');

(async () => {
  if (process.env.NECKBEARD_SUBAGENTS === '0') return;
  const input = await readInput();
  const level = readLevel(input.session_id);
  if (level === 'off') return;

  const cwd = input.cwd || process.cwd();
  const ensembleInfo = detectCrewEnsemble('neckbeard', cwd, process.env);
  let text = formatEnsembleRules(rules(level), ensembleInfo);
  try {
    ensureFreshBoundaryMap(cwd);
    const ctx = formatProjectContext(cwd, process.env, { includeCrewContext: ensembleInfo.isEnsembleLeader });
    if (ctx) text += '\n\n' + ctx;
  } catch { /* best-effort */ }
  try {
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
  } catch { /* best-effort */ }
  try {
    const memDigest = formatCompactMemoryDigest({}, process.env);
    if (memDigest) text += '\n\n' + memDigest;
  } catch { /* best-effort */ }

  emitContext('SubagentStart', text);
})().finally(() => setTimeout(() => process.exit(0), 0));
