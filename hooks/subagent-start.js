'use strict';
// SubagentStart: inject NeckBeard ruleset only when the spawned subagent matches NeckBeard
// (or in Singleton / CREW_EAGER_LOAD=1 mode). Skips utility subagents (Explore/Plan/research)
// and sibling Crew persona subagents to avoid multi-thousand-token context bloat.
// NECKBEARD_SUBAGENTS=0 turns this off completely.

const { readInput, readLevel, emitContext, rules } = require('./lib');
const {
  detectCrewEnsemble,
  formatEnsembleRules,
  formatEnsembleRosterIndex,
  decideSubagentInjection,
} = require('./ensemble');
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
  const mode = decideSubagentInjection('neckbeard', input, ensembleInfo, process.env);
  if (mode === 'skip') return;
  if (mode === 'roster') {
    const roster = formatEnsembleRosterIndex(ensembleInfo);
    if (roster) emitContext('SubagentStart', roster);
    return;
  }

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
