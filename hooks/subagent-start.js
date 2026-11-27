'use strict';
const _act = require('./activation');
// SubagentStart: inject NeckBeard ruleset only when the spawned subagent matches NeckBeard
// (or in Singleton / CREW_EAGER_LOAD=1 mode). Skips utility subagents (Explore/Plan/research)
// and sibling Crew persona subagents to avoid multi-thousand-token context bloat.
// NECKBEARD_SUBAGENTS=0 turns this off completely.

const { readInput, readLevel, emitContext, rules,   stateDir,
  defaultLevel,
} = require('./lib');
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
  const _sid = input.session_id || input.sessionId || '';
  const _cwd0 = input.cwd || process.cwd();
  const _ens0 = detectCrewEnsemble('neckbeard', _cwd0, process.env);
  if (_act.isSubagentUtilityOrSibling('neckbeard', input, _ens0)) return;
  const _selfSub = _act.isSubagentTargetingSelf('neckbeard', input);
  const _sDir = typeof stateDir === 'function' ? stateDir(process.env) : null;
  const _actRes = _act.resolveActivation('neckbeard', _sid, process.env, {
    personaStateDir: _sDir,
    defaultLevelFn: typeof defaultLevel === 'function' ? defaultLevel : null,
  });
  if (!_selfSub && !_actRes.active) return;
  const level = _actRes.active ? _actRes.level : (typeof defaultLevel === 'function' && defaultLevel(process.env) !== 'off' ? defaultLevel(process.env) : 'full');
  if (!_selfSub && _actRes.mode === 'crew') {
    if (_ens0.isEnsembleLeader || (_ens0.installedPeers && _ens0.installedPeers.length <= 1)) {
      const roster = _act.formatCrewRosterBanner(_ens0, level);
      if (roster) emitContext('SubagentStart', roster);
    }
    return;
  }

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
