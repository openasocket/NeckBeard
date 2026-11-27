'use strict';
const _act = require('./activation');
// SessionStart: load the NeckBeard ruleset for this session's level.
// In Multi-Peer Ensemble mode (default lazy loading; CREW_EAGER_LOAD=1 for upfront):
//   - Only the elected Ensemble Leader emits a compact Crew Roster Index (~250 tokens).
//   - Non-leader peers defer (0 bytes) and hydrate on demand via UserPromptSubmit when relevant.
// In Singleton mode (or CREW_SOLO_PERSONA=neckbeard), loads immediately.

const path = require('path');
const { execFileSync } = require('child_process');
const { readInput, readLevel, writeLevel, stateDir, emitContext, rules, defaultLevel } = require('./lib');
const {
  detectCrewEnsemble,
  formatEnsembleRules,
  shouldDeferSessionStart,
  formatEnsembleRosterIndex,
  markPersonaHydrated,
} = require('./ensemble');
const { ensureFreshBoundaryMap, formatProjectContext } = require('./surface');
const { hasVibes, formatVibesContext } = require('./vibes');
const { formatCompactMemoryDigest } = require('./memory');

function buildFullNeckbeardContext(input = {}, env = process.env, ensembleInfoOverride = null, levelOverride = null) {
  const safeInput = input || {};
  const safeEnv = env || process.env;
  const level = levelOverride || readLevel(safeInput.session_id, safeEnv);
  if (level === 'off') return '';

  const cwd = safeInput.cwd || process.cwd();
  const ensembleInfo = ensembleInfoOverride || detectCrewEnsemble('neckbeard', cwd, safeEnv);
  let text = formatEnsembleRules(rules(level), ensembleInfo);

  try {
    ensureFreshBoundaryMap(cwd);
    const ctx = formatProjectContext(cwd, safeEnv, { includeCrewContext: ensembleInfo.isEnsembleLeader });
    if (ctx) text += '\n\n' + ctx;
  } catch { /* best-effort */ }

  try {
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
  } catch { /* best-effort */ }

  try {
    const memDigest = formatCompactMemoryDigest({}, safeEnv);
    if (memDigest) text += '\n\n' + memDigest;
  } catch { /* best-effort */ }

  if (safeEnv.NECKBEARD_SURFACE === '1') {
    try {
      const map = execFileSync(process.execPath, [path.join(__dirname, 'surface.js'), cwd], {
        encoding: 'utf8', timeout: 3000, maxBuffer: 256 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (map) text += '\n\n' + map;
    } catch { /* a slow or failed map never costs the rules */ }
  }
  return text;
}

module.exports = { buildFullNeckbeardContext, buildFullContext: buildFullNeckbeardContext };

if (require.main === module) {
  (async () => {
    const input = await readInput();
    const sessionId = input.session_id || input.sessionId || '';
    const cwd = input.cwd || process.cwd();
    const act = _act.resolveActivation('neckbeard', sessionId, process.env, {
      personaStateDir: typeof stateDir === 'function' ? stateDir() : null,
      defaultLevelFn: typeof defaultLevel === 'function' ? defaultLevel : null,
    });
    if (!act.active) return;
    const level = act.level;
    try { writeLevel(sessionId, level); } catch { /* best-effort */ }
    const ensembleInfo = detectCrewEnsemble('neckbeard', cwd, process.env);
    if (act.mode === 'crew') {
      if (ensembleInfo.isEnsembleLeader || (ensembleInfo.installedPeers && ensembleInfo.installedPeers.length <= 1)) {
        let roster = _act.formatCrewRosterBanner(ensembleInfo, level);
        try {
          const ctx = formatProjectContext(cwd, process.env, { includeCrewContext: true });
          const peersLine = ctx && ctx.split('\n').find((l) => l.includes('Crew Peers [active]'));
          if (peersLine) roster += '\n' + peersLine;
        } catch { /* best-effort */ }
        if (roster) emitContext('SessionStart', roster);
      }
      return;
    }
    if (shouldDeferSessionStart(ensembleInfo, process.env) && act.mode !== 'orchestrated' && act.mode !== 'persona' && act.mode !== 'env') {
      if (ensembleInfo.isEnsembleLeader) {
        const roster = formatEnsembleRosterIndex(ensembleInfo);
        if (roster) emitContext('SessionStart', roster);
      }
      return;
    }
    const text = buildFullNeckbeardContext(input, process.env, ensembleInfo, level);
    _act.markHydrated('neckbeard', sessionId, typeof stateDir === 'function' ? stateDir() : null);
    markPersonaHydrated('neckbeard', sessionId, stateDir());
    if (text) emitContext('SessionStart', text);
  })().finally(() => setTimeout(() => process.exit(0), 0));
}
