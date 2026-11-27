'use strict';
// SessionStart: load the NeckBeard ruleset for this session's level.
// In Multi-Peer Ensemble mode (default lazy loading; CREW_EAGER_LOAD=1 for upfront):
//   - Only the elected Ensemble Leader emits a compact Crew Roster Index (~250 tokens).
//   - Non-leader peers defer (0 bytes) and hydrate on demand via UserPromptSubmit when relevant.
// In Singleton mode (or CREW_SOLO_PERSONA=neckbeard), loads immediately.

const path = require('path');
const { execFileSync } = require('child_process');
const { readInput, readLevel, writeLevel, stateDir, emitContext, rules } = require('./lib');
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

module.exports = { buildFullNeckbeardContext };

if (require.main === module) {
  (async () => {
    const input = await readInput();
    const level = readLevel(input.session_id);
    try { writeLevel(input.session_id, level); } catch { /* state is best-effort */ }
    if (level === 'off') return;

    const cwd = input.cwd || process.cwd();
    const ensembleInfo = detectCrewEnsemble('neckbeard', cwd, process.env);
    if (shouldDeferSessionStart(ensembleInfo, process.env)) {
      if (ensembleInfo.isEnsembleLeader) {
        let roster = formatEnsembleRosterIndex(ensembleInfo);
        try {
          const ctx = formatProjectContext(cwd, process.env, { includeCrewContext: true });
          const peersLine = ctx && ctx.split('\n').find((l) => l.includes('Crew Peers [active]'));
          if (peersLine) roster += '\n' + peersLine;
        } catch { /* best-effort */ }
        if (roster) emitContext('SessionStart', roster);
      }
      return;
    }

    const text = buildFullNeckbeardContext(input, process.env, ensembleInfo, level);
    markPersonaHydrated('neckbeard', input.session_id, stateDir());
    if (text) emitContext('SessionStart', text);
  })().finally(() => setTimeout(() => process.exit(0), 0));
}
