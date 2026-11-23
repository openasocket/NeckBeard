'use strict';
// Smart Singleton vs. Multi-Peer Ensemble Coexistence Helper (`hooks/ensemble.js`).
// 1. Singleton / Solo Persona (only 1 Crew plugin detected, or CREW_SOLO_PERSONA=neckbeard):
//    - Emits exact solo rules(level) and mandatory 3-line footer unchanged.
// 2. Multi-Peer Ensemble (2+ Crew plugins installed together on the same harness):
//    - Elects a single deterministic Ensemble Leader (pipeline order:
//      rainmaker -> propellerhead -> neckbeard -> hipster -> edgelord) so `Crew Peers [active]`
//      is emitted once instead of 5 times.
//    - Adapts 'End every reply with ...' to domain-routed Ensemble mode so multiple
//      installed Crew plugins never demand competing reply footers at once.

const fs = require('fs');
const os = require('os');
const path = require('path');

const CREW_PIPELINE_ORDER = ['rainmaker', 'propellerhead', 'neckbeard', 'hipster', 'edgelord'];

const CREW_STORE_FILES = {
  rainmaker: '.rainmaker.json',
  propellerhead: '.propellerhead.json',
  neckbeard: '.neckbeard.json',
  hipster: '.hipster.json',
  edgelord: '.edgelord.json',
};

function getHomeDir(env = process.env) {
  return env.HOME || env.USERPROFILE || os.homedir();
}

function detectCrewEnsemble(selfId, cwd = process.cwd(), env = process.env) {
  const normalizedSelf = String(selfId || 'neckbeard').toLowerCase().trim() || 'neckbeard';
  if (env.CREW_SOLO_PERSONA && env.CREW_SOLO_PERSONA.toLowerCase().trim() === normalizedSelf) {
    return {
      selfId: normalizedSelf,
      installedPeers: [normalizedSelf],
      isEnsemble: false,
      isEnsembleLeader: true,
      leaderId: normalizedSelf,
    };
  }

  const home = getHomeDir(env);
  const claudeRoot = env.CLAUDE_CONFIG_DIR || path.join(home, '.claude');
  const detected = new Set();
  if (CREW_PIPELINE_ORDER.includes(normalizedSelf)) {
    detected.add(normalizedSelf);
  }

  let claudeEnabled = null;
  const claudeSettingsPath = path.join(claudeRoot, 'settings.json');
  if (fs.existsSync(claudeSettingsPath)) {
    try {
      const s = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'));
      if (s && s.enabledPlugins && typeof s.enabledPlugins === 'object') {
        claudeEnabled = s.enabledPlugins;
      }
    } catch {}
  }

  for (const id of CREW_PIPELINE_ORDER) {
    if (claudeEnabled && claudeEnabled[`${id}@${id}`] === true) {
      detected.add(id);
      continue;
    }
    if (fs.existsSync(path.join(claudeRoot, 'plugins', 'marketplaces', id))) {
      if (!claudeEnabled || claudeEnabled[`${id}@${id}`] !== false) {
        detected.add(id);
        continue;
      }
    }
    if (fs.existsSync(path.join(home, '.codex', 'plugins', 'cache', id))) {
      detected.add(id);
      continue;
    }
    if (fs.existsSync(path.join(home, '.gemini', 'config', 'plugins', id))) {
      detected.add(id);
      continue;
    }
    if (cwd && fs.existsSync(path.join(cwd, CREW_STORE_FILES[id]))) {
      detected.add(id);
    }
  }

  const installedPeers = CREW_PIPELINE_ORDER.filter((id) => detected.has(id));
  const leaderId = installedPeers[0] || normalizedSelf;
  const isEnsemble = installedPeers.length >= 2;
  const isEnsembleLeader = leaderId === normalizedSelf;

  return {
    selfId: normalizedSelf,
    installedPeers,
    isEnsemble,
    isEnsembleLeader,
    leaderId,
  };
}

function formatEnsembleRules(rawRulesText, ensembleInfo) {
  const text = String(rawRulesText || '');
  if (!ensembleInfo || !ensembleInfo.isEnsemble) {
    return text;
  }

  const adapted = text.replace(
    /End every reply with ([^.\n]+)\./i,
    'When acting as the lead specialist for this domain (or when invoked directly via its slash command / subagent), end your reply with $1.'
  );

  if (ensembleInfo.isEnsembleLeader) {
    const header =
      `[5-Character Crew Ensemble Active: ${ensembleInfo.installedPeers.join(' -> ')}]\n` +
      'Multiple Crew Universe personas are installed in unison on this harness. Apply every active persona\'s 3 Gates to its domain (RainMaker for scope/cutline/ROI, PropellerHead for DAG decomposition & root-cause invariants, NeckBeard for Safe/Fast@Load/Done implementation, Hipster for <5s UX/DX & live-glass verification, EdgeLord for hostile red-team & chaos testing). Use the 3-line footer of the persona that owns the primary task domain rather than stacking all 5 footers on one reply.\n\n';
    return header + adapted;
  }

  return adapted;
}

module.exports = {
  CREW_PIPELINE_ORDER,
  CREW_STORE_FILES,
  detectCrewEnsemble,
  formatEnsembleRules,
};
