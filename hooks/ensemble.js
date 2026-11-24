'use strict';
// 13-Persona Universal Crew Singleton vs. Multi-Peer Ensemble Coexistence (`hooks/ensemble.js`)
//
// 1. Singleton / Solo Persona (1 persona detected, or CREW_SOLO_PERSONA=neckbeard):
//    - Emits the full solo NeckBeard ruleset and mandatory 3-line footer unchanged.
// 2. Multi-Peer Ensemble (2+ Crew personas detected across any of the 8 harness plugin roots
//    or repo-local `.{id}.json` stores):
//    - Elects a single deterministic Ensemble Leader using the exact 13-persona
//      `CREW_PIPELINE_ORDER` from Crew/docs/11 §4.1 & CREW_PROTOCOL.md Section 1:
//      headhoncho -> rainmaker -> propellerhead -> neckbeard -> hipster -> edgelord ->
//      infrasmith -> storyteller -> cloutchaser -> userchamp -> redline -> measureup -> dealmaker
//    - Adapts "End every reply with ..." to domain-routed Ensemble mode so active
//      personas never stack competing reply footers at once.
//    - Gates the `[Crew Universe Ensemble Active: ...]` banner and shared
//      `Crew Peers [active]` summary to `isEnsembleLeader === true` so each is
//      emitted once per session.

const fs = require('fs');
const os = require('os');
const path = require('path');

const CREW_PIPELINE_ORDER = [
  'headhoncho',
  'rainmaker',
  'propellerhead',
  'neckbeard',
  'hipster',
  'edgelord',
  'infrasmith',
  'storyteller',
  'cloutchaser',
  'userchamp',
  'redline',
  'measureup',
  'dealmaker',
];

const CREW_STORE_FILES = Object.freeze(
  CREW_PIPELINE_ORDER.reduce((acc, id) => {
    acc[id] = `.${id}.json`;
    return acc;
  }, {})
);

function getHomeDir(env = process.env) {
  return (env && (env.HOME || env.USERPROFILE)) || os.homedir();
}

function safeExists(targetPath) {
  try {
    return Boolean(targetPath) && fs.existsSync(targetPath);
  } catch {
    return false;
  }
}

function safeReadDirLower(dirPath) {
  if (!safeExists(dirPath)) return null;
  try {
    return fs.readdirSync(dirPath).map((entry) => String(entry).toLowerCase());
  } catch {
    return null;
  }
}

function detectCrewEnsemble(selfId, cwd = process.cwd(), env = process.env) {
  const safeEnv = env || process.env;
  const normalizedSelf = String(selfId || 'neckbeard').toLowerCase().trim() || 'neckbeard';

  if (
    safeEnv.CREW_SOLO_PERSONA &&
    String(safeEnv.CREW_SOLO_PERSONA).toLowerCase().trim() === normalizedSelf
  ) {
    return {
      selfId: normalizedSelf,
      installedPeers: [normalizedSelf],
      isEnsemble: false,
      isEnsembleLeader: true,
      leaderId: normalizedSelf,
    };
  }

  const home = getHomeDir(safeEnv);
  const xdgConfig = safeEnv.XDG_CONFIG_HOME || path.join(home, '.config');
  const claudeRoot = safeEnv.CLAUDE_CONFIG_DIR || path.join(home, '.claude');
  const codexRoot = safeEnv.CODEX_HOME || path.join(home, '.codex');
  const copilotRoot = safeEnv.COPILOT_HOME || path.join(home, '.copilot');
  const grokInstalledDir = path.join(home, '.grok', 'installed-plugins');
  const agyPluginsDir = path.join(home, '.gemini', 'config', 'plugins');
  const geminiExtDir = path.join(home, '.gemini', 'extensions');
  const piExtDirs = [
    path.join(home, '.pi', 'agent', 'extensions'),
    path.join(home, '.omp', 'agent', 'extensions'),
    path.join(home, '.omp', 'extensions'),
  ];
  const openCodeDirs = Array.from(
    new Set([
      path.join(xdgConfig, 'opencode', 'plugins'),
      path.join(home, '.config', 'opencode', 'plugins'),
    ])
  );

  const detected = new Set();
  if (CREW_PIPELINE_ORDER.includes(normalizedSelf)) {
    detected.add(normalizedSelf);
  }

  let claudeEnabled = null;
  const claudeSettingsPath = path.join(claudeRoot, 'settings.json');
  if (safeExists(claudeSettingsPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'));
      if (parsed && parsed.enabledPlugins && typeof parsed.enabledPlugins === 'object') {
        claudeEnabled = parsed.enabledPlugins;
      }
    } catch {
      /* ignore malformed settings */
    }
  }

  const grokEntries = safeReadDirLower(grokInstalledDir);
  const copilotInstalledEntries = safeReadDirLower(path.join(copilotRoot, 'installed-plugins'));
  const copilotPluginsEntries = safeReadDirLower(path.join(copilotRoot, 'plugins'));

  for (const id of CREW_PIPELINE_ORDER) {
    // 1. Claude Code (.claude)
    if (claudeEnabled && claudeEnabled[`${id}@${id}`] === true) {
      detected.add(id);
      continue;
    }
    const claudeExplicitlyDisabled = Boolean(
      claudeEnabled && claudeEnabled[`${id}@${id}`] === false
    );
    if (
      !claudeExplicitlyDisabled &&
      (safeExists(path.join(claudeRoot, 'plugins', 'marketplaces', id)) ||
        safeExists(path.join(claudeRoot, 'plugins', 'cache', id)))
    ) {
      detected.add(id);
      continue;
    }

    // 2. OpenAI Codex (.codex)
    if (
      safeExists(path.join(codexRoot, 'plugins', 'cache', id)) ||
      safeExists(path.join(codexRoot, 'plugins', id))
    ) {
      detected.add(id);
      continue;
    }

    // 3. GitHub Copilot CLI (.copilot)
    if (
      safeExists(path.join(copilotRoot, 'plugins', id)) ||
      safeExists(path.join(copilotRoot, 'installed-plugins', id)) ||
      safeExists(path.join(copilotRoot, 'plugins', 'cache', id)) ||
      safeExists(path.join(copilotRoot, 'marketplace-cache', id)) ||
      (copilotInstalledEntries &&
        copilotInstalledEntries.some((e) => e === id || e.startsWith(`${id}@`))) ||
      (copilotPluginsEntries &&
        copilotPluginsEntries.some((e) => e === id || e.startsWith(`${id}@`)))
    ) {
      detected.add(id);
      continue;
    }

    // 4. Grok CLI (.grok/installed-plugins)
    if (grokEntries && grokEntries.some((e) => e === id || e.startsWith(`${id}-`))) {
      detected.add(id);
      continue;
    }

    // 5. Antigravity CLI (.gemini/config/plugins)
    if (safeExists(path.join(agyPluginsDir, id))) {
      detected.add(id);
      continue;
    }

    // 6. Gemini CLI (.gemini/extensions)
    if (safeExists(path.join(geminiExtDir, id))) {
      detected.add(id);
      continue;
    }

    // 7. Pi / Oh My Pi (.pi/agent/extensions & .omp)
    let foundPi = false;
    for (const dir of piExtDirs) {
      if (
        safeExists(path.join(dir, id)) ||
        safeExists(path.join(dir, `${id}.js`)) ||
        safeExists(path.join(dir, `${id}.mjs`))
      ) {
        foundPi = true;
        break;
      }
    }
    if (foundPi) {
      detected.add(id);
      continue;
    }

    // 8. OpenCode / Kilo Code ($XDG_CONFIG_HOME/opencode/plugins & ~/.config/opencode/plugins)
    let foundOpenCode = false;
    for (const dir of openCodeDirs) {
      if (
        safeExists(path.join(dir, `${id}.mjs`)) ||
        safeExists(path.join(dir, `${id}.js`)) ||
        safeExists(path.join(dir, id))
      ) {
        foundOpenCode = true;
        break;
      }
    }
    if (foundOpenCode) {
      detected.add(id);
      continue;
    }

    // 9. Repo-local single-owner store (.{id}.json)
    if (cwd && safeExists(path.join(cwd, CREW_STORE_FILES[id]))) {
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
    const peers = Array.isArray(ensembleInfo.installedPeers)
      ? ensembleInfo.installedPeers.join(' -> ')
      : '';
    const header =
      `[Crew Universe Ensemble Active: ${peers}]\n` +
      'Multiple Crew Universe personas are active in unison on this harness. Route each task to its owning domain specialist and apply each active persona\'s 3 Gates without stacking competing footers (Governance: HeadHoncho; Build: RainMaker, PropellerHead, NeckBeard, Hipster, EdgeLord; Ship & Run: InfraSmith, UserChamp, RedLine; Growth: StoryTeller, CloutChaser, MeasureUp, DealMaker). Emit only the 3-line footer of the persona owning the primary task domain.\n\n';
    return header + adapted;
  }

  return adapted;
}

module.exports = {
  CREW_PIPELINE_ORDER,
  CREW_STORE_FILES,
  getHomeDir,
  detectCrewEnsemble,
  formatEnsembleRules,
};
