'use strict';
// Dynamic Self-Describing Persona Discovery & Multi-Peer Ensemble Coexistence (`hooks/ensemble.js`)
// Implements Crew/docs/11 Section 4.1 & Section 4.5:
//   - Built-in 13-persona signed fallback map (headhoncho:10 .. dealmaker:130)
//   - Dynamic drop-in discovery from $CREW_CONFIG_DIR/registry/personas/*.json
//   - Strict anti-hijack invariants on load:
//       * reject symlinks (lstatSync().isSymbolicLink()), files > 32768B, invalid JSON,
//         invalid id (!/^[a-z][a-z0-9-]{1,47}$/), storeFile !== "." + id + ".json",
//         and secrets / URLs / local paths
//       * clamp any non-core/unsigned descriptor (kind !== "universal" or id not in official 13)
//         whose pipelinePriority < 200 to 200
//   - Deterministic sorting by (pipelinePriority ASC, id ASC) for ANY N personas.

const fs = require('fs');
const os = require('os');
const path = require('path');

const OFFICIAL_CORE_PRIORITIES = Object.freeze({
  headhoncho: 10,
  rainmaker: 20,
  propellerhead: 30,
  neckbeard: 40,
  hipster: 50,
  edgelord: 60,
  infrasmith: 70,
  storyteller: 80,
  cloutchaser: 90,
  userchamp: 100,
  redline: 110,
  measureup: 120,
  dealmaker: 130,
});

const CREW_PIPELINE_ORDER = Object.freeze(Object.keys(OFFICIAL_CORE_PRIORITIES));

const CREW_STORE_FILES = Object.freeze(
  CREW_PIPELINE_ORDER.reduce((acc, id) => {
    acc[id] = `.${id}.json`;
    return acc;
  }, {})
);

const PERSONA_ID_RE = /^[a-z][a-z0-9-]{1,47}$/;
const MAX_DESCRIPTOR_BYTES = 32768;
const MAX_REGISTRY_FILES = 256;
const NON_CORE_MIN_PRIORITY = 200;

// Fail-closed descriptor text guard (rejects secrets, URLs, internal hosts, IPs, emails, local paths).
const UNSAFE_DESCRIPTOR_RE =
  /(?:https?:\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[\w.+-]+@[\w-]+\.[\w.-]+\b|\b[\w-]+\.(?:internal|corp|local|lan|intranet|amazonaws\.com|rds\.amazonaws\.com|svc\.cluster\.local)\b|(?<![A-Za-z0-9_.-])(?:\/(?:Users|home|private|var\/folders|tmp|Volumes|etc|root)\/\S+|~\/[^\s"'<>]+)|(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s"'<>]+|-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\b(?:AKIA|ASIA)(?![A-Z0-9]*EXAMPLE)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:ant-|proj-|live-)[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk|pk)_live_[0-9A-Za-z]{20,})\b)/i;

function getHomeDir(env = process.env) {
  return (env && (env.HOME || env.USERPROFILE)) || os.homedir();
}

function getCrewConfigDir(env = process.env) {
  const safeEnv = env || process.env;
  const explicit = safeEnv.CREW_CONFIG_DIR && String(safeEnv.CREW_CONFIG_DIR).trim();
  if (explicit) return explicit;
  return path.join(getHomeDir(safeEnv), '.config', 'crew');
}

function getPersonasRegistryDir(env = process.env) {
  return path.join(getCrewConfigDir(env), 'registry', 'personas');
}

function getPresenceLogPath(env = process.env) {
  return path.join(getCrewConfigDir(env), 'registry', 'presence.jsonl');
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

function collectDescriptorStrings(value, out = [], depth = 0) {
  if (depth > 8 || value === null || value === undefined) return out;
  if (typeof value === 'string') {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectDescriptorStrings(item, out, depth + 1);
    return out;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      collectDescriptorStrings(v, out, depth + 1);
    }
  }
  return out;
}

function hasUnsafeDescriptorText(rawText, parsedObj) {
  if (rawText && UNSAFE_DESCRIPTOR_RE.test(String(rawText))) return true;
  if (parsedObj) {
    for (const s of collectDescriptorStrings(parsedObj)) {
      if (UNSAFE_DESCRIPTOR_RE.test(s)) return true;
    }
  }
  return false;
}

function comparePeers(a, b) {
  if (a.pipelinePriority !== b.pipelinePriority) {
    return a.pipelinePriority - b.pipelinePriority;
  }
  return a.id.localeCompare(b.id);
}

// Validates and normalizes a §4.5 crew-persona.json descriptor with anti-hijack clamping.
function validatePersonaDescriptor(rawOrObj, opts = {}) {
  let rawText = '';
  let parsed = rawOrObj;

  if (typeof rawOrObj === 'string') {
    rawText = rawOrObj;
    if (Buffer.byteLength(rawText, 'utf8') > MAX_DESCRIPTOR_BYTES) {
      return { valid: false, reason: `descriptor exceeds ${MAX_DESCRIPTOR_BYTES} bytes` };
    }
    try {
      parsed = JSON.parse(rawText);
    } catch {
      return { valid: false, reason: 'invalid JSON' };
    }
  } else if (rawOrObj && typeof rawOrObj === 'object' && !Array.isArray(rawOrObj)) {
    rawText = JSON.stringify(rawOrObj);
    if (Buffer.byteLength(rawText, 'utf8') > MAX_DESCRIPTOR_BYTES) {
      return { valid: false, reason: `descriptor exceeds ${MAX_DESCRIPTOR_BYTES} bytes` };
    }
  } else {
    return { valid: false, reason: 'descriptor must be a JSON object' };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { valid: false, reason: 'descriptor must be a JSON object' };
  }

  if (parsed.schemaVersion !== 1) {
    return { valid: false, reason: 'schemaVersion must be 1' };
  }

  const id = typeof parsed.id === 'string' ? parsed.id.trim() : '';
  if (!PERSONA_ID_RE.test(id)) {
    return { valid: false, reason: `invalid persona id "${id}"` };
  }

  const expectedStoreFile = `.${id}.json`;
  if (typeof parsed.storeFile !== 'string' || parsed.storeFile !== expectedStoreFile) {
    return { valid: false, reason: `storeFile must equal "${expectedStoreFile}"` };
  }

  if (hasUnsafeDescriptorText(rawText, parsed)) {
    return { valid: false, reason: 'descriptor contains forbidden secret, URL, IP, email, or local path' };
  }

  const kind = typeof parsed.kind === 'string' && parsed.kind.trim()
    ? parsed.kind.trim().toLowerCase()
    : 'domaincraft';
  const isOfficialCore = Object.prototype.hasOwnProperty.call(OFFICIAL_CORE_PRIORITIES, id);

  // Reject non-universal spoofing of an official core persona ID when loading from drop-in registry.
  if (opts.fromRegistry && isOfficialCore && kind !== 'universal') {
    return { valid: false, reason: `non-universal descriptor cannot claim official core id "${id}"` };
  }

  const rawPriority = Number(parsed.pipelinePriority);
  let pipelinePriority;
  if (isOfficialCore && kind === 'universal') {
    const corePrio = OFFICIAL_CORE_PRIORITIES[id];
    pipelinePriority = Number.isFinite(rawPriority) ? Math.max(corePrio, Math.floor(rawPriority)) : corePrio;
  } else {
    const candidate = Number.isFinite(rawPriority) ? Math.floor(rawPriority) : NON_CORE_MIN_PRIORITY;
    pipelinePriority = Math.max(NON_CORE_MIN_PRIORITY, candidate);
  }

  const descriptor = {
    schemaVersion: 1,
    id,
    handle: typeof parsed.handle === 'string' && parsed.handle.trim() ? parsed.handle.trim().slice(0, 64) : id,
    version: typeof parsed.version === 'string' && parsed.version.trim() ? parsed.version.trim().slice(0, 32) : '0.0.0',
    kind,
    squad: typeof parsed.squad === 'string' && parsed.squad.trim() ? parsed.squad.trim().slice(0, 32) : 'domaincraft',
    pipelinePriority,
    storeFile: expectedStoreFile,
    wireEnvelope: typeof parsed.wireEnvelope === 'string' ? parsed.wireEnvelope.trim().slice(0, 64) : '',
    alterEgos: Array.isArray(parsed.alterEgos) ? parsed.alterEgos.slice(0, 4) : [],
    themePosture: typeof parsed.themePosture === 'string' ? parsed.themePosture.trim().slice(0, 32) : '',
    gates: Array.isArray(parsed.gates) ? parsed.gates.map((g) => String(g)).slice(0, 6) : [],
    pushbackDomain: typeof parsed.pushbackDomain === 'string' ? parsed.pushbackDomain.trim().slice(0, 240) : '',
    skills: Array.isArray(parsed.skills) ? parsed.skills.map((s) => String(s)).slice(0, 32) : [],
    memoryNamespace: typeof parsed.memoryNamespace === 'string' ? parsed.memoryNamespace.trim().slice(0, 128) : `memory/agents/${id}`,
    enclaveAware: Boolean(parsed.enclaveAware),
    installerScript: typeof parsed.installerScript === 'string' ? parsed.installerScript.trim().slice(0, 128) : '',
    source: opts.fromRegistry ? 'registry' : 'manifest',
  };

  return { valid: true, descriptor };
}

// Loads all valid drop-in persona descriptors from $CREW_CONFIG_DIR/registry/personas/*.json.
function loadRegisteredPersonas(env = process.env) {
  const dir = getPersonasRegistryDir(env);
  const loaded = new Map();

  let dirStat;
  try {
    dirStat = fs.lstatSync(dir);
  } catch {
    return loaded;
  }
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) return loaded;

  let realDir;
  try {
    realDir = fs.realpathSync(dir);
  } catch {
    return loaded;
  }

  let entries = [];
  try {
    entries = fs.readdirSync(dir).filter((name) => name.endsWith('.json')).sort().slice(0, MAX_REGISTRY_FILES);
  } catch {
    return loaded;
  }

  for (const fileName of entries) {
    const filePath = path.join(dir, fileName);
    let st;
    try {
      st = fs.lstatSync(filePath);
    } catch {
      continue;
    }
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_DESCRIPTOR_BYTES) continue;

    try {
      const realFile = fs.realpathSync(filePath);
      const rel = path.relative(realDir, realFile);
      if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) continue;
      const raw = fs.readFileSync(realFile, 'utf8');
      const res = validatePersonaDescriptor(raw, { fromRegistry: true });
      if (!res.valid) continue;
      loaded.set(res.descriptor.id, res.descriptor);
    } catch {
      continue;
    }
  }

  return loaded;
}

// Merges built-in 13-persona fallback map with dynamically discovered registry descriptors,
// sorted deterministically by (pipelinePriority ASC, id ASC).
function getDynamicPeerCatalog(env = process.env) {
  const merged = new Map();
  for (const id of CREW_PIPELINE_ORDER) {
    merged.set(id, {
      schemaVersion: 1,
      id,
      handle: id,
      version: '0.0.0',
      kind: 'universal',
      squad: id === 'headhoncho' ? 'governance' : 'core',
      pipelinePriority: OFFICIAL_CORE_PRIORITIES[id],
      storeFile: CREW_STORE_FILES[id],
      source: 'builtin',
    });
  }
  const registered = loadRegisteredPersonas(env);
  for (const [id, desc] of registered.entries()) {
    merged.set(id, desc);
  }
  return [...merged.values()].sort(comparePeers);
}

// Returns { [id]: storeFile } for every OTHER registered or built-in persona (used by guard.js & surface.js).
function getDynamicPeerStoreFiles(selfId = 'neckbeard', env = process.env) {
  const normalizedSelf = String(selfId || 'neckbeard').toLowerCase().trim() || 'neckbeard';
  const catalog = getDynamicPeerCatalog(env);
  const out = {};
  for (const desc of catalog) {
    if (desc.id === normalizedSelf) continue;
    out[desc.id] = desc.storeFile;
  }
  return out;
}

function detectCrewEnsemble(selfId, cwd = process.cwd(), env = process.env) {
  const safeEnv = env || process.env;
  const normalizedSelf = String(selfId || 'neckbeard').toLowerCase().trim() || 'neckbeard';

  const registered = loadRegisteredPersonas(safeEnv);
  const catalog = getDynamicPeerCatalog(safeEnv);
  const byId = new Map(catalog.map((d) => [d.id, d]));

  if (!byId.has(normalizedSelf) && PERSONA_ID_RE.test(normalizedSelf)) {
    const fallbackDesc = {
      schemaVersion: 1,
      id: normalizedSelf,
      handle: normalizedSelf,
      version: '0.0.0',
      kind: 'domaincraft',
      squad: 'custom',
      pipelinePriority: OFFICIAL_CORE_PRIORITIES[normalizedSelf] || NON_CORE_MIN_PRIORITY,
      storeFile: `.${normalizedSelf}.json`,
      source: 'self',
    };
    byId.set(normalizedSelf, fallbackDesc);
    catalog.push(fallbackDesc);
    catalog.sort(comparePeers);
  }

  const peerOrder = catalog.map((d) => d.id);

  if (
    safeEnv.CREW_SOLO_PERSONA &&
    String(safeEnv.CREW_SOLO_PERSONA).toLowerCase().trim() === normalizedSelf
  ) {
    return {
      selfId: normalizedSelf,
      installedPeers: [normalizedSelf],
      peerOrder,
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
  if (byId.has(normalizedSelf)) {
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

  for (const desc of catalog) {
    const id = desc.id;
    const claudeExplicitlyDisabled = Boolean(
      claudeEnabled && claudeEnabled[`${id}@${id}`] === false
    );

    // 0. §4.5 Dynamic Drop-In Presence Registry ($CREW_CONFIG_DIR/registry/personas/<id>.json)
    if (registered.has(id) && !claudeExplicitlyDisabled) {
      detected.add(id);
      continue;
    }

    // 1. Claude Code (.claude)
    if (claudeEnabled && claudeEnabled[`${id}@${id}`] === true) {
      detected.add(id);
      continue;
    }
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
    if (cwd && safeExists(path.join(cwd, desc.storeFile))) {
      detected.add(id);
    }
  }

  const installedDescriptors = catalog.filter((d) => detected.has(d.id)).sort(comparePeers);
  const installedPeers = installedDescriptors.map((d) => d.id);
  const leaderId = installedPeers[0] || normalizedSelf;
  const isEnsemble = installedPeers.length >= 2;
  const isEnsembleLeader = leaderId === normalizedSelf;

  return {
    selfId: normalizedSelf,
    installedPeers,
    peerOrder,
    installedDescriptors,
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
      'Multiple Crew Universe personas are active in unison on this harness. Route each task to its owning domain specialist and apply each active persona\'s 3 Gates without stacking competing footers (Governance: HeadHoncho; Build: RainMaker, PropellerHead, NeckBeard, Hipster, EdgeLord; Ship & Run: InfraSmith, UserChamp, RedLine; Growth: StoryTeller, CloutChaser, MeasureUp, DealMaker; plus registered DomainCraft specialists). Emit only the 3-line footer of the persona owning the primary task domain.\n\n';
    return header + adapted;
  }

  return adapted;
}

module.exports = {
  OFFICIAL_CORE_PRIORITIES,
  CREW_PIPELINE_ORDER,
  CREW_STORE_FILES,
  PERSONA_ID_RE,
  MAX_DESCRIPTOR_BYTES,
  NON_CORE_MIN_PRIORITY,
  getHomeDir,
  getCrewConfigDir,
  getPersonasRegistryDir,
  getPresenceLogPath,
  comparePeers,
  validatePersonaDescriptor,
  loadRegisteredPersonas,
  getDynamicPeerCatalog,
  getDynamicPeerStoreFiles,
  detectCrewEnsemble,
  formatEnsembleRules,
};
