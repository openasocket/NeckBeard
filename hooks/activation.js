'use strict';
// Zero-dependency standalone standby, explicit enable, whole-Crew toggle, and one-shot
// activation coordinator shared across all 13 Crew Universe persona plugins.
//
// Standalone Default: STANDBY (0 bytes on SessionStart, 0 bytes on ordinary prompts,
// 0 guard interference) until the user explicitly:
//   1. Runs a one-shot ("onesie-twosie") task: /<persona> <prompt>
//      (activates persona + guard for THIS turn only; next ordinary prompt returns to standby)
//   2. Enables a single persona for the session: /<persona> on|enable|lite|full|paranoid
//   3. Enables the entire Crew for the session:  /crew on|enable|lite|full|paranoid
//      (lazy relevance-gated: each persona hydrates ONCE only when a prompt matches its domain)
//   4. Launches via Crew Studio / explicit env opt-in:
//      - CREW_ACTIVE_PERSONA=<id> or CREW_SOLO_PERSONA=<id> (active ONLY for that persona)
//      - CREW_ENABLED=1 (Crew lazy relevance-gated mode active immediately)
//      - CREW_EAGER_LOAD=1 (legacy upfront loading)
//      - <PERSONA>_LEVEL=lite|full|paranoid|ultra (explicit env level override)

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHash } = require('crypto');

const VALID_LEVELS = new Set(['lite', 'full', 'paranoid']);

const PERSONA_RELEVANCE_PATTERNS = Object.freeze({
  headhoncho: /\b(headhoncho|mandate|chief\s+of\s+staff|acting\s+ceo|governance|charter|escalat|arbitrat|executive\s+brief|enclave|decision\s+log)\b/i,
  rainmaker: /\b(rainmaker|value\s*val|valentino|valentina|scope|cutline|mvp|prioriti[sz]|backlog|roi|market|competitor|moneti[sz]|triage|north\s*star|worth\s+building|should\s+we\s+build)\b/i,
  propellerhead: /\b(propellerhead|decomp|danny|dani|post[\s-]?mortem|pre[\s-]?mortem|root[\s-]?cause|5[\s-]?whys|fault[\s-]?tree|outage|failing\s+test|stack\s*trace|decompos|slice|dag|invariant|migration)\b/i,
  neckbeard: /\b(neckbeard|larry|lari|implement|refactor|endpoint|api|database|sql|sqlite|postgres|auth|jwt|session|token|security|boundary|scale|perf|latency|cache|concurrency|race|backend|server|cli|trust\s*boundary|memory\s*leak|fix\s+(?:the\s+)?(?:bug|race|leak|auth|sql|api|endpoint|crash|handler))\b/i,
  hipster: /\b(hipster|sammy|samuel|samantha|ui|ux|dx|css|html|layout|design|landing\s*page|website|frontend|react|component|drawer|modal|theme|brand|color|contrast|a11y|accessibility|mobile|viewport|responsive|pptx|deck|slide|docx|pdf|polish|slop|live[\s-]?glass)\b/i,
  edgelord: /\b(edgelord|ruckus|ronnie|ronica|red[\s-]?team|fuzz|chaos|pentest|exploit|idor|ssrf|xss|sqli|injection|traversal|symlink|bypass|hostile|adversarial|stress[\s-]?test|load[\s-]?test|toctou|double[\s-]?submit|vulnerab|breach)\b/i,
  infrasmith: /\b(infrasmith|deploy|ci\/cd|github\s+actions|docker|dockerfile|kubernetes|k8s|terraform|iac|helm|rollback|observability|prometheus|grafana|sre|pipeline|container|infra)\b/i,
  storyteller: /\b(storyteller|narrative|copywriting|launch\s+post|release\s+notes|announcement|blog\s+post|positioning|messaging|changelog|pitch\s+deck|readme\s+copy)\b/i,
  cloutchaser: /\b(cloutchaser|seo|growth\s+loop|distribution|viral|funnel|acquisition|social\s+media|launch\s+strategy|gtm|go[\s-]to[\s-]market|content\s+marketing)\b/i,
  userchamp: /\b(userchamp|customer\s+support|onboarding|churn|nps|csat|support\s+ticket|user\s+feedback|help\s+docs|faq|retention|customer\s+empathy)\b/i,
  redline: /\b(redline|legal|privacy|gdpr|ccpa|hipaa|soc2|cmmc|compliance|license|licensing|terms\s+of\s+service|tos|dpa|contract|liability|ip\s+review)\b/i,
  measureup: /\b(measureup|analytics|telemetry|a\/b\s+test|experiment|cohort|conversion\s+rate|kpi|metric|funnel\s+analysis|attribution|statistical\s+signific)\b/i,
  dealmaker: /\b(dealmaker|pricing|packaging|enterprise\s+sales|deal\s+desk|quote|rfp|procurement|arr|mrr|discount|tier|contract\s+value|commercial)\b/i,
});

const PERSONA_ROSTER_SUMMARY = Object.freeze({
  headhoncho: '- HeadHoncho (/headhoncho): Executive governance, vision & escalation policy',
  rainmaker: '- RainMaker (/rainmaker): Product scope, ValueScore backlog, ROI & 80% cutline',
  propellerhead: '- PropellerHead (/propellerhead): Feature DAG slicing, pre-mortem & post-mortem root-cause',
  neckbeard: '- NeckBeard (/neckbeard): Minimal boundary-safe code, load/scale & security invariants',
  hipster: '- Hipster (/hipster): 5s UX/DX hierarchy, brand systems, anti-slop & live-glass verification',
  edgelord: '- EdgeLord (/edgelord): Adversarial red-team, hostile fuzzing, concurrency chaos & DLP',
  infrasmith: '- InfraSmith (/infrasmith): CI/CD, IaC, containers, rollback & production operations',
  storyteller: '- StoryTeller (/storyteller): Product narrative, launch copy & release notes',
  cloutchaser: '- CloutChaser (/cloutchaser): Distribution, SEO & growth loops',
  userchamp: '- UserChamp (/userchamp): Customer empathy, support triage & onboarding',
  redline: '- RedLine (/redline): Legal, privacy, licensing & compliance review',
  measureup: '- MeasureUp (/measureup): Analytics, telemetry funnels & experiment rigor',
  dealmaker: '- DealMaker (/dealmaker): Pricing, packaging & enterprise commercial readiness',
});

const UTILITY_SUBAGENTS = new Set([
  'explore',
  'plan',
  'claude-code-guide',
  'statusline-setup',
  'research',
  'image-generator',
  'compaction',
  'summarizer',
]);

function normalizeLevelValue(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'ultra') return 'paranoid';
  if (v === 'off' || VALID_LEVELS.has(v)) return v;
  return null;
}

function isTruthyEnv(value) {
  const v = String(value || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function sessionHash(sessionId) {
  return createHash('sha256').update(String(sessionId || 'default')).digest('hex').slice(0, 32);
}

function crewSessionStateDir(env = process.env) {
  const safe = env || process.env;
  if (safe.CREW_SESSION_STATE_DIR && String(safe.CREW_SESSION_STATE_DIR).trim()) {
    return String(safe.CREW_SESSION_STATE_DIR).trim();
  }
  if (safe.CREW_CONFIG_DIR && String(safe.CREW_CONFIG_DIR).trim()) {
    return path.join(String(safe.CREW_CONFIG_DIR).trim(), 'session-state');
  }
  const envHome = safe.HOME || safe.USERPROFILE;
  if (envHome && path.resolve(envHome) !== path.resolve(os.homedir())) {
    return path.join(envHome, '.config', 'crew', 'session-state');
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'u';
  return path.join(os.tmpdir(), `crew-sessions-${uid}`);
}

function atomicWriteJson(filePath, data) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const suffix = `${process.pid}.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 8)}`;
    const tmp = `${filePath}.${suffix}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    fs.renameSync(tmp, filePath);
  } catch { /* best-effort */ }
}

function readJsonSafe(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return null;
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function crewStatePath(sessionId, env = process.env) {
  if (!sessionId) return null;
  return path.join(crewSessionStateDir(env), `${sessionHash(sessionId)}.crew.json`);
}

function personaStatePath(personaId, sessionId, env = process.env, personaStateDir = null) {
  if (!sessionId) return null;
  const id = String(personaId || 'crew').trim().toLowerCase();
  const base = personaStateDir || crewSessionStateDir(env);
  return path.join(base, `${sessionHash(sessionId)}.${id}.activation.json`);
}

function readCrewSessionState(sessionId, env = process.env) {
  return readJsonSafe(crewStatePath(sessionId, env));
}

function writeCrewSessionState(sessionId, patch, env = process.env) {
  const file = crewStatePath(sessionId, env);
  if (!file) return null;
  const cur = readJsonSafe(file) || {};
  const next = { ...cur, ...patch, updatedAt: Date.now() };
  atomicWriteJson(file, next);
  return next;
}

function readPersonaSessionState(personaId, sessionId, env = process.env, personaStateDir = null) {
  return readJsonSafe(personaStatePath(personaId, sessionId, env, personaStateDir));
}

function writePersonaSessionState(personaId, sessionId, patch, env = process.env, personaStateDir = null) {
  const file = personaStatePath(personaId, sessionId, env, personaStateDir);
  if (!file) return null;
  const cur = readJsonSafe(file) || {};
  const next = { ...cur, ...patch, updatedAt: Date.now() };
  atomicWriteJson(file, next);
  return next;
}

function clearPersonaOneShot(personaId, sessionId, env = process.env, personaStateDir = null) {
  const cur = readPersonaSessionState(personaId, sessionId, env, personaStateDir);
  if (!cur || !cur.oneShot) return;
  writePersonaSessionState(personaId, sessionId, { oneShot: false, oneShotLevel: null }, env, personaStateDir);
}

function isStandaloneAutoEnabled(personaId, env = process.env) {
  const safe = env || process.env;
  const id = String(personaId || '').trim().toLowerCase();
  const activeTarget = String(safe.CREW_ACTIVE_PERSONA || safe.CREW_SOLO_PERSONA || '').trim().toLowerCase();
  if (activeTarget) return activeTarget === id;
  if (isTruthyEnv(safe.CREW_EAGER_LOAD) || isTruthyEnv(safe.CREW_ENABLED)) return true;
  const explicitEnvLevel = normalizeLevelValue(safe[`${id.toUpperCase()}_LEVEL`]);
  if (explicitEnvLevel && explicitEnvLevel !== 'off') return true;
  if (isTruthyEnv(safe[`${id.toUpperCase()}_AUTO_ACTIVATE`])) return true;
  return false;
}

function resolveActivation(personaId, sessionId, env = process.env, opts = {}) {
  const safe = env || process.env;
  const id = String(personaId || '').trim().toLowerCase();
  const envPrefix = id.toUpperCase();
  const explicitEnvLevel = normalizeLevelValue(safe[`${envPrefix}_LEVEL`]);
  let fallbackLevel = 'full';
  if (typeof opts.defaultLevelFn === 'function') {
    const dl = normalizeLevelValue(opts.defaultLevelFn(safe));
    if (dl && dl !== 'off') fallbackLevel = dl;
  }

  const personaState = readPersonaSessionState(id, sessionId, safe, opts.personaStateDir || null);
  const crewState = readCrewSessionState(sessionId, safe);
  const crewEnabled = Boolean(crewState && crewState.enabled === true);

  // 1. Turn-scoped one-shot beats standby and prior session off
  if (personaState && personaState.oneShot === true) {
    const lvl = normalizeLevelValue(personaState.oneShotLevel) || fallbackLevel;
    return {
      active: true,
      mode: 'oneshot',
      level: lvl === 'off' ? fallbackLevel : lvl,
      oneShot: true,
      crewEnabled,
      personaEnabled: Boolean(personaState.enabled === true),
    };
  }

  // 2. Explicit session disable for this persona
  if (personaState && personaState.enabled === false) {
    return {
      active: false,
      mode: 'off',
      level: 'off',
      oneShot: false,
      crewEnabled,
      personaEnabled: false,
    };
  }

  // 3. Explicit session enable for this persona (/neckbeard on|lite|full|paranoid)
  if (personaState && personaState.enabled === true) {
    const lvl = normalizeLevelValue(personaState.level) || fallbackLevel;
    return {
      active: true,
      mode: 'persona',
      level: lvl === 'off' ? fallbackLevel : lvl,
      oneShot: false,
      crewEnabled,
      personaEnabled: true,
    };
  }

  // 4. Explicit env <PERSONA>_LEVEL=off
  if (explicitEnvLevel === 'off') {
    return {
      active: false,
      mode: 'off',
      level: 'off',
      oneShot: false,
      crewEnabled: false,
      personaEnabled: false,
    };
  }

  // 5. Shared Crew session enable (/crew on|lite|full|paranoid)
  if (crewEnabled) {
    const lvl = normalizeLevelValue(crewState.level) || explicitEnvLevel || fallbackLevel;
    return {
      active: true,
      mode: 'crew',
      level: lvl === 'off' ? fallbackLevel : lvl,
      oneShot: false,
      crewEnabled: true,
      personaEnabled: false,
    };
  }

  // 6. Crew Studio / orchestrator targeting (CREW_ACTIVE_PERSONA or CREW_SOLO_PERSONA)
  const activeTarget = String(safe.CREW_ACTIVE_PERSONA || safe.CREW_SOLO_PERSONA || '').trim().toLowerCase();
  if (activeTarget) {
    if (activeTarget === id) {
      const lvl = explicitEnvLevel || fallbackLevel;
      return {
        active: true,
        mode: 'orchestrated',
        level: lvl === 'off' ? fallbackLevel : lvl,
        oneShot: false,
        crewEnabled: false,
        personaEnabled: true,
      };
    }
    return {
      active: false,
      mode: 'standby',
      level: 'off',
      oneShot: false,
      crewEnabled: false,
      personaEnabled: false,
    };
  }

  // 7. Explicit env opt-in (CREW_EAGER_LOAD=1, CREW_ENABLED=1, <PERSONA>_LEVEL=<lvl>, <PERSONA>_AUTO_ACTIVATE=1)
  if (isTruthyEnv(safe.CREW_EAGER_LOAD)) {
    const lvl = explicitEnvLevel || fallbackLevel;
    return {
      active: true,
      mode: 'eager',
      level: lvl === 'off' ? fallbackLevel : lvl,
      oneShot: false,
      crewEnabled: true,
      personaEnabled: true,
    };
  }
  if (isTruthyEnv(safe.CREW_ENABLED)) {
    const lvl = explicitEnvLevel || fallbackLevel;
    return {
      active: true,
      mode: 'crew',
      level: lvl === 'off' ? fallbackLevel : lvl,
      oneShot: false,
      crewEnabled: true,
      personaEnabled: false,
    };
  }
  if (explicitEnvLevel && explicitEnvLevel !== 'off') {
    return {
      active: true,
      mode: 'env',
      level: explicitEnvLevel,
      oneShot: false,
      crewEnabled: false,
      personaEnabled: true,
    };
  }
  if (isTruthyEnv(safe[`${envPrefix}_AUTO_ACTIVATE`])) {
    return {
      active: true,
      mode: 'env',
      level: fallbackLevel,
      oneShot: false,
      crewEnabled: false,
      personaEnabled: true,
    };
  }

  // 8. Standalone default: silent standby (0 bytes until user calls /<persona> <prompt>, /<persona> on, or /crew on)
  return {
    active: false,
    mode: 'standby',
    level: 'off',
    oneShot: false,
    crewEnabled: false,
    personaEnabled: false,
  };
}

function parseCrewCommand(prompt) {
  const raw = String(prompt || '').trim();
  if (!raw) return null;
  const low = raw.toLowerCase();
  if (/^(?:stop\s+crew|crew\s+off|disable\s+crew)\s*$/i.test(low)) {
    return { crewAction: 'off' };
  }
  if (/^(?:enable\s+crew|start\s+crew|crew\s+on)\s*$/i.test(low)) {
    return { crewAction: 'on', level: 'full' };
  }
  const m = raw.match(/^[/@$]crew(?:\s+([\s\S]+))?$/i);
  if (!m) return null;
  if (!m[1] || !m[1].trim()) return { crewAction: 'status' };
  const tokens = m[1].trim().split(/\s+/);
  const sub = tokens[0].toLowerCase();
  if (sub === 'status') return { crewAction: 'status' };
  if (sub === 'on' || sub === 'enable' || sub === 'start') {
    const lvl = normalizeLevelValue(tokens[1]) || 'full';
    return { crewAction: 'on', level: lvl === 'off' ? 'full' : lvl };
  }
  if (sub === 'off' || sub === 'disable' || sub === 'stop') {
    return { crewAction: 'off' };
  }
  const directLvl = normalizeLevelValue(sub);
  if (directLvl) {
    return directLvl === 'off' ? { crewAction: 'off' } : { crewAction: 'on', level: directLvl };
  }
  return null;
}

function isPersonaBranchSlash(personaId, aliases, prompt) {
  const raw = String(prompt || '').trim();
  if (!raw || !/^[/@$]/.test(raw)) return false;
  const names = [String(personaId || '').toLowerCase(), ...(Array.isArray(aliases) ? aliases : [])]
    .map((s) => String(s || '').trim().toLowerCase())
    .filter(Boolean);
  for (const name of names) {
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`^[/@$](?:${esc}(?::${esc})?)-[a-z0-9-]+(?:\\s|$)`, 'i').test(raw)) {
      return true;
    }
  }
  return false;
}

function matchesPersonaRelevance(personaId, prompt) {
  const id = String(personaId || '').trim().toLowerCase();
  const text = String(prompt || '').trim();
  if (!id || !text) return false;
  const re = PERSONA_RELEVANCE_PATTERNS[id];
  if (re && re.test(text)) return true;
  return new RegExp(`\\b${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(text);
}

function isSubagentTargetingSelf(personaId, input) {
  const selfId = String(personaId || '').trim().toLowerCase();
  if (!input || typeof input !== 'object') return false;
  const raw = String(input.agent_type || input.subagent_type || input.agent_name || input.agent || '').trim().toLowerCase();
  if (!raw) return false;
  if (UTILITY_SUBAGENTS.has(raw)) return false;
  const base = raw.includes(':') ? raw.split(':').pop() : raw;
  return base === selfId || base.startsWith(`${selfId}-`) || raw.startsWith(`${selfId}:`);
}

function isSubagentUtilityOrSibling(personaId, input, ensembleInfo) {
  const selfId = String(personaId || '').trim().toLowerCase();
  if (!input || typeof input !== 'object') return false;
  const raw = String(input.agent_type || input.subagent_type || input.agent_name || input.agent || '').trim().toLowerCase();
  if (!raw) return false;
  if (UTILITY_SUBAGENTS.has(raw)) return true;
  const base = raw.includes(':') ? raw.split(':').pop() : raw;
  const peers = new Set([
    ...Object.keys(PERSONA_ROSTER_SUMMARY),
    ...((ensembleInfo && Array.isArray(ensembleInfo.installedPeers)) ? ensembleInfo.installedPeers : []),
  ]);
  for (const peer of peers) {
    if (peer !== selfId && (base === peer || base.startsWith(`${peer}-`) || raw.startsWith(`${peer}:`))) {
      return true;
    }
  }
  return false;
}

function formatCrewRosterBanner(ensembleInfo, level = 'full') {
  const installed = (ensembleInfo && Array.isArray(ensembleInfo.installedPeers) && ensembleInfo.installedPeers.length > 0)
    ? ensembleInfo.installedPeers
    : [ensembleInfo && ensembleInfo.selfId ? ensembleInfo.selfId : 'crew'];
  const peers = installed.join(' -> ');
  const lines = installed.map((id) => PERSONA_ROSTER_SUMMARY[id] || `- ${id} (/${id}): Domain specialist`);
  const gates = [];
  if (installed.includes('hipster')) {
    gates.push('- Live-Glass UI Gate (Hipster): Verify created/modified UI/web/HTML/CSS files via live browser DOM/contrast/mobile checks before finishing (cap <= 3 loops).');
  }
  if (installed.includes('edgelord')) {
    gates.push('- Red-Team & DLP Gate (EdgeLord): Audit created/modified source files for secrets/PII, innerHTML sinks, and trust-boundary attacks before finishing (cap <= 3 loops).');
  }
  const gateBlock = gates.length > 0 ? `\nMandatory Pre-Completion Specialist Gates:\n${gates.join('\n')}` : '';
  return (
    `[Crew Universe Ensemble Active: ${peers}]\n` +
    `Crew Universe ENABLED for this session (level: ${level}). Lazy persona loading active (only relevant personas hydrate on demand; disable with /crew off, enable one persona with /<persona> on, or run a one-shot task with /<persona> <prompt>). Governance: HeadHoncho; Build: RainMaker, PropellerHead, NeckBeard, Hipster, EdgeLord; Ship & Run: InfraSmith, UserChamp, RedLine; Growth: StoryTeller, CloutChaser, MeasureUp, DealMaker. Confirm in one short line.\n` +
    `Installed Specialists:\n${lines.join('\n')}` +
    gateBlock
  ).trim();
}

function formatCrewStatusBanner(ensembleInfo, sessionId, env = process.env) {
  const crewState = readCrewSessionState(sessionId, env);
  const crewOn = Boolean(crewState && crewState.enabled === true) || isTruthyEnv((env || process.env).CREW_ENABLED);
  const installed = (ensembleInfo && Array.isArray(ensembleInfo.installedPeers) && ensembleInfo.installedPeers.length > 0)
    ? ensembleInfo.installedPeers
    : [ensembleInfo && ensembleInfo.selfId ? ensembleInfo.selfId : 'crew'];
  const enabledPersonas = [];
  for (const pid of installed) {
    const ps = readPersonaSessionState(pid, sessionId, env);
    if (ps && ps.enabled === true) enabledPersonas.push(`${pid}(${ps.level || 'full'})`);
  }
  const modeLabel = crewOn ? `ACTIVE (level: ${(crewState && crewState.level) || 'full'}, relevance-gated)` : 'STANDBY (dormant until enabled)';
  return (
    `[Crew Universe Status] Mode: ${modeLabel}\n` +
    `Installed specialists: ${installed.join(', ')}\n` +
    `Individually enabled this session: ${enabledPersonas.length ? enabledPersonas.join(', ') : 'none'}\n` +
    'Commands: /crew on | /crew off | /<persona> on | /<persona> off | /<persona> <one-shot prompt>. Confirm in one short line.'
  );
}

function formatOneShotHeader(displayName, personaId, level) {
  const upper = String(displayName || personaId).toUpperCase();
  const id = String(personaId || '').toLowerCase();
  return `${upper} ONE-SHOT TASK ACTIVE (level: ${level}; session stays standby on subsequent prompts — use /${id} on or /crew on to keep enabled). Apply ${displayName}'s ruleset and gates to this prompt:`;
}

function formatPersonaEnabledHeader(displayName, personaId, level, extra = '') {
  const upper = String(displayName || personaId).toUpperCase();
  const id = String(personaId || '').toLowerCase();
  const detail = extra ? ` (${extra})` : '';
  return `${upper} ENABLED for this session (level: ${level}${detail}). Apply ${displayName}'s ruleset and gates on prompts relevant to ${displayName}'s domain; stay out of the way on unrelated prompts. Disable anytime with /${id} off. Confirm in one short line.`;
}

function formatPersonaStatusLine(displayName, personaId, activation) {
  const upper = String(displayName || personaId).toUpperCase();
  const id = String(personaId || '').toLowerCase();
  const stateLabel = activation.active ? `ACTIVE (${activation.mode}, level: ${activation.level})` : `STANDBY (${activation.mode})`;
  return `${upper} status: ${stateLabel}. Commands: /${id} on | /${id} off | /${id} <one-shot prompt> | /crew on | /crew off. Confirm in one short line.`;
}

function hydrationMarker(stateDirPath, personaId, sessionId) {
  return path.join(stateDirPath, `${sessionHash(sessionId)}.${String(personaId || 'crew').toLowerCase()}.hydrated`);
}

function isHydrated(personaId, sessionId, stateDirPath) {
  if (!stateDirPath) return false;
  try { return fs.existsSync(hydrationMarker(stateDirPath, personaId, sessionId)); } catch { return false; }
}

function markHydrated(personaId, sessionId, stateDirPath) {
  if (!stateDirPath) return;
  try {
    fs.mkdirSync(stateDirPath, { recursive: true, mode: 0o700 });
    fs.writeFileSync(hydrationMarker(stateDirPath, personaId, sessionId), '1', { mode: 0o600 });
  } catch { /* best-effort */ }
}

function clearHydrated(personaId, sessionId, stateDirPath) {
  if (!stateDirPath) return;
  try {
    const p = hydrationMarker(stateDirPath, personaId, sessionId);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  } catch { /* best-effort */ }
}

module.exports = {
  PERSONA_RELEVANCE_PATTERNS,
  PERSONA_ROSTER_SUMMARY,
  UTILITY_SUBAGENTS,
  normalizeLevelValue,
  isTruthyEnv,
  crewSessionStateDir,
  readCrewSessionState,
  writeCrewSessionState,
  readPersonaSessionState,
  writePersonaSessionState,
  clearPersonaOneShot,
  isStandaloneAutoEnabled,
  resolveActivation,
  parseCrewCommand,
  isPersonaBranchSlash,
  matchesPersonaRelevance,
  isSubagentTargetingSelf,
  isSubagentUtilityOrSibling,
  formatCrewRosterBanner,
  formatCrewStatusBanner,
  formatOneShotHeader,
  formatPersonaEnabledHeader,
  formatPersonaStatusLine,
  isHydrated,
  markHydrated,
  clearHydrated,
};
