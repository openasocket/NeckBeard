'use strict';
const _act = require('./activation');
// UserPromptSubmit:
//   - "/neckbeard <level>", "$neckbeard <level>", "@neckbeard <level>", and "stop neckbeard" change this session's level.
//   - "/neckbeard load [value]" views or saves the project's default load parameters (strictly censored).
//   - "/neckbeard map" builds/refreshes the concise internal & external trust-boundary map.
//   - "/neckbeard share [on|off]" toggles git sharing of .neckbeard.json (default: shared in repo root).
//   - "/neckbeard band [on|off|import|board]" controls the Claude Code banner and local telemetry board.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { readInput, readLevel, writeLevel, normalizeLevel, stateDir, claudeDir, emitContext, rules,   defaultLevel,
} = require('./lib');
const {
  detectCrewEnsemble,
  shouldDeferSessionStart,
  matchesPersonaIntent,
  isPersonaHydrated,
  markPersonaHydrated,
  clearPersonaHydrated,
} = require('./ensemble');
const { buildFullNeckbeardContext } = require('./session-start');
const { buildBoundaryMap, buildArchitectureMap, readProjectConfig, writeProjectConfig, formatProjectContext, formatCrewContext } = require('./surface');
const { runMemoryCommand } = require('./memory');

function parseCommand(prompt) {
  const raw = String(prompt || '').trim();
  const p = raw.toLowerCase();
  if (/^(stop neckbeard|neckbeard off|normal mode)\b/.test(p)) return 'off';
  const mapSlash = raw.match(/^[/@$](?:neckbeard(?::neckbeard)?|larry|lari)-map(?:\s+([\s\S]+))?$/i);
  if (mapSlash) {
    return /(?:^|\s)--uncapped(?:\s|$)/i.test(mapSlash[1] || '')
      ? { action: 'map', uncapped: true }
      : { action: 'map' };
  }
  const memSlash = raw.match(/^[/@$](?:neckbeard(?::neckbeard)?|larry|lari)-memory(?:\s+([\s\S]+))?$/i);
  if (memSlash) return { action: 'memory', value: (memSlash[1] || '').trim() };
  const m = raw.match(/^[/@$](?:neckbeard(?::neckbeard)?|larry|lari)(?:\s+([\s\S]+))?$/i);
  if (!m) return null;
  if (!m[1]) return 'on';
  const rest = m[1].trim();
  const tokens = rest.split(/\s+/);
  const sub = tokens[0].toLowerCase();

  if (tokens.length === 1) {
    if (sub === 'on' || sub === 'enable') return 'on';
    if (sub === 'disable') return 'off';
    if (sub === 'status') return { action: 'status' };
    const lvl = normalizeLevel(sub);
    if (lvl) return lvl;
    if (sub === 'map') return { action: 'map' };
    if (sub === 'crew') return { action: 'crew' };
    if (sub === 'memory') return { action: 'memory', value: 'inspect' };
    if (sub === 'load') return { action: 'load', value: '' };
    if (sub === 'share') return { action: 'share', value: '' };
    if (sub === 'band') return { action: 'band', value: 'toggle' };
    return 'unknown';
  }

  if (sub === 'load') return { action: 'load', value: rest.slice(4).trim() };
  if (sub === 'map') {
    return tokens.slice(1).some((t) => t.toLowerCase() === '--uncapped')
      ? { action: 'map', uncapped: true }
      : { action: 'map' };
  }
  if (sub === 'crew') return { action: 'crew' };
  if (sub === 'memory') return { action: 'memory', value: rest.slice(6).trim() };
  if (sub === 'share') {
    const mode = tokens[1].toLowerCase();
    return mode === 'on' || mode === 'off' ? { action: 'share', value: mode } : 'unknown';
  }
  if (sub === 'band') {
    const mode = tokens[1].toLowerCase();
    return ['on', 'off', 'import', 'board'].includes(mode) ? { action: 'band', value: mode } : 'unknown';
  }
  const _lvlHead = normalizeLevel(sub);
  if (_lvlHead && _lvlHead !== 'off' && tokens.length >= 2) {
    return { action: 'oneshot', level: _lvlHead, prompt: rest.slice(tokens[0].length).trim() };
  }
  if (tokens.length >= 2) {
    return { action: 'oneshot', prompt: rest };
  }
  return 'unknown';
}

function handleSubcommand(cmd, cwd) {
  if (cmd.action === 'load') {
    if (!cmd.value) {
      const cfg = readProjectConfig(cwd);
      const current = cfg && cfg.load ? cfg.load : 'unset';
      const overrides = cfg && cfg.boundaryLoad && Object.keys(cfg.boundaryLoad).length
        ? ` (per-boundary: ${Object.entries(cfg.boundaryLoad).map(([k, v]) => `${k}=${v}`).join(', ')})`
        : '';
      const mode = cfg && cfg.shared === false ? 'local' : 'shared in .neckbeard.json';
      return `NECKBEARD load default (${mode}): ${current}${overrides}. Set global load with /neckbeard load <parameters> or per-boundary load with /neckbeard load <sink>=<parameters>. Confirm in one short line.`;
    }
    const kv = cmd.value.match(/^([a-z-]+)\s*=\s*([\s\S]*)$/i);
    if (kv) {
      const key = kv[1].toLowerCase();
      const val = kv[2].trim();
      const saved = writeProjectConfig(cwd, { boundaryLoad: { [key]: val } });
      return `NECKBEARD per-boundary load [${key}] saved (${saved.shared ? '.neckbeard.json, shared' : 'local'}): "${(saved.boundaryLoad && saved.boundaryLoad[key]) || 'cleared'}". Confirm in one short line.\n\n${formatProjectContext(cwd)}`;
    }
    const saved = writeProjectConfig(cwd, { load: cmd.value });
    return `NECKBEARD load default saved (${saved.shared ? '.neckbeard.json, shared' : 'local'}): "${saved.load}". Confirm in one short line.\n\n${formatProjectContext(cwd)}`;
  }

  if (cmd.action === 'map') {
    const scanOpts = cmd.uncapped ? { uncapped: true } : {};
    const boundaries = buildBoundaryMap(cwd, 16, scanOpts);
    const architecture = buildArchitectureMap(cwd, 16, 24, scanOpts);
    const saved = writeProjectConfig(cwd, { boundaries, architecture }, process.env, scanOpts);
    try {
      const childEnv = cmd.uncapped ? { ...process.env, NECKBEARD_UNCAPPED: '1' } : process.env;
      const child = spawn(process.execPath, [path.join(__dirname, 'band-import.js')], { cwd, env: childEnv, detached: true, stdio: 'ignore' });
      child.unref();
    } catch { /* best-effort */ }
    const capNotice = boundaries.notice || architecture.notice;
    const suffix = capNotice ? `\nWARNING: ${capNotice}` : '';
    return `NECKBEARD trust-boundary & architecture map updated (${saved.shared ? '.neckbeard.json, shared' : 'local'}).\n\n${formatProjectContext(cwd, process.env, { ...scanOpts, liveMap: boundaries, architecture })}${suffix}`;
  }

  if (cmd.action === 'crew') {
    const crewSummary = formatCrewContext(cwd) || 'No sibling Crew Universe stores (.headhoncho.json, .rainmaker.json, .propellerhead.json, .hipster.json, .edgelord.json, etc.) initialized in this workspace yet.';
    return `NECKBEARD (Ashy Larry / Ashy Lari) Crew Universe Status:\n${crewSummary}\n\n${formatProjectContext(cwd)}`;
  }

  if (cmd.action === 'memory') {
    const argv = String(cmd.value || 'inspect').trim().split(/\s+/).filter(Boolean);
    try {
      return runMemoryCommand(argv, process.env);
    } catch (err) {
      return `NECKBEARD memory error: ${err.message}`;
    }
  }

  if (cmd.action === 'share') {
    if (!cmd.value) {
      const cfg = readProjectConfig(cwd);
      const shared = !cfg || cfg.shared !== false;
      return `NECKBEARD sharing is currently ${shared ? 'ON (stored in .neckbeard.json for git commit)' : 'OFF (stored locally in ~/.config/neckbeard/projects/ and excluded via .git/info/exclude)'}. Toggle with /neckbeard share on|off. Confirm in one short line.`;
    }
    const shared = cmd.value === 'on';
    writeProjectConfig(cwd, { shared });
    return shared
      ? `NECKBEARD sharing enabled: sanitized load default and trust-boundary map written to .neckbeard.json (ready to commit to git). Confirm in one short line.\n\n${formatProjectContext(cwd)}`
      : 'NECKBEARD sharing disabled: .neckbeard.json moved to local storage (~/.config/neckbeard/projects/) and added to .git/info/exclude. Confirm in one short line.';
  }

  if (cmd.action === 'band') {
    const flagFile = path.join(claudeDir(), '.neckbeard-band');
    if (cmd.value === 'import' || cmd.value === 'board') {
      try {
        const args = [path.join(__dirname, 'band-import.js')];
        if (cmd.value === 'board') args.push('--open');
        const child = spawn(process.execPath, args, { cwd, detached: true, stdio: 'ignore' });
        child.unref();
      } catch { /* best-effort */ }
      return cmd.value === 'board'
        ? 'NECKBEARD local telemetry board is building and opening (~/.config/neckbeard/band/board.html). Confirm in one short line.'
        : 'NECKBEARD background telemetry import started (reading .ai-audit/ VIBES data and past session transcripts into ~/.config/neckbeard/band/). Confirm in one short line.';
    }
    let cur = 'on';
    try { cur = fs.readFileSync(flagFile, 'utf8').trim() === 'off' ? 'off' : 'on'; } catch { /* default on */ }
    const next = cmd.value === 'toggle' ? (cur === 'off' ? 'on' : 'off') : cmd.value;
    try {
      fs.mkdirSync(path.dirname(flagFile), { recursive: true });
      fs.writeFileSync(flagFile, next);
    } catch { /* best-effort */ }
    return `NECKBEARD Claude Code band is now ${next}. Confirm in one short line.`;
  }

  return '';
}


function _buildActivationFullContext(input, env, ensembleInfo, level) {
  try {
    const ss = require('./session-start');
    if (typeof ss.buildFullContext === 'function') {
      const out = ss.buildFullContext(input, env, ensembleInfo, level);
      if (out) return typeof out === 'string' ? out : (typeof out.text === 'string' ? out.text : '');
    }
    if (typeof ss.buildSessionStartContext === 'function') {
      const out = ss.buildSessionStartContext(input, { ...(env || process.env), NECKBEARD_LEVEL: level });
      if (out) return typeof out === 'string' ? out : (typeof out.text === 'string' ? out.text : '');
    }
    if (typeof ss.buildSessionContext === 'function') {
      const out = ss.buildSessionContext(input, { ...(env || process.env), NECKBEARD_LEVEL: level });
      if (out) return typeof out === 'string' ? out : (typeof out.text === 'string' ? out.text : '');
    }
  } catch { /* fallback to rules */ }
  try {
    return typeof formatEnsembleRules === 'function'
      ? formatEnsembleRules(rules(level), ensembleInfo)
      : rules(level);
  } catch {
    return '';
  }
}

function _handleActivatedPrompt(input, env = process.env) {
  const safeInput = input && typeof input === 'object' ? input : {};
  const safeEnv = env || process.env;
  const promptText = String(safeInput.prompt || '');
  const sessionId = safeInput.session_id || safeInput.sessionId || '';
  const cwd = safeInput.cwd || process.cwd();
  const sDir = typeof stateDir === 'function' ? stateDir(safeEnv) : null;
  const ensembleInfo = detectCrewEnsemble('neckbeard', cwd, safeEnv);
  const isLeader = Boolean(ensembleInfo.isEnsembleLeader || !ensembleInfo.installedPeers || ensembleInfo.installedPeers.length <= 1);
  const defLvl = (typeof defaultLevel === 'function' && defaultLevel(safeEnv) !== 'off') ? defaultLevel(safeEnv) : 'full';

  // 1. Global /crew on | /crew off | /crew status toggle
  const crewCmd = _act.parseCrewCommand(promptText);
  if (crewCmd) {
    if (crewCmd.crewAction === 'on') {
      _act.writeCrewSessionState(sessionId, { enabled: true, level: crewCmd.level || defLvl }, safeEnv);
      _act.writePersonaSessionState('neckbeard', sessionId, { enabled: null, oneShot: false, oneShotLevel: null }, safeEnv, sDir);
      _act.clearHydrated('neckbeard', sessionId, sDir);
      return isLeader ? _act.formatCrewRosterBanner(ensembleInfo, crewCmd.level || defLvl) : '';
    }
    if (crewCmd.crewAction === 'off') {
      _act.writeCrewSessionState(sessionId, { enabled: false }, safeEnv);
      _act.writePersonaSessionState('neckbeard', sessionId, { enabled: false, level: 'off', oneShot: false }, safeEnv, sDir);
      _act.clearHydrated('neckbeard', sessionId, sDir);
      return isLeader
        ? 'CREW MODE OFF for this session. All personas returned to standby (use /<persona> <prompt> for one-shot tasks, /<persona> on to enable one persona, or /crew on to re-enable Crew). Confirm in one short line.'
        : '';
    }
    if (crewCmd.crewAction === 'status') {
      return isLeader ? _act.formatCrewStatusBanner(ensembleInfo, sessionId, safeEnv) : '';
    }
  }

  const cmd = parseCommand(promptText);
  const actBefore = _act.resolveActivation('neckbeard', sessionId, safeEnv, {
    personaStateDir: sDir,
    defaultLevelFn: typeof defaultLevel === 'function' ? defaultLevel : null,
  });

  // 2. Ordinary prompt (no /<persona> command)
  if (!cmd) {
    if (_act.isPersonaBranchSlash('neckbeard', ["larry","lari"], promptText)) {
      _act.writePersonaSessionState('neckbeard', sessionId, { oneShot: true, oneShotLevel: actBefore.active ? actBefore.level : defLvl }, safeEnv, sDir);
      return '';
    }
    _act.clearPersonaOneShot('neckbeard', sessionId, safeEnv, sDir);
    const act = _act.resolveActivation('neckbeard', sessionId, safeEnv, {
      personaStateDir: sDir,
      defaultLevelFn: typeof defaultLevel === 'function' ? defaultLevel : null,
    });
    if (!act.active) return '';
    if ((act.mode === 'crew' || act.mode === 'persona') && !_act.isHydrated('neckbeard', sessionId, sDir) && _act.matchesPersonaRelevance('neckbeard', promptText)) {
      _act.markHydrated('neckbeard', sessionId, sDir);
      return _buildActivationFullContext(safeInput, safeEnv, ensembleInfo, act.level);
    }
    return '';
  }

  // 3. One-shot ("onesie-twosie") task invocation: /<id> <prompt>
  if (typeof cmd === 'object' && cmd.action === 'oneshot') {
    const oneLevel = cmd.level || (actBefore.active ? actBefore.level : defLvl);
    _act.writePersonaSessionState('neckbeard', sessionId, { oneShot: true, oneShotLevel: oneLevel }, safeEnv, sDir);
    const fullCtx = _buildActivationFullContext(safeInput, safeEnv, ensembleInfo, oneLevel);
    return _act.formatOneShotHeader('NeckBeard', 'neckbeard', oneLevel) + (fullCtx ? '\n\n' + fullCtx : '');
  }

  // 4. Status query: /<id> status
  if (typeof cmd === 'object' && cmd.action === 'status') {
    return _act.formatPersonaStatusLine('NeckBeard', 'neckbeard', actBefore);
  }

  // 5. Known subcommands (map, load, memory, triage, verify, persona, share, etc.)
  if (typeof cmd === 'object' && cmd.action) {
    return null; // delegate to native main() subcommand handler
  }

  // 6. Explicit enable / disable / level switch
  if (cmd === 'off') {
    _act.writePersonaSessionState('neckbeard', sessionId, { enabled: false, level: 'off', oneShot: false }, safeEnv, sDir);
    _act.clearHydrated('neckbeard', sessionId, sDir);
    try { writeLevel(sessionId, 'off', safeEnv); } catch { /* best-effort */ }
    return 'NECKBEARD MODE OFF for this session (returned to standby). Confirm in one short line.';
  }
  if (cmd === 'on' || cmd === 'lite' || cmd === 'full' || cmd === 'paranoid') {
    const curLvl = actBefore.active ? actBefore.level : defLvl;
    const next = cmd === 'on' ? curLvl : cmd;
    _act.writePersonaSessionState('neckbeard', sessionId, { enabled: true, level: next, oneShot: false }, safeEnv, sDir);
    _act.markHydrated('neckbeard', sessionId, sDir);
    try { writeLevel(sessionId, next, safeEnv); } catch { /* best-effort */ }
    return null; // delegate to native main() to emit persona-flavored level confirmation + rules
  }

  return null;
}

async function main() {
  const input = await readInput();
  const _activatedOut = _handleActivatedPrompt(input, process.env);
  if (_activatedOut !== null) {
    if (_activatedOut) emitContext('UserPromptSubmit', _activatedOut);
    return;
  }
  const cmd = parseCommand(input.prompt);
  const id = input.session_id;
  const cwd = input.cwd || process.cwd();
  const current = readLevel(id);
  const sDir = stateDir();

  if (!cmd) {
    if (current === 'off') return;
    const ensembleInfo = detectCrewEnsemble('neckbeard', cwd, process.env);
    if (
      shouldDeferSessionStart(ensembleInfo, process.env) &&
      !isPersonaHydrated('neckbeard', id, sDir) &&
      matchesPersonaIntent('neckbeard', input.prompt)
    ) {
      markPersonaHydrated('neckbeard', id, sDir);
      const hydrated = buildFullNeckbeardContext(input, process.env, ensembleInfo, current);
      if (hydrated) emitContext('UserPromptSubmit', hydrated);
    }
    return;
  }

  if (typeof cmd === 'object' && cmd.action) {
    markPersonaHydrated('neckbeard', id, sDir);
    emitContext('UserPromptSubmit', handleSubcommand(cmd, cwd));
    return;
  }

  if (cmd === 'unknown') {
    emitContext('UserPromptSubmit', `NECKBEARD: unknown command or level. Use lite, full, paranoid, off, load <val>, map, share on|off, or band on|off|import|board. Level stays ${current}.`);
    return;
  }
  const next = cmd === 'on' ? (current === 'off' ? 'full' : current) : cmd;
  writeLevel(id, next);
  if (next === 'off') {
    clearPersonaHydrated('neckbeard', id, sDir);
  } else {
    markPersonaHydrated('neckbeard', id, sDir);
  }
  emitContext('UserPromptSubmit', next === 'off'
    ? 'NECKBEARD MODE OFF for this session. Confirm in one short line.'
    : `NECKBEARD level is now ${next}. Confirm in one short line.\n\n${rules(next)}`);
}

module.exports = { parseCommand, handleSubcommand };

if (require.main === module) main().finally(() => setTimeout(() => process.exit(0), 0));
