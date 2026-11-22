'use strict';
// UserPromptSubmit:
//   - "/neckbeard <level>", "$neckbeard <level>", "@neckbeard <level>", and "stop neckbeard" change this session's level.
//   - "/neckbeard load [value]" views or saves the project's default load parameters (strictly censored).
//   - "/neckbeard map" builds/refreshes the concise internal & external trust-boundary map.
//   - "/neckbeard share [on|off]" toggles git sharing of .neckbeard.json (default: shared in repo root).
//   - "/neckbeard band [on|off|import|board]" controls the Claude Code banner and local telemetry board.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { readInput, readLevel, writeLevel, normalizeLevel, claudeDir, emitContext, rules } = require('./lib');
const { buildBoundaryMap, buildArchitectureMap, readProjectConfig, writeProjectConfig, formatProjectContext } = require('./surface');

function parseCommand(prompt) {
  const raw = String(prompt || '').trim();
  const p = raw.toLowerCase();
  if (/^(stop neckbeard|neckbeard off|normal mode)\b/.test(p)) return 'off';
  if (/^[/@$]neckbeard(?::neckbeard)?-map(?:\s|$)/i.test(raw)) return { action: 'map' };
  const m = raw.match(/^[/@$]neckbeard(?::neckbeard)?(?:\s+([\s\S]+))?$/i);
  if (!m) return null;
  if (!m[1]) return 'on';
  const rest = m[1].trim();
  const tokens = rest.split(/\s+/);
  const sub = tokens[0].toLowerCase();

  if (tokens.length === 1) {
    const lvl = normalizeLevel(sub);
    if (lvl) return lvl;
    if (sub === 'map') return { action: 'map' };
    if (sub === 'load') return { action: 'load', value: '' };
    if (sub === 'share') return { action: 'share', value: '' };
    if (sub === 'band') return { action: 'band', value: 'toggle' };
    return 'unknown';
  }

  if (sub === 'load') return { action: 'load', value: rest.slice(4).trim() };
  if (sub === 'map') return { action: 'map' };
  if (sub === 'share') {
    const mode = tokens[1].toLowerCase();
    return mode === 'on' || mode === 'off' ? { action: 'share', value: mode } : 'unknown';
  }
  if (sub === 'band') {
    const mode = tokens[1].toLowerCase();
    return ['on', 'off', 'import', 'board'].includes(mode) ? { action: 'band', value: mode } : 'unknown';
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
    const boundaries = buildBoundaryMap(cwd);
    const architecture = buildArchitectureMap(cwd);
    const saved = writeProjectConfig(cwd, { boundaries, architecture });
    try {
      const child = spawn(process.execPath, [path.join(__dirname, 'band-import.js')], { cwd, detached: true, stdio: 'ignore' });
      child.unref();
    } catch { /* best-effort */ }
    return `NECKBEARD trust-boundary & architecture map updated (${saved.shared ? '.neckbeard.json, shared' : 'local'}).\n\n${formatProjectContext(cwd)}`;
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

async function main() {
  const input = await readInput();
  const cmd = parseCommand(input.prompt);
  if (!cmd) return;
  const id = input.session_id;
  const cwd = input.cwd || process.cwd();
  const current = readLevel(id);

  if (typeof cmd === 'object' && cmd.action) {
    emitContext('UserPromptSubmit', handleSubcommand(cmd, cwd));
    return;
  }

  if (cmd === 'unknown') {
    emitContext('UserPromptSubmit', `NECKBEARD: unknown command or level. Use lite, full, paranoid, off, load <val>, map, share on|off, or band on|off|import|board. Level stays ${current}.`);
    return;
  }
  const next = cmd === 'on' ? (current === 'off' ? 'full' : current) : cmd;
  writeLevel(id, next);
  emitContext('UserPromptSubmit', next === 'off'
    ? 'NECKBEARD MODE OFF for this session. Confirm in one short line.'
    : `NECKBEARD level is now ${next}. Confirm in one short line.\n\n${rules(next)}`);
}

module.exports = { parseCommand, handleSubcommand };

if (require.main === module) main().finally(() => setTimeout(() => process.exit(0), 0));
