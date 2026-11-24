'use strict';
// Shared by every neckbeard hook: levels, per-session state, guard telemetry counters, hook I/O.
// No dependencies, no network, writes only its own state files.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHash } = require('crypto');

const LEVELS = ['lite', 'full', 'paranoid'];
const DEFAULT_LEVEL = 'full';

function normalizeLevel(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'ultra') return 'paranoid';
  return v === 'off' || LEVELS.includes(v) ? v : null;
}

function configBase(env = process.env) {
  return env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
}

function claudeDir(env = process.env) {
  return env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
}

function bandDir(env = process.env) {
  return path.join(configBase(env), 'neckbeard', 'telemetry');
}

// NECKBEARD_LEVEL beats the config file; anything unreadable falls back to full.
function defaultLevel(env = process.env) {
  const fromEnv = normalizeLevel(env.NECKBEARD_LEVEL);
  if (fromEnv) return fromEnv;
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(configBase(env), 'neckbeard', 'config.json'), 'utf8'));
    return normalizeLevel(cfg.defaultLevel) || DEFAULT_LEVEL;
  } catch {
    return DEFAULT_LEVEL;
  }
}

// One file per session, so parallel agents in the same project (Maestro, worktrees)
// never flip each other's level. Session ids are hashed: never used as a path.
function stateDir(env = process.env) {
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'u';
  return env.NECKBEARD_STATE_DIR || path.join(os.tmpdir(), `neckbeard-${uid}`);
}

function statePath(sessionId, env = process.env) {
  if (!sessionId) return null;
  const key = createHash('sha256').update(String(sessionId)).digest('hex').slice(0, 32);
  return path.join(stateDir(env), key);
}

function readLevel(sessionId, env = process.env) {
  const file = statePath(sessionId, env);
  if (file) {
    try {
      const v = normalizeLevel(fs.readFileSync(file, 'utf8'));
      if (v) return v;
    } catch { /* no state yet */ }
  }
  return defaultLevel(env);
}

function writeLevel(sessionId, level, env = process.env) {
  const file = statePath(sessionId, env);
  if (file) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, level, { mode: 0o600 });
    fs.renameSync(tmp, file);
  }
  // Also sync the active level flag in stateDir (and CLAUDE_CONFIG_DIR when writable) for the Claude Code band & statusline.
  try {
    const dir = stateDir(env);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, '.neckbeard-active'), level, { mode: 0o600 });
  } catch { /* best-effort */ }
}

// Local-only security telemetry counter for PreToolUse guard blocks (never records secret values).
function guardStatsPath(env = process.env) {
  return path.join(stateDir(env), 'guard-stats.json');
}

function recordGuardBlock(sessionId, kind, cwd = process.cwd(), env = process.env) {
  try {
    const file = guardStatsPath(env);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    let data = { total: 0, sessions: {}, projects: {} };
    try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* fresh */ }
    data.total = (Number(data.total) || 0) + 1;
    const sid = String(sessionId || 'default');
    const proj = path.basename(path.resolve(cwd || process.cwd())) || 'default';
    data.sessions[sid] = (Number(data.sessions[sid]) || 0) + 1;
    if (!data.projects[proj]) data.projects[proj] = { blocks: 0, byKind: {} };
    data.projects[proj].blocks = (Number(data.projects[proj].blocks) || 0) + 1;
    data.projects[proj].byKind[kind] = (Number(data.projects[proj].byKind[kind]) || 0) + 1;
    fs.writeFileSync(file, JSON.stringify(data), { mode: 0o600 });
  } catch { /* best-effort */ }
}

function readGuardStats(env = process.env) {
  try {
    return JSON.parse(fs.readFileSync(guardStatsPath(env), 'utf8'));
  } catch {
    return { total: 0, sessions: {}, projects: {} };
  }
}

// Hooks get one JSON object on stdin. Never hang the session on a stuck pipe or unbounded payload.
const MAX_INPUT = 4 * 1024 * 1024;

function readInput(timeoutMs = 1000) {
  return new Promise((resolve) => {
    let raw = '';
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      try { resolve(JSON.parse(raw.replace(/^\uFEFF/, '') || '{}')); } catch { resolve({}); }
    };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => {
      if (raw.length < MAX_INPUT) raw += c.slice(0, MAX_INPUT - raw.length);
      if (raw.length >= MAX_INPUT) finish();
    });
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
    setTimeout(finish, timeoutMs).unref();
  });
}

function emitContext(event, text) {
  if (!text) return;
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: event, additionalContext: text } }));
}

function emitDeny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
  }));
}

const SKILL = path.join(__dirname, '..', 'skills', 'neckbeard', 'SKILL.md');

// The ruleset is the neckbeard skill body, so /neckbeard and the hooks never drift apart.
function rules(level) {
  let body;
  try {
    body = fs.readFileSync(SKILL, 'utf8').replace(/^---[\s\S]*?---\s*/, '');
  } catch {
    body = 'Smallest change that is correct, safe at the boundary it crosses, fast and scalable at a named load, simple for the end user, and finished. Never cut trust checks, object authorization, secret handling, or error handling that prevents data loss.';
  }
  return `NECKBEARD MODE ACTIVE, level: ${level}. Switch with /neckbeard, $neckbeard, or @neckbeard, then lite, full, paranoid, or off.\n\n${body.trim()}`;
}

const { CREW_PIPELINE_ORDER, CREW_STORE_FILES, detectCrewEnsemble, formatEnsembleRules } = require('./ensemble');

module.exports = {
  LEVELS, DEFAULT_LEVEL, normalizeLevel, defaultLevel, stateDir, statePath, readLevel, writeLevel,
  configBase, claudeDir, bandDir, recordGuardBlock, readGuardStats,
  readInput, emitContext, emitDeny, rules,
  CREW_PIPELINE_ORDER, CREW_STORE_FILES, detectCrewEnsemble, formatEnsembleRules,
};
