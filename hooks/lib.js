'use strict';
// Shared by every neckbeard hook: levels, per-session state, hook I/O.
// No dependencies, no network, writes only its own state files.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHash } = require('crypto');

const LEVELS = ['lite', 'full', 'paranoid'];
const DEFAULT_LEVEL = 'full';

function normalizeLevel(value) {
  const v = String(value || '').trim().toLowerCase();
  return v === 'off' || LEVELS.includes(v) ? v : null;
}

// NECKBEARD_LEVEL beats the config file; anything unreadable falls back to full.
function defaultLevel(env = process.env) {
  const fromEnv = normalizeLevel(env.NECKBEARD_LEVEL);
  if (fromEnv) return fromEnv;
  try {
    const base = env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    const cfg = JSON.parse(fs.readFileSync(path.join(base, 'neckbeard', 'config.json'), 'utf8'));
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
  if (!file) return;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, level, { mode: 0o600 });
  fs.renameSync(tmp, file);
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
      try { resolve(JSON.parse(raw.replace(/^﻿/, '') || '{}')); } catch { resolve({}); }
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

module.exports = {
  LEVELS, DEFAULT_LEVEL, normalizeLevel, defaultLevel, statePath, readLevel, writeLevel,
  readInput, emitContext, emitDeny, rules,
};
