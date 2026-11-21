'use strict';
// UserPromptSubmit: "/neckbeard <level>", "$neckbeard <level>", "@neckbeard <level>", and "stop neckbeard" change this session's level.

const { readInput, readLevel, writeLevel, normalizeLevel, emitContext, rules } = require('./lib');

function parseCommand(prompt) {
  const p = String(prompt || '').trim().toLowerCase();
  if (/^(stop neckbeard|neckbeard off|normal mode)\b/.test(p)) return 'off';
  const m = p.match(/^[/@$]neckbeard(?::neckbeard)?(?:\s+(\S+))?\s*$/);
  if (!m) return null;
  return m[1] ? normalizeLevel(m[1]) || 'unknown' : 'on';
}

async function main() {
  const input = await readInput();
  const cmd = parseCommand(input.prompt);
  if (!cmd) return;
  const id = input.session_id;
  const current = readLevel(id);
  if (cmd === 'unknown') {
    emitContext('UserPromptSubmit', `NECKBEARD: unknown level. Use lite, full, paranoid or off. Level stays ${current}.`);
    return;
  }
  const next = cmd === 'on' ? (current === 'off' ? 'full' : current) : cmd;
  writeLevel(id, next);
  emitContext('UserPromptSubmit', next === 'off'
    ? 'NECKBEARD MODE OFF for this session. Confirm in one short line.'
    : `NECKBEARD level is now ${next}. Confirm in one short line.\n\n${rules(next)}`);
}

module.exports = { parseCommand };

if (require.main === module) main().finally(() => setTimeout(() => process.exit(0), 0));
