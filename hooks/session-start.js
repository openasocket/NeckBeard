'use strict';
// SessionStart: load the ruleset for this session's level; when NECKBEARD_SURFACE=1,
// include a map of where the codebase touches untrusted input and dangerous sinks.

const path = require('path');
const { execFileSync } = require('child_process');
const { readInput, readLevel, writeLevel, emitContext, rules } = require('./lib');

(async () => {
  const input = await readInput();
  const level = readLevel(input.session_id); // compact and resume keep the session's level
  try { writeLevel(input.session_id, level); } catch { /* state is best-effort */ }
  if (level === 'off') return;

  let text = rules(level);
  if (process.env.NECKBEARD_SURFACE === '1') {
    try {
      const map = execFileSync(process.execPath, [path.join(__dirname, 'surface.js'), input.cwd || process.cwd()], {
        encoding: 'utf8', timeout: 3000, maxBuffer: 256 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (map) text += '\n\n' + map;
    } catch { /* a slow or failed map never costs the rules */ }
  }
  emitContext('SessionStart', text);
})().finally(() => setTimeout(() => process.exit(0), 0));
