'use strict';
// SubagentStart: session context never reaches subagents, so hand them the ruleset too.
// NECKBEARD_SUBAGENTS=0 turns this off.

const { readInput, readLevel, emitContext, rules } = require('./lib');

(async () => {
  if (process.env.NECKBEARD_SUBAGENTS === '0') return;
  const input = await readInput();
  const level = readLevel(input.session_id);
  if (level !== 'off') emitContext('SubagentStart', rules(level));
})().finally(() => setTimeout(() => process.exit(0), 0));
