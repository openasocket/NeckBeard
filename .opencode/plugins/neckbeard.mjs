// NeckBeard — OpenCode & Kilo Code server plugin (supports V2 setup(ctx) and V1 server()).
// Injects the active NeckBeard ruleset, project load default + internal/external trust-boundary map,
// and VIBES (.ai-audit/) summary on every turn, and registers the /neckbeard skills and commands.

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { defaultLevel, normalizeLevel, rules } = require('../../hooks/lib.js');
const { handleSubcommand, parseCommand } = require('../../hooks/prompt.js');
const { readProjectConfig, formatProjectContext } = require('../../hooks/surface.js');
const { hasVibes, formatVibesContext } = require('../../hooks/vibes.js');

let activeLevel = defaultLevel();

function buildSystemText(cwd = process.cwd()) {
  if (!activeLevel || activeLevel === 'off') return '';
  let text = rules(activeLevel);
  try {
    if (readProjectConfig(cwd) || process.env.NECKBEARD_SURFACE === '1') {
      const ctx = formatProjectContext(cwd);
      if (ctx) text += '\n\n' + ctx;
    }
  } catch {}
  try {
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
  } catch {}
  return text;
}

function readSkills() {
  const dir = path.resolve(__dirname, '../../skills');
  try {
    return fs.readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => {
        const file = path.join(dir, entry.name, 'SKILL.md');
        const raw = fs.readFileSync(file, 'utf8');
        const body = raw.replace(/^---[\s\S]*?---\s*/, '').trim();
        return {
          id: entry.name,
          name: entry.name,
          description: `NeckBeard skill: ${entry.name}`,
          path: file,
          content: body,
        };
      });
  } catch {
    return [];
  }
}

export default {
  id: 'neckbeard',

  async setup(ctx) {
    const skills = readSkills();
    if (ctx?.skill?.transform) {
      await ctx.skill.transform((editor) => {
        for (const skill of skills) editor.add(skill);
      });
    }
    if (ctx?.command?.transform) {
      await ctx.command.transform((editor) => {
        editor.add({
          name: 'neckbeard',
          description: 'Switch NeckBeard level (lite|full|paranoid|off) or manage load, map, share, and band',
          execute: async ({ prompt }) => {
            const cmd = parseCommand(`/neckbeard ${(prompt && prompt.text) || ''}`);
            if (typeof cmd === 'string' && normalizeLevel(cmd)) activeLevel = cmd;
            else if (cmd === 'on') activeLevel = activeLevel === 'off' ? 'full' : activeLevel;
            else if (cmd && typeof cmd === 'object') handleSubcommand(cmd, process.cwd());
          },
        });
      });
    }
    const inject = (event) => {
      const text = buildSystemText(process.cwd());
      if (text && Array.isArray(event?.system)) event.system.push({ type: 'text', text });
    };
    if (ctx?.session?.hook) {
      await ctx.session.hook('context', inject);
      await ctx.session.hook('compaction', inject);
    }
  },

  async server() {
    return {
      config: async (config) => {
        config.skills = config.skills || {};
        config.skills.paths = config.skills.paths || [];
        const skillsDir = path.resolve(__dirname, '../../skills');
        if (!config.skills.paths.includes(skillsDir)) config.skills.paths.push(skillsDir);
      },
      'experimental.chat.system.transform': async (_input, output) => {
        const text = buildSystemText(process.cwd());
        if (!text) return;
        if (output.system.length > 0) output.system[output.system.length - 1] += '\n\n' + text;
        else output.system.push(text);
      },
    };
  },
};
