// NeckBeard native plugin for OpenCode & Kilo Code.
// 100% original implementation: mounts the five NeckBeard skills and injects the active ruleset,
// .neckbeard.json load target & trust-boundary map, and VIBES telemetry into system context.

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pluginDir = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { defaultLevel, normalizeLevel, rules } = require('../../hooks/lib.js');
const { handleSubcommand, parseCommand } = require('../../hooks/prompt.js');
const { ensureFreshBoundaryMap, formatProjectContext } = require('../../hooks/surface.js');
const { hasVibes, formatVibesContext } = require('../../hooks/vibes.js');

let sessionLevel = defaultLevel();

function assembleContextPayload(workspaceRoot = process.cwd()) {
  if (!sessionLevel || sessionLevel === 'off') return '';
  const blocks = [rules(sessionLevel)];
  try {
    ensureFreshBoundaryMap(workspaceRoot);
    const mapBlock = formatProjectContext(workspaceRoot);
    if (mapBlock) blocks.push(mapBlock);
  } catch {}
  try {
    if (hasVibes(workspaceRoot)) {
      const vibesBlock = formatVibesContext(workspaceRoot);
      if (vibesBlock) blocks.push(vibesBlock);
    }
  } catch {}
  return blocks.join('\n\n');
}

function loadBundledSkills() {
  const rootSkillsDir = path.resolve(pluginDir, '../../skills');
  try {
    return fs
      .readdirSync(rootSkillsDir, { withFileTypes: true })
      .filter((ent) => ent.isDirectory())
      .map((ent) => {
        const skillPath = path.join(rootSkillsDir, ent.name, 'SKILL.md');
        const raw = fs.readFileSync(skillPath, 'utf8');
        return {
          id: ent.name,
          name: ent.name,
          description: `NeckBeard skill (${ent.name})`,
          path: skillPath,
          content: raw.replace(/^---[\s\S]*?---\s*/, '').trim(),
        };
      });
  } catch {
    return [];
  }
}

export default {
  id: 'neckbeard',

  async setup(hostCtx) {
    const skills = loadBundledSkills();
    if (hostCtx?.skill?.transform) {
      await hostCtx.skill.transform((registry) => {
        for (const s of skills) registry.add(s);
      });
    }
    if (hostCtx?.command?.transform) {
      await hostCtx.command.transform((registry) => {
        registry.add({
          name: 'neckbeard',
          description: 'Manage NeckBeard level, load target, trust-boundary map, git sharing, and telemetry',
          execute: async ({ prompt }) => {
            const parsed = parseCommand(`/neckbeard ${(prompt && prompt.text) || ''}`);
            if (typeof parsed === 'string' && normalizeLevel(parsed)) sessionLevel = normalizeLevel(parsed);
            else if (parsed === 'on') sessionLevel = sessionLevel === 'off' ? 'full' : sessionLevel;
            else if (parsed && typeof parsed === 'object') handleSubcommand(parsed, process.cwd());
          },
        });
      });
    }
    const appendSystemContext = (evt) => {
      const payload = assembleContextPayload(process.cwd());
      if (payload && Array.isArray(evt?.system)) {
        evt.system.push({ type: 'text', text: payload });
      }
    };
    if (hostCtx?.session?.hook) {
      await hostCtx.session.hook('context', appendSystemContext);
      await hostCtx.session.hook('compaction', appendSystemContext);
    }
  },

  async server() {
    return {
      config: async (cfg) => {
        cfg.skills = cfg.skills || {};
        cfg.skills.paths = cfg.skills.paths || [];
        const rootSkillsDir = path.resolve(pluginDir, '../../skills');
        if (!cfg.skills.paths.includes(rootSkillsDir)) cfg.skills.paths.push(rootSkillsDir);
      },
      'experimental.chat.system.transform': async (_req, res) => {
        const payload = assembleContextPayload(process.cwd());
        if (!payload) return;
        if (res.system.length > 0) res.system[res.system.length - 1] += '\n\n' + payload;
        else res.system.push(payload);
      },
    };
  },
};
