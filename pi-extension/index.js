import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  LEVELS,
  DEFAULT_LEVEL,
  normalizeLevel,
  defaultLevel,
  readGuardStats,
  rules,
} = require('../hooks/lib.js');
const {
  buildBoundaryMap,
  readProjectConfig,
  writeProjectConfig,
  formatProjectContext,
  detectBoundaryDrift,
} = require('../hooks/surface.js');
const { hasVibes, formatVibesContext } = require('../hooks/vibes.js');

const COMMAND_DESCRIPTION = 'Set level: lite|full|paranoid|off. Commands: status, load <val>, map, share on|off';

export function completeNeckbeardArgs(prefix) {
  const typed = String(prefix || '').trimStart();
  const values = [
    ...LEVELS,
    'off',
    'status',
    'map',
    'share on',
    'share off',
    'load ',
  ].filter((v) => v.startsWith(typed));
  return values.length ? values.map((value) => ({ value, label: value })) : null;
}

export function parseNeckbeardCommand(text, currentLevel = DEFAULT_LEVEL) {
  const raw = String(text || '').trim();
  const lower = raw.toLowerCase();
  if (!raw) {
    return currentLevel && currentLevel !== 'off'
      ? { type: 'status' }
      : { type: 'set-level', level: DEFAULT_LEVEL };
  }
  const tokens = raw.split(/\s+/);
  const sub = tokens[0].toLowerCase();
  if (sub === 'status') return { type: 'status' };
  if (sub === 'map') return { type: 'map' };
  if (sub === 'load') return { type: 'load', value: raw.slice(4).trim() };
  if (sub === 'share') {
    const mode = (tokens[1] || '').toLowerCase();
    return mode === 'on' || mode === 'off' ? { type: 'share', value: mode } : { type: 'invalid' };
  }
  const lvl = normalizeLevel(sub);
  return lvl ? { type: 'set-level', level: lvl } : { type: 'invalid' };
}

export default function neckbeardExtension(pi) {
  let currentLevel = defaultLevel();
  let isActive = false;
  let lastCtx = null;

  function syncStatus(ctx) {
    if (ctx) lastCtx = ctx;
    const c = ctx || lastCtx;
    if (!c?.ui?.setStatus) return;
    let theme;
    try {
      theme = c.ui.theme;
      if (!theme?.fg) return;
    } catch {
      return;
    }
    if (currentLevel === 'off') {
      c.ui.setStatus('neckbeard', undefined);
      return;
    }
    const levelIcons = { lite: '🌿', full: '🛡️', paranoid: '🔒' };
    const icon = levelIcons[currentLevel] || '🛡️';
    const label = currentLevel.toUpperCase();
    const indicator = isActive ? theme.fg('accent', '●') : theme.fg('dim', '○');
    const cfg = readProjectConfig(process.cwd());
    const drift = detectBoundaryDrift(process.cwd());
    const guard = readGuardStats();
    const extras = [];
    if (cfg && cfg.load) extras.push(cfg.load.slice(0, 20));
    if (guard && guard.total > 0) extras.push(`${guard.total} blocked`);
    if (drift && drift.added.length > 0) extras.push(`⚠ +${drift.added.length} boundary`);
    const tail = extras.length ? theme.fg('muted', ' · ' + extras.join(' · ')) : '';
    c.ui.setStatus(
      'neckbeard',
      indicator + ' 🧔 ' + theme.fg('muted', 'neckbeard: ') + theme.fg('text', `${icon} ${label}`) + tail
    );
  }

  const setLevel = (level, ctx) => {
    const normalized = normalizeLevel(level);
    if (!normalized) return;
    currentLevel = normalized;
    pi.appendEntry?.('neckbeard-level', { level: normalized });
    syncStatus(ctx);
    ctx?.ui?.notify?.(`NeckBeard level set to ${normalized}.`, 'info');
  };

  const sendAlias = (skillName, args, ctx) => {
    const normalized = String(args || '').trim();
    const message = normalized ? `${skillName} ${normalized}` : skillName;
    if (ctx?.isIdle?.() === false) {
      pi.sendUserMessage(message, { expandPromptTemplates: true, deliverAs: 'followUp' });
      ctx?.ui?.notify?.(`${skillName} queued as follow-up.`, 'info');
      return;
    }
    pi.sendUserMessage(message, { expandPromptTemplates: true });
  };

  pi.registerCommand('neckbeard', {
    description: COMMAND_DESCRIPTION,
    getArgumentCompletions: (prefix) => completeNeckbeardArgs(prefix),
    handler: async (args, ctx) => {
      const parsed = parseNeckbeardCommand(args, currentLevel);
      if (parsed.type === 'status') {
        const cfg = readProjectConfig(process.cwd());
        ctx?.ui?.notify?.(`NeckBeard: level ${currentLevel} • load ${(cfg && cfg.load) || 'unset'}`, 'info');
        return;
      }
      if (parsed.type === 'set-level') {
        setLevel(parsed.level, ctx);
        return;
      }
      if (parsed.type === 'load') {
        if (!parsed.value) {
          const cfg = readProjectConfig(process.cwd());
          ctx?.ui?.notify?.(`NeckBeard load: ${(cfg && cfg.load) || 'unset'}`, 'info');
          return;
        }
        const kv = parsed.value.match(/^([a-z-]+)\s*=\s*([\s\S]*)$/i);
        const saved = kv
          ? writeProjectConfig(process.cwd(), { boundaryLoad: { [kv[1].toLowerCase()]: kv[2].trim() } })
          : writeProjectConfig(process.cwd(), { load: parsed.value });
        syncStatus(ctx);
        ctx?.ui?.notify?.(`Saved load default (${saved.shared ? 'shared' : 'local'}): ${saved.load}`, 'info');
        return;
      }
      if (parsed.type === 'map') {
        writeProjectConfig(process.cwd(), { boundaries: buildBoundaryMap(process.cwd()) });
        syncStatus(ctx);
        ctx?.ui?.notify?.('NeckBeard trust-boundary map refreshed.', 'info');
        return;
      }
      if (parsed.type === 'share') {
        const shared = parsed.value === 'on';
        writeProjectConfig(process.cwd(), { shared });
        syncStatus(ctx);
        ctx?.ui?.notify?.(`NeckBeard git sharing ${shared ? 'enabled (.neckbeard.json)' : 'disabled (local)'}.`, 'info');
        return;
      }
      ctx?.ui?.notify?.('Unknown /neckbeard command. Use lite|full|paranoid|off, load, map, or share on|off.', 'warning');
    },
  });

  for (const cmd of ['neckbeard-review', 'neckbeard-audit', 'neckbeard-debt', 'neckbeard-gain']) {
    pi.registerCommand(cmd, {
      description: cmd === 'neckbeard-audit' ? 'Run /skill:neckbeard-audit [lite|complete]' : `Run /skill:${cmd}`,
      getArgumentCompletions: cmd === 'neckbeard-audit'
        ? (prefix) => ['lite', 'complete'].filter((v) => v.startsWith(String(prefix || '').trimStart())).map((value) => ({ value, label: value }))
        : undefined,
      handler: (args, ctx) => sendAlias(`/skill:${cmd}`, args, ctx),
    });
  }

  pi.on('session_start', async (_event, ctx) => {
    currentLevel = defaultLevel();
    syncStatus(ctx);
  });

  for (const eventName of ['session_tree', 'session_switch', 'session_branch']) {
    pi.on(eventName, async (_event, ctx) => syncStatus(ctx));
  }

  pi.on('agent_start', async (_event, ctx) => {
    isActive = true;
    syncStatus(ctx);
  });

  pi.on('agent_end', async (_event, ctx) => {
    isActive = false;
    syncStatus(ctx);
  });

  pi.on('before_agent_start', async (event) => {
    if (!currentLevel || currentLevel === 'off') {
      if (event?.systemPromptOptions?.sections) delete event.systemPromptOptions.sections.neckbeard;
      return;
    }
    let text = rules(currentLevel);
    const cwd = process.cwd();
    if (readProjectConfig(cwd) || process.env.NECKBEARD_SURFACE === '1') {
      const ctx = formatProjectContext(cwd);
      if (ctx) text += '\n\n' + ctx;
    }
    if (hasVibes(cwd)) {
      const vibes = formatVibesContext(cwd);
      if (vibes) text += '\n\n' + vibes;
    }
    const sections = event?.systemPromptOptions?.sections;
    if (sections && typeof sections === 'object') {
      sections.neckbeard = text;
      return;
    }
    if (Array.isArray(event?.systemPrompt)) {
      return { systemPrompt: [...event.systemPrompt, text] };
    }
    const base = event?.systemPrompt ? `${event.systemPrompt}\n\n` : '';
    return { systemPrompt: `${base}${text}` };
  });
}
