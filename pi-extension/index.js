// NeckBeard native extension for Pi and Oh My Pi (omp).
// 100% original implementation: renders live TUI status indicator, registers /neckbeard* commands,
// and injects active NeckBeard gates, .neckbeard.json load/trust-boundary map, and VIBES telemetry.

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
  buildArchitectureMap,
  readProjectConfig,
  writeProjectConfig,
  ensureFreshBoundaryMap,
  formatProjectContext,
  detectBoundaryDrift,
} = require('../hooks/surface.js');
const { hasVibes, formatVibesContext } = require('../hooks/vibes.js');

export function parseNeckbeardCommand(rawInput, currentLevel = DEFAULT_LEVEL) {
  const trimmed = String(rawInput || '').trim();
  if (!trimmed) {
    return currentLevel && currentLevel !== 'off'
      ? { type: 'status' }
      : { type: 'set-level', level: DEFAULT_LEVEL };
  }
  const parts = trimmed.split(/\s+/);
  const verb = parts[0].toLowerCase();
  if (verb === 'status') return { type: 'status' };
  if (verb === 'map') {
    return parts.slice(1).some((t) => t.toLowerCase() === '--uncapped')
      ? { type: 'map', uncapped: true }
      : { type: 'map' };
  }
  if (verb === 'load') return { type: 'load', value: trimmed.slice(4).trim() };
  if (verb === 'share') {
    const toggle = (parts[1] || '').toLowerCase();
    return toggle === 'on' || toggle === 'off' ? { type: 'share', value: toggle } : { type: 'invalid' };
  }
  const normalized = normalizeLevel(verb);
  return normalized ? { type: 'set-level', level: normalized } : { type: 'invalid' };
}

export default function registerNeckbeardPi(host) {
  let activeLevel = defaultLevel();
  let agentBusy = false;

  function renderStatusStrip(ctx) {
    const ui = ctx?.ui;
    if (!ui?.setStatus) return;
    if (activeLevel === 'off') {
      ui.setStatus('neckbeard', undefined);
      return;
    }
    let paint = (_tone, text) => text;
    try {
      if (ui.theme && typeof ui.theme.fg === 'function') paint = (t, s) => ui.theme.fg(t, s);
    } catch {
      return;
    }
    const dot = agentBusy ? paint('accent', '●') : paint('dim', '○');
    const badge = `${dot} 🧔 ${paint('muted', 'neckbeard:')} ${paint('text', activeLevel.toUpperCase())}`;
    const workspaceCfg = readProjectConfig(process.cwd());
    const drift = detectBoundaryDrift(process.cwd());
    const guard = readGuardStats();
    const details = [];
    if (workspaceCfg && workspaceCfg.load) details.push(workspaceCfg.load.slice(0, 22));
    if (guard && guard.total > 0) details.push(`🛡️ ${guard.total} blocked`);
    if (drift && drift.added.length > 0) details.push(`⚠ +${drift.added.length} boundary`);
    const suffix = details.length ? paint('muted', ` · ${details.join(' · ')}`) : '';
    ui.setStatus('neckbeard', badge + suffix);
  }

  host.registerCommand('neckbeard', {
    description: 'Configure NeckBeard level (lite|full|paranoid|off), load target, trust map, or git sharing',
    getArgumentCompletions: (prefix) => {
      const p = String(prefix || '').trimStart();
      return [...LEVELS, 'ultra', 'off', 'status', 'map', 'share on', 'share off', 'load ']
        .filter((opt) => opt.startsWith(p))
        .map((value) => ({ value, label: value }));
    },
    handler: async (args, ctx) => {
      const cmd = parseNeckbeardCommand(args, activeLevel);
      if (cmd.type === 'status') {
        const cfg = readProjectConfig(process.cwd());
        ctx?.ui?.notify?.(`NeckBeard [${activeLevel}] • load: ${(cfg && cfg.load) || 'unset'}`, 'info');
        return;
      }
      if (cmd.type === 'set-level') {
        activeLevel = cmd.level;
        host.appendEntry?.('neckbeard-level', { level: activeLevel });
        renderStatusStrip(ctx);
        ctx?.ui?.notify?.(`NeckBeard level switched to ${activeLevel}.`, 'info');
        return;
      }
      if (cmd.type === 'load') {
        if (!cmd.value) {
          const cfg = readProjectConfig(process.cwd());
          ctx?.ui?.notify?.(`NeckBeard load target: ${(cfg && cfg.load) || 'unset'}`, 'info');
          return;
        }
        const kv = cmd.value.match(/^([a-z-]+)\s*=\s*([\s\S]*)$/i);
        const saved = kv
          ? writeProjectConfig(process.cwd(), { boundaryLoad: { [kv[1].toLowerCase()]: kv[2].trim() } })
          : writeProjectConfig(process.cwd(), { load: cmd.value });
        renderStatusStrip(ctx);
        ctx?.ui?.notify?.(`Saved load target (${saved.shared ? 'shared' : 'local'}): ${saved.load}`, 'info');
        return;
      }
      if (cmd.type === 'map') {
        const scanOpts = cmd.uncapped ? { uncapped: true } : {};
        const boundaries = buildBoundaryMap(process.cwd(), 16, scanOpts);
        const architecture = buildArchitectureMap(process.cwd(), 16, 24, scanOpts);
        writeProjectConfig(process.cwd(), { boundaries, architecture }, process.env, scanOpts);
        renderStatusStrip(ctx);
        const capNotice = boundaries.notice || architecture.notice;
        ctx?.ui?.notify?.(
          capNotice
            ? `Refreshed Trust-Boundary & Architecture Map (truncated: ${capNotice})`
            : 'Refreshed External & Internal Trust-Boundary & Architecture Map.',
          capNotice ? 'warning' : 'info'
        );
        return;
      }
      if (cmd.type === 'share') {
        const shared = cmd.value === 'on';
        writeProjectConfig(process.cwd(), { shared });
        renderStatusStrip(ctx);
        ctx?.ui?.notify?.(`Git sharing of .neckbeard.json ${shared ? 'enabled' : 'disabled (moved local)'}.`, 'info');
        return;
      }
      ctx?.ui?.notify?.('Usage: /neckbeard [lite|full|paranoid|off|load <val>|map|share on|off]', 'warning');
    },
  });

  for (const skillCmd of ['neckbeard-review', 'neckbeard-audit', 'neckbeard-debt', 'neckbeard-gain', 'neckbeard-map', 'neckbeard-memory']) {
    host.registerCommand(skillCmd, {
      description: skillCmd === 'neckbeard-audit' ? 'Run /skill:neckbeard-audit [lite|complete]' : `Run /skill:${skillCmd}`,
      getArgumentCompletions:
        skillCmd === 'neckbeard-audit'
          ? (prefix) =>
              ['lite', 'complete']
                .filter((opt) => opt.startsWith(String(prefix || '').trimStart()))
                .map((value) => ({ value, label: value }))
          : undefined,
      handler: (args, ctx) => {
        const trimmed = String(args || '').trim();
        const prompt = trimmed ? `/skill:${skillCmd} ${trimmed}` : `/skill:${skillCmd}`;
        if (ctx?.isIdle?.() === false) {
          host.sendUserMessage(prompt, { expandPromptTemplates: true, deliverAs: 'followUp' });
        } else {
          host.sendUserMessage(prompt, { expandPromptTemplates: true });
        }
      },
    });
  }

  host.on('session_start', async (_evt, ctx) => {
    activeLevel = defaultLevel();
    renderStatusStrip(ctx);
  });

  host.on('agent_start', async (_evt, ctx) => {
    agentBusy = true;
    renderStatusStrip(ctx);
  });

  host.on('agent_end', async (_evt, ctx) => {
    agentBusy = false;
    renderStatusStrip(ctx);
  });

  host.on('before_agent_start', async (evt) => {
    if (!activeLevel || activeLevel === 'off') {
      if (evt?.systemPromptOptions?.sections) delete evt.systemPromptOptions.sections.neckbeard;
      return;
    }
    const cwd = process.cwd();
    const parts = [rules(activeLevel)];
    try {
      ensureFreshBoundaryMap(cwd);
      const projCtx = formatProjectContext(cwd);
      if (projCtx) parts.push(projCtx);
    } catch {}
    if (hasVibes(cwd)) {
      const vibesCtx = formatVibesContext(cwd);
      if (vibesCtx) parts.push(vibesCtx);
    }
    const bundle = parts.join('\n\n');
    if (evt?.systemPromptOptions?.sections && typeof evt.systemPromptOptions.sections === 'object') {
      evt.systemPromptOptions.sections.neckbeard = bundle;
      return;
    }
    if (Array.isArray(evt?.systemPrompt)) {
      return { systemPrompt: [...evt.systemPrompt, bundle] };
    }
    const prefix = evt?.systemPrompt ? `${evt.systemPrompt}\n\n` : '';
    return { systemPrompt: `${prefix}${bundle}` };
  });
}
