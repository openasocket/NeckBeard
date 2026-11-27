'use strict';
// Cross-platform Cursor IDE / CLI sync helper (scripts/cursor-sync.js).
// Zero external dependencies, zero shell interpolation, fail-closed symlink checks,
// and idempotent multi-persona merging into ~/.cursor/hooks.json.

const fs = require('fs');
const os = require('os');
const path = require('path');

const CURSOR_EVENTS = [
  { event: 'sessionStart' },
  { event: 'subagentStart' },
  { event: 'beforeSubmitPrompt' },
  { event: 'preToolUse', matcher: 'Write|Edit|MultiEdit|StrReplace|Shell|Bash' },
];

function assertNotSymlinkIfExists(targetPath, label = 'path') {
  let st;
  try {
    st = fs.lstatSync(targetPath);
  } catch (err) {
    if (err && err.code === 'ENOENT') return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refused symlink ${label}: ${targetPath}`);
  }
}

function resolveCursorRoot(home, env = process.env) {
  if (env && env.CURSOR_CONFIG_DIR && String(env.CURSOR_CONFIG_DIR).trim()) {
    return path.resolve(String(env.CURSOR_CONFIG_DIR).trim());
  }
  return path.join(home || os.homedir(), '.cursor');
}

function findCursorBinary(env = process.env) {
  const isWin = process.platform === 'win32';
  const home = (env && (env.HOME || env.USERPROFILE)) || os.homedir();
  const pathSep = isWin ? ';' : ':';
  const rawDirs = ((env && env.PATH) || '').split(pathSep).filter(Boolean);
  const extraDirs = isWin
    ? [path.join(home, 'AppData', 'Local', 'Programs', 'cursor', 'resources', 'app', 'bin')]
    : ['/usr/local/bin', '/opt/homebrew/bin', path.join(home, '.local', 'bin')];
  const dirs = [...new Set([...rawDirs, ...extraDirs])];
  const names = isWin ? ['cursor.cmd', 'cursor.exe', 'cursor-agent.cmd', 'cursor-agent.exe'] : ['cursor', 'cursor-agent'];
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch { /* next */ }
    }
  }
  return null;
}

function mergeCursorHooksJson(existing, pluginId, pluginDir) {
  const base = existing && typeof existing === 'object' && !Array.isArray(existing) ? { ...existing } : {};
  base.version = 1;
  const hooks = base.hooks && typeof base.hooks === 'object' && !Array.isArray(base.hooks)
    ? { ...base.hooks }
    : {};
  const adapterPath = path.join(pluginDir, 'hooks', 'cursor-adapter.js');
  const marker = `/${pluginId}/hooks/cursor-adapter.js`;
  const winMarker = `\\${pluginId}\\hooks\\cursor-adapter.js`;

  for (const spec of CURSOR_EVENTS) {
    const prev = Array.isArray(hooks[spec.event]) ? hooks[spec.event] : [];
    const filtered = prev.filter((item) => {
      if (!item || typeof item !== 'object') return true;
      const cmd = String(item.command || '');
      return !cmd.includes(marker) && !cmd.includes(winMarker) && item._crewPersona !== pluginId;
    });
    const entry = {
      command: `node "${adapterPath}" ${spec.event}`,
      timeout: 10,
    };
    if (spec.matcher) entry.matcher = spec.matcher;
    filtered.push(entry);
    hooks[spec.event] = filtered;
  }

  base.hooks = hooks;
  return base;
}

function syncCursorHarness({ rootDir, pluginId, version, env = process.env, home, dryRun = false, syncItems = [] }) {
  const resolvedHome = home || (env && (env.HOME || env.USERPROFILE)) || os.homedir();
  const cursorRoot = resolveCursorRoot(resolvedHome, env);
  const binPath = findCursorBinary(env);
  const hasDir = fs.existsSync(cursorRoot);

  if (!binPath && !hasDir) {
    return {
      harness: 'Cursor',
      id: 'cursor',
      detected: false,
      status: 'skipped',
      pruned: [],
      targets: [],
      copiedCount: 0,
      action: 'skipped (not installed)',
    };
  }

  if (dryRun) {
    return {
      harness: 'Cursor',
      id: 'cursor',
      detected: true,
      binary: binPath || cursorRoot,
      status: 'would-sync',
      pruned: [],
      targets: [cursorRoot],
      copiedCount: 0,
      action: `would sync plugin, rules, skills, agents & hooks -> v${version}`,
    };
  }

  assertNotSymlinkIfExists(cursorRoot, 'cursor root');
  fs.mkdirSync(cursorRoot, { recursive: true });

  const pluginsDir = path.join(cursorRoot, 'plugins');
  const pluginDest = path.join(pluginsDir, pluginId);
  assertNotSymlinkIfExists(pluginsDir, 'cursor plugins dir');
  assertNotSymlinkIfExists(pluginDest, 'cursor plugin dir');
  fs.mkdirSync(pluginDest, { recursive: true });

  const items = syncItems.length > 0
    ? syncItems
    : ['AGENTS.md', 'README.md', 'package.json', 'crew-persona.json', '.cursor-plugin', 'rules', 'skills', 'agents', 'hooks', 'assets'];
  for (const item of items) {
    const src = path.join(rootDir, item);
    if (!fs.existsSync(src)) continue;
    fs.cpSync(src, path.join(pluginDest, item), { recursive: true, force: true });
  }

  // Sync skills into ~/.cursor/skills/<skill-name>
  const srcSkills = path.join(rootDir, 'skills');
  if (fs.existsSync(srcSkills)) {
    const destSkills = path.join(cursorRoot, 'skills');
    assertNotSymlinkIfExists(destSkills, 'cursor skills dir');
    fs.mkdirSync(destSkills, { recursive: true });
    for (const ent of fs.readdirSync(srcSkills, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      if (!fs.existsSync(path.join(srcSkills, ent.name, 'SKILL.md'))) continue;
      const target = path.join(destSkills, ent.name);
      assertNotSymlinkIfExists(target, 'cursor skill dir');
      fs.cpSync(path.join(srcSkills, ent.name), target, { recursive: true, force: true });
    }
  }

  // Sync agents into ~/.cursor/agents/
  const srcAgents = path.join(rootDir, 'agents');
  if (fs.existsSync(srcAgents)) {
    const destAgents = path.join(cursorRoot, 'agents');
    assertNotSymlinkIfExists(destAgents, 'cursor agents dir');
    fs.mkdirSync(destAgents, { recursive: true });
    for (const ent of fs.readdirSync(srcAgents, { withFileTypes: true })) {
      if (!ent.isFile() || !ent.name.endsWith('.md')) continue;
      const target = path.join(destAgents, ent.name);
      assertNotSymlinkIfExists(target, 'cursor agent file');
      fs.copyFileSync(path.join(srcAgents, ent.name), target);
    }
  }

  // Sync Cursor MDC rule into ~/.cursor/rules/<pluginId>.mdc
  const srcRules = path.join(rootDir, 'rules');
  if (fs.existsSync(srcRules)) {
    const destRules = path.join(cursorRoot, 'rules');
    assertNotSymlinkIfExists(destRules, 'cursor rules dir');
    fs.mkdirSync(destRules, { recursive: true });
    for (const ent of fs.readdirSync(srcRules, { withFileTypes: true })) {
      if (!ent.isFile() || !ent.name.endsWith('.mdc')) continue;
      const target = path.join(destRules, ent.name);
      assertNotSymlinkIfExists(target, 'cursor rule file');
      fs.copyFileSync(path.join(srcRules, ent.name), target);
    }
  }

  // Idempotently merge Cursor hooks into ~/.cursor/hooks.json (preserving sibling personas & user hooks)
  const hooksFile = path.join(cursorRoot, 'hooks.json');
  assertNotSymlinkIfExists(hooksFile, 'cursor hooks.json');
  let existingHooks = {};
  try {
    if (fs.existsSync(hooksFile)) {
      existingHooks = JSON.parse(fs.readFileSync(hooksFile, 'utf8'));
    }
  } catch {
    existingHooks = {};
  }
  const mergedHooks = mergeCursorHooksJson(existingHooks, pluginId, pluginDest);
  const tmpHooks = `${hooksFile}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.writeFileSync(tmpHooks, JSON.stringify(mergedHooks, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpHooks, hooksFile);

  return {
    harness: 'Cursor',
    id: 'cursor',
    detected: true,
    binary: binPath || cursorRoot,
    status: 'synced',
    pruned: [],
    targets: [pluginDest],
    copiedCount: items.length,
    action: `synced plugin, rules, skills, agents & hooks -> v${version}`,
  };
}

module.exports = {
  CURSOR_EVENTS,
  resolveCursorRoot,
  findCursorBinary,
  mergeCursorHooksJson,
  syncCursorHarness,
};
