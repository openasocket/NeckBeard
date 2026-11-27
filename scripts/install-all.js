#!/usr/bin/env node
'use strict';
// Cross-platform (Windows, macOS, Linux) auto-discovery installer & updater for NeckBeard.
// Finds all installed local AI coding agent harnesses compatible with NeckBeard (Claude Code,
// Codex, GitHub Copilot CLI, Grok CLI, Antigravity CLI, Gemini CLI, Pi, Oh My Pi, OpenCode,
// Kilo Code), updates their plugins/caches to the current NeckBeard release, and rebuilds
// the local NeckBeard Security & Engineering Command Center (~/.config/neckbeard/telemetry/dashboard.html).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { syncCursorHarness, mergeCursorHooksJson } = require('./cursor-sync');
const {
  getCrewConfigDir,
  getPersonasRegistryDir,
  getPresenceLogPath,
  validatePersonaDescriptor,
} = require('../hooks/ensemble');

const ROOT = path.resolve(__dirname, '..');
const REPO_SLUG = 'openasocket/NeckBeard';
const REPO_URL = 'https://github.com/openasocket/NeckBeard';
const PERSONA_MANIFEST_FILE = path.join(ROOT, 'crew-persona.json');
const MAX_PRESENCE_LINE_BYTES = 4096;

const SYNC_ITEMS = [
  'AGENTS.md',
  'README.md',
  'INSTALL.md',
  'SPEC.md',
  'LICENSE',
  'crew-persona.json',
  'package.json',
  'plugin.json',
  'gemini-extension.json',
  '.crew',
  '.claude-plugin',
  '.cursor-plugin',
  'rules',
  '.codex-plugin',
  '.github',
  '.grok-plugin',
  '.opencode',
  'pi-extension',
  'agents',
  'skills',
  'hooks',
  'assets',
  'docs',
];

function readCurrentVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version || '0.3.0';
  } catch {
    return '0.3.0';
  }
}

function getHomeDir(env = process.env) {
  return env.HOME || env.USERPROFILE || os.homedir();
}

function findBinaryOnPath(binaryName, env = process.env) {
  const isWin = process.platform === 'win32';
  const home = getHomeDir(env);
  const pathSep = isWin ? ';' : ':';
  const rawDirs = (env.PATH || '').split(pathSep).filter(Boolean);
  const extraDirs = isWin
    ? [
        path.join(home, '.grok', 'bin'),
        path.join(home, 'AppData', 'Roaming', 'npm'),
        path.join(home, 'AppData', 'Local', 'Programs'),
      ]
    : [
        path.join(home, '.grok', 'bin'),
        path.join(home, '.local', 'bin'),
        '/opt/homebrew/bin',
        '/usr/local/bin',
      ];
  const searchDirs = [...new Set([...rawDirs, ...extraDirs])];
  const exts = isWin
    ? (env.PATHEXT ? env.PATHEXT.split(';').filter(Boolean) : ['.exe', '.cmd', '.bat', '.ps1'])
    : [''];

  for (const dir of searchDirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, isWin ? `${binaryName}${ext}` : binaryName);
      try {
        const st = fs.statSync(candidate);
        if (st.isFile()) return candidate;
      } catch {
        continue;
      }
    }
  }
  return null;
}

function runCliSafe(binPath, args, env = process.env, timeoutMs = 25000) {
  if (!binPath || !Array.isArray(args)) return { ok: false, status: -1, stdout: '', stderr: 'invalid command' };
  const isWinCmd = process.platform === 'win32' && /\.(cmd|bat)$/i.test(binPath);
  const res = spawnSync(binPath, args, {
    cwd: ROOT,
    env,
    encoding: 'utf8',
    timeout: timeoutMs,
    shell: isWinCmd,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    ok: res.status === 0,
    status: res.status ?? -1,
    stdout: String(res.stdout || '').trim(),
    stderr: String(res.stderr || '').trim(),
  };
}

function copyTreeFiltered(srcDir, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const item of SYNC_ITEMS) {
    const srcPath = path.join(srcDir, item);
    if (!fs.existsSync(srcPath)) continue;
    const destPath = path.join(destDir, item);
    fs.cpSync(srcPath, destPath, { recursive: true, force: true });
  }
}

function getLatestCommitSha() {
  const gitBin = findBinaryOnPath('git');
  if (!gitBin) return '';
  const res = runCliSafe(gitBin, ['rev-parse', 'HEAD'], process.env, 5000);
  return res.ok ? res.stdout.slice(0, 40) : '';
}

function syncClaudeCode(binPath, home, version, commitSha, opts) {
  const claudeRoot = opts.env.CLAUDE_CONFIG_DIR || path.join(home, '.claude');
  const pluginsRoot = path.join(claudeRoot, 'plugins');
  const hasDir = fs.existsSync(claudeRoot);
  if (!binPath && !hasDir) return { harness: 'Claude Code', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'Claude Code', detected: true, binary: binPath || claudeRoot, action: `would update to v${version}` };
  }

  const actions = [];
  if (binPath) {
    runCliSafe(binPath, ['plugin', 'marketplace', 'add', REPO_SLUG], opts.env);
    runCliSafe(binPath, ['plugin', 'marketplace', 'update', 'neckbeard'], opts.env);
    const up = runCliSafe(binPath, ['plugin', 'update', 'neckbeard@neckbeard'], opts.env);
    if (!up.ok) {
      runCliSafe(binPath, ['plugin', 'install', 'neckbeard@neckbeard'], opts.env);
    }
    actions.push('CLI updated');
  }

  // Sync local repo directly into Claude Code marketplace & versioned plugin cache so v0.3.0 is immediately active
  if (fs.existsSync(pluginsRoot)) {
    const mpDir = path.join(pluginsRoot, 'marketplaces', 'neckbeard');
    copyTreeFiltered(ROOT, mpDir);

    const cacheParent = path.join(pluginsRoot, 'cache', 'neckbeard', 'neckbeard');
    const targetCacheDir = path.join(cacheParent, version);
    copyTreeFiltered(ROOT, targetCacheDir);
    if (fs.existsSync(cacheParent)) {
      for (const sub of fs.readdirSync(cacheParent)) {
        const subPath = path.join(cacheParent, sub);
        if (sub !== version && fs.statSync(subPath).isDirectory()) {
          fs.rmSync(subPath, { recursive: true, force: true });
        }
      }
    }

    const nowIso = new Date().toISOString();
    const knownMpFile = path.join(pluginsRoot, 'known_marketplaces.json');
    try {
      const known = fs.existsSync(knownMpFile) ? JSON.parse(fs.readFileSync(knownMpFile, 'utf8')) : {};
      known.neckbeard = {
        source: { source: 'github', repo: REPO_SLUG },
        installLocation: mpDir,
        lastUpdated: nowIso,
      };
      fs.writeFileSync(knownMpFile, JSON.stringify(known, null, 2) + '\n');
    } catch {}

    const installedFile = path.join(pluginsRoot, 'installed_plugins.json');
    if (fs.existsSync(installedFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(installedFile, 'utf8'));
        data.plugins = data.plugins || {};
        const prevEntry = Array.isArray(data.plugins['neckbeard@neckbeard']) && data.plugins['neckbeard@neckbeard'][0];
        data.plugins['neckbeard@neckbeard'] = [
          {
            scope: (prevEntry && prevEntry.scope) || 'user',
            installPath: targetCacheDir,
            version,
            installedAt: (prevEntry && prevEntry.installedAt) || nowIso,
            lastUpdated: nowIso,
            ...(commitSha ? { gitCommitSha: commitSha } : {}),
          },
        ];
        if (opts.removePonytail && data.plugins['ponytail@ponytail']) {
          delete data.plugins['ponytail@ponytail'];
        }
        fs.writeFileSync(installedFile, JSON.stringify(data, null, 2) + '\n');
      } catch {}
    }

    const settingsFile = path.join(claudeRoot, 'settings.json');
    if (fs.existsSync(settingsFile)) {
      try {
        const s = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
        s.enabledPlugins = s.enabledPlugins || {};
        s.enabledPlugins['neckbeard@neckbeard'] = true;
        s.extraKnownMarketplaces = s.extraKnownMarketplaces || {};
        s.extraKnownMarketplaces.neckbeard = {
          source: { source: 'github', repo: REPO_SLUG },
        };
        if (opts.removePonytail && 'ponytail@ponytail' in s.enabledPlugins) {
          s.enabledPlugins['ponytail@ponytail'] = false;
        }
        fs.writeFileSync(settingsFile, JSON.stringify(s, null, 2) + '\n');
      } catch {}
    }
    actions.push(`cache synced -> v${version}`);
  }

  return { harness: 'Claude Code', detected: true, binary: binPath || claudeRoot, action: actions.join(' · ') };
}

function syncCodex(binPath, home, version, opts) {
  const codexRoot = path.join(home, '.codex');
  const hasDir = fs.existsSync(codexRoot);
  if (!binPath && !hasDir) return { harness: 'OpenAI Codex', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'OpenAI Codex', detected: true, binary: binPath || codexRoot, action: `would update to v${version}` };
  }

  const actions = [];
  if (binPath) {
    runCliSafe(binPath, ['plugin', 'marketplace', 'add', REPO_SLUG], opts.env);
    runCliSafe(binPath, ['plugin', 'add', 'neckbeard@neckbeard'], opts.env);
  }

  const cacheParent = path.join(codexRoot, 'plugins', 'cache', 'neckbeard', 'neckbeard');
  if (fs.existsSync(codexRoot)) {
    const targetCacheDir = path.join(cacheParent, version);
    copyTreeFiltered(ROOT, targetCacheDir);
    if (fs.existsSync(cacheParent)) {
      for (const sub of fs.readdirSync(cacheParent)) {
        const subPath = path.join(cacheParent, sub);
        if (sub !== version && fs.statSync(subPath).isDirectory()) {
          fs.rmSync(subPath, { recursive: true, force: true });
        }
      }
    }
    actions.push(`cache synced -> v${version}`);

    const configToml = path.join(codexRoot, 'config.toml');
    if (fs.existsSync(configToml)) {
      try {
        let toml = fs.readFileSync(configToml, 'utf8');
        let changed = false;
        if (opts.removePonytail) {
          const next = toml.replace(/(\[plugins\."ponytail@ponytail"\]\s*\n\s*enabled\s*=\s*)true/g, '$1false');
          if (next !== toml) {
            toml = next;
            actions.push('disabled ponytail@ponytail collision');
            changed = true;
          }
        }
        if (!toml.includes('[marketplaces.neckbeard]')) {
          toml = toml.trimEnd() + `\n\n[marketplaces.neckbeard]\nsource_type = "git"\nsource = "${REPO_URL}.git"\n`;
          changed = true;
        }
        if (!toml.includes('[plugins."neckbeard@neckbeard"]')) {
          toml = toml.trimEnd() + '\n\n[plugins."neckbeard@neckbeard"]\nenabled = true\n';
          changed = true;
        } else {
          const next = toml.replace(/(\[plugins\."neckbeard@neckbeard"\]\s*\n\s*enabled\s*=\s*)false/g, '$1true');
          if (next !== toml) {
            toml = next;
            changed = true;
          }
        }
        if (changed) fs.writeFileSync(configToml, toml);
      } catch {}
    }
  }

  return { harness: 'OpenAI Codex', detected: true, binary: binPath || codexRoot, action: actions.join(' · ') || `updated to v${version}` };
}

// Safely merges a validated plugin ID (^[a-z0-9-]+$) into the single `[plugins]` `enabled = [...]` array in Grok's config.toml,
// supporting both single-line and multi-line arrays and collapsing any duplicate `enabled = [...]` blocks.
function mergeGrokEnabledPluginsToml(tomlContent, pluginId) {
  const safeId = String(pluginId || '').trim();
  if (!/^[a-z0-9-]+$/.test(safeId)) {
    throw new Error(`Invalid Grok plugin ID "${safeId}": must match ^[a-z0-9-]+$`);
  }
  const text = String(tomlContent || '');
  if (!/^\[plugins\]\s*$/m.test(text)) {
    return text.trimEnd() + `\n\n[plugins]\nenabled = ["${safeId}"]\n`;
  }

  const lines = text.split('\n');
  const collected = new Set();

  let scanInPlugins = false;
  let inArray = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!inArray && /^\[.+\]$/.test(trimmed)) {
      scanInPlugins = trimmed === '[plugins]';
      continue;
    }
    if (scanInPlugins && (inArray || /^enabled\s*=\s*\[/.test(trimmed))) {
      const matches = trimmed.match(/"([^"]+)"|'([^']+)'/g) || [];
      for (const m of matches) {
        const clean = m.slice(1, -1).trim();
        if (clean) collected.add(clean);
      }
      if (/^enabled\s*=\s*\[/.test(trimmed) && !trimmed.includes(']')) {
        inArray = true;
      } else if (inArray && trimmed.includes(']')) {
        inArray = false;
      }
    }
  }

  collected.add(safeId);
  const formattedArray = `enabled = [${[...collected].map((p) => `"${p}"`).join(', ')}]`;

  const out = [];
  let inPlugins = false;
  let skippingArray = false;
  let insertedEnabledLine = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (skippingArray) {
      if (trimmed.includes(']')) skippingArray = false;
      continue;
    }
    if (/^\[.+\]$/.test(trimmed)) {
      if (inPlugins && !insertedEnabledLine) {
        out.push(formattedArray);
        insertedEnabledLine = true;
      }
      inPlugins = trimmed === '[plugins]';
      out.push(line);
      continue;
    }
    if (inPlugins && /^enabled\s*=\s*\[/.test(trimmed)) {
      if (!insertedEnabledLine) {
        out.push(formattedArray);
        insertedEnabledLine = true;
      }
      if (!trimmed.includes(']')) {
        skippingArray = true;
      }
      continue;
    }
    out.push(line);
  }
  if (inPlugins && !insertedEnabledLine) {
    out.push(formattedArray);
  }
  return out.join('\n');
}

function syncGrok(binPath, home, version, commitSha, opts) {
  const grokRoot = path.join(home, '.grok');
  const hasDir = fs.existsSync(grokRoot);
  if (!binPath && !hasDir) return { harness: 'Grok CLI', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'Grok CLI', detected: true, binary: binPath || grokRoot, action: `would update to v${version}` };
  }

  const actions = [];
  if (binPath) {
    runCliSafe(binPath, ['plugin', 'install', REPO_SLUG, '--trust'], opts.env);
  }

  const installedDir = path.join(grokRoot, 'installed-plugins');
  if (fs.existsSync(installedDir) || hasDir) {
    fs.mkdirSync(installedDir, { recursive: true });
    const entries = fs.readdirSync(installedDir).filter((e) => e.startsWith('neckbeard'));
    const targetFolder = entries[0] || 'neckbeard-local';
    const targetPath = path.join(installedDir, targetFolder);
    copyTreeFiltered(ROOT, targetPath);

    const regFile = path.join(installedDir, 'registry.json');
    try {
      const reg = fs.existsSync(regFile) ? JSON.parse(fs.readFileSync(regFile, 'utf8')) : { version: 1, repos: {} };
      reg.repos = reg.repos || {};
      const nowIso = new Date().toISOString();
      const existing = reg.repos[targetFolder];
      reg.repos[targetFolder] = {
        kind: {
          type: 'Git',
          url: REPO_URL,
          commit: commitSha || (existing && existing.kind && existing.kind.commit) || 'HEAD',
        },
        installed_at: (existing && existing.installed_at) || nowIso,
        updated_at: nowIso,
        path: targetPath,
        plugins: { neckbeard: {} },
      };
      fs.writeFileSync(regFile, JSON.stringify(reg, null, 2) + '\n');
    } catch {}
    actions.push(`synced ${targetFolder} -> v${version}`);
  }

  const cfgFile = path.join(grokRoot, 'config.toml');
  if (fs.existsSync(cfgFile)) {
    try {
      const cfg = fs.readFileSync(cfgFile, 'utf8');
      const updated = mergeGrokEnabledPluginsToml(cfg, 'neckbeard');
      if (updated !== cfg) {
        fs.writeFileSync(cfgFile, updated);
        actions.push('enabled in config.toml');
      }
    } catch {}
  }

  return { harness: 'Grok CLI', detected: true, binary: binPath || grokRoot, action: actions.join(' · ') || `updated to v${version}` };
}

function syncAntigravity(binPath, home, version, opts) {
  const agyPluginDir = path.join(home, '.gemini', 'config', 'plugins', 'neckbeard');
  const hasDir = fs.existsSync(path.join(home, '.gemini', 'config', 'plugins'));
  if (!binPath && !hasDir) return { harness: 'Antigravity CLI', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'Antigravity CLI', detected: true, binary: binPath || agyPluginDir, action: `would update to v${version}` };
  }

  if (binPath) {
    runCliSafe(binPath, ['plugin', 'install', REPO_URL], opts.env);
  }
  if (hasDir || fs.existsSync(agyPluginDir)) {
    copyTreeFiltered(ROOT, agyPluginDir);
  }
  return { harness: 'Antigravity CLI', detected: true, binary: binPath || agyPluginDir, action: `synced ~/.gemini/config/plugins/neckbeard -> v${version}` };
}

function syncGeminiCli(binPath, home, version, opts) {
  const geminiExtRoot = path.join(home, '.gemini', 'extensions');
  const hasDir = fs.existsSync(geminiExtRoot);
  if (!binPath && !hasDir) return { harness: 'Gemini CLI', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'Gemini CLI', detected: true, binary: binPath || geminiExtRoot, action: `would update to v${version}` };
  }

  const extDir = path.join(geminiExtRoot, 'neckbeard');
  if (fs.existsSync(path.join(home, '.gemini'))) {
    copyTreeFiltered(ROOT, extDir);
  }
  return { harness: 'Gemini CLI', detected: true, binary: binPath || extDir, action: `synced ~/.gemini/extensions/neckbeard -> v${version}` };
}

function syncCopilotCli(binPath, version, opts) {
  if (!binPath) return { harness: 'GitHub Copilot CLI', detected: false, action: 'skipped (not installed)' };
  if (opts.dryRun) {
    return { harness: 'GitHub Copilot CLI', detected: true, binary: binPath, action: `would update to v${version}` };
  }
  runCliSafe(binPath, ['plugin', 'marketplace', 'add', REPO_SLUG], opts.env);
  const up = runCliSafe(binPath, ['plugin', 'update', 'neckbeard@neckbeard'], opts.env);
  if (!up.ok) runCliSafe(binPath, ['plugin', 'install', 'neckbeard@neckbeard'], opts.env);
  return { harness: 'GitHub Copilot CLI', detected: true, binary: binPath, action: `CLI updated -> v${version}` };
}

function syncPiAndOpenCode(bins, home, version, opts) {
  const results = [];
  const piBin = bins.pi || bins.omp;
  const piDir = path.join(home, '.pi', 'agent', 'extensions');
  if (piBin || fs.existsSync(piDir)) {
    if (opts.dryRun) {
      results.push({ harness: 'Pi / Oh My Pi', detected: true, binary: piBin || piDir, action: `would sync pi-extension -> v${version}` });
    } else {
      if (piBin) runCliSafe(piBin, ['install', ROOT], opts.env);
      results.push({ harness: 'Pi / Oh My Pi', detected: true, binary: piBin || piDir, action: `synced pi-extension -> v${version}` });
    }
  } else {
    results.push({ harness: 'Pi / Oh My Pi', detected: false, action: 'skipped (not installed)' });
  }

  const ocBin = bins.opencode || bins.kilo;
  const ocDir = path.join(home, '.config', 'opencode', 'plugins');
  if (ocBin || fs.existsSync(path.join(home, '.config', 'opencode'))) {
    if (opts.dryRun) {
      results.push({ harness: 'OpenCode / Kilo', detected: true, binary: ocBin || ocDir, action: `would sync neckbeard.mjs -> v${version}` });
    } else {
      fs.mkdirSync(ocDir, { recursive: true });
      fs.copyFileSync(path.join(ROOT, '.opencode', 'plugins', 'neckbeard.mjs'), path.join(ocDir, 'neckbeard.mjs'));
      results.push({ harness: 'OpenCode / Kilo', detected: true, binary: ocBin || ocDir, action: `synced neckbeard.mjs -> v${version}` });
    }
  } else {
    results.push({ harness: 'OpenCode / Kilo', detected: false, action: 'skipped (not installed)' });
  }

  return results;
}

// §4.5 Atomic Drop-In Presence Registration:
// Reads & validates crew-persona.json, then unless --dry-run atomically writes ONLY
// $CREW_CONFIG_DIR/registry/personas/neckbeard.json and appends one <4096B LF-only
// presence record to $CREW_CONFIG_DIR/registry/presence.jsonl.
function registerPersonaPresence(options = {}) {
  const env = options.env || process.env;
  const dryRun = Boolean(options.dryRun);
  const manifestPath = options.manifestPath || PERSONA_MANIFEST_FILE;

  const rawManifest = fs.readFileSync(manifestPath, 'utf8');
  const validated = validatePersonaDescriptor(rawManifest, { fromRegistry: false });
  if (!validated.valid) {
    throw new Error(`Invalid crew-persona.json: ${validated.reason}`);
  }
  const manifestObj = JSON.parse(rawManifest);
  const desc = validated.descriptor;

  const crewDir = getCrewConfigDir(env);
  const personasDir = getPersonasRegistryDir(env);
  const targetPath = path.join(personasDir, `${desc.id}.json`);
  const presencePath = getPresenceLogPath(env);

  if (dryRun) {
    return {
      registered: false,
      dryRun: true,
      id: desc.id,
      crewConfigDir: crewDir,
      targetPath,
      presencePath,
      action: `would register ${targetPath} + append ${presencePath}`,
    };
  }

  // Reject symlink escape on existing registry dir or target file
  for (const checkPath of [crewDir, path.join(crewDir, 'registry'), personasDir, targetPath, presencePath]) {
    try {
      const st = fs.lstatSync(checkPath);
      if (st.isSymbolicLink()) {
        throw new Error(`Refusing symlink target in Crew registry: ${checkPath}`);
      }
    } catch (err) {
      if (err && /Refusing symlink/.test(err.message)) throw err;
    }
  }

  fs.mkdirSync(personasDir, { recursive: true, mode: 0o700 });
  const serialized = JSON.stringify(manifestObj, null, 2) + '\n';
  const tmpFile = `${targetPath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.writeFileSync(tmpFile, serialized, { mode: 0o600 });
  fs.renameSync(tmpFile, targetPath);

  const presenceRecord = {
    tsIso: new Date().toISOString(),
    event: 'installed',
    id: desc.id,
    handle: desc.handle,
    version: desc.version,
    pipelinePriority: desc.pipelinePriority,
    storeFile: desc.storeFile,
  };
  const presenceLine = JSON.stringify(presenceRecord).replace(/\r/g, '') + '\n';
  if (Buffer.byteLength(presenceLine, 'utf8') >= MAX_PRESENCE_LINE_BYTES) {
    throw new Error(`Presence event exceeds < ${MAX_PRESENCE_LINE_BYTES} UTF-8 bytes`);
  }
  fs.appendFileSync(presencePath, presenceLine, { encoding: 'utf8', mode: 0o600 });

  return {
    registered: true,
    dryRun: false,
    id: desc.id,
    crewConfigDir: crewDir,
    targetPath,
    presencePath,
    event: presenceRecord,
    action: `registered ${targetPath}`,
  };
}

function syncAllHarnesses(options = {}) {
  const env = options.env || process.env;
  const dryRun = Boolean(options.dryRun);
  const removePonytail = options.removePonytail !== false;
  const autoPull = options.autoPull !== false && !dryRun;
  const home = getHomeDir(env);

  const gitBin = findBinaryOnPath('git', env);
  if (autoPull && gitBin && fs.existsSync(path.join(ROOT, '.git'))) {
    const statusRes = runCliSafe(gitBin, ['status', '--porcelain'], env, 5000);
    if (statusRes.ok && statusRes.stdout === '') {
      runCliSafe(gitBin, ['pull', '--ff-only', 'origin', 'main', '--tags'], env, 15000);
    }
  }

  const version = readCurrentVersion();
  const commitSha = getLatestCommitSha();

  const bins = {
    claude: findBinaryOnPath('claude', env),
    codex: findBinaryOnPath('codex', env),
    copilot: findBinaryOnPath('copilot', env),
    grok: findBinaryOnPath('grok', env),
    agy: findBinaryOnPath('agy', env),
    gemini: findBinaryOnPath('gemini', env),
    pi: findBinaryOnPath('pi', env),
    omp: findBinaryOnPath('omp', env),
    opencode: findBinaryOnPath('opencode', env),
    kilo: findBinaryOnPath('kilo', env),
  };

  const opts = { env, dryRun, removePonytail };
  const results = [
    syncClaudeCode(bins.claude, home, version, commitSha, opts),
    syncCodex(bins.codex, home, version, opts),
    syncGrok(bins.grok, home, version, commitSha, opts),
    syncAntigravity(bins.agy, home, version, opts),
    syncGeminiCli(bins.gemini, home, version, opts),
    syncCopilotCli(bins.copilot, version, opts),
    ...syncPiAndOpenCode(bins, home, version, opts),
    syncCursorHarness({ rootDir: ROOT, pluginId: 'neckbeard', version, env, home, dryRun, syncItems: SYNC_ITEMS }),
  ];

  const presence = registerPersonaPresence({ env, dryRun });

  let dashboardFile = '';
  if (!dryRun && !options.skipDashboard) {
    try {
      const bandImport = require('../hooks/band-import');
      const built = bandImport.run(ROOT, env);
      dashboardFile = built.boardFile || '';
    } catch {}
  }

  return {
    version,
    platform: `${process.platform} (${os.arch()})`,
    dryRun,
    dashboardFile,
    presence,
    results,
  };
}

function formatSyncReport(report) {
  const lines = [
    `NeckBeard Multi-Harness Installer & Updater (v${report.version} · ${report.platform}${report.dryRun ? ' · DRY RUN' : ''})`,
    '─'.repeat(86),
  ];
  for (const r of report.results) {
    const icon = r.detected ? '✓' : '○';
    const name = r.harness.padEnd(20, ' ');
    lines.push(`  ${icon} ${name} : ${r.action}`);
  }
  lines.push('─'.repeat(86));
  const updatedCount = report.results.filter((r) => r.detected).length;
  lines.push(`  Harnesses updated : ${updatedCount} / ${report.results.length} compatible agent harnesses detected`);
  if (report.presence && report.presence.targetPath) {
    lines.push(`  Crew Registry     : ${report.presence.action}`);
  }
  if (report.dashboardFile) {
    lines.push(`  Command Center    : ${report.dashboardFile}`);
  }
  return lines.join('\n');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const keepPonytail = args.includes('--keep-ponytail');
  const asJson = args.includes('--json');

  const report = syncAllHarnesses({ dryRun, removePonytail: !keepPonytail });
  if (asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(formatSyncReport(report) + '\n');
  }
}

module.exports = {
  syncCursorHarness,
  mergeCursorHooksJson,
  findBinaryOnPath,
  mergeGrokEnabledPluginsToml,
  registerPersonaPresence,
  syncAllHarnesses,
  formatSyncReport,
};
