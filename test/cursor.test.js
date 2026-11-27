'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { runCursorEvent, mapCursorToolName } = require('../hooks/cursor-adapter');
const { syncCursorHarness, mergeCursorHooksJson } = require('../scripts/cursor-sync');
const { detectCrewEnsemble } = require('../hooks/ensemble');

function makeTmpDir(prefix = 'cursor-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('Cursor plugin manifests, .mdc rule, and cursor-hooks.json match package.json and keep hooks/hooks.json absent', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const claudePlugin = JSON.parse(fs.readFileSync(path.join(ROOT, '.claude-plugin', 'plugin.json'), 'utf8'));
  const cursorPlugin = JSON.parse(fs.readFileSync(path.join(ROOT, '.cursor-plugin', 'plugin.json'), 'utf8'));
  const cursorMp = JSON.parse(fs.readFileSync(path.join(ROOT, '.cursor-plugin', 'marketplace.json'), 'utf8'));
  const cursorHooks = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks', 'cursor-hooks.json'), 'utf8'));
  const mdcRule = fs.readFileSync(path.join(ROOT, 'rules', 'neckbeard.mdc'), 'utf8');

  assert.strictEqual(fs.existsSync(path.join(ROOT, 'hooks', 'hooks.json')), false, 'hooks/hooks.json must remain absent');
  assert.strictEqual(cursorPlugin.name, 'neckbeard');
  assert.strictEqual(cursorPlugin.version, pkg.version);
  assert.strictEqual(cursorPlugin.description, claudePlugin.description);
  assert.strictEqual(cursorPlugin.hooks, './hooks/cursor-hooks.json');
  assert.strictEqual(cursorPlugin.rules, './rules');
  assert.strictEqual(cursorPlugin.skills, './skills');
  assert.strictEqual(cursorPlugin.agents, './agents');

  assert.strictEqual(cursorMp.name, 'neckbeard');
  assert.strictEqual(cursorMp.plugins[0].name, 'neckbeard');
  assert.strictEqual(cursorMp.plugins[0].source, './');

  assert.strictEqual(cursorHooks.version, 1);
  for (const ev of ['sessionStart', 'subagentStart', 'beforeSubmitPrompt', 'preToolUse']) {
    assert.ok(Array.isArray(cursorHooks.hooks[ev]) && cursorHooks.hooks[ev].length >= 1, `missing cursor hook ${ev}`);
    assert.ok(cursorHooks.hooks[ev][0].command.includes('cursor-adapter.js'));
  }

  assert.ok(mdcRule.startsWith('---\n'), '.mdc rule must have YAML frontmatter');
  assert.ok(mdcRule.includes('alwaysApply: false'), '.mdc rule must default to lazy alwaysApply: false');
});

test('hooks/cursor-adapter.js translates Cursor lifecycle events and fails closed with exit 2 on secret write', () => {
  assert.strictEqual(mapCursorToolName('Shell'), 'Bash');
  assert.strictEqual(mapCursorToolName('StrReplace'), 'Edit');

  const tmpHome = makeTmpDir('cursor-home-');
  const tmpCwd = makeTmpDir('cursor-cwd-');
  const env = {
    ...process.env,
    HOME: tmpHome,
    USERPROFILE: tmpHome,
    XDG_CONFIG_HOME: path.join(tmpHome, '.config'),
    CREW_SOLO_PERSONA: 'neckbeard',
  };
  delete env.CLAUDE_CONFIG_DIR;
  delete env.CODEX_HOME;

  // 1. sessionStart returns additional_context
  const startRes = runCursorEvent('sessionStart', { conversation_id: 'cur-1', workspace_roots: [tmpCwd] }, env);
  assert.strictEqual(startRes.exitCode, 0);
  assert.ok(typeof startRes.output.additional_context === 'string' && startRes.output.additional_context.length > 50);

  // 2. beforeSubmitPrompt returns continue: true
  const promptRes = runCursorEvent('beforeSubmitPrompt', { conversation_id: 'cur-1', workspace_roots: [tmpCwd], prompt: 'hello world' }, env);
  assert.strictEqual(promptRes.exitCode, 0);
  assert.strictEqual(promptRes.output.continue, true);

  // 3. subagentStart returns permission: allow
  const subRes = runCursorEvent('subagentStart', { conversation_id: 'cur-1', workspace_roots: [tmpCwd], subagent_type: 'neckbeard' }, env);
  assert.strictEqual(subRes.exitCode, 0);
  assert.strictEqual(subRes.output.permission, 'allow');

  // 4. preToolUse blocks hardcoded AWS secret with exitCode 2 and permission: deny
  const secretPayload = 'AKIA' + '1234567890ABCDEF';
  const denyRes = runCursorEvent(
    'preToolUse',
    {
      conversation_id: 'cur-1',
      workspace_roots: [tmpCwd],
      tool_name: 'Write',
      tool_input: { file_path: 'src/config.js', content: `const key = "${secretPayload}";` },
    },
    env
  );
  assert.strictEqual(denyRes.exitCode, 2);
  assert.strictEqual(denyRes.output.permission, 'deny');
  assert.ok(typeof denyRes.output.agentMessage === 'string' && denyRes.output.agentMessage.length > 0);

  // 5. preToolUse allows clean edits
  const allowRes = runCursorEvent(
    'preToolUse',
    {
      conversation_id: 'cur-1',
      workspace_roots: [tmpCwd],
      tool_name: 'Write',
      tool_input: { file_path: 'src/ok.js', content: 'export const ok = true;\n' },
    },
    env
  );
  assert.strictEqual(allowRes.exitCode, 0);
  assert.strictEqual(allowRes.output.permission, 'allow');

  fs.rmSync(tmpHome, { recursive: true, force: true });
  fs.rmSync(tmpCwd, { recursive: true, force: true });
});

test('Cursor sync installs plugin/skills/agents/rules, preserves sibling hooks in hooks.json, and detectCrewEnsemble detects Cursor peers', () => {
  const tmpHome = makeTmpDir('cursor-sync-home-');
  const tmpCwd = makeTmpDir('cursor-sync-cwd-');
  const cursorDir = path.join(tmpHome, '.cursor');
  fs.mkdirSync(cursorDir, { recursive: true });
  fs.writeFileSync(
    path.join(cursorDir, 'hooks.json'),
    JSON.stringify({
      version: 1,
      hooks: {
        sessionStart: [{ command: 'node "/other/custom-hook.js"' }],
      },
    })
  );

  const env = {
    ...process.env,
    HOME: tmpHome,
    USERPROFILE: tmpHome,
    XDG_CONFIG_HOME: path.join(tmpHome, '.config'),
    PATH: '',
  };
  delete env.CURSOR_CONFIG_DIR;
  delete env.CLAUDE_CONFIG_DIR;
  delete env.CODEX_HOME;
  delete env.CREW_SOLO_PERSONA;

  // Dry run leaves disk untouched
  const dry = syncCursorHarness({ rootDir: ROOT, pluginId: 'neckbeard', version: '0.3.8', env, home: tmpHome, dryRun: true });
  assert.strictEqual(dry.detected, true);
  assert.strictEqual(dry.status, 'would-sync');
  assert.strictEqual(fs.existsSync(path.join(cursorDir, 'plugins', 'neckbeard')), false);

  // Live sync writes plugin, rule, skills, agents, and merges hooks.json without clobbering user hooks
  const live = syncCursorHarness({ rootDir: ROOT, pluginId: 'neckbeard', version: '0.3.8', env, home: tmpHome, dryRun: false });
  assert.strictEqual(live.detected, true);
  assert.strictEqual(live.status, 'synced');
  assert.strictEqual(fs.existsSync(path.join(cursorDir, 'plugins', 'neckbeard', '.cursor-plugin', 'plugin.json')), true);
  assert.strictEqual(fs.existsSync(path.join(cursorDir, 'rules', 'neckbeard.mdc')), true);
  assert.strictEqual(fs.existsSync(path.join(cursorDir, 'skills', 'neckbeard', 'SKILL.md')), true);
  assert.strictEqual(fs.existsSync(path.join(cursorDir, 'agents', 'neckbeard.md')), true);

  const hooksAfter = JSON.parse(fs.readFileSync(path.join(cursorDir, 'hooks.json'), 'utf8'));
  assert.strictEqual(hooksAfter.hooks.sessionStart.length, 2);
  assert.ok(hooksAfter.hooks.sessionStart.some((h) => h.command.includes('custom-hook.js')));
  assert.ok(hooksAfter.hooks.sessionStart.some((h) => h.command.includes('neckbeard/hooks/cursor-adapter.js')));

  // Second merge is idempotent (no duplicate entries)
  const mergedAgain = mergeCursorHooksJson(hooksAfter, 'neckbeard', path.join(cursorDir, 'plugins', 'neckbeard'));
  assert.strictEqual(mergedAgain.hooks.sessionStart.length, 2);

  // detectCrewEnsemble detects sibling Cursor plugins in ~/.cursor/plugins/<peer>
  const siblingPeer = 'neckbeard' === 'neckbeard' ? 'hipster' : 'neckbeard';
  fs.mkdirSync(path.join(cursorDir, 'plugins', siblingPeer), { recursive: true });
  const ens = detectCrewEnsemble('neckbeard', tmpCwd, env);
  assert.strictEqual(ens.isEnsemble, true);
  assert.ok(ens.installedPeers.includes(siblingPeer), `expected detectCrewEnsemble to detect Cursor peer ${siblingPeer}`);

  fs.rmSync(tmpHome, { recursive: true, force: true });
  fs.rmSync(tmpCwd, { recursive: true, force: true });
});
