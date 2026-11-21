'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PITCH = 'Smallest change that is correct, safe at the boundary it crosses, fast and scalable at a named load, simple for the end user, and finished.';

function p(rel) {
  return path.join(ROOT, rel);
}

function readText(rel) {
  return fs.readFileSync(p(rel), 'utf8');
}

function readJson(rel) {
  return JSON.parse(readText(rel));
}

test('hook file split and host adapter manifests', () => {
  assert.strictEqual(fs.existsSync(p('hooks/hooks.json')), false);
  assert.strictEqual(fs.existsSync(p('hooks/claude-hooks.json')), true);

  const claudePlugin = readJson('.claude-plugin/plugin.json');
  const codexPlugin = readJson('.codex-plugin/plugin.json');
  assert.ok(Array.isArray(claudePlugin.hooks) && claudePlugin.hooks.some((h) => h.includes('hooks/claude-hooks.json')));
  assert.ok(typeof codexPlugin.hooks === 'string' && codexPlugin.hooks.includes('hooks/claude-hooks.json'));

  for (const manifest of ['plugin.json', 'skills/plugin.json', '.github/plugin/plugin.json']) {
    assert.strictEqual('hooks' in readJson(manifest), false, `${manifest} must not have a hooks key`);
  }

  const grokMarketplace = readJson('.grok-plugin/marketplace.json');
  assert.strictEqual(grokMarketplace.plugins[0].source, './skills');

  const geminiExt = readJson('gemini-extension.json');
  assert.strictEqual(geminiExt.contextFileName, 'AGENTS.md');
});

test('skill directory layout', () => {
  for (const removed of ['skills/neckbeard-threat', 'skills/neckbeard-deps']) {
    assert.strictEqual(fs.existsSync(p(removed)), false, `${removed} must not exist`);
  }
  for (const required of [
    'skills/neckbeard/SKILL.md',
    'skills/neckbeard-review/SKILL.md',
    'skills/neckbeard-audit/SKILL.md',
    'skills/neckbeard-debt/SKILL.md',
    'AGENTS.md',
  ]) {
    assert.strictEqual(fs.existsSync(p(required)), true, `${required} must exist`);
  }
});

test('core ruleset parity, line limits, required sentences, and forbidden terms', () => {
  const skillRaw = readText('skills/neckbeard/SKILL.md');
  const skillBody = skillRaw.replace(/^---[\s\S]*?---\s*/, '');
  const agents = readText('AGENTS.md');

  assert.ok(skillBody.trimEnd().split('\n').length <= 150, 'skill body after frontmatter must be <= 150 lines');
  assert.ok(agents.trimEnd().split('\n').length <= 110, 'AGENTS.md must be <= 110 lines');
  assert.strictEqual(skillBody.trim(), agents.trim(), 'skill body after frontmatter and AGENTS.md must not drift');

  const verbatim = [
    'A change that crosses no trust boundary, writes no shared state, and cannot grow with input skips the gates.',
    'Name the trust boundary this change crosses, or say that it crosses none.',
    'Name the load as a number. Design for that number, not for 100 times it.',
    'Authorize the object on the server, every time. Logged in is not allowed.',
    'Hide necessary complexity inside the module; keep the user experience and caller interface simple with safe defaults.',
    'A risk: comment may defer a cache or a queue. It may not defer a trust check or a write that can lose data.',
    'Apply a Fast rule only when breaking it misses the named load.',
    'Unbounded input gets a limit.',
    'A write that can be retried is idempotent.',
    'No check-then-write race, no query per item, and no list that only grows.',
    'No quadratic work, no blocking work on the request or UI thread, and no unindexed filter.',
    'Canonicalise a path and reject a symlink escape before the root check.',
    'Lean is this ladder, not a fourth gate.',
  ];

  for (const line of verbatim) {
    assert.ok(skillRaw.includes(line), `skills/neckbeard/SKILL.md missing: ${line}`);
    assert.ok(agents.includes(line), `AGENTS.md missing: ${line}`);
  }

  const forbidden = [
    'the guard',
    'CLAUDE_PLUGIN_ROOT',
    'hookSpecificOutput',
    'CWE',
    'STRIDE',
    'neckbeard-threat',
    'neckbeard-deps',
    'make illegal states unrepresentable',
  ];

  for (const file of [
    'skills/neckbeard/SKILL.md',
    'AGENTS.md',
    'skills/neckbeard-review/SKILL.md',
    'skills/neckbeard-audit/SKILL.md',
  ]) {
    const content = readText(file);
    for (const term of forbidden) {
      assert.ok(!content.includes(term), `${file} must not contain "${term}"`);
    }
  }
});

test('review, audit, and copilot instructions content', () => {
  const review = readText('skills/neckbeard-review/SKILL.md');
  assert.ok(review.trimEnd().split('\n').length <= 90, 'neckbeard-review must be <= 90 lines');
  assert.match(review, /variant search/i);
  assert.match(review, /Must[- ]fix/);
  assert.ok(review.includes('--ci'));
  assert.ok(review.includes('.ai-audit/'));
  assert.match(review, /print the findings/i);
  assert.match(review, /does not set the process exit code/i);
  assert.ok(!review.includes('skip conversational prose'));

  const audit = readText('skills/neckbeard-audit/SKILL.md');
  assert.ok(audit.trimEnd().split('\n').length <= 90, 'neckbeard-audit must be <= 90 lines');
  assert.match(audit, /variant search/i);
  assert.match(audit, /Say when you stopped/);
  assert.match(audit, /Do not search past the findings in this report/);
  assert.match(audit, /doc promises/i);
  assert.ok(audit.includes('AGENTS.md'));
  assert.ok(audit.includes('CLAUDE.md'));
  assert.ok(audit.includes('.ai-audit/'));
  assert.match(audit, /draft `SPEC.md`/);
  assert.ok(!audit.includes('approved `SPEC.md`'));
  assert.ok(audit.includes('.maestro/playbooks/'));

  const debt = readText('skills/neckbeard-debt/SKILL.md');
  assert.ok(debt.trimEnd().split('\n').length <= 45, 'neckbeard-debt must be <= 45 lines');
  assert.ok(debt.includes('unrecorded-decision'));
  assert.ok(debt.includes('.ai-audit/manifest.json'));

  const copilot = readText('.github/copilot-instructions.md');
  assert.ok(copilot.includes('AGENTS.md'));
  assert.ok(!copilot.includes('Authorize the object on the server'));
  assert.ok(!copilot.includes('Apply a Fast rule only when breaking it misses the named load.'));
});

test('shared description pitch across manifests, README, and hooks/lib.js', () => {
  assert.strictEqual(readJson('package.json').description, PITCH);
  assert.strictEqual(readJson('.claude-plugin/plugin.json').description, PITCH);
  const claudeMarketplace = readJson('.claude-plugin/marketplace.json');
  assert.strictEqual(claudeMarketplace.description, PITCH);
  assert.strictEqual(claudeMarketplace.plugins[0].description, PITCH);
  assert.strictEqual(readJson('.codex-plugin/plugin.json').description, PITCH);
  assert.strictEqual(readJson('.github/plugin/plugin.json').description, PITCH);
  assert.strictEqual(readJson('plugin.json').description, PITCH);
  assert.strictEqual(readJson('skills/plugin.json').description, PITCH);
  assert.strictEqual(readJson('gemini-extension.json').description, PITCH);
  assert.strictEqual(readJson('.grok-plugin/marketplace.json').plugins[0].description, PITCH);

  const readme = readText('README.md');
  for (const s of [
    PITCH,
    'claude plugin marketplace add openasocket/NeckBeard',
    'claude plugin install neckbeard@neckbeard',
    'codex plugin marketplace add openasocket/NeckBeard',
    'codex plugin add neckbeard@neckbeard',
    'copilot plugin marketplace add openasocket/NeckBeard',
    'copilot plugin install neckbeard@neckbeard',
    'grok plugin install openasocket/NeckBeard --trust',
    'agy plugin install https://github.com/openasocket/NeckBeard',
    'gemini extensions install https://github.com/openasocket/NeckBeard',
    'AGENTS.md',
    'NECKBEARD_SURFACE=1',
  ]) {
    assert.ok(readme.includes(s), `README.md missing: ${s}`);
  }
  for (const doc of ['README.md', 'INSTALL.md', 'docs/agent-portability.md']) {
    const text = readText(doc);
    assert.ok(!/\/(?:Users|home)\//.test(text), `${doc} must not contain local home directory paths`);
    assert.ok(!text.includes('dev-' + 'shit'), `${doc} must not contain local workspace paths`);
  }

  const lib = readText('hooks/lib.js');
  assert.ok(lib.includes('Switch with /neckbeard, $neckbeard, or @neckbeard, then lite, full, paranoid, or off.'));
});
