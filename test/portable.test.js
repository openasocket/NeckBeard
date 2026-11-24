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
    'crew-persona.json',
    'SPEC.md',
    '.crew/sparks.example.yaml',
    'skills/neckbeard/SKILL.md',
    'skills/neckbeard-review/SKILL.md',
    'skills/neckbeard-audit/SKILL.md',
    'skills/neckbeard-debt/SKILL.md',
    'skills/neckbeard-gain/SKILL.md',
    'skills/neckbeard-map/SKILL.md',
    'skills/neckbeard-memory/SKILL.md',
    'agents/neckbeard.md',
    'agents/neckbeard-reviewer.md',
    'docs/crew-protocol.md',
    'hooks/claude-band.json',
    'hooks/band/register.tsx',
    'hooks/band/analyzer.ts',
    'hooks/band/dashboard.ts',
    'hooks/band-import.js',
    'hooks/memory.js',
    'hooks/vibes.js',
    'scripts/install-all.js',
    'pi-extension/index.js',
    '.opencode/plugins/neckbeard.mjs',
    'assets/badge.svg',
    'assets/badge.png',
    'assets/seal.svg',
    'assets/seal.png',
    'AGENTS.md',
  ]) {
    assert.strictEqual(fs.existsSync(p(required)), true, `${required} must exist`);
  }
});

test('crew-persona.json matches §4.5 locked schema, skills directory, and package.json version', () => {
  const pkg = readJson('package.json');
  const persona = readJson('crew-persona.json');
  const { validatePersonaDescriptor } = require('../hooks/ensemble');

  const validated = validatePersonaDescriptor(persona);
  assert.strictEqual(validated.valid, true, validated.reason);
  assert.strictEqual(persona.schemaVersion, 1);
  assert.strictEqual(persona.id, 'neckbeard');
  assert.strictEqual(persona.handle, 'NeckBeard');
  assert.strictEqual(persona.version, pkg.version);
  assert.strictEqual(persona.kind, 'universal');
  assert.strictEqual(persona.squad, 'build');
  assert.strictEqual(persona.pipelinePriority, 40);
  assert.strictEqual(persona.storeFile, '.neckbeard.json');
  assert.strictEqual(persona.wireEnvelope, '[NECKBEARD-GATE]');
  assert.deepStrictEqual(persona.alterEgos, [
    { id: 'larry', name: 'Ashy Larry' },
    { id: 'lari', name: 'Ashy Lari' },
  ]);
  assert.strictEqual(persona.themePosture, 'dark-only');
  assert.deepStrictEqual(persona.gates, ['Safe', 'Fast@Load', 'Done']);
  assert.strictEqual(
    persona.pushbackDomain,
    'Unvalidated trust boundaries, O(n^2) / unbounded memory bottlenecks at named load, unfinished error paths'
  );
  assert.strictEqual(persona.memoryNamespace, 'memory/agents/neckbeard');
  assert.strictEqual(persona.enclaveAware, true);
  assert.strictEqual(persona.installerScript, 'scripts/install-all.js');

  const actualSkills = fs
    .readdirSync(p('skills'), { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(p('skills'), d.name, 'SKILL.md')))
    .map((d) => d.name)
    .sort();
  assert.deepStrictEqual([...persona.skills].sort(), actualSkills);

  const sparks = readText('.crew/sparks.example.yaml');
  assert.ok(sparks.includes('engine: crew-spark'));
  assert.ok(!/Crew Cue/i.test(sparks), 'Never brand Crew Spark as Crew Cue');
  for (const doc of ['SPEC.md', '.crew/sparks.example.yaml', 'skills/neckbeard-memory/SKILL.md']) {
    const content = readText(doc);
    assert.ok(!/\/(?:Users|home)\//.test(content), `${doc} must not contain local home directory paths`);
    assert.ok(!content.includes('dev-' + 'shit'), `${doc} must not contain local workspace paths`);
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

  // Crew Operational Upgrade contracts (Verbatim Output Proof, INV-LLM-06, INV-LLM-07)
  for (const token of [
    '[NECKBEARD-DONE]',
    'verbatim',
    'exit code',
    'prose summaries alone fail',
    'INV-LLM-06',
    'CREW_PORT_BASE',
    'CREW_DB_PATH',
    'CREW_TMP_DIR',
    '[PROPELLERHEAD-SPEC]',
    'filesOutOfScope',
    'INV-LLM-07',
    'neckbeard-reviewer',
    'EdgeLord',
    '>= 2',
    'max 3 rounds',
  ]) {
    assert.ok(agents.includes(token), `AGENTS.md missing operational contract token: ${token}`);
    assert.ok(skillRaw.includes(token), `skills/neckbeard/SKILL.md missing operational contract token: ${token}`);
  }

  for (const agentDoc of ['agents/neckbeard.md', 'agents/neckbeard-reviewer.md', 'docs/crew-protocol.md']) {
    const text = readText(agentDoc);
    for (const token of [
      '[NECKBEARD-DONE',
      'verbatim',
      'exit code',
      'INV-LLM-06',
      'CREW_PORT_BASE',
      'CREW_DB_PATH',
      'CREW_TMP_DIR',
      'filesOutOfScope',
      'INV-LLM-07',
      'max 3 rounds',
    ]) {
      assert.ok(text.includes(token), `${agentDoc} missing operational contract token: ${token}`);
    }
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
  for (const token of [
    'Pasted, Not Summarized',
    '[NECKBEARD-DONE]',
    'verbatim',
    'exit code',
    'INV-LLM-06',
    'CREW_PORT_BASE',
    'CREW_DB_PATH',
    'CREW_TMP_DIR',
    'filesOutOfScope',
    'INV-LLM-07',
    'neckbeard-reviewer',
    'EdgeLord',
    '>= 2',
    'max 3 rounds',
    '[CREW-PUSHBACK]',
  ]) {
    assert.ok(review.includes(token), `skills/neckbeard-review/SKILL.md missing: ${token}`);
  }

  const audit = readText('skills/neckbeard-audit/SKILL.md');
  assert.ok(audit.trimEnd().split('\n').length <= 90, 'neckbeard-audit must be <= 90 lines');
  assert.match(audit, /Modes:\s*`lite`\s*\(default\)\s*vs\.\s*`complete`/);
  assert.match(audit, /every single tracked code, configuration, script, workflow, and documentation file/i);
  assert.match(audit, /long time, consume a large number of tokens, and require many tool calls/i);
  assert.match(audit, /variant search/i);
  assert.match(audit, /Never cap or hide findings/i);
  assert.match(audit, /explicitly prompt the user/i);
  assert.match(audit, /exceedingly rare/i);
  assert.match(audit, /E_patch/);
  assert.match(audit, /E_rewrite/);
  assert.ok(!audit.includes('at most 20 findings'), 'neckbeard-audit must not cap findings at 20');
  assert.ok(!audit.includes('Do not search past the findings in this report'), 'neckbeard-audit must not forbid searching past 20 findings');
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
    assert.ok(text.includes('scripts/install-all.js'), `${doc} must document scripts/install-all.js`);
    assert.ok(!/\/(?:Users|home)\//.test(text), `${doc} must not contain local home directory paths`);
    assert.ok(!text.includes('dev-' + 'shit'), `${doc} must not contain local workspace paths`);
  }

  const lib = readText('hooks/lib.js');
  assert.ok(lib.includes('Switch with /neckbeard, $neckbeard, or @neckbeard, then lite, full, paranoid, or off.'));
});
