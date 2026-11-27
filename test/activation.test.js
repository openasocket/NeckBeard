'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const HOOKS = path.join(ROOT, 'hooks');
const FAKE_AWS_KEY = 'AKIA' + '1234567890ABCDEF';

function makeStandaloneEnv(extra = {}) {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'neckbeard-standby-'));
  const env = { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome, CREW_CONFIG_DIR: path.join(tmpHome, '.config', 'crew'), NECKBEARD_STATE_DIR: path.join(tmpHome, 'state') };
  delete env.CREW_ACTIVE_PERSONA;
  delete env.CREW_SOLO_PERSONA;
  delete env.CREW_ENABLED;
  delete env.CREW_EAGER_LOAD;
  delete env.NECKBEARD_LEVEL;
  delete env.NECKBEARD_AUTO_ACTIVATE;
  delete env.NECKBEARD_GUARD;
  delete env.NECKBEARD_SUBAGENTS;
  delete env.CREW_SESSION_STATE_DIR;
  Object.assign(env, extra);
  return { tmpHome, env };
}

function runHook(script, input, env) {
  const res = spawnSync(process.execPath, [path.join(HOOKS, script)], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    env,
    timeout: 8000,
    shell: false,
  });
  assert.strictEqual(res.status, 0, `${script} failed: ${res.stderr}`);
  return res.stdout && res.stdout.trim() ? JSON.parse(res.stdout) : null;
}

test('NeckBeard standalone mode defaults to silent standby (0 bytes on SessionStart, ordinary prompts, generic subagents, and guard)', () => {
  const { tmpHome, env } = makeStandaloneEnv();
  try {
    const sid = 'standby-sess-1';
    assert.strictEqual(runHook('session-start.js', { session_id: sid, cwd: tmpHome, source: 'startup' }, env), null);
    assert.strictEqual(runHook('prompt.js', { session_id: sid, cwd: tmpHome, prompt: "refactor the auth endpoint and fix the SQL race condition" }, env), null);
    assert.strictEqual(runHook('subagent-start.js', { session_id: sid, cwd: tmpHome, agent_type: 'Explore' }, env), null);
    assert.strictEqual(runHook('subagent-start.js', { session_id: sid, cwd: tmpHome }, env), null);
    assert.strictEqual(runHook('guard.js', { session_id: sid, cwd: tmpHome, tool_name: 'Write', tool_input: { file_path: 'a.js', content: `const k = "${FAKE_AWS_KEY}";` } }, env), null);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

test('NeckBeard one-shot /neckbeard <prompt> runs for that turn only and returns to standby on the next ordinary prompt', () => {
  const { tmpHome, env } = makeStandaloneEnv();
  try {
    const sid = 'oneshot-sess-1';
    // 1. One-shot task while standby
    const oneOut = runHook('prompt.js', { session_id: sid, cwd: tmpHome, prompt: '/neckbeard ' + "refactor the auth endpoint and fix the SQL race condition" }, env);
    assert.ok(oneOut && oneOut.hookSpecificOutput && oneOut.hookSpecificOutput.additionalContext, 'one-shot must inject persona context');
    assert.match(oneOut.hookSpecificOutput.additionalContext, /ONE-SHOT TASK ACTIVE/i);

    // 2. PreToolUse guard is active during the one-shot turn
    const denyOut = runHook('guard.js', { session_id: sid, cwd: tmpHome, tool_name: 'Write', tool_input: { file_path: 'src/app.js', content: `const k = "${FAKE_AWS_KEY}";` } }, env);
    assert.ok(denyOut && denyOut.hookSpecificOutput && denyOut.hookSpecificOutput.permissionDecision === 'deny', 'guard must enforce during one-shot turn');

    // 3. Next ordinary prompt clears one-shot and returns to 0-byte standby
    assert.strictEqual(runHook('prompt.js', { session_id: sid, cwd: tmpHome, prompt: "write a haiku about autumn leaves" }, env), null);
    assert.strictEqual(runHook('guard.js', { session_id: sid, cwd: tmpHome, tool_name: 'Write', tool_input: { file_path: 'src/app.js', content: `const k = "${FAKE_AWS_KEY}";` } }, env), null);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

test('NeckBeard explicit enable (/neckbeard on / off) and whole-Crew (/crew on / off) relevance-gated activation work end-to-end', () => {
  const { tmpHome, env } = makeStandaloneEnv();
  try {
    // Part A: Explicit single-persona enable & disable
    const sidA = 'persona-enable-sess';
    const onOut = runHook('prompt.js', { session_id: sidA, cwd: tmpHome, prompt: '/neckbeard on' }, env);
    assert.ok(onOut && onOut.hookSpecificOutput && onOut.hookSpecificOutput.additionalContext);
    const guardOn = runHook('guard.js', { session_id: sidA, cwd: tmpHome, tool_name: 'Write', tool_input: { file_path: 'src/app.js', content: `const k = "${FAKE_AWS_KEY}";` } }, env);
    assert.strictEqual(guardOn.hookSpecificOutput.permissionDecision, 'deny');

    const offOut = runHook('prompt.js', { session_id: sidA, cwd: tmpHome, prompt: '/neckbeard off' }, env);
    assert.match(offOut.hookSpecificOutput.additionalContext, /OFF/i);
    assert.strictEqual(runHook('guard.js', { session_id: sidA, cwd: tmpHome, tool_name: 'Write', tool_input: { file_path: 'src/app.js', content: `const k = "${FAKE_AWS_KEY}";` } }, env), null);

    // Part B: Whole-Crew /crew on -> hydrates ONLY on relevant prompt, ignores irrelevant prompt, /crew off returns to standby
    const sidB = 'crew-enable-sess';
    const crewOn = runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: '/crew on' }, env);
    assert.ok(crewOn && crewOn.hookSpecificOutput && crewOn.hookSpecificOutput.additionalContext);
    assert.match(crewOn.hookSpecificOutput.additionalContext, /Crew Universe ENABLED/i);

    assert.strictEqual(runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: "write a haiku about autumn leaves" }, env), null);
    const relOut = runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: "refactor the auth endpoint and fix the SQL race condition" }, env);
    assert.ok(relOut && relOut.hookSpecificOutput && relOut.hookSpecificOutput.additionalContext, 'relevant prompt under /crew on must hydrate persona');
    // Subsequent relevant prompt does not re-dump full rules (already hydrated)
    assert.strictEqual(runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: "refactor the auth endpoint and fix the SQL race condition" }, env), null);

    const crewOff = runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: '/crew off' }, env);
    assert.match(crewOff.hookSpecificOutput.additionalContext, /CREW MODE OFF/i);
    assert.strictEqual(runHook('prompt.js', { session_id: sidB, cwd: tmpHome, prompt: "refactor the auth endpoint and fix the SQL race condition" }, env), null);

    // Part C: Crew Studio CREW_ACTIVE_PERSONA isolation
    const otherEnv = { ...env, CREW_ACTIVE_PERSONA: 'rainmaker' };
    assert.strictEqual(runHook('session-start.js', { session_id: 'orch-other', cwd: tmpHome, source: 'startup' }, otherEnv), null);
    const selfEnv = { ...env, CREW_ACTIVE_PERSONA: 'neckbeard' };
    const selfOut = runHook('session-start.js', { session_id: 'orch-self', cwd: tmpHome, source: 'startup' }, selfEnv);
    assert.ok(selfOut && selfOut.hookSpecificOutput && selfOut.hookSpecificOutput.additionalContext);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

test('all skills/*/SKILL.md declare disable-model-invocation: true so standalone hosts never auto-invoke uninvited', () => {
  const skillsDir = path.join(ROOT, 'skills');
  for (const ent of fs.readdirSync(skillsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const p = path.join(skillsDir, ent.name, 'SKILL.md');
    if (!fs.existsSync(p)) continue;
    const raw = fs.readFileSync(p, 'utf8');
    const fm = raw.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    assert.ok(fm, `${ent.name}/SKILL.md missing frontmatter`);
    assert.match(fm[1], /^disable-model-invocation:\s*true$/m, `${ent.name}/SKILL.md must set disable-model-invocation: true`);
  }
});
