'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const {
  MAX_FILES,
  DEFAULT_MAX_CHUNK_FILES,
  DEFAULT_MAX_CHUNK_BYTES,
  validateScopeSubpath,
  validateRepoRelPath,
  buildAuditPlan,
  checkCoverage,
  emitPlaybook,
} = require('../hooks/audit-plan');

const AUDIT_PLAN_BIN = path.join(__dirname, '..', 'hooks', 'audit-plan.js');

function tmpDir(prefix = 'nb-audit-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function initGitRepo(dir) {
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
}

function writeFileRel(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

function runCli(args, env = {}) {
  const childEnv = { ...process.env };
  delete childEnv.NECKBEARD_UNCAPPED;
  Object.assign(childEnv, env);
  return spawnSync(process.execPath, [AUDIT_PLAN_BIN, ...args], {
    encoding: 'utf8',
    timeout: 15000,
    maxBuffer: 64 * 1024 * 1024,
    env: childEnv,
  });
}

test('audit-plan enumerates git files, separates binaries (Not read) and vendored trees (Not checked), and outputs exact totals', () => {
  const repo = tmpDir();
  try {
    initGitRepo(repo);
    writeFileRel(repo, 'README.md', '# Demo Repo\n');
    writeFileRel(repo, 'src/index.js', 'console.log("hello");\n');
    writeFileRel(repo, 'app/(auth)/[id]/route.ts', 'export async function GET() { return new Response("ok"); }\n');
    writeFileRel(repo, 'docs/Release Notes.md', '# Notes\n');
    writeFileRel(repo, 'assets/logo.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
    // Known binary extensions
    writeFileRel(repo, 'assets/banner.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]));
    writeFileRel(repo, 'assets/font.woff2', Buffer.alloc(128, 0x42));
    // Extensionless binary with NUL byte
    writeFileRel(repo, 'bin/native-blob', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x02, 0x01]));
    // Vendored third-party trees
    writeFileRel(repo, 'vendor/third/lib.js', 'module.exports = 1;\n');
    writeFileRel(repo, 'third_party/zlib/adler32.c', 'int adler() { return 0; }\n');
    writeFileRel(repo, 'packages/web/node_modules/pkg/index.js', 'module.exports = 2;\n');

    execFileSync('git', ['add', '-f', '.'], { cwd: repo });

    const plan = buildAuditPlan(repo);
    assert.strictEqual(plan.source, 'git');
    assert.strictEqual(plan.tier, 'small');
    assert.strictEqual(plan.totals.trackedFiles, 11);
    assert.strictEqual(plan.totals.inScopeFiles, 5); // README, src/index.js, route.ts, Release Notes.md, logo.svg
    assert.strictEqual(plan.totals.binaryFiles, 3); // banner.png, font.woff2, bin/native-blob
    assert.strictEqual(plan.totals.vendoredFiles, 3);
    assert.strictEqual(
      plan.totals.inScopeBytes + plan.totals.binaryBytes + plan.totals.vendoredBytes,
      plan.totals.trackedBytes
    );
    assert.deepStrictEqual(plan.notRead.files.sort(), ['assets/banner.png', 'assets/font.woff2', 'bin/native-blob']);
    assert.deepStrictEqual(plan.notChecked.vendoredRoots, [
      'packages/web/node_modules/',
      'third_party/',
      'vendor/',
    ]);
    assert.ok(plan.chunks.some((c) => c.files.some((f) => f.path === 'assets/logo.svg')), 'SVG stays in-scope');
    assert.ok(plan.chunks.some((c) => c.files.some((f) => f.path === 'app/(auth)/[id]/route.ts')), 'Bracket/paren Next.js path stays in-scope');
    assert.ok(plan.chunks.some((c) => c.files.some((f) => f.path === 'docs/Release Notes.md')), 'Path with space stays in-scope');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('audit-plan deterministically partitions in-scope files into disjoint chunks bounded by BOTH file count and byte size, ordered highest-risk first', () => {
  const repo = tmpDir();
  try {
    initGitRepo(repo);
    // 1. Directory with 60 small files (> 35 default max files -> must split into <= 35 per chunk)
    for (let i = 0; i < 60; i++) {
      writeFileRel(repo, `src/many/f${String(i).padStart(2, '0')}.js`, `export const n${i} = ${i};\n`);
    }
    // 2. Directory with 6 files of 110 KB each (<= 300 KB -> max 2 files per chunk, never overpacked)
    const block110k = 'a'.repeat(110 * 1024);
    for (let i = 0; i < 6; i++) {
      writeFileRel(repo, `src/heavy/h${i}.js`, block110k);
    }
    // 3. Single oversized file of 380 KB (> 300 KB -> isolated in its own 1-file chunk, never dropped)
    writeFileRel(repo, 'src/heavy/giant-lock.json', 'x'.repeat(380 * 1024));
    // 4. Risk-ordered boundary directories:
    //    - src/z-gateway/entry.js is a [ext] -> [int] bridge in .neckbeard.json
    //    - src/y-crypto/signer.js has PRISM risk_score 0.88 in .ai-audit/annotations.jsonl
    //    - docs/low.md has PRISM risk_score 0.20 (below 0.60 threshold)
    writeFileRel(repo, 'src/z-gateway/entry.js', 'export function handle(req) { return req; }\n');
    writeFileRel(repo, 'src/z-gateway/helper.js', 'export const ok = true;\n');
    writeFileRel(repo, 'src/y-crypto/signer.js', 'export function sign(x) { return x; }\n');
    writeFileRel(repo, 'docs/low.md', '# Low risk doc\n');

    writeFileRel(
      repo,
      '.neckbeard.json',
      JSON.stringify({
        shared: true,
        load: '500 rps',
        boundaries: {
          external: { ingress: ['src/z-gateway/entry.js->http-in'], egress: [], supply: [] },
          internal: { auth: [], data: ['src/z-gateway/entry.js->fs'], exec: ['src/z-gateway/entry.js->proc'], ai: [] },
        },
      }, null, 2) + '\n'
    );
    writeFileRel(
      repo,
      '.ai-audit/annotations.jsonl',
      [
        JSON.stringify({ file_path: 'src/y-crypto/signer.js', risk_score: 0.88 }),
        JSON.stringify({ file_path: 'docs/low.md', risk_score: 0.20 }),
      ].join('\n') + '\n'
    );

    execFileSync('git', ['add', '-f', '.'], { cwd: repo });

    const planA = buildAuditPlan(repo);
    const planB = buildAuditPlan(repo);

    // Byte-for-byte determinism
    assert.strictEqual(JSON.stringify(planA), JSON.stringify(planB));
    assert.strictEqual(planA.bounds.maxChunkFiles, DEFAULT_MAX_CHUNK_FILES);
    assert.strictEqual(planA.bounds.maxChunkBytes, DEFAULT_MAX_CHUNK_BYTES);
    assert.strictEqual(planA.tier, 'medium'); // > 1 MB in-scope

    // Exact disjoint union & strict file + byte bounds
    const seen = new Set();
    let giantChunk = null;
    for (const ch of planA.chunks) {
      assert.ok(ch.fileCount <= DEFAULT_MAX_CHUNK_FILES, `${ch.id} fileCount ${ch.fileCount} <= 35`);
      if (ch.fileCount > 1) {
        assert.ok(ch.bytes <= DEFAULT_MAX_CHUNK_BYTES, `${ch.id} bytes ${ch.bytes} <= 300 KB`);
      }
      for (const f of ch.files) {
        assert.strictEqual(seen.has(f.path), false, `duplicate file ${f.path}`);
        seen.add(f.path);
        if (f.path === 'src/heavy/giant-lock.json') giantChunk = ch;
      }
    }
    assert.strictEqual(seen.size, planA.totals.inScopeFiles);
    assert.ok(giantChunk && giantChunk.fileCount === 1 && giantChunk.oversizedSingleFile === true);

    // Risk-first ordering: bridge chunk and PRISM >= 0.60 chunk MUST come before non-high-risk chunks
    const top2 = planA.chunks.slice(0, 2);
    assert.strictEqual(top2[0].hasHighRisk, true);
    assert.strictEqual(top2[1].hasHighRisk, true);
    assert.ok(top2[0].bridgeFiles.includes('src/z-gateway/entry.js'), 'Chunk 1 runs [ext]->[int] bridge first');
    assert.ok(top2[1].prismHighFiles.some((p) => p.path === 'src/y-crypto/signer.js' && p.riskScore === 0.88), 'Chunk 2 runs PRISM >= 0.60 hotspot second');
    // Related files in src/z-gateway stay grouped together in Chunk 1
    assert.ok(top2[0].files.some((f) => f.path === 'src/z-gateway/helper.js'));
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('audit-plan enforces 20,000-file cap notice and honors --uncapped / NECKBEARD_UNCAPPED=1', () => {
  const repo = tmpDir();
  try {
    initGitRepo(repo);
    assert.strictEqual(MAX_FILES, 20000);
    writeFileRel(repo, 'src/main.js', 'export const ok = 1;\n');
    const blobSha = execFileSync('git', ['hash-object', '-w', '--stdin'], { cwd: repo, input: '', encoding: 'utf8' }).trim();
    const lines = [];
    for (let i = 0; i < 20004; i++) {
      lines.push(`100644 ${blobSha}\tsrc/file-${String(i).padStart(5, '0')}.js`);
    }
    execFileSync('git', ['update-index', '--index-info'], { cwd: repo, input: lines.join('\n') + '\n' });
    execFileSync('git', ['add', 'src/main.js'], { cwd: repo });

    const capped = runCli([repo, '--json']);
    assert.strictEqual(capped.status, 0, capped.stderr);
    assert.match(capped.stderr, /20005 matching files exceed cap of 20000/);
    assert.ok(capped.stderr.includes('--uncapped'));
    const cappedJson = JSON.parse(capped.stdout);
    assert.strictEqual(cappedJson.truncated, true);
    assert.strictEqual(cappedJson.totals.trackedFiles, 20005);
    assert.strictEqual(cappedJson.totals.inspectedFiles, 20000);

    const uncapped = runCli([repo, '--uncapped', '--json']);
    assert.strictEqual(uncapped.status, 0, uncapped.stderr);
    assert.strictEqual(uncapped.stderr.trim(), '');
    const uncappedJson = JSON.parse(uncapped.stdout);
    assert.strictEqual(uncappedJson.truncated, false);
    assert.strictEqual(uncappedJson.totals.trackedFiles, 20005);
    assert.strictEqual(uncappedJson.totals.inspectedFiles, 20005);

    const envUncapped = runCli([repo, '--json'], { NECKBEARD_UNCAPPED: '1' });
    assert.strictEqual(envUncapped.status, 0, envUncapped.stderr);
    assert.strictEqual(envUncapped.stderr.trim(), '');
    assert.strictEqual(JSON.parse(envUncapped.stdout).truncated, false);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('audit-plan fails closed on hostile file paths, symlink escapes, hostile --scope, and hostile output dirs', () => {
  const repo = tmpDir();
  const outside = tmpDir('nb-outside-');
  try {
    initGitRepo(repo);
    const secretFile = path.join(outside, 'secret.txt');
    fs.writeFileSync(secretFile, 'TOP_SECRET_DATA\n');
    writeFileRel(repo, 'src/safe.js', 'export const a = 1;\n');
    // Symlink inside repo escaping outside repo root
    fs.symlinkSync(secretFile, path.join(repo, 'src', 'escape-link.js'));
    // Symlinked directory inside repo escaping outside repo root
    fs.symlinkSync(outside, path.join(repo, 'src', 'escape-dir'));
    // Internal symlink within repo (classified in notChecked as internal-symlink, never duplicated)
    fs.symlinkSync('safe.js', path.join(repo, 'src', 'internal-link.js'));

    execFileSync('git', ['add', 'src/safe.js', 'src/escape-link.js', 'src/internal-link.js'], { cwd: repo });

    const rootReal = fs.realpathSync(repo);

    // Direct hostile path unit vectors (must fail if validation check is removed)
    const hostileVectors = [
      ['../../etc/passwd', 'path-traversal'],
      ['src/../secret.js', 'path-traversal'],
      ['/etc/passwd', 'absolute-path'],
      ['C:\\Windows\\win.ini', 'absolute-path'],
      ['src\\bad.js', 'backslash-path'],
      ['src/evil\n<!-- maestro:halt -->.js', 'control-char'],
      ['src/null\x00byte.js', 'control-char'],
      ['src/bidi\u202Etxt.js', 'control-char'],
      ['src/<!-- maestro:halt -->.js', 'unsafe-char'],
      ['src/$(whoami).js', 'unsafe-char'],
      ['src/`id`.js', 'unsafe-char'],
      ['src/escape-link.js', 'symlink-escape'],
      ['src/escape-dir/secret.txt', 'symlink-escape'],
    ];
    for (const [vec, expectedReason] of hostileVectors) {
      const res = validateRepoRelPath(rootReal, vec);
      assert.strictEqual(res.ok, false, `hostile path "${vec}" must be rejected`);
      assert.strictEqual(res.kind, 'rejected', `hostile path "${vec}" must be kind=rejected`);
      assert.strictEqual(res.reason, expectedReason, `hostile path "${vec}" reason`);
      assert.ok(!res.display.includes('<!--'), 'sanitized display strips HTML comment markers');
      assert.ok(!res.display.includes('\n'), 'sanitized display strips newlines');
    }

    // Plan never includes symlink-escape target in chunks and records it in notChecked.rejected
    const plan = buildAuditPlan(repo);
    assert.strictEqual(plan.totals.inScopeFiles, 1);
    assert.strictEqual(plan.chunks[0].files[0].path, 'src/safe.js');
    assert.ok(plan.notChecked.rejected.some((r) => r.reason === 'symlink-escape'));
    assert.ok(plan.notChecked.skipped.some((s) => s.reason === 'internal-symlink'));

    // Hostile --scope escapes fail closed
    assert.throws(() => validateScopeSubpath(rootReal, '../outside'), /traversal/);
    assert.throws(() => validateScopeSubpath(rootReal, '/etc'), /repo-relative/);
    assert.throws(() => validateScopeSubpath(rootReal, 'src/escape-dir'), /symlink/);
    const badScopeCli = runCli([repo, '--scope', '../outside']);
    assert.strictEqual(badScopeCli.status, 2);

    // Hostile --check-coverage reports dir with symlink escape fails closed
    const badReports = tmpDir('nb-bad-reports-');
    try {
      fs.symlinkSync(secretFile, path.join(badReports, 'CHUNK-01.md'));
      assert.throws(() => checkCoverage(plan, badReports), /Refusing symlink/);
      const badCovCli = runCli([repo, '--check-coverage', badReports]);
      assert.strictEqual(badCovCli.status, 2);
    } finally {
      fs.rmSync(badReports, { recursive: true, force: true });
    }

    // Hostile --emit-playbook targets (symlink or .ai-audit) fail closed
    const linkOut = path.join(repo, 'out-link');
    fs.symlinkSync(outside, linkOut);
    assert.throws(() => emitPlaybook(plan, linkOut), /Refusing symlink/);
    assert.throws(() => emitPlaybook(plan, path.join(linkOut, 'nested')), /Refusing symlink/);
    assert.throws(() => emitPlaybook(plan, path.join(repo, '.ai-audit', 'playbooks')), /protected directory/);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('audit-plan --check-coverage proves 0 missing files and rejects partial or basename-spoofed reports, and --emit-playbook creates task-based docs', () => {
  const repo = tmpDir();
  const reportsDir = tmpDir('nb-reports-');
  const playbookDir = path.join(repo, '.maestro', 'playbooks', 'neckbeard-audit');
  try {
    initGitRepo(repo);
    writeFileRel(repo, 'src/auth/login.js', 'export function login() {}\n');
    writeFileRel(repo, 'src/auth/session.js', 'export function session() {}\n');
    writeFileRel(repo, 'app/(auth)/[id]/route.ts', 'export function GET() {}\n');
    writeFileRel(repo, 'docs/Release Notes.md', '# Release\n');
    execFileSync('git', ['add', '.'], { cwd: repo });

    // 1. Partial report + basename spoof ('route.ts' without dir) MUST fail with exit code 1
    fs.writeFileSync(
      path.join(reportsDir, 'CHUNK-01.md'),
      '# CHUNK-01\n\n## Files audited\n- `src/auth/login.js:1`\n- `route.ts`\n'
    );
    const partialCli = runCli([repo, '--check-coverage', reportsDir, '--json']);
    assert.strictEqual(partialCli.status, 1);
    const partialCov = JSON.parse(partialCli.stdout);
    assert.strictEqual(partialCov.pass, false);
    assert.strictEqual(partialCov.coveredCount, 1);
    assert.strictEqual(partialCov.missingCount, 3);
    assert.deepStrictEqual(partialCov.missingFiles, [
      'app/(auth)/[id]/route.ts',
      'docs/Release Notes.md',
      'src/auth/session.js',
    ]);

    // 2. Complete coverage via Markdown backticks + JSON auditedFiles passes with exit code 0
    fs.writeFileSync(
      path.join(reportsDir, 'CHUNK-02.md'),
      '# CHUNK-02\n\n## Files audited\n- `src/auth/session.js`\n- `docs/Release Notes.md`\n'
    );
    fs.writeFileSync(
      path.join(reportsDir, 'CHUNK-03.json'),
      JSON.stringify({ auditedFiles: ['app/(auth)/[id]/route.ts'] })
    );
    const fullCli = runCli([repo, '--check-coverage', reportsDir, '--json']);
    assert.strictEqual(fullCli.status, 0, fullCli.stderr);
    const fullCov = JSON.parse(fullCli.stdout);
    assert.strictEqual(fullCov.pass, true);
    assert.strictEqual(fullCov.missingCount, 0);
    assert.strictEqual(fullCov.coveredCount, 4);

    // 3. --emit-playbook generates crash-resumable Maestro Auto Run task-based docs with zero bare halt markers
    const emitCli = runCli([repo, '--emit-playbook', playbookDir, '--json']);
    assert.strictEqual(emitCli.status, 0, emitCli.stderr);
    const emitted = JSON.parse(emitCli.stdout);
    assert.strictEqual(emitted.playbook.playbookType, 'task-based');
    assert.ok(fs.existsSync(path.join(playbookDir, 'audit-plan.json')));
    assert.ok(fs.existsSync(path.join(playbookDir, 'AUDIT-01.md')));
    assert.ok(fs.existsSync(path.join(playbookDir, 'AUDIT-02-SYNTHESIS.md')));

    const phase1 = fs.readFileSync(path.join(playbookDir, 'AUDIT-01.md'), 'utf8');
    const synth = fs.readFileSync(path.join(playbookDir, 'AUDIT-02-SYNTHESIS.md'), 'utf8');
    assert.match(phase1, /^- \[ \] Audit CHUNK-01/m);
    assert.ok(phase1.includes('Skip repo-wide README, lockfile, and Refactor-vs-Rewrite boilerplate'));
    assert.ok(phase1.includes('`app/(auth)/[id]/route.ts`'));
    assert.ok(phase1.includes('`docs/Release Notes.md`'));
    assert.match(synth, /^- \[ \] Verify 100% file coverage/m);
    assert.ok(synth.includes('--check-coverage'));
    assert.ok(synth.includes('E_patch'));
    assert.ok(synth.includes('E_rewrite'));
    assert.ok(!phase1.includes('<!-- maestro:halt'));
    assert.ok(!synth.includes('<!-- maestro:halt'));

    // 4. Passing the unexecuted playbook directory itself to --check-coverage MUST NOT spoof coverage
    const spoofedPlaybookCov = runCli([repo, '--check-coverage', playbookDir, '--json']);
    assert.strictEqual(spoofedPlaybookCov.status, 1);
    const spoofedJson = JSON.parse(spoofedPlaybookCov.stdout);
    assert.strictEqual(spoofedJson.pass, false);
    assert.strictEqual(spoofedJson.coveredCount, 0);
    assert.strictEqual(spoofedJson.missingCount, 4);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(reportsDir, { recursive: true, force: true });
  }
});
