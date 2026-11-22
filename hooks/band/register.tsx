import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import { boardHtml, tasksFrom } from './board'
import type { Band } from './types'
import type { Col } from './metrics'
import {
  GREP_DEFS,
  NO_TOKENS,
  addTokens,
  addedLines,
  callsIn,
  defsIn,
  elapsed,
  fmtTokens,
  hits,
  inProject,
  isCode,
  isSource,
  isTestCommand,
  lineDelta,
  mainModel,
  markdown,
  metricsSvg,
  MODEL_PATTERN,
  parseDefs,
  percent,
  relPath,
  resume,
  sinksIn,
  snapshot,
  testCounts,
  sessionTitle,
  taskKey,
  testsLabel,
  TITLE_RECORD,
  totalTokens,
  upsertCsv,
} from './metrics'

const LEVELS = ['off', 'lite', 'full', 'paranoid']
const EMPTY: Band = {
  level: 'full',
  model: '',
  cost: 0,
  spent: 0,
  turns: 0,
  turnCosts: [],
  tokens: NO_TOKENS,
  busyMs: 0,
  name: '',
  project: '',
  session: '',
  transcript: '',
  reused: [],
  created: [],
  removed: [],
  linesAdded: 0,
  linesRemoved: 0,
  openCallers: [],
  newBoundaries: [],
  guardBlocks: 0,
  secFound: 0,
  secFixed: 0,
  vibesRisk: null,
  loadTarget: '',
  tests: { state: 'none' },
  details: false,
}

const TASK = {
  spent: 0,
  turns: 0,
  turnCosts: [],
  tokens: NO_TOKENS,
  busyMs: 0,
  name: '',
  model: '',
  reused: [],
  created: [],
  removed: [],
  linesAdded: 0,
  linesRemoved: 0,
  openCallers: [],
  newBoundaries: [],
  guardBlocks: 0,
  secFound: 0,
  secFixed: 0,
  vibesRisk: null,
  tests: { state: 'none' as const },
}

const band = atom({ plugin: 'neckbeard', key: 'band' } as const, EMPTY)
const load = async ($: EngineInterface): Promise<Band> => ({ ...EMPTY, ...(await read($, band)) })
const union = (a: string[], b: string[]) => [...new Set([...a, ...b])]
const base = (p: string) => p.replace(/\/+$/, '').split('/').pop() ?? p

const home = async ($: EngineInterface) => (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'))
const claudeDir = async ($: EngineInterface) => (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${await home($)}/.claude`

async function bandHidden($: EngineInterface): Promise<boolean> {
  try {
    return (await $.fs.read(`${await claudeDir($)}/.neckbeard-band`)).trim() === 'off'
  } catch {
    return false
  }
}

async function readLevel($: EngineInterface): Promise<string> {
  const fromEnv = (await $.env.get('NECKBEARD_LEVEL'))?.trim().toLowerCase()
  if (fromEnv && LEVELS.includes(fromEnv)) return fromEnv
  return 'full'
}

// Read project's saved load target and baseline trust-boundary entries from .neckbeard.json when present.
async function readProjectBaseline($: EngineInterface, root: string): Promise<{ load: string; boundaries: Set<string> }> {
  try {
    const raw = await $.fs.read(`${root}/.neckbeard.json`)
    const cfg = JSON.parse(raw) as {
      load?: string
      boundaries?: {
        external?: Record<string, string[]>
        internal?: Record<string, string[]>
      }
    }
    const set = new Set<string>()
    for (const group of [cfg.boundaries?.external, cfg.boundaries?.internal]) {
      if (!group) continue
      for (const arr of Object.values(group)) {
        if (Array.isArray(arr)) for (const item of arr) set.add(item)
      }
    }
    return { load: typeof cfg.load === 'string' ? cfg.load.trim() : '', boundaries: set }
  } catch {
    return { load: '', boundaries: new Set() }
  }
}

// Default to reading VIBES (.ai-audit/annotations.jsonl) when present in the project.
async function readVibesMetrics($: EngineInterface, root: string): Promise<{ risk: number | null; found: number; fixed: number; added: number; removed: number }> {
  try {
    const raw = await $.fs.read(`${root}/.ai-audit/annotations.jsonl`)
    let maxRisk: number | null = null
    let found = 0
    let fixed = 0
    let added = 0
    let removed = 0
    for (const line of raw.split('\n')) {
      const t = line.trim()
      if (!t.startsWith('{')) continue
      try {
        const a = JSON.parse(t) as Record<string, unknown>
        const risk = typeof a.risk_score === 'number' ? a.risk_score : null
        if (risk !== null) {
          maxRisk = maxRisk === null ? risk : Math.max(maxRisk, risk)
          if (risk >= 0.6) {
            found++
            if (a.verified === true || a.resolved === true || a.status === 'resolved') fixed++
          }
        }
        if (a.type === 'incident' || a.record_type === 'incident') {
          found++
          if (a.resolved === true || a.status === 'resolved' || a.status === 'mitigated') fixed++
        }
        if (typeof a.lines_added === 'number') added += a.lines_added
        if (typeof a.lines_removed === 'number') removed += a.lines_removed
      } catch {
        continue
      }
    }
    return { risk: maxRisk, found, fixed, added, removed }
  } catch {
    return { risk: null, found: 0, fixed: 0, added: 0, removed: 0 }
  }
}

const run = ($: EngineInterface, command: string, args = '') => $.command.run({ command, args })

type Options = { readonly [field: string]: unknown }

async function readTitle($: EngineInterface, transcript: string): Promise<string | undefined> {
  if (transcript === '') return undefined
  const grep = await $.process.run(['grep', '-F', TITLE_RECORD, transcript]).catch(() => undefined)
  const text = grep !== undefined && grep.exitCode <= 1 ? grep.stdout : await $.fs.read(transcript).catch(() => '')
  return sessionTitle(text)
}

async function readModel($: EngineInterface, transcript: string): Promise<string> {
  if (transcript === '') return ''
  const grep = await $.process.run(['grep', '-o', MODEL_PATTERN, transcript]).catch(() => undefined)
  return grep?.exitCode === 0 ? mainModel(grep.stdout) : ''
}

async function findTranscript($: EngineInterface, session: string): Promise<string> {
  const projects = `${await claudeDir($)}/projects`
  const exists = (file: string) => $.fs.exists(file).catch(() => false)
  const root = await $.session.root().catch(() => '')
  const named = `${projects}/${root.replace(/[^a-zA-Z0-9]/g, '-')}/${session}.jsonl`
  if (root !== '' && (await exists(named))) return named
  const dirs = (await $.fs.list(projects).catch(() => [])).filter(d => d.kind === 'dir')
  for (const dir of dirs) {
    const file = `${projects}/${dir.name}/${session}.jsonl`
    if (await exists(file)) return file
  }
  return ''
}

async function ledgerDir($: EngineInterface) {
  return `${(await $.env.get('XDG_CONFIG_HOME')) ?? `${await home($)}/.config`}/neckbeard/band`
}

const ledgerFile = (dir: string, project: string) => `${dir}/${project.replace(/[^\w.-]/g, '_')}.csv`

async function record($: EngineInterface, b: Band, options: Options) {
  const startedAt = (await $.session.usage()).startedAt
  const row = snapshot(b, startedAt)
  if (options.ledger !== false && b.project !== '') {
    const dir = await ledgerDir($)
    const file = ledgerFile(dir, b.project)
    const existing = await $.fs.read(file).catch(() => '')
    await $.fs.write(file, upsertCsv(existing, row))
    await writeBoard($, dir)
  }
}

async function writeBoard($: EngineInterface, dir: string) {
  const entries = await $.fs.list(dir).catch(() => [])
  const texts = await Promise.all(entries.filter(f => f.kind === 'file' && f.name.endsWith('.csv')).map(f => $.fs.read(`${dir}/${f.name}`).catch(() => '')))
  const file = `${dir}/board.html`
  await $.fs.write(file, boardHtml(texts.flatMap(tasksFrom), await $.clock.now()))
  return file
}

async function openBoard($: EngineInterface) {
  const file = await writeBoard($, await ledgerDir($))
  const windows = (await $.env.get('OS')) === 'Windows_NT'
  const mac = !windows && (await $.process.run(['uname'])).stdout.trim() === 'Darwin'
  await $.process.run(windows ? ['cmd', '/c', 'start', '', file] : [mac ? 'open' : 'xdg-open', file])
}

async function start($: EngineInterface): Promise<{ defs: Map<string, string>; boundaries: Set<string> }> {
  const grep = await $.process.run(['git', 'grep', '--untracked', '-nE', GREP_DEFS]).catch(() => undefined)
  const level = await readLevel($)
  const details = (await $.store.get('details')) === true
  const repo = await $.session.repo().catch(() => null)
  const root = repo?.root ?? (await $.session.cwd())
  const project = base(root)
  const session = await $.session.id()
  const baseline = await readProjectBaseline($, root)
  const vibes = await readVibesMetrics($, root)
  const usage = await $.session.usage().catch(() => undefined)
  const csv = usage ? await $.fs.read(ledgerFile(await ledgerDir($), project)).catch(() => '') : ''
  const key = usage ? taskKey(session, usage.startedAt) : ''
  await update($, band, b =>
    resume(
      {
        ...EMPTY,
        ...b,
        level,
        details,
        project,
        session,
        loadTarget: baseline.load,
        vibesRisk: vibes.risk,
        secFound: Math.max(b.secFound, vibes.found),
        secFixed: Math.max(b.secFixed, vibes.fixed),
        linesAdded: Math.max(b.linesAdded, vibes.added),
        linesRemoved: Math.max(b.linesRemoved, vibes.removed),
        cost: usage?.cost?.usd ?? b.cost,
      },
      csv,
      key
    )
  )
  return {
    defs: grep?.exitCode === 0 ? parseDefs(grep.stdout) : new Map(),
    boundaries: baseline.boundaries,
  }
}

export const register: Register = (on, options) => {
  let known = new Map<string, string>()
  let baselineBoundaries = new Set<string>()

  on('session.start', async ($, e, next) => {
    const s = await start($)
    known = s.defs
    baselineBoundaries = s.boundaries
    return next(e)
  }).catch(($, e, next) => next(e))

  on('command.run', { command: ['clear', 'resume', 'branch'] }, async ($, e, next) => {
    const session = await $.session.id()
    const result = await next(e)
    if ((await $.session.id()) !== session) {
      const s = await start($).catch(() => ({ defs: known, boundaries: baselineBoundaries }))
      known = s.defs
      baselineBoundaries = s.boundaries
    }
    return result
  }).catch(($, e, next) => next(e))

  on('session.end', async ($, e, next) => {
    if (e.reason === 'clear') await update($, band, b => ({ ...EMPTY, ...b, ...TASK }))
    return next(e)
  }).catch(($, e, next) => next(e))

  on('prompt.submit', async ($, e, next) => {
    const text = e.text.trim()
    if (e.origin.kind !== 'plugin' && text !== '' && !text.startsWith('/')) {
      const name = (text.split('\n')[0] ?? '').slice(0, 60)
      await update($, band, b => (b.name === '' ? { ...EMPTY, ...b, name } : b))
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  on('tool.call', async ($, e, next) => {
    if (e.tool === 'Bash') {
      const ran = await next(e)
      if (ran.deny !== undefined) {
        await update($, band, b => ({ ...b, guardBlocks: b.guardBlocks + 1, secFound: b.secFound + 1, secFixed: b.secFixed + 1 }))
        return ran
      }
      if (isTestCommand(e.command)) {
        const tests = { state: ran.isError ? ('fail' as const) : ('pass' as const), ...testCounts(ran.text ?? '') }
        await update($, band, b => ({ ...b, tests }))
      }
      return ran
    }

    if (e.tool !== 'Edit' && e.tool !== 'Write') return next(e)

    const file = e.file_path
    const repo = await $.session.repo().catch(() => null)
    const root = repo?.root ?? (await $.session.cwd())
    if (!inProject(file, root)) return next(e)
    const before = e.tool === 'Write' ? await $.fs.read(file).catch(() => '') : e.old_string
    const after = e.tool === 'Write' ? e.content : e.new_string
    const ran = await next(e)
    if (ran.deny !== undefined) {
      await update($, band, b => ({ ...b, guardBlocks: b.guardBlocks + 1, secFound: b.secFound + 1, secFixed: b.secFixed + 1 }))
      return ran
    }
    if (ran.isError) return ran

    const oldDefs = defsIn(file, before)
    const newDefs = defsIn(file, after)
    const created = isSource(file) ? newDefs.filter(n => !oldDefs.includes(n)) : []
    const removed = oldDefs.filter(n => !newDefs.includes(n))
    const reused = isSource(file) ? callsIn(addedLines(before, after), known, newDefs) : []
    const delta = lineDelta(before, after)

    // Detect trust-boundary expansion introduced by this edit/write against baseline .neckbeard.json
    const rel = relPath(file, root)
    const beforeSinks = new Set(sinksIn(rel, before))
    const addedSinks = sinksIn(rel, after).filter(s => !beforeSinks.has(s) && !baselineBoundaries.has(s))

    await update($, band, b => ({
      ...b,
      reused: union(b.reused, reused),
      created: union(b.created, created),
      removed: union(b.removed, removed),
      linesAdded: b.linesAdded + delta.added,
      linesRemoved: b.linesRemoved + delta.removed,
      newBoundaries: union(b.newBoundaries, addedSinks),
      tests: isCode(file) && b.tests.state !== 'none' ? { ...b.tests, state: 'stale' as const } : b.tests,
    }))

    return ran
  }).catch(($, e, next) => next(e))

  on('turn.complete', async ($, e, next) => {
    const used = e.usage
    if (e.agentId !== undefined) {
      if (used) await update($, band, b => ({ ...EMPTY, ...b, tokens: addTokens(b.tokens ?? NO_TOKENS, used) }))
      return next(e)
    }

    const usage = await $.session.usage()
    const turns = await $.session.turns()
    const { removed, transcript: saved } = await load($)
    const session = await $.session.id()
    const repo = await $.session.repo().catch(() => null)
    const root = repo?.root ?? (await $.session.cwd())
    const baseline = await readProjectBaseline($, root)
    const vibes = await readVibesMetrics($, root)
    const kept = base(saved) === `${session}.jsonl` && (await $.fs.exists(saved).catch(() => false))
    const transcript = kept ? saved : await findTranscript($, session)
    const title = await readTitle($, transcript)
    const model = await readModel($, transcript)

    const stillRemoved: string[] = []
    const open: string[] = []
    for (const name of removed) {
      const grep = await $.process.run(['git', 'grep', '--untracked', '-nw', '-e', name]).catch(() => undefined)
      const rows = hits(grep?.stdout ?? '')
      if (rows.some(r => defsIn(r.file, r.text.trimStart()).includes(name))) continue
      const call = new RegExp(`(?<![\\w$])${name.replace(/\$/g, '\\$')}\\s*\\(`)
      const refs = rows.filter(r => call.test(r.text)).map(r => `${r.file}:${r.line}`)
      if (refs.length > 0) {
        stillRemoved.push(name)
        open.push(...refs)
      }
    }

    const b = await update($, band, x => {
      const b = { ...EMPTY, ...x }
      const cost = usage.cost?.usd ?? b.cost
      const turn = cost >= b.cost ? cost - b.cost : cost
      return {
        ...b,
        transcript,
        cost,
        spent: usage.cost?.usd ?? b.spent + turn,
        turns,
        turnCosts: [...b.turnCosts, turn].slice(-20),
        tokens: used ? addTokens(b.tokens, used) : b.tokens,
        busyMs: b.busyMs + e.durationMs,
        name: title ?? b.name,
        model: model || b.model,
        removed: stillRemoved,
        openCallers: open,
        loadTarget: baseline.load || b.loadTarget,
        vibesRisk: vibes.risk ?? b.vibesRisk,
        secFound: Math.max(b.secFound, vibes.found),
        secFixed: Math.max(b.secFixed, vibes.fixed),
      }
    })
    await record($, b, options).catch(() => $.ui.status('neckbeard band: could not write the task ledger'))

    return next(e)
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey || (await bandHidden($))) return next(e)
    const below = await next(e).catch(() => undefined)

    const b = await load($)
    const now = await $.clock.now()
    const startedAt = (await $.session.usage().catch(() => undefined))?.startedAt ?? now
    const reuse = percent(b.reused.length, b.created.length)
    const avg = b.turns > 0 ? b.spent / b.turns : 0
    const last = b.turnCosts[b.turnCosts.length - 1]

    const setLevel = async (level: string) => {
      await update($, band, x => ({ ...x, level }))
      await run($, 'neckbeard:neckbeard', level)
    }
    const toggle = async () => {
      await update($, band, x => ({ ...x, details: !x.details }))
      await $.store.set('details', !b.details)
    }
    const review = () => run($, 'neckbeard:neckbeard-review')
    const audit = () => run($, 'neckbeard:neckbeard-audit')
    const board = () => openBoard($).catch(() => $.ui.toast('neckbeard band: could not open the board'))
    const copy = async () => {
      const done = await $.ui.copy({ text: markdown(snapshot(await load($), startedAt)), surface: e.surface })
      $.ui.toast(done.isCopied ? 'Task copied as Markdown' : `Copy failed: ${done.reason}`)
    }

    const { Box, Text, Button } = $.ui.resolve(e)
    const width = e.surface === 'terminal' ? e.props.bodyColumns : undefined
    const stack = (mine: NonNullable<typeof below>) => (below ? <Box flexDirection="column">{mine}{below}</Box> : mine)

    const testsText =
      b.tests.state === 'pass'
        ? `✓ ${b.tests.passed ?? ''} tests`
        : b.tests.state === 'fail'
          ? `✗ ${b.tests.failed ?? ''} failed`
          : b.tests.state === 'stale'
            ? 'no test since change'
            : ''
    const testsColor = b.tests.state === 'pass' ? 'success' : b.tests.state === 'fail' ? 'error' : undefined
    const hasOpen = b.openCallers.length > 0
    const hasNewBounds = b.newBoundaries.length > 0

    if (!b.details) {
      return stack(
        <Box flexDirection="row" alignItems="center" gap={2} width={width}>
          <Button key="level" plain onPress={toggle}>
            <Text color={b.level === 'off' ? 'inactive' : 'suggestion'}>●</Text> {b.level}
          </Button>
          <Text>${b.spent.toFixed(2)}</Text>
          {last !== undefined && <Text dimColor>last ${last.toFixed(2)}</Text>}
          <Text dimColor>{elapsed(b.busyMs)}</Text>
          {reuse !== undefined && <Text>{reuse}% reuse</Text>}
          {(b.linesAdded > 0 || b.linesRemoved > 0) && <Text dimColor>+{b.linesAdded}/-{b.linesRemoved}</Text>}
          {b.guardBlocks > 0 && <Text color="success">🛡️ {b.guardBlocks} blocked</Text>}
          {b.secFound > 0 && <Text color={b.secFixed >= b.secFound ? 'success' : 'warning'}>🔒 {b.secFixed}/{b.secFound} sec</Text>}
          {b.vibesRisk !== null && <Text color={b.vibesRisk >= 0.6 ? 'warning' : 'success'}>VIBES {b.vibesRisk.toFixed(2)}</Text>}
          {hasNewBounds && <Text color="warning">⚠ +{b.newBoundaries.length} boundary</Text>}
          {hasOpen && <Text color="warning">⚠ {b.openCallers.length} callers open</Text>}
          {testsText !== '' && (
            <Text color={testsColor} dimColor={b.tests.state === 'stale'}>
              {testsText}
            </Text>
          )}
          <Box flexGrow={1} />
          <Button key="review" plain label="Review" onPress={review} />
          <Button key="audit" plain label="Audit" onPress={audit} />
          <Button key="board" plain label="Board" onPress={board} />
          <Button key="details" plain label="Details" onPress={toggle} />
        </Box>
      )
    }

    const cols: Col[] = [
      { key: 'cost', label: 'cost', value: `$${b.spent.toFixed(2)}`, sub: last === undefined ? '' : `last $${last.toFixed(2)} · ⌀ $${avg.toFixed(2)}` },
      { key: 'tokens', label: 'tokens', value: fmtTokens(totalTokens(b.tokens)), sub: `${b.turns} ${b.turns === 1 ? 'turn' : 'turns'}` },
      { key: 'time', label: 'agent time', value: elapsed(b.busyMs), sub: b.turns > 0 ? `⌀ ${elapsed(b.busyMs / b.turns)} / turn` : '' },
      {
        key: 'refactor',
        label: 'reuse & delta',
        value: reuse !== undefined ? `${reuse}% reuse` : `+${b.linesAdded}/-${b.linesRemoved}`,
        sub: `${b.reused.length} reused · ${b.created.length} new`,
      },
      {
        key: 'security',
        label: 'security & guard',
        value: `${b.guardBlocks} blocked`,
        sub: `${b.secFixed}/${b.secFound} fixed${b.vibesRisk !== null ? ` · PRISM ${b.vibesRisk.toFixed(2)}` : ''}`,
        tone: b.secFound > b.secFixed ? 'warning' : 'success',
      },
    ]
    if (b.loadTarget) {
      cols.push({ key: 'load', label: 'load target', value: b.loadTarget.slice(0, 18), sub: '.neckbeard.json' })
    }
    if (hasNewBounds) {
      cols.push({ key: 'boundaries', label: 'boundary drift', value: `+${b.newBoundaries.length} new`, sub: b.newBoundaries.slice(0, 2).join(', '), tone: 'warning' })
    }
    if (hasOpen) {
      cols.push({ key: 'callers', label: 'callers', value: `${b.openCallers.length} open`, sub: b.openCallers.slice(0, 2).join(', '), tone: 'warning' })
    }
    if (b.tests.state !== 'none') {
      cols.push({
        key: 'tests',
        label: 'tests',
        value: testsLabel(b.tests),
        sub: b.tests.state === 'pass' ? 'after last change' : b.tests.state === 'fail' ? 'last run' : 'code changed since',
        tone: b.tests.state === 'pass' ? 'success' : b.tests.state === 'fail' ? 'error' : undefined,
      })
    }

    let metrics = (
      <Box flexDirection="column">
        <Text dimColor wrap="truncate-end">
          {'─'.repeat(e.props.bodyColumns)}
        </Text>
        <Box flexDirection="row" gap={2}>
          {cols.map(c => (
            <Box key={c.key} flexDirection="column" {...(width === undefined ? { flexGrow: 1 } : { width: Math.max(10, Math.floor(width / cols.length) - 2) })}>
              <Text dimColor>{c.label}</Text>
              <Text bold color={c.tone}>
                {c.value}
              </Text>
              <Text dimColor wrap="truncate-end">
                {c.sub}
              </Text>
            </Box>
          ))}
        </Box>
      </Box>
    )
    if (e.surface === 'desktop') {
      const { Svg } = $.ui.resolve(e)
      metrics = <Svg source={metricsSvg(cols, b.turnCosts)} alt={cols.map(c => `${c.label} ${c.value}`).join(', ')} />
    }

    return stack(
      <Box flexDirection="column" width={width} gap={e.surface === 'desktop' ? 1 : 0}>
        <Box flexDirection="row" alignItems="center" gap={1}>
          {LEVELS.map(level => (
            <Button
              key={`level-${level}`}
              label={level}
              {...(level === b.level ? { variant: 'primary' as const } : { plain: true as const, dimColor: true })}
              onPress={() => setLevel(level)}
            />
          ))}
          <Box flexGrow={1} />
          <Button key="copy" plain label="Copy" onPress={copy} />
          <Button key="review" plain label="Review" onPress={review} />
          <Button key="audit" plain label="Audit" onPress={audit} />
          <Button key="board" plain label="Board" onPress={board} />
          <Button key="details" plain label="Compact" onPress={toggle} />
        </Box>
        {metrics}
      </Box>
    )
  }).catch(($, e, next) => next(e))
}
