// NeckBeard Claude Code AbovePrompt HUD & Local Telemetry Command Center.
// 100% original implementation: tracks symbol reuse, net refactor line delta, trust-boundary drift,
// PreToolUse guard blocks, VIBES (.ai-audit/) PRISM risk & TRACE forensics, and writes JSONL telemetry
// to ~/.config/neckbeard/telemetry/sessions.jsonl and ~/.config/neckbeard/telemetry/dashboard.html.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import { parseJsonlRecords, renderDashboardHtml } from './dashboard'
import type { HudMetricCard } from './analyzer'
import {
  EMPTY_TOKEN_BUCKETS,
  SYMBOL_GREP_REGEX,
  accumulateTokenBuckets,
  computeReusePercentage,
  detectBoundarySinks,
  evaluateTestOutput,
  extractPromptTaskTitle,
  extractSymbols,
  formatDurationMs,
  formatTestStatusBadge,
  formatTokenCount,
  indexWorkspaceSymbols,
  isProductionSourceFile,
  isTestRunnerCommand,
  isTrackedCodeFile,
  isWithinWorkspace,
  measureDiffImpact,
  renderDesktopHudSvg,
  renderMarkdownReport,
  serializeSessionRecord,
  sumTokenBuckets,
  toWorkspaceRelativePath,
  upsertJsonlLedger,
} from './analyzer'
import type { NeckbeardHudState } from './types'

const SUPPORTED_LEVELS = ['off', 'lite', 'full', 'paranoid']

const INITIAL_HUD_STATE: NeckbeardHudState = {
  activeLevel: 'full',
  modelId: '',
  baselineCostUsd: 0,
  taskCostUsd: 0,
  turnCount: 0,
  recentTurnCosts: [],
  tokenBuckets: EMPTY_TOKEN_BUCKETS,
  activeDurationMs: 0,
  taskTitle: '',
  projectName: '',
  sessionId: '',
  transcriptPath: '',
  reusedSymbols: [],
  createdSymbols: [],
  deletedSymbols: [],
  linesInserted: 0,
  linesDeleted: 0,
  unmigratedCallers: [],
  unreviewedBoundaries: [],
  guardBlockCount: 0,
  securityFindingsTotal: 0,
  securityFindingsResolved: 0,
  vibesMaxPrismRisk: null,
  loadEnvelope: '',
  testStatus: { verdict: 'untested' },
  expandedDrawer: false,
}

const hudAtom = atom({ plugin: 'neckbeard', key: 'hud' } as const, INITIAL_HUD_STATE)
const readHud = async ($: EngineInterface): Promise<NeckbeardHudState> => ({
  ...INITIAL_HUD_STATE,
  ...(await read($, hudAtom)),
})

const mergeUnique = (a: string[], b: string[]) => [...new Set([...a, ...b])]
const basenameOf = (p: string) => p.replace(/\/+$/, '').split('/').pop() ?? p

async function resolveHomeDir($: EngineInterface): Promise<string> {
  return (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE')) ?? ''
}

async function resolveTelemetryDir($: EngineInterface): Promise<string> {
  const xdg = await $.env.get('XDG_CONFIG_HOME')
  const base = xdg ?? `${await resolveHomeDir($)}/.config`
  return `${base}/neckbeard/telemetry`
}

async function isHudHidden($: EngineInterface): Promise<boolean> {
  const claudeDir = (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${await resolveHomeDir($)}/.claude`
  try {
    return (await $.fs.read(`${claudeDir}/.neckbeard-band`)).trim() === 'off'
  } catch {
    return false
  }
}

async function inspectWorkspaceConfig($: EngineInterface, rootDir: string): Promise<{ load: string; knownBoundaries: Set<string> }> {
  try {
    const raw = await $.fs.read(`${rootDir}/.neckbeard.json`)
    const parsed = JSON.parse(raw) as {
      load?: string
      boundaries?: { external?: Record<string, string[]>; internal?: Record<string, string[]> }
    }
    const set = new Set<string>()
    for (const tier of [parsed.boundaries?.external, parsed.boundaries?.internal]) {
      if (!tier) continue
      for (const list of Object.values(tier)) {
        if (Array.isArray(list)) for (const entry of list) set.add(entry)
      }
    }
    return { load: typeof parsed.load === 'string' ? parsed.load.trim() : '', knownBoundaries: set }
  } catch {
    return { load: '', knownBoundaries: new Set() }
  }
}

async function inspectVibesAnnotations($: EngineInterface, rootDir: string) {
  try {
    const hasConfig = await $.fs.exists(`${rootDir}/.ai-audit/config.json`).catch(() => false)
    const hasManifest = await $.fs.exists(`${rootDir}/.ai-audit/manifest.json`).catch(() => false)
    const hasAnnotations = await $.fs.exists(`${rootDir}/.ai-audit/annotations.jsonl`).catch(() => false)
    const hasAuditDb = await $.fs.exists(`${rootDir}/.ai-audit/audit.db`).catch(() => false)
    const hasSessionState = await $.fs.exists(`${rootDir}/.ai-audit/.session_state.json`).catch(() => false)
    if (!hasConfig && !hasManifest && !hasAnnotations && !hasAuditDb && !hasSessionState) {
      return {
        present: false,
        annotationsCount: 0,
        verifiedCount: 0,
        maxRisk: null,
        findings: 0,
        resolved: 0,
        inserted: 0,
        deleted: 0,
        prismBuckets: { low: 0, moderate: 0, high: 0, critical: 0 },
        fileHotspots: [],
      }
    }
    const raw = await $.fs.read(`${rootDir}/.ai-audit/annotations.jsonl`).catch(() => '')
    let maxRisk: number | null = null
    let findings = 0
    let resolved = 0
    let inserted = 0
    let deleted = 0
    let annotationsCount = 0
    let verifiedCount = 0
    const prismBuckets = { low: 0, moderate: 0, high: 0, critical: 0 }
    const fileMap = new Map<string, { file: string; annotations: number; linesAdded: number; linesRemoved: number; maxRisk: number; verified: boolean }>()

    for (const line of raw.split('\n')) {
      const t = line.trim()
      if (!t.startsWith('{')) continue
      try {
        const rec = JSON.parse(t) as Record<string, unknown>
        annotationsCount++
        const isVer = Boolean(rec.verified === true || rec.status === 'verified' || rec.assurance_level === 'high' || rec.attestation_id)
        if (isVer) verifiedCount++
        const rangeAdd =
          typeof rec.line_start === 'number' && typeof rec.line_end === 'number'
            ? Math.max(1, rec.line_end - rec.line_start + 1)
            : 0
        const add = typeof rec.lines_added === 'number' ? rec.lines_added : rangeAdd
        const del = typeof rec.lines_removed === 'number' ? rec.lines_removed : 0
        inserted += add
        deleted += del

        let riskVal = 0
        if (typeof rec.risk_score === 'number') {
          riskVal = rec.risk_score
          maxRisk = maxRisk === null ? rec.risk_score : Math.max(maxRisk, rec.risk_score)
          if (rec.risk_score >= 0.8) prismBuckets.critical++
          else if (rec.risk_score >= 0.6) prismBuckets.high++
          else if (rec.risk_score >= 0.3) prismBuckets.moderate++
          else prismBuckets.low++

          if (rec.risk_score >= 0.6) {
            findings++
            if (isVer || rec.resolved === true || rec.status === 'resolved') resolved++
          }
        }
        if (rec.type === 'incident' || rec.record_type === 'incident') {
          findings++
          if (rec.resolved === true || rec.status === 'resolved' || rec.status === 'mitigated') resolved++
        }
        const fpath = typeof rec.file_path === 'string' ? rec.file_path : typeof rec.file === 'string' ? rec.file : ''
        if (fpath) {
          const prev = fileMap.get(fpath) ?? { file: fpath, annotations: 0, linesAdded: 0, linesRemoved: 0, maxRisk: 0, verified: true }
          prev.annotations++
          prev.linesAdded += add
          prev.linesRemoved += del
          if (riskVal > prev.maxRisk) prev.maxRisk = +riskVal.toFixed(2)
          prev.verified = prev.verified && isVer
          fileMap.set(fpath, prev)
        }
      } catch {
        continue
      }
    }
    return {
      present: true,
      annotationsCount,
      verifiedCount,
      maxRisk,
      findings,
      resolved,
      inserted,
      deleted,
      prismBuckets,
      fileHotspots: [...fileMap.values()].sort((a, b) => b.maxRisk - a.maxRisk).slice(0, 6),
    }
  } catch {
    return {
      present: false,
      annotationsCount: 0,
      verifiedCount: 0,
      maxRisk: null,
      findings: 0,
      resolved: 0,
      inserted: 0,
      deleted: 0,
      prismBuckets: { low: 0, moderate: 0, high: 0, critical: 0 },
      fileHotspots: [],
    }
  }
}

async function buildCurrentWorkspaceMeta($: EngineInterface, state: NeckbeardHudState, telemetryDir?: string) {
  const dir = telemetryDir ?? (await resolveTelemetryDir($))
  let existingMetaMap: Record<string, Record<string, unknown>> = {}
  try {
    const rawMeta = await $.fs.read(`${dir}/workspaces-meta.json`)
    existingMetaMap = JSON.parse(rawMeta) as Record<string, Record<string, unknown>>
  } catch {
    try {
      const prevHtml = await $.fs.read(`${dir}/dashboard.html`)
      const m = /<script type="application\/json" id="nb-telemetry-payload">([\s\S]*?)<\/script>/.exec(prevHtml)
      if (m && m[1]) {
        const parsed = JSON.parse(m[1]) as { workspacesMeta?: Record<string, Record<string, unknown>> }
        if (parsed.workspacesMeta) existingMetaMap = parsed.workspacesMeta
      }
    } catch {}
  }

  const repo = await $.session.repo().catch(() => null)
  const rootDir = repo?.root ?? (await $.session.cwd())
  const wsName = state.projectName || basenameOf(rootDir)
  const prevWs = (existingMetaMap[wsName] ?? {}) as Record<string, unknown>
  const prevVibes = (prevWs.vibes ?? null) as Record<string, unknown> | null

  const vibes = await inspectVibesAnnotations($, rootDir)
  let parsedCfg: { load?: string; boundaryLoad?: Record<string, string>; boundaries?: Record<string, unknown> } = {}
  try {
    parsedCfg = JSON.parse(await $.fs.read(`${rootDir}/.neckbeard.json`))
  } catch {}

  const mergedVibes = vibes.present
    ? {
        ...(prevVibes ?? {}),
        present: true,
        annotationsCount: Math.max(vibes.annotationsCount, Number(prevVibes?.annotationsCount ?? 0)),
        verifiedCount: Math.max(vibes.verifiedCount, Number(prevVibes?.verifiedCount ?? 0)),
        maxPrismRisk: vibes.maxRisk ?? Number(prevVibes?.maxPrismRisk ?? 0),
        highRiskCount: Math.max(vibes.findings, Number(prevVibes?.highRiskCount ?? 0)),
        traceIncidents: Math.max(vibes.findings, Number(prevVibes?.traceIncidents ?? 0)),
        traceResolved: Math.max(vibes.resolved, Number(prevVibes?.traceResolved ?? 0)),
        linesAdded: Math.max(vibes.inserted, Number(prevVibes?.linesAdded ?? 0)),
        linesRemoved: Math.max(vibes.deleted, Number(prevVibes?.linesRemoved ?? 0)),
        filesTouchedCount: Math.max(vibes.fileHotspots.length, Number(prevVibes?.filesTouchedCount ?? 0)),
        prismBuckets: vibes.annotationsCount > 0 ? vibes.prismBuckets : (prevVibes?.prismBuckets ?? vibes.prismBuckets),
        fileHotspots: vibes.fileHotspots.length > 0 ? vibes.fileHotspots : (prevVibes?.fileHotspots ?? []),
      }
    : prevVibes

  const updatedMap = {
    ...existingMetaMap,
    [wsName]: {
      ...prevWs,
      load: parsedCfg.load ?? state.loadEnvelope ?? (prevWs.load as string) ?? '',
      boundaryLoad: parsedCfg.boundaryLoad ?? (prevWs.boundaryLoad as Record<string, string>) ?? {},
      boundaries: (parsedCfg.boundaries as Record<string, unknown>) ?? (prevWs.boundaries as Record<string, unknown>) ?? { external: {}, internal: {} },
      driftAdded: state.unreviewedBoundaries.length > 0 ? state.unreviewedBoundaries : ((prevWs.driftAdded as string[]) ?? []),
      prismRisk: vibes.maxRisk ?? (prevWs.prismRisk as number | null) ?? null,
      vibes: mergedVibes,
    },
  }
  await $.fs.write(`${dir}/workspaces-meta.json`, JSON.stringify(updatedMap)).catch(() => {})
  return updatedMap
}

async function persistTelemetryAndDashboard($: EngineInterface, state: NeckbeardHudState) {
  if (!state.projectName) return
  const startedAtMs = (await $.session.usage().catch(() => undefined))?.startedAt ?? (await $.clock.now())
  const record = serializeSessionRecord(state, startedAtMs)
  const dir = await resolveTelemetryDir($)
  const jsonlFile = `${dir}/sessions.jsonl`
  const existing = await $.fs.read(jsonlFile).catch(() => '')
  const updatedJsonl = upsertJsonlLedger(existing, record)
  await $.fs.write(jsonlFile, updatedJsonl)
  const allRecords = parseJsonlRecords(updatedJsonl)
  const wsMeta = await buildCurrentWorkspaceMeta($, state)
  const html = renderDashboardHtml(allRecords, wsMeta, await $.clock.now())
  await $.fs.write(`${dir}/dashboard.html`, html)
}

async function launchDashboardInBrowser($: EngineInterface) {
  const dir = await resolveTelemetryDir($)
  const htmlFile = `${dir}/dashboard.html`
  const homeDir = await resolveHomeDir($)
  try {
    const claudeDir = (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${homeDir}/.claude`
    const importScript = `${claudeDir}/plugins/marketplaces/neckbeard/hooks/band-import.js`
    if (await $.fs.exists(importScript).catch(() => false)) {
      await $.process.run(['node', importScript]).catch(() => {})
    }
    const hasExistingHtml = await $.fs.exists(htmlFile).catch(() => false)
    if (!hasExistingHtml) {
      const state = await readHud($)
      const jsonlFile = `${dir}/sessions.jsonl`
      const existing = await $.fs.read(jsonlFile).catch(() => '')
      const wsMeta = await buildCurrentWorkspaceMeta($, state)
      await $.fs.write(htmlFile, renderDashboardHtml(parseJsonlRecords(existing), wsMeta, await $.clock.now()))
    }
  } catch {
    // Even if rebuilding fails or times out on a large ledger, still open the existing dashboard.html
  }
  const isWin = (await $.env.get('OS')) === 'Windows_NT'
  if (isWin) {
    await $.process.run(['cmd', '/c', 'start', '', htmlFile])
    return
  }
  const uname = await $.process.run(['uname']).catch(() => ({ stdout: homeDir.startsWith('/Users/') ? 'Darwin' : 'Linux' }))
  const isMac = uname.stdout.trim() === 'Darwin' || homeDir.startsWith('/Users/')
  if (isMac) {
    const res = await $.process.run(['open', htmlFile]).catch(() => ({ exitCode: 1 }))
    if (res.exitCode !== 0) {
      await $.process.run(['/usr/bin/open', htmlFile])
    }
  } else {
    await $.process.run(['xdg-open', htmlFile])
  }
}

async function initializeHudSession($: EngineInterface) {
  const grepRes = await $.process.run(['git', 'grep', '--untracked', '-nE', SYMBOL_GREP_REGEX]).catch(() => undefined)
  const rawEnvLevel = (await $.env.get('NECKBEARD_LEVEL'))?.trim().toLowerCase()
  const envLevel = rawEnvLevel === 'ultra' ? 'paranoid' : rawEnvLevel
  const activeLevel = envLevel && SUPPORTED_LEVELS.includes(envLevel) ? envLevel : 'full'
  const expandedDrawer = (await $.store.get('expandedDrawer')) === true
  const repo = await $.session.repo().catch(() => null)
  const rootDir = repo?.root ?? (await $.session.cwd())
  const projectName = basenameOf(rootDir)
  const sessionId = await $.session.id()
  const wsCfg = await inspectWorkspaceConfig($, rootDir)
  const vibes = await inspectVibesAnnotations($, rootDir)
  const usage = await $.session.usage().catch(() => undefined)

  await update($, hudAtom, (prev) => ({
    ...INITIAL_HUD_STATE,
    ...prev,
    activeLevel,
    expandedDrawer,
    projectName,
    sessionId,
    loadEnvelope: wsCfg.load,
    vibesMaxPrismRisk: vibes.maxRisk,
    securityFindingsTotal: Math.max(prev.securityFindingsTotal, vibes.findings),
    securityFindingsResolved: Math.max(prev.securityFindingsResolved, vibes.resolved),
    linesInserted: Math.max(prev.linesInserted, vibes.inserted),
    linesDeleted: Math.max(prev.linesDeleted, vibes.deleted),
    baselineCostUsd: usage?.cost?.usd ?? prev.baselineCostUsd,
  }))

  return {
    symbolMap: grepRes?.exitCode === 0 ? indexWorkspaceSymbols(grepRes.stdout) : new Map<string, string>(),
    knownBoundaries: wsCfg.knownBoundaries,
  }
}

export const register: Register = (on) => {
  let workspaceSymbols = new Map<string, string>()
  let baselineBoundaries = new Set<string>()

  on('session.start', async ($, evt, next) => {
    const init = await initializeHudSession($)
    workspaceSymbols = init.symbolMap
    baselineBoundaries = init.knownBoundaries
    return next(evt)
  }).catch(($, evt, next) => next(evt))

  on('command.run', { command: ['clear', 'resume', 'branch'] }, async ($, evt, next) => {
    const prevId = await $.session.id()
    const res = await next(evt)
    if ((await $.session.id()) !== prevId) {
      const init = await initializeHudSession($).catch(() => ({ symbolMap: workspaceSymbols, knownBoundaries: baselineBoundaries }))
      workspaceSymbols = init.symbolMap
      baselineBoundaries = init.knownBoundaries
    }
    return res
  }).catch(($, evt, next) => next(evt))

  on('prompt.submit', async ($, evt, next) => {
    const clean = evt.text.trim()
    if (evt.origin.kind !== 'plugin' && clean !== '' && !clean.startsWith('/')) {
      const title = extractPromptTaskTitle(clean)
      await update($, hudAtom, (s) => (s.taskTitle === '' ? { ...s, taskTitle: title } : s))
    }
    return next(evt)
  }).catch(($, evt, next) => next(evt))

  on('tool.call', async ($, evt, next) => {
    if (evt.tool === 'Bash') {
      const outcome = await next(evt)
      if (outcome.deny !== undefined) {
        await update($, hudAtom, (s) => ({
          ...s,
          guardBlockCount: s.guardBlockCount + 1,
          securityFindingsTotal: s.securityFindingsTotal + 1,
          securityFindingsResolved: s.securityFindingsResolved + 1,
        }))
        return outcome
      }
      if (isTestRunnerCommand(evt.command)) {
        const testStatus = evaluateTestOutput(outcome.text ?? '', Boolean(outcome.isError))
        await update($, hudAtom, (s) => ({ ...s, testStatus }))
      }
      return outcome
    }

    if (evt.tool !== 'Edit' && evt.tool !== 'Write') return next(evt)

    const targetPath = evt.file_path
    const repo = await $.session.repo().catch(() => null)
    const rootDir = repo?.root ?? (await $.session.cwd())
    if (!isWithinWorkspace(targetPath, rootDir)) return next(evt)

    const beforeText = evt.tool === 'Write' ? await $.fs.read(targetPath).catch(() => '') : evt.old_string
    const afterText = evt.tool === 'Write' ? evt.content : evt.new_string
    const outcome = await next(evt)

    if (outcome.deny !== undefined) {
      await update($, hudAtom, (s) => ({
        ...s,
        guardBlockCount: s.guardBlockCount + 1,
        securityFindingsTotal: s.securityFindingsTotal + 1,
        securityFindingsResolved: s.securityFindingsResolved + 1,
      }))
      return outcome
    }
    if (outcome.isError) return outcome

    const impact = measureDiffImpact(targetPath, beforeText, afterText, workspaceSymbols)
    const relPath = toWorkspaceRelativePath(targetPath, rootDir)
    const priorSinks = new Set(detectBoundarySinks(relPath, beforeText))
    const newBoundarySinks = detectBoundarySinks(relPath, afterText).filter(
      (sink) => !priorSinks.has(sink) && !baselineBoundaries.has(sink)
    )

    await update($, hudAtom, (s) => ({
      ...s,
      reusedSymbols: mergeUnique(s.reusedSymbols, impact.reusedSymbols),
      createdSymbols: mergeUnique(s.createdSymbols, impact.createdSymbols),
      deletedSymbols: mergeUnique(s.deletedSymbols, impact.deletedSymbols),
      linesInserted: s.linesInserted + impact.linesInserted,
      linesDeleted: s.linesDeleted + impact.linesDeleted,
      unreviewedBoundaries: mergeUnique(s.unreviewedBoundaries, newBoundarySinks),
      testStatus:
        isTrackedCodeFile(targetPath) && s.testStatus.verdict !== 'untested'
          ? { ...s.testStatus, verdict: 'outdated' }
          : s.testStatus,
    }))

    return outcome
  }).catch(($, evt, next) => next(evt))

  on('turn.complete', async ($, evt, next) => {
    const turnUsage = evt.usage
    if (evt.agentId !== undefined) {
      if (turnUsage) {
        await update($, hudAtom, (s) => ({
          ...s,
          tokenBuckets: accumulateTokenBuckets(s.tokenBuckets, turnUsage),
        }))
      }
      return next(evt)
    }

    const sessionUsage = await $.session.usage()
    const totalTurns = await $.session.turns()
    const current = await readHud($)
    const repo = await $.session.repo().catch(() => null)
    const rootDir = repo?.root ?? (await $.session.cwd())
    const wsCfg = await inspectWorkspaceConfig($, rootDir)
    const vibes = await inspectVibesAnnotations($, rootDir)

    // Verify if any deleted symbols still have unmigrated callers in the repository
    const remainingDeleted: string[] = []
    const unmigratedCallers: string[] = []
    for (const sym of current.deletedSymbols) {
      const grepRes = await $.process.run(['git', 'grep', '--untracked', '-nw', '-e', sym]).catch(() => undefined)
      const lines = (grepRes?.stdout ?? '').split('\n').filter(Boolean)
      const reDefined = lines.some((row) => {
        const m = /^(.+?):(\d+):(.*)$/.exec(row)
        return m ? extractSymbols(m[1] ?? '', (m[3] ?? '').trimStart()).includes(sym) : false
      })
      if (reDefined) continue
      const callRe = new RegExp(`(?<![\\w$])${sym.replace(/\$/g, '\\$')}\\s*\\(`)
      for (const row of lines) {
        const m = /^(.+?):(\d+):(.*)$/.exec(row)
        if (m && callRe.test(m[3] ?? '')) unmigratedCallers.push(`${m[1]}:${m[2]}`)
      }
      if (unmigratedCallers.length > 0) remainingDeleted.push(sym)
    }

    const updated = await update($, hudAtom, (s) => {
      const currentTotalCost = sessionUsage.cost?.usd ?? s.baselineCostUsd
      const turnDeltaCost = currentTotalCost >= s.baselineCostUsd ? currentTotalCost - s.baselineCostUsd : currentTotalCost
      return {
        ...s,
        baselineCostUsd: currentTotalCost,
        taskCostUsd: sessionUsage.cost?.usd ?? s.taskCostUsd + turnDeltaCost,
        turnCount: totalTurns,
        recentTurnCosts: [...s.recentTurnCosts, turnDeltaCost].slice(-16),
        tokenBuckets: turnUsage ? accumulateTokenBuckets(s.tokenBuckets, turnUsage) : s.tokenBuckets,
        activeDurationMs: s.activeDurationMs + evt.durationMs,
        deletedSymbols: remainingDeleted,
        unmigratedCallers,
        loadEnvelope: wsCfg.load || s.loadEnvelope,
        vibesMaxPrismRisk: vibes.maxRisk ?? s.vibesMaxPrismRisk,
        securityFindingsTotal: Math.max(s.securityFindingsTotal, vibes.findings),
        securityFindingsResolved: Math.max(s.securityFindingsResolved, vibes.resolved),
      }
    })

    await persistTelemetryAndDashboard($, updated).catch(() =>
      $.ui.status('neckbeard: failed to update local telemetry store')
    )
    return next(evt)
  }).catch(($, evt, next) => next(evt))

  on('ui.render', { component: 'AbovePrompt' }, async ($, evt, next) => {
    if (evt.props.hasSurvey || (await isHudHidden($))) return next(evt)
    const downstream = await next(evt).catch(() => undefined)
    const state = await readHud($)
    const reusePct = computeReusePercentage(state.reusedSymbols.length, state.createdSymbols.length)
    const latestTurnCost = state.recentTurnCosts[state.recentTurnCosts.length - 1]
    const avgTurnCost = state.turnCount > 0 ? state.taskCostUsd / state.turnCount : 0

    const switchLevel = async (lvl: string) => {
      const nextLvl = lvl.trim().toLowerCase() === 'ultra' ? 'paranoid' : lvl
      await update($, hudAtom, (s) => ({ ...s, activeLevel: nextLvl }))
      await $.command.run({ command: 'neckbeard:neckbeard', args: nextLvl })
    }
    const toggleDrawer = async () => {
      await update($, hudAtom, (s) => ({ ...s, expandedDrawer: !s.expandedDrawer }))
      await $.store.set('expandedDrawer', !state.expandedDrawer)
    }
    const triggerReview = () => $.command.run({ command: 'neckbeard:neckbeard-review', args: '' })
    const triggerAudit = () => $.command.run({ command: 'neckbeard:neckbeard-audit', args: '' })
    const openCommandCenter = () =>
      launchDashboardInBrowser($).catch(() => $.ui.toast('neckbeard: unable to launch dashboard.html'))
    const copyMarkdownSummary = async () => {
      const nowMs = await $.clock.now()
      const rec = serializeSessionRecord(await readHud($), nowMs)
      const copied = await $.ui.copy({ text: renderMarkdownReport(rec), surface: evt.surface })
      $.ui.toast(copied.isCopied ? 'NeckBeard telemetry report copied' : `Copy failed: ${copied.reason}`)
    }

    const { Box, Text, Button } = $.ui.resolve(evt)
    const termWidth = evt.surface === 'terminal' ? evt.props.bodyColumns : undefined
    const compose = (hudNode: NonNullable<typeof downstream>) =>
      downstream ? (
        <Box flexDirection="column">
          {hudNode}
          {downstream}
        </Box>
      ) : (
        hudNode
      )

    if (!state.expandedDrawer) {
      return compose(
        <Box flexDirection="row" alignItems="center" gap={2} width={termWidth}>
          <Button key="nb-lvl" plain onPress={toggleDrawer}>
            <Text color={state.activeLevel === 'off' ? 'inactive' : 'success'}>●</Text> 🧔 {state.activeLevel}
          </Button>
          <Text>${state.taskCostUsd.toFixed(2)}</Text>
          <Text dimColor>{formatDurationMs(state.activeDurationMs)}</Text>
          {reusePct !== null && <Text>{reusePct}% reuse</Text>}
          {(state.linesInserted > 0 || state.linesDeleted > 0) && (
            <Text dimColor>
              +{state.linesInserted}/-{state.linesDeleted} LOC
            </Text>
          )}
          {state.guardBlockCount > 0 && <Text color="success">🛡️ {state.guardBlockCount} blocked</Text>}
          {state.vibesMaxPrismRisk !== null && (
            <Text color={state.vibesMaxPrismRisk >= 0.6 ? 'warning' : 'success'}>
              PRISM {state.vibesMaxPrismRisk.toFixed(2)}
            </Text>
          )}
          {state.unreviewedBoundaries.length > 0 && (
            <Text color="warning">⚠ +{state.unreviewedBoundaries.length} boundary</Text>
          )}
          {state.unmigratedCallers.length > 0 && (
            <Text color="warning">⚠ {state.unmigratedCallers.length} callers</Text>
          )}
          <Box flexGrow={1} />
          <Button key="nb-rev" plain label="Review" onPress={triggerReview} />
          <Button key="nb-aud" plain label="Audit" onPress={triggerAudit} />
          <Button key="nb-cmd" plain label="Dashboard" onPress={openCommandCenter} />
          <Button key="nb-exp" plain label="HUD" onPress={toggleDrawer} />
        </Box>
      )
    }

    const cards: HudMetricCard[] = [
      {
        id: 'cost',
        heading: 'cost & turns',
        primaryValue: `$${state.taskCostUsd.toFixed(2)}`,
        secondaryNote:
          latestTurnCost === undefined ? `${state.turnCount} turns` : `last $${latestTurnCost.toFixed(2)} · ⌀ $${avgTurnCost.toFixed(2)}`,
      },
      {
        id: 'tokens',
        heading: 'tokens & time',
        primaryValue: formatTokenCount(sumTokenBuckets(state.tokenBuckets)),
        secondaryNote: formatDurationMs(state.activeDurationMs),
      },
      {
        id: 'shrink',
        heading: 'code minimalism',
        primaryValue: reusePct !== null ? `${reusePct}% reuse` : `+${state.linesInserted}/-${state.linesDeleted} LOC`,
        secondaryNote: `${state.reusedSymbols.length} reused · ${state.createdSymbols.length} new`,
      },
      {
        id: 'shield',
        heading: 'guard & vibes',
        primaryValue: `${state.guardBlockCount} blocked`,
        secondaryNote: `${state.securityFindingsResolved}/${state.securityFindingsTotal} fixed${
          state.vibesMaxPrismRisk !== null ? ` · PRISM ${state.vibesMaxPrismRisk.toFixed(2)}` : ''
        }`,
        statusTone: state.securityFindingsTotal > state.securityFindingsResolved ? 'warning' : 'success',
      },
    ]

    if (state.loadEnvelope) {
      cards.push({
        id: 'scale',
        heading: 'target load',
        primaryValue: state.loadEnvelope.slice(0, 18),
        secondaryNote: 'right-sized (.neckbeard.json)',
      })
    }
    if (state.unreviewedBoundaries.length > 0) {
      cards.push({
        id: 'drift',
        heading: 'boundary drift',
        primaryValue: `+${state.unreviewedBoundaries.length} new`,
        secondaryNote: state.unreviewedBoundaries.slice(0, 2).join(', '),
        statusTone: 'warning',
      })
    }
    if (state.testStatus.verdict !== 'untested') {
      cards.push({
        id: 'tests',
        heading: 'gate tests',
        primaryValue: formatTestStatusBadge(state.testStatus),
        secondaryNote: state.testStatus.verdict === 'passing' ? 'verified' : 'check required',
        statusTone: state.testStatus.verdict === 'passing' ? 'success' : 'error',
      })
    }

    let detailsNode = (
      <Box flexDirection="column">
        <Text dimColor wrap="truncate-end">
          {'─'.repeat(evt.props.bodyColumns)}
        </Text>
        <Box flexDirection="row" gap={2}>
          {cards.map((c) => (
            <Box
              key={c.id}
              flexDirection="column"
              {...(termWidth === undefined ? { flexGrow: 1 } : { width: Math.max(10, Math.floor(termWidth / cards.length) - 2) })}
            >
              <Text dimColor>{c.heading}</Text>
              <Text bold color={c.statusTone}>
                {c.primaryValue}
              </Text>
              <Text dimColor wrap="truncate-end">
                {c.secondaryNote}
              </Text>
            </Box>
          ))}
        </Box>
      </Box>
    )

    if (evt.surface === 'desktop') {
      const { Svg } = $.ui.resolve(evt)
      detailsNode = (
        <Svg
          source={renderDesktopHudSvg(cards)}
          alt={cards.map((c) => `${c.heading}: ${c.primaryValue}`).join(', ')}
        />
      )
    }

    return compose(
      <Box flexDirection="column" width={termWidth} gap={evt.surface === 'desktop' ? 1 : 0}>
        <Box flexDirection="row" alignItems="center" gap={1}>
          {SUPPORTED_LEVELS.map((lvl) => (
            <Button
              key={`nb-mode-${lvl}`}
              label={lvl}
              {...(lvl === state.activeLevel ? { variant: 'primary' as const } : { plain: true as const, dimColor: true })}
              onPress={() => switchLevel(lvl)}
            />
          ))}
          <Box flexGrow={1} />
          <Button key="nb-copy" plain label="Copy Report" onPress={copyMarkdownSummary} />
          <Button key="nb-rev" plain label="Review" onPress={triggerReview} />
          <Button key="nb-aud" plain label="Audit" onPress={triggerAudit} />
          <Button key="nb-dash" plain label="Dashboard" onPress={openCommandCenter} />
          <Button key="nb-fold" plain label="Compact" onPress={toggleDrawer} />
        </Box>
        {detailsNode}
      </Box>
    )
  }).catch(($, evt, next) => next(evt))
}
