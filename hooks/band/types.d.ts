export type GateTestStatus = {
  verdict: 'untested' | 'passing' | 'failing' | 'outdated'
  passCount?: number
  failCount?: number
}

export type TokenBuckets = {
  promptTokens: number
  completionTokens: number
  cachedReadTokens: number
  cachedWriteTokens: number
}

export type TelemetrySessionRecord = {
  recordId: string
  timestampIso: string
  startedAtMs: number
  projectName: string
  taskTitle: string
  sessionId: string
  activeLevel: string
  modelId: string
  totalCostUsd: number
  latestTurnCostUsd: number | null
  turnCount: number
  activeDurationMs: number
  tokenBuckets: TokenBuckets
  reusePercent: number | null
  reusedSymbolCount: number
  newSymbolCount: number
  linesInserted: number
  linesDeleted: number
  unmigratedCallerCount: number
  boundaryDriftCount: number
  guardBlockCount: number
  securityFindingsTotal: number
  securityFindingsResolved: number
  vibesMaxPrismRisk: number | null
  loadEnvelope: string
  testStatusLabel: string
}

export type NeckbeardHudState = {
  activeLevel: string
  modelId: string
  baselineCostUsd: number
  taskCostUsd: number
  turnCount: number
  recentTurnCosts: number[]
  tokenBuckets: TokenBuckets
  activeDurationMs: number
  taskTitle: string
  projectName: string
  sessionId: string
  transcriptPath: string
  reusedSymbols: string[]
  createdSymbols: string[]
  deletedSymbols: string[]
  linesInserted: number
  linesDeleted: number
  unmigratedCallers: string[]
  unreviewedBoundaries: string[]
  guardBlockCount: number
  securityFindingsTotal: number
  securityFindingsResolved: number
  vibesMaxPrismRisk: number | null
  loadEnvelope: string
  testStatus: GateTestStatus
  expandedDrawer: boolean
}

declare module 'claude-code' {
  interface PluginState {
    neckbeard: { hud: NeckbeardHudState }
  }
}
