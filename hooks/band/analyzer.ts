// NeckBeard original code-diff, symbol-reuse, boundary-drift, and gate telemetry analyzer.
// Pure functions with zero runtime dependencies.

import type { GateTestStatus, NeckbeardHudState, TelemetrySessionRecord, TokenBuckets } from './types'

export const EMPTY_TOKEN_BUCKETS: TokenBuckets = {
  promptTokens: 0,
  completionTokens: 0,
  cachedReadTokens: 0,
  cachedWriteTokens: 0,
}

export const SYMBOL_GREP_REGEX = '^[[:space:]]*(export|async|def|class|function|func|pub|fn)[[:space:]]'

const IGNORED_PATH_SEGMENTS = /(^|\/)(node_modules|\.git|dist|build|out|vendor|venv|\.venv|__pycache__|coverage|\.next|target|migrations|fixtures|tests?|__tests__|spec)(\/|$)/
const NON_PROD_FILENAME = /(^|\/)(test_[^/]*|[^/]*(_test|\.test|\.spec|\.gen|\.min|\.d)\.[a-z]+)$/

const COMMON_BOILERPLATE_NAMES = new Set([
  'main', 'init', 'run', 'get', 'set', 'test', 'setup', 'open', 'close',
  'read', 'write', 'start', 'stop', 'load', 'save', 'update', 'create',
  'delete', 'handle', 'render', 'index', 'new', 'call', 'apply',
])

const LANGUAGE_SYMBOL_PATTERNS: Array<{ matchExt: RegExp; extractors: RegExp[] }> = [
  {
    matchExt: /\.py$/,
    extractors: [/^(?:async\s+)?def\s+([A-Za-z]\w*)/gm, /^class\s+([A-Za-z]\w*)/gm],
  },
  {
    matchExt: /\.[cm]?[jt]sx?$/,
    extractors: [
      /^export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)/gm,
      /^(?:async\s+)?function\*?\s+([A-Za-z_$][\w$]*)/gm,
    ],
  },
  {
    matchExt: /\.go$/,
    extractors: [/^func\s+(?:\([^)]*\)\s*)?([A-Za-z]\w*)/gm],
  },
  {
    matchExt: /\.rs$/,
    extractors: [/^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)/gm],
  },
  {
    matchExt: /\.rb$/,
    extractors: [/^\s*def\s+(?:self\.)?([A-Za-z]\w*[?!]?)/gm],
  },
]

const TRUST_SINK_DETECTORS: Array<{ sinkTag: string; pattern: RegExp }> = [
  {
    sinkTag: 'http-in',
    pattern: /\b(?:app|router|server|api|hono|fastify)\.(?:get|post|put|patch|delete|all|use|route)\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\bhttp\.HandleFunc\b|\bipcMain\.(?:handle|on)\s*\(|#\[tauri::command\]|\b(?:axum::Router|actix_web|HttpServer::new|warp::Filter|tonic::transport::Server|FastAPI\s*\(|APIRouter\s*\(|gin\.(?:Default|New)|chi\.NewRouter|echo\.New|fiber\.New|WebSocketServer)\b/,
  },
  {
    sinkTag: 'cli-in',
    pattern: /\b(?:process\.argv|process\.stdin|readInput\s*\(|parseArgs\s*\(|commander\b|yargs\b|argparse\b|sys\.argv\b|click\.(?:command|group)|typer\.Typer|clap::|#\[derive\([^)]*(?:Parser|Subcommand|Args)\b|#\[command\(|std::env::args|env::args(?:_os)?\s*\(|os\.Args\b|flag\.Parse|cobra\.Command)\b/,
  },
  {
    sinkTag: 'webhook-in',
    pattern: /\b(?:webhook|stripe\.webhooks|verifyWebhook|svix|consumer\.(?:run|subscribe)|on_message\b|kafka|rdkafka|amqp|sqs|pubsub)\b/i,
  },
  {
    sinkTag: 'http-out',
    pattern: /\b(?:fetch\s*\(|axios\.(?:get|post|put|delete|request)\s*\(|https?\.request\s*\(|reqwest::|ureq::|hyper::Client|requests\.(?:get|post|put|delete|request)\s*\(|httpx\.|aiohttp\.ClientSession|urllib\.request\.urlopen|http\.(?:Get|Post|NewRequest)\s*\(|URLSession\.shared)\b/,
  },
  {
    sinkTag: 'auth',
    pattern: /\b(?:jwt|jsonwebtoken|jose|bcrypt|argon2|scrypt|pbkdf2|passport|set-cookie|setCookie|req\.headers\.authorization|Bearer\s+|oauth2?|oidc|saml|csrf|verifyToken|verify_token|authenticate|authorize|requireAuth|require_auth|checkPermission|hasPermission|api[_-]?key|ed25519_dalek|VerifyingKey|SigningKey|cosign|dsse|timingSafeEqual)\b/i,
  },
  {
    sinkTag: 'sql',
    pattern: /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE)\b|\b(?:rusqlite|sqlx::|diesel::|sea_orm|better-sqlite3|sqlite3|prisma\.|drizzle|knex|sequelize|sqlalchemy|cursor\.execute|Connection::open)\b/i,
  },
  {
    sinkTag: 'fs',
    pattern: /\b(?:(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rm|cp|mkdir|readdir|realpath)(?:Sync)?\s*\(|std::fs::|tokio::fs::|fs::(?:read_to_string|read|write|OpenOptions|create_dir|remove_file|remove_dir|copy|rename)|File::(?:open|create)|NamedTempFile|shutil\.(?:copy|rmtree|move)|os\.(?:ReadFile|WriteFile|OpenFile|Create|RemoveAll))\b/,
  },
  {
    sinkTag: 'serde',
    pattern: /\b(?:JSON\.parse\s*\(|serde_json::(?:from_str|from_slice|from_reader|from_value)|toml::from_str|serde_yaml::from_|bincode::deserialize|yaml\.(?:load|safe_load)|pickle\.loads?|marshal\.loads|ObjectInputStream|unserialize\s*\(|XMLParser|DOMParser|xml2js|prost::Message)\b/,
  },
  {
    sinkTag: 'proc',
    pattern: /\b(?:child_process|exec(?:File)?Sync\s*\(|spawn(?:Sync)?\s*\(|execFile\s*\(|std::process::Command|tokio::process::Command|Command::new\s*\(|subprocess\.(?:run|Popen|call|check_output)|os\.system\s*\(|os\.popen\s*\(|exec\.Command\s*\(|\beval\s*\(|new Function\s*\()\b/,
  },
  {
    sinkTag: 'crypto',
    pattern: /\b(?:createHash|createHmac|createCipher(?:iv)?|createDecipher(?:iv)?|crypto\.subtle|crypto\.(?:sign|verify|randomBytes)|sha2::|Sha256|Sha512|ed25519_dalek|hmac::|ring::|aes_gcm|chacha20poly1305|rustls|hashlib\.|hmac\.new|crypto\/(?:sha256|ed25519|hmac|tls|aes))\b/,
  },
  {
    sinkTag: 'env',
    pattern: /\b(?:process\.env(?:\.[A-Za-z0-9_]+|\[)|os\.environ\b|os\.getenv\s*\(|std::env::(?:var|var_os|vars)|env::(?:var|var_os)\s*\(|os\.Getenv\s*\(|dotenv)\b/,
  },
  {
    sinkTag: 'ai',
    pattern: /\b(?:anthropic|openai|gemini|messages\.create\s*\(|chat\.completions|tool_use|function_call|McpServer|mcp_schemas|langchain|additionalContext|hookSpecificOutput|embedder|candle_)\b/i,
  },
]

export function isTrackedCodeFile(filePath: string): boolean {
  return LANGUAGE_SYMBOL_PATTERNS.some((entry) => entry.matchExt.test(filePath))
}

export function isProductionSourceFile(filePath: string): boolean {
  return isTrackedCodeFile(filePath) && !IGNORED_PATH_SEGMENTS.test(filePath) && !NON_PROD_FILENAME.test(filePath)
}

export function isWithinWorkspace(filePath: string, workspaceRoot: string): boolean {
  const normFile = filePath.replace(/\\/g, '/')
  const normRoot = workspaceRoot.replace(/\\/g, '/').replace(/\/+$/, '')
  return normFile === normRoot || normFile.startsWith(`${normRoot}/`)
}

export function toWorkspaceRelativePath(filePath: string, workspaceRoot: string): string {
  const normFile = filePath.replace(/\\/g, '/')
  const normRoot = workspaceRoot.replace(/\\/g, '/').replace(/\/+$/, '')
  return normFile.startsWith(`${normRoot}/`) ? normFile.slice(normRoot.length + 1) : normFile
}

export function extractSymbols(filePath: string, sourceText: string): string[] {
  const rule = LANGUAGE_SYMBOL_PATTERNS.find((entry) => entry.matchExt.test(filePath))
  if (!rule) return []
  const found = new Set<string>()
  for (const regex of rule.extractors) {
    for (const match of sourceText.matchAll(regex)) {
      if (match[1]) found.add(match[1])
    }
  }
  return [...found]
}

export function indexWorkspaceSymbols(grepStdout: string): Map<string, string> {
  const symbolIndex = new Map<string, string>()
  for (const rawLine of grepStdout.split('\n')) {
    const match = /^(.+?):(\d+):(.*)$/.exec(rawLine)
    if (!match) continue
    const file = match[1] ?? ''
    const lineNo = match[2] ?? ''
    const codeLine = match[3] ?? ''
    if (!isProductionSourceFile(file)) continue
    for (const sym of extractSymbols(file, codeLine.trimStart())) {
      if (!symbolIndex.has(sym)) symbolIndex.set(sym, `${file}:${lineNo}`)
    }
  }
  return symbolIndex
}

export function detectBoundarySinks(relativeFilePath: string, sourceText: string): string[] {
  if (!relativeFilePath || IGNORED_PATH_SEGMENTS.test(relativeFilePath) || NON_PROD_FILENAME.test(relativeFilePath)) {
    return []
  }
  if (/^\.github\/workflows\/.+\.(?:yml|yaml)$/.test(relativeFilePath)) {
    return [`${relativeFilePath}->ci`]
  }
  const detected: string[] = []
  for (const detector of TRUST_SINK_DETECTORS) {
    if (detector.pattern.test(sourceText)) {
      detected.push(`${relativeFilePath}->${detector.sinkTag}`)
    }
  }
  return detected
}

export function measureDiffImpact(
  filePath: string,
  beforeText: string,
  afterText: string,
  workspaceSymbols: Map<string, string>
): {
  reusedSymbols: string[]
  createdSymbols: string[]
  deletedSymbols: string[]
  linesInserted: number
  linesDeleted: number
} {
  const prevSymbols = extractSymbols(filePath, beforeText)
  const nextSymbols = extractSymbols(filePath, afterText)
  const prod = isProductionSourceFile(filePath)
  const createdSymbols = prod ? nextSymbols.filter((s) => !prevSymbols.includes(s)) : []
  const deletedSymbols = prevSymbols.filter((s) => !nextSymbols.includes(s))

  const beforeLines = beforeText === '' ? [] : beforeText.split('\n')
  const afterLines = afterText === '' ? [] : afterText.split('\n')
  const beforeSet = new Set(beforeLines)
  const afterSet = new Set(afterLines)

  const insertedLines = afterLines.filter((l) => l.trim() !== '' && !beforeSet.has(l))
  const removedLines = beforeLines.filter((l) => l.trim() !== '' && !afterSet.has(l))

  const reusedSet = new Set<string>()
  if (prod) {
    const addedBlock = insertedLines.join('\n')
    for (const match of addedBlock.matchAll(/(?<![\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
      const candidate = match[1] ?? ''
      if (
        workspaceSymbols.has(candidate) &&
        !nextSymbols.includes(candidate) &&
        !COMMON_BOILERPLATE_NAMES.has(candidate.toLowerCase())
      ) {
        reusedSet.add(candidate)
      }
    }
  }

  return {
    reusedSymbols: [...reusedSet],
    createdSymbols,
    deletedSymbols,
    linesInserted: insertedLines.length,
    linesDeleted: removedLines.length,
  }
}

export function computeReusePercentage(reusedCount: number, createdCount: number): number | null {
  const total = reusedCount + createdCount
  if (total < 3) return null
  return Math.round((reusedCount / total) * 100)
}

const TEST_RUNNER_COMMAND_PATTERN =
  /\b(npm (run )?test|pnpm (run )?test|yarn test|bun test|npx (jest|vitest)|jest|vitest|pytest|python3? -m pytest|go test|cargo test|mvn test|gradle test|rspec|phpunit|dotnet test|node --test|deno test|make test)\b/

export function isTestRunnerCommand(commandLine: string): boolean {
  return TEST_RUNNER_COMMAND_PATTERN.test(commandLine)
}

export function evaluateTestOutput(stdout: string, hasError: boolean): GateTestStatus {
  const extractCount = (pattern: RegExp): number | undefined => {
    const m = pattern.exec(stdout)
    return m ? Number(m[1]) : undefined
  }
  return {
    verdict: hasError ? 'failing' : 'passing',
    passCount: extractCount(/(\d+) (?:passed|passing)\b/) ?? extractCount(/(?:ℹ |# )pass (\d+)/),
    failCount: extractCount(/(\d+) (?:failed|failing)\b/) ?? extractCount(/(?:ℹ |# )fail (\d+)/),
  }
}

export function formatTestStatusBadge(status: GateTestStatus): string {
  if (status.verdict === 'passing') return `${status.passCount ?? ''} passed`.trim()
  if (status.verdict === 'failing') return `${status.failCount ?? ''} failed`.trim()
  if (status.verdict === 'outdated') return 'stale since edit'
  return 'untested'
}

export function accumulateTokenBuckets(
  current: TokenBuckets,
  delta: {
    input_tokens: number
    output_tokens: number
    cache_read_input_tokens: number
    cache_creation_input_tokens: number
  }
): TokenBuckets {
  return {
    promptTokens: current.promptTokens + (delta.input_tokens || 0),
    completionTokens: current.completionTokens + (delta.output_tokens || 0),
    cachedReadTokens: current.cachedReadTokens + (delta.cache_read_input_tokens || 0),
    cachedWriteTokens: current.cachedWriteTokens + (delta.cache_creation_input_tokens || 0),
  }
}

export function sumTokenBuckets(buckets: TokenBuckets): number {
  return buckets.promptTokens + buckets.completionTokens + buckets.cachedReadTokens + buckets.cachedWriteTokens
}

export function formatTokenCount(count: number): string {
  if (count < 1000) return `${Math.round(count)}`
  if (count < 1e6) return `${+(count / 1e3).toFixed(1)}k`
  return `${+(count / 1e6).toFixed(1)}M`
}

export function formatDurationMs(ms: number): string {
  const totalSec = Math.max(0, Math.round(ms / 1000))
  if (totalSec < 60) return `${totalSec}s`
  const totalMin = Math.floor(totalSec / 60)
  const remSec = totalSec % 60
  if (totalMin < 60) return remSec > 0 ? `${totalMin}m ${remSec}s` : `${totalMin}m`
  const hours = Math.floor(totalMin / 60)
  const remMin = totalMin % 60
  return `${hours}h ${remMin}m`
}

export function formatTimestampIso(epochMs: number): string {
  const d = new Date(epochMs)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function buildRecordId(sessionId: string, startedAtMs: number): string {
  return `${String(sessionId || 'nb').slice(0, 8)}-${startedAtMs}`
}

export function serializeSessionRecord(state: NeckbeardHudState, startedAtMs: number): TelemetrySessionRecord {
  return {
    recordId: buildRecordId(state.sessionId, startedAtMs),
    timestampIso: formatTimestampIso(startedAtMs),
    startedAtMs,
    projectName: state.projectName,
    taskTitle: state.taskTitle || 'Interactive session',
    sessionId: state.sessionId,
    activeLevel: state.activeLevel,
    modelId: state.modelId,
    totalCostUsd: +state.taskCostUsd.toFixed(4),
    latestTurnCostUsd: state.recentTurnCosts[state.recentTurnCosts.length - 1] ?? null,
    turnCount: state.turnCount,
    activeDurationMs: state.activeDurationMs,
    tokenBuckets: state.tokenBuckets,
    reusePercent: computeReusePercentage(state.reusedSymbols.length, state.createdSymbols.length),
    reusedSymbolCount: state.reusedSymbols.length,
    newSymbolCount: state.createdSymbols.length,
    linesInserted: state.linesInserted,
    linesDeleted: state.linesDeleted,
    unmigratedCallerCount: state.unmigratedCallers.length,
    boundaryDriftCount: state.unreviewedBoundaries.length,
    guardBlockCount: state.guardBlockCount,
    securityFindingsTotal: state.securityFindingsTotal,
    securityFindingsResolved: state.securityFindingsResolved,
    vibesMaxPrismRisk: state.vibesMaxPrismRisk,
    loadEnvelope: state.loadEnvelope,
    testStatusLabel: formatTestStatusBadge(state.testStatus),
  }
}

export function extractPromptTaskTitle(rawPrompt: string): string {
  const clean = String(rawPrompt || '').trim()
  if (!clean) return 'Interactive session'
  const pbMatch = /Process tasks from this document:\s+([^\s\n]+)/i.exec(clean)
  if (pbMatch && pbMatch[1]) {
    const base = pbMatch[1].replace(/\\/g, '/').split('/').pop()?.replace(/\.md$/i, '') ?? ''
    if (base) return `Playbook: ${base}`.slice(0, 64)
  }
  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim()
    if (!line || /^---+$/.test(line)) continue
    if (/^#{1,6}\s*(?:Context|Instructions|Overview|Task|Tasks|Prior Conversation|Your Role|Rules|Guidelines)\b/i.test(line)) continue
    if (/^(?:Your name is\b|-\s*\*\*(?:Agent Path|Project|Playbook|Mode):)/i.test(line)) continue
    return line.replace(/^#{1,6}\s+/, '').slice(0, 64)
  }
  return (clean.split('\n')[0] ?? 'Interactive session').slice(0, 64)
}

export function upsertJsonlLedger(existingJsonl: string, record: TelemetrySessionRecord): string {
  const keptLines = existingJsonl
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => {
      if (!l.startsWith('{')) return false
      try {
        const parsed = JSON.parse(l) as { recordId?: string; sessionId?: string }
        if (parsed.recordId === record.recordId) return false
        if (record.sessionId && parsed.sessionId === record.sessionId) return false
        return true
      } catch {
        return false
      }
    })
  keptLines.push(JSON.stringify(record))
  return keptLines.join('\n') + '\n'
}

export type HudMetricCard = {
  id: string
  heading: string
  primaryValue: string
  secondaryNote: string
  statusTone?: 'warning' | 'success' | 'error'
}

export function renderDesktopHudSvg(cards: HudMetricCard[], widthPx = 760): string {
  const heightPx = 66
  const slotWidth = widthPx / Math.max(1, cards.length)
  const escapeXml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const clipText = (s: string, maxChars: number) => (s.length > maxChars ? `${s.slice(0, Math.max(1, maxChars - 1))}…` : s)

  const css =
    '.h{fill:#7d8b82;font:600 11px ui-monospace,Menlo,monospace;letter-spacing:.05em;text-transform:uppercase}' +
    '.p{fill:#eef2ef;font:700 15px ui-monospace,Menlo,monospace}' +
    '.n{fill:#68776e;font:11.5px -apple-system,BlinkMacSystemFont,sans-serif}' +
    '.sep{stroke:#22c55e;stroke-opacity:.22}' +
    '.warning{fill:#f59e0b}.success{fill:#22c55e}.error{fill:#ef4444}'

  let elements = `<rect width="${widthPx}" height="${heightPx}" rx="8" fill="#090d0b" stroke="#22c55e" stroke-opacity="0.28"/>`
  cards.forEach((card, idx) => {
    const xOffset = idx * slotWidth + 14
    const toneClass = card.statusTone ? ` ${card.statusTone}` : ''
    if (idx > 0) {
      elements += `<line class="sep" x1="${idx * slotWidth}" y1="10" x2="${idx * slotWidth}" y2="${heightPx - 10}"/>`
    }
    elements += `<text class="h" x="${xOffset}" y="21">${escapeXml(card.heading)}</text>`
    elements += `<text class="p${toneClass}" x="${xOffset}" y="42">${escapeXml(clipText(card.primaryValue, Math.floor((slotWidth - 20) / 8.5)))}</text>`
    if (card.secondaryNote) {
      elements += `<text class="n" x="${xOffset}" y="58">${escapeXml(clipText(card.secondaryNote, Math.floor((slotWidth - 20) / 6)))}</text>`
    }
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${widthPx}" height="${heightPx}" viewBox="0 0 ${widthPx} ${heightPx}"><style>${css}</style>${elements}</svg>`
}

export function renderMarkdownReport(rec: TelemetrySessionRecord): string {
  const tb = rec.tokenBuckets
  const netLoc = rec.linesInserted - rec.linesDeleted
  const lines = [
    `## NeckBeard Gate & Telemetry Report — ${rec.taskTitle}`,
    '',
    '| Metric | Value |',
    '| :--- | :--- |',
    `| **Project & Level** | \`${rec.projectName}\` · level \`${rec.activeLevel}\` · model \`${rec.modelId || 'default'}\` |`,
    `| **Target Load Envelope** | ${rec.loadEnvelope || 'unset (\`/neckbeard load <params>\`)'} |`,
    `| **Code Shrinkage & Reuse** | ${rec.reusePercent === null ? '–' : `${rec.reusePercent}% symbol reuse`} (${rec.reusedSymbolCount} reused, ${rec.newSymbolCount} new) · \`+${rec.linesInserted} / -${rec.linesDeleted}\` lines (net \`${netLoc > 0 ? `+${netLoc}` : netLoc}\` LOC) |`,
    `| **Security & PreToolUse Guard** | \`${rec.guardBlockCount}\` blocked tool calls · \`${rec.securityFindingsResolved}/${rec.securityFindingsTotal}\` findings resolved${rec.vibesMaxPrismRisk === null ? '' : ` · VIBES PRISM max risk \`${rec.vibesMaxPrismRisk.toFixed(2)}\``} |`,
    `| **Boundary & Caller Integrity** | \`${rec.boundaryDriftCount}\` unreviewed boundary drift · \`${rec.unmigratedCallerCount}\` open callers · tests: \`${rec.testStatusLabel}\` |`,
    `| **Tokens, Cost & Active Time** | \`${formatTokenCount(sumTokenBuckets(tb))}\` tokens (\`$${rec.totalCostUsd.toFixed(2)}\`) across \`${rec.turnCount}\` turns in \`${formatDurationMs(rec.activeDurationMs)}\` |`,
  ]
  return lines.join('\n')
}
