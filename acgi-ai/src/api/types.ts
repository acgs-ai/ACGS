// API contract types for the ACGS console.
//
// Shapes are hand-written to match FastAPI Pydantic models in the upstream
// monorepo at /home/martin/Downloads/govern-zone/ACGS. When the bus and
// gateway expose stable list endpoints and we add an OpenAPI codegen step
// (openapi-typescript or hey-api), this file is the migration target.
//
// Until then, treat every type below as load-bearing — every console hook
// depends on these shapes lining up with what the MSW handlers return today
// and what the FastAPI services will return tomorrow.

export type MaciLane = 'Proposer' | 'Validator' | 'Executor' | 'Custodian'

export type Posture = 'confirmed' | 'partial' | 'blocked' | 'privileged'

export type Agent = {
  id: string
  name: string
  role: string
  lane: MaciLane
  model: string
  refusals24h: number
  health: Posture
  lastSeen: string
}

export type HealthSummary = {
  constitutionHash: string
  agentsOnline: number
  agentsTotal: number
  driftBytes: number
  uptimeSeconds: number
  auditAnchorSeconds: number
}

export type BadgeAttestation = {
  agentId: string
  constitutionHash: string
  issuedAt: string
  signature: string
  pqcMode: 'enforced' | 'permissive' | 'off'
}

export type ConsoleSummaryEvent = {
  id: string
  body: string
  ts: string
}

export type ConsoleSummaryCoverage = {
  label: string
  posture: Extract<Posture, 'confirmed' | 'partial'>
  value: string
}

export type ConsoleSummary = {
  constitutionHash: string
  agentsOnline: number
  agentsTotal: number
  checks: number
  runtimeLabel: string
  driftBytes: number
  auditAnchorSeconds: number
  nextRefreshSeconds: number
  medianLatencyMs: number
  refusals24h: number
  humanReview: number
  appeals: number
  retryBackoff: number
  recentEvents: ConsoleSummaryEvent[]
  coverage: ConsoleSummaryCoverage[]
}

export type ActionReceipt = {
  title: string
  body: string
  meta: string
}

// ─── Overview ─────────────────────────────────────────────────────────────

export type OverviewStat = { label: string; value: string; sub: string }

export type ActiveCase = {
  name: string
  stage: string
  lane: string
  age: string
  evidence: string
  event: string
  posture: Posture
}

export type QueueStat = {
  label: string
  value: string
  detail: string
  posture: Posture
}

export type RefusalByArticle = {
  article: string
  citation: string
  refusals: number
  trend: string
  posture: Posture
}

export type OverviewSummary = {
  stats: OverviewStat[]
  activeCases: ActiveCase[]
  queues: QueueStat[]
  refusalsByArticle: RefusalByArticle[]
}

// ─── MACI ─────────────────────────────────────────────────────────────────

export type MaciCard = {
  id: string
  title: string
  body: string
  agent: string
  ts: string
  posture: Posture
}

export type MaciLanes = {
  proposer: MaciCard[]
  validator: MaciCard[]
  executor: MaciCard[]
}

// ─── Deliberations ────────────────────────────────────────────────────────

export type Deliberation = {
  id: string
  matter: string
  title: string
  /** Single word from `title` rendered in italic-rust (DESIGN.md §2.2). */
  emphasis: string
  citation: string
  body: string
  opened: string
  due: string
  posture: Posture
}

// ─── Incidents ────────────────────────────────────────────────────────────

export type Incident = {
  id: string
  ts: string
  posture: Posture
  title: string
  /** Single word from `title` rendered in italic-rust (DESIGN.md §2.2). */
  emphasis: string
  src: string
  body: string
  hash: string
}

// ─── Policies ─────────────────────────────────────────────────────────────

export type PolicyRule = {
  id: string
  name: string
  citation: string
  posture: Posture
  prose: string
}

// ─── Compile ──────────────────────────────────────────────────────────────

export type PolicyChangeKind = 'added' | 'amended' | 'removed'

export type PolicyChange = {
  id: string
  name: string
  citation: string
  change: PolicyChangeKind
  note: string
}

export type CompileDraft = {
  currentHash: string
  proposedHash: string
  changes: PolicyChange[]
}

export type CompileActionRequest = {
  currentHash: string
  proposedHash: string
}

// ─── Audit ────────────────────────────────────────────────────────────────

export type AuditEvent = {
  ts: string
  posture: Posture
  ev: string
  src: string
  hash: string
  matter?: string
}

// ─── Settings ─────────────────────────────────────────────────────────────

export type SettingSource = 'constitution' | 'operator' | 'default'

export type Setting = {
  key: string
  desc: string
  value: string
  source: SettingSource
}

export type SettingSection = {
  title: string
  settings: Setting[]
}

// ─── Tenants ──────────────────────────────────────────────────────────────

export type TenantTier = 'Examined' | 'Governed' | 'Custodial'

export type TenantState = 'active' | 'standby' | 'sealed'

export type Tenant = {
  id: string
  name: string
  tier: TenantTier
  agents: number
  matters: number
  refusals24h: number
  state: TenantState
  lastActivity: string
  jurisdiction: string
}

// ─── Account ──────────────────────────────────────────────────────────────

export type IdentitySource = 'sso' | 'self' | 'constitution'

export type IdentityField = {
  key: string
  value: string
  source: IdentitySource
}

export type Session = {
  id: string
  device: string
  ip: string
  location: string
  started: string
  current: boolean
}

export type AccountAction = {
  ts: string
  posture: Posture
  action: string
  cite: string
}

export type AccountView = {
  identity: IdentityField[]
  sessions: Session[]
  recentActions: AccountAction[]
}
