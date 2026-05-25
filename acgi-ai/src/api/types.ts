// API contract types for the ACGS console.
//
// `/api/v1` shapes are hand-written to match FastAPI Pydantic models in
// the upstream monorepo at /home/martin/Downloads/govern-zone/ACGS. The
// `/api/bus/*` shapes are generated from `contracts/bus.openapi.json` into
// `src/api/bus.generated.ts` and aliased below.
//
// Treat every type below as load-bearing: every console hook depends on these
// shapes lining up with what the MSW handlers return locally and what the
// deployed services return through the same-origin proxy.

import type { components as BusApiComponents } from './bus.generated'

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

export type DecisionOutcome = 'allowed' | 'denied' | 'transformed' | 'escalated'

export type GovernanceCheck = {
  id: string
  label: string
  posture: Posture
  reason: string
}

export type GovernedAction = {
  id: string
  agent: string
  action: string
  target: string
  attemptedAt: string
  outcome: DecisionOutcome
  plainReason: string
  receiptId: string
  receiptHash: string
  traceId: string
  replayCommand: string
  auditEventId: string
  checks: GovernanceCheck[]
  before: string
  after: string
}

export type EvidenceSignatureSummary = {
  status: 'signed' | 'unsigned-local-digest' | 'missing' | 'malformed'
  label: string
  algorithm: string
  keyId?: string
  digest?: string
  reason?: string
}

export type ReceiptProofPacket = {
  receiptId: string
  receiptHash: string
  traceId: string
  phoenixTraceId?: string
  phoenixSpanId?: string
  phoenixParentSpanId?: string
  replayCommand: string
  auditEventId: string
  signedEvidencePacket: string
  evidenceSignature: EvidenceSignatureSummary
  hashChainVerified: boolean
  policyPath: string
  toolExecuted: boolean
  action: GovernedAction
}

export type ActionTestRequest = {
  actionId: string
  payload: string
}

export type ActionTestReceipt = ActionReceipt

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

export type EvaluationEvidenceStatus = 'passed' | 'failed'
export type EvaluationEvidenceSource = 'gove-zone' | 'agentdojo' | 'injecagent' | 'toolemu'

export type EvaluationEvidenceApi = {
  source: EvaluationEvidenceSource
  dataset: string
  status: EvaluationEvidenceStatus
  report_hash: string
  policy_version: string
  scenario_count: number
  passed: number
  failed: number
  attack_success_rate: number | null
  utility_retention_rate: number | null
  p95_latency_ms: number | null
  event_id?: string | null
  tenant?: string | null
  allow?: boolean
  previous_hash?: string | null
  event_hash?: string | null
  claim_safe?: boolean
  ingested_at?: string
}

export type EvaluationEvidence = {
  source: EvaluationEvidenceSource
  dataset: string
  status: EvaluationEvidenceStatus
  reportHash: string
  policyVersion: string
  scenarioCount: number
  passed: number
  failed: number
  attackSuccessRate: number | null
  utilityRetentionRate: number | null
  p95LatencyMs: number | null
  eventId?: string | null
  tenant?: string | null
  allow?: boolean
  previousHash?: string | null
  eventHash?: string | null
  claimSafe?: boolean
  ingestedAt?: string
}

export type AuditEvent = {
  ts: string
  posture: Posture
  ev: string
  src: string
  hash: string
  matter?: string
  evaluationEvidence?: EvaluationEvidence
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

export type OperatorRole = 'custodian' | 'validator' | 'proposer' | 'executor' | 'observer'

export type OperatorSession = {
  operatorId: string
  tenantId: string
  email: string
  roles: OperatorRole[]
  permittedLanes: MaciLane[]
  expiresAt: string
}

// ─── Bus traces ───────────────────────────────────────────────────────────
//
// Snake_case mirrors the analyzer OpenAPI contract literally. Only the
// /api/bus/* surface is generated; /api/v1 console contracts stay hand-written.

type BusSchemas = BusApiComponents['schemas']
type BusEventSchema = Required<BusSchemas['Event']>
type BusTraceListSchema = Required<BusSchemas['TraceList']>
type BusSingleTraceSchema = Required<BusSchemas['SingleTrace']>
type BusReceiptProofSchema = Required<BusSchemas['ReceiptProof']>

export type BusEventStatus = BusEventSchema['status']
export type BusIntegrityStatus = BusSchemas['TraceListItem']['integrity_status']
export type BusEventKind = BusEventSchema['kind']
export type BusDecisionVerdict = NonNullable<BusEventSchema['decision']>
export type BusTraceEvent = BusEventSchema
export type BusTraceListItem = BusSchemas['TraceListItem']
export type BusTraceList = Omit<BusTraceListSchema, 'items'> & {
  items: BusTraceListItem[]
}
export type BusSingleTrace = Omit<BusSingleTraceSchema, 'events'> & {
  events: BusTraceEvent[]
}
export type BusReceiptProof = Omit<
  BusReceiptProofSchema,
  'events' | 'policy_path' | 'flagged_rules'
> & {
  events: BusTraceEvent[]
  policy_path: string[]
  flagged_rules: string[]
}

export type BusExpired = {
  kind: 'expired'
  correlation_id: string
  retention_policy: {
    max_age_days: number
    purged_at: string
  }
}
