// Single fetch wrapper for the ACGS console.
//
// Path strategy: every call is relative — `/api/v1/<resource>`. In dev,
// Vite either intercepts via MSW (when VITE_USE_MOCKS=true) or proxies to
// VITE_API_PROXY_TARGET (see vite.config.ts). In prod, Caddy on
// console.acgs.ai reverse-proxies the same prefix to the API gateway.
// The browser never sees an absolute API origin — that keeps the privilege
// boundary visible at the network layer (DEPLOY.md §3, §7).

import type {
  AccountView,
  ActionReceipt,
  ActionTestReceipt,
  ActionTestRequest,
  Agent,
  AuditEvent,
  BusDefectList,
  BusExpired,
  BusReceiptProof,
  BusSingleTrace,
  BusTraceList,
  CompileActionRequest,
  CompileDraft,
  ConsoleSummary,
  Deliberation,
  EvaluationEvidence,
  EvaluationEvidenceApi,
  EvaluationEvidenceStatus,
  GovernedAction,
  Incident,
  MaciLanes,
  OverviewSummary,
  PolicyRule,
  ProcessComplianceReport,
  ProcessDetail,
  ProcessList,
  ProcessVariantList,
  ReceiptProofPacket,
  SettingSection,
  Tenant,
} from './types'

export class ApiError extends Error {
  status: number
  url: string

  constructor(status: number, url: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.url = url
  }
}

export function makeHttp(prefix: string) {
  return async function http<T>(path: string, init?: RequestInit): Promise<T> {
    const url = `${prefix}${path}`
    const res = await fetch(url, {
      ...init,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...init?.headers,
      },
      credentials: 'same-origin',
    })
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new ApiError(res.status, url, body || res.statusText)
    }
    return res.json() as Promise<T>
  }
}

const http = makeHttp('/api/v1')
const busHttp = makeHttp('/api/bus')
// Versioned alias mounted by agent-bus-analyzer's mount_process_intelligence();
// analytical read-only projections over the audit chain — never an execution path.
const processHttp = makeHttp('/api/process-intelligence/v1')

function evaluationEvidenceQuery(status?: EvaluationEvidenceStatus): string {
  return status ? `?status=${encodeURIComponent(status)}` : ''
}

function normalizeEvaluationEvidence(item: EvaluationEvidenceApi): EvaluationEvidence {
  return {
    source: item.source,
    dataset: item.dataset,
    status: item.status,
    reportHash: item.report_hash,
    policyVersion: item.policy_version,
    scenarioCount: item.scenario_count,
    passed: item.passed,
    failed: item.failed,
    attackSuccessRate: item.attack_success_rate,
    utilityRetentionRate: item.utility_retention_rate,
    p95LatencyMs: item.p95_latency_ms,
    eventId: item.event_id,
    tenant: item.tenant,
    allow: item.allow,
    previousHash: item.previous_hash,
    eventHash: item.event_hash,
    claimSafe: item.claim_safe,
    ingestedAt: item.ingested_at,
  }
}

export const api = {
  consoleSummary: {
    get: () => http<ConsoleSummary>('/console-summary'),
  },
  agents: {
    list: () => http<Agent[]>('/agents'),
  },
  actions: {
    list: () => http<GovernedAction[]>('/actions'),
    getProof: (receiptId: string) =>
      http<ReceiptProofPacket>(`/actions/${encodeURIComponent(receiptId)}/proof`),
    test: (body: ActionTestRequest) =>
      http<ActionTestReceipt>('/actions/test', { method: 'POST', body: JSON.stringify(body) }),
  },
  overview: {
    get: () => http<OverviewSummary>('/overview'),
  },
  maci: {
    get: () => http<MaciLanes>('/maci'),
  },
  deliberations: {
    list: () => http<Deliberation[]>('/deliberations'),
  },
  incidents: {
    list: () => http<Incident[]>('/incidents'),
  },
  policies: {
    list: () => http<PolicyRule[]>('/policies'),
  },
  compile: {
    draft: () => http<CompileDraft>('/compile/draft'),
    replay: (body: CompileActionRequest) =>
      http<ActionReceipt>('/compile/replay', { method: 'POST', body: JSON.stringify(body) }),
    promote: (body: CompileActionRequest) =>
      http<ActionReceipt>('/compile/promote', { method: 'POST', body: JSON.stringify(body) }),
  },
  audit: {
    list: () => http<AuditEvent[]>('/audit'),
  },
  evaluationEvidence: {
    list: (status?: EvaluationEvidenceStatus) =>
      http<EvaluationEvidenceApi[]>(
        `/evidence/evaluation-reports${evaluationEvidenceQuery(status)}`,
      ).then((items) => items.map(normalizeEvaluationEvidence)),
  },
  settings: {
    get: () => http<SettingSection[]>('/settings'),
  },
  tenants: {
    list: () => http<Tenant[]>('/tenants'),
  },
  account: {
    get: () => http<AccountView>('/account'),
  },
  process: {
    list: (offset = 0, limit = 50) =>
      processHttp<ProcessList>(`/processes?offset=${offset}&limit=${limit}`),
    detail: (processId: string) =>
      processHttp<ProcessDetail>(`/processes/${encodeURIComponent(processId)}`),
    variants: (processId: string, offset = 0, limit = 50) =>
      processHttp<ProcessVariantList>(
        `/processes/${encodeURIComponent(processId)}/variants?offset=${offset}&limit=${limit}`,
      ),
    compliance: (processId: string) =>
      processHttp<ProcessComplianceReport>(
        `/processes/${encodeURIComponent(processId)}/compliance`,
      ),
  },
  bus: {
    listTraces: (cursor?: string | null) => {
      const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
      return busHttp<BusTraceList>(`/traces${qs}`)
    },
    // encodeURIComponent on correlation_id is defense in depth against a
    // path-traversal payload arriving via the address bar or a paste, mirroring
    // the analyzer store-layer fix applied in 081843a. The Python side enforces
    // UUID format independently.
    getTrace: (correlationId: string) =>
      busHttp<BusSingleTrace | BusExpired>(`/traces/${encodeURIComponent(correlationId)}`),
    getReceiptProof: (receiptId: string) =>
      busHttp<BusReceiptProof>(`/receipts/${encodeURIComponent(receiptId)}`),
    listDefects: () => busHttp<BusDefectList>('/defects?window_seconds=60'),
  },
}
