// Typed client for the agent-bus-analyzer query API.
//
// Source of truth for the wire shapes:
//   packages/agent-bus-analyzer/contracts/trace-query.schema.json
//   packages/agent-bus-analyzer/contracts/trace-event.schema.json
//
// Field names are snake_case to mirror the JSON Schema literally; the page
// renders them with no transform layer. When an OpenAPI codegen step is
// introduced for the analyzer, this file becomes the migration target.
//
// Path strategy: every call is relative under /api/bus. The console origin
// (console.acgs.ai per DEPLOY.md §3) reverse-proxies /api/bus/* to the
// analyzer's FastAPI app (packages/agent-bus-analyzer/src/agent_bus_analyzer/api.py).
// The privileged origin's CSP keeps this on the same site so cookies + matter
// IDs in the URL never leak to a third-party host (DEPLOY.md §6).

const BUS_PREFIX = '/api/bus'

export type EventStatus =
  | 'completed'
  | 'policy-violation'
  | 'dispatch-failure'
  | 'unwired-handler'
  | 'orphan-response'
  | 'incomplete-pair'
  | 'ingest-gap'

export type IntegrityStatus = 'intact' | 'tampered' | 'unknown'

export type EventKind = 'dispatch' | 'response' | 'decision'

export type DecisionVerdict = 'allow' | 'deny' | 'transform' | 'escalate'

export type TraceEvent = {
  event_id: string
  correlation_id: string
  causal_index: number
  recorded_at: string
  source_agent: string
  target_handler_declared: string | null
  target_handler_resolved: string | null
  payload_ref: string
  kind: EventKind
  decision: DecisionVerdict | null
  flagged_rule: string | null
  audit_receipt_hash: string | null
  constitutional_hash: string
  event_hash: string
  prev_hash: string | null
  status: EventStatus
  gap_started_at: string | null
  gap_ended_at: string | null
}

export type TraceListItem = {
  correlation_id: string
  started_at: string
  completed_at: string | null
  event_count: number
  worst_event_status: EventStatus
  integrity_status: IntegrityStatus
  constitutional_hash: string
}

export type TraceList = {
  kind: 'trace-list'
  items: TraceListItem[]
  next_cursor?: string | null
}

export type SingleTrace = {
  kind: 'single-trace'
  trace: TraceListItem
  events: TraceEvent[]
  integrity_status: IntegrityStatus
  rotation_at_index?: number | null
}

export type Expired = {
  kind: 'expired'
  correlation_id: string
  retention_policy: {
    max_age_days: number
    purged_at: string
  }
}

export class BusApiError extends Error {
  status: number
  url: string

  constructor(status: number, url: string, message: string) {
    super(message)
    this.name = 'BusApiError'
    this.status = status
    this.url = url
  }
}

async function busHttp<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${BUS_PREFIX}${path}`
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
    credentials: 'same-origin',
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new BusApiError(res.status, url, body || res.statusText)
  }
  return res.json() as Promise<T>
}

function encodeCorrelationId(correlationId: string): string {
  // Server enforces UUID format on the Python side; encodeURIComponent here
  // is defense in depth against a path-traversal payload arriving via the
  // browser address bar or a paste. Mirrors the analyzer store-layer fix
  // applied in 081843a.
  return encodeURIComponent(correlationId)
}

export const busAnalysis = {
  listTraces: (cursor?: string | null) => {
    const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
    return busHttp<TraceList>(`/traces${qs}`)
  },
  getTrace: (correlationId: string) =>
    busHttp<SingleTrace | Expired>(`/traces/${encodeCorrelationId(correlationId)}`),
}
