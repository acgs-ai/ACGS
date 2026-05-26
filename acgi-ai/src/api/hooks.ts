import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { ApiError, api } from './client'
import type {
  BusReceiptProof,
  DecisionOutcome,
  EvaluationEvidenceStatus,
  EvidenceSignatureSummary,
  GovernanceCheck,
  ReceiptProofPacket,
} from './types'

export const POLL_WINDOWS = {
  live: { staleTime: 5_000, minInterval: 5_000, maxInterval: 10_000 },
  slow: { staleTime: 30_000, minInterval: 30_000, maxInterval: 60_000 },
} as const

type PollingProfile = keyof typeof POLL_WINDOWS
type QueryPollContext = { state: { fetchFailureCount: number } }

function isDocumentVisible(): boolean {
  if (typeof document === 'undefined') return true
  return document.visibilityState !== 'hidden'
}

export function getBusHealthBackoffMultiplier(fetchFailureCount: number): number {
  if (fetchFailureCount <= 0) return 1
  return Math.min(4, 1 + fetchFailureCount)
}

export function jitteredRefetchInterval(
  profile: PollingProfile,
  fetchFailureCount: number,
): number | false {
  if (import.meta.env.VITE_EVAL_MODE === 'true') return false
  if (!isDocumentVisible()) return false

  const window = POLL_WINDOWS[profile]
  const spread = window.maxInterval - window.minInterval
  const jitter = spread <= 0 ? 0 : Math.floor(Math.random() * (spread + 1))
  return (window.minInterval + jitter) * getBusHealthBackoffMultiplier(fetchFailureCount)
}

function refetchIntervalFor(profile: PollingProfile) {
  return (query: QueryPollContext) =>
    jitteredRefetchInterval(profile, query.state.fetchFailureCount)
}

export function useBusHealth(profile: PollingProfile) {
  const [visible, setVisible] = useState(isDocumentVisible)

  useEffect(() => {
    if (typeof document === 'undefined') return
    const onVisibilityChange = () => setVisible(isDocumentVisible())
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => document.removeEventListener('visibilitychange', onVisibilityChange)
  }, [])

  return useMemo(
    () => ({
      staleTime: POLL_WINDOWS[profile].staleTime,
      enabled: visible,
      refetchInterval: refetchIntervalFor(profile),
      refetchIntervalInBackground: false,
      refetchOnWindowFocus: true,
    }),
    [profile, visible],
  )
}

// Single-trace inspector: trace is effectively immutable for a reader's
// session (append-only, but the user clicks away to refresh the list view).
// No polling — keep just enough staleness to dedupe re-mounts.
const SNAPSHOT = { staleTime: 5_000 }

function canUseFixtureFallback(): boolean {
  if (import.meta.env.PROD) {
    return false
  }
  return import.meta.env.VITE_USE_MOCKS === 'true'
}

function isNetworkUnavailable(error: unknown): boolean {
  if (error instanceof ApiError) {
    return false
  }
  if (!(error instanceof TypeError)) {
    return false
  }

  const message = error.message.toLowerCase()
  return (
    message.includes('failed to fetch') ||
    message.includes('fetch failed') ||
    message.includes('networkerror') ||
    message.includes('network request failed') ||
    message.includes('load failed')
  )
}

async function withFixtureFallback<T>(
  request: () => Promise<T>,
  fallback: () => Promise<T>,
): Promise<T> {
  try {
    return await request()
  } catch (error) {
    if (!canUseFixtureFallback() || !isNetworkUnavailable(error)) {
      throw error
    }
    console.warn('ACGS API unavailable; rendering fixture-backed console data.', error)
    return fallback()
  }
}

export function useAgents() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['agents'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.agents.list, () =>
            import('../mocks/data/agents').then((m) => m.AGENTS),
          )
      : api.agents.list,
    ...busHealth,
  })
}

export function useConsoleSummary() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['console-summary'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.consoleSummary.get, () =>
            import('../mocks/data/console-summary').then((m) => m.CONSOLE_SUMMARY),
          )
      : api.consoleSummary.get,
    ...busHealth,
  })
}

export function useGovernedActions() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['governed-actions'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.actions.list, () =>
            import('../mocks/data/actions').then((m) => m.GOVERNED_ACTIONS),
          )
      : api.actions.list,
    ...busHealth,
  })
}

function outcomeFromBusDecision(decision: BusReceiptProof['decision']): DecisionOutcome {
  switch (decision) {
    case 'allow':
      return 'allowed'
    case 'deny':
      return 'denied'
    case 'transform':
      return 'transformed'
    case 'escalate':
    case null:
    case undefined:
      return 'escalated'
  }
}

function actionNameFromBusProof(proof: BusReceiptProof): string {
  return (
    proof.events.find((event) => event.kind === 'decision')?.target_handler_resolved ??
    proof.events.find((event) => event.kind === 'decision')?.target_handler_declared ??
    proof.events[0]?.target_handler_declared ??
    'bus.receipt'
  )
}

function busChecks(proof: BusReceiptProof): GovernanceCheck[] {
  return proof.policy_path.map((step, index) => ({
    id: step,
    label: index === 0 ? 'Bus policy path' : 'Matched governance rule',
    posture: index === 0 ? 'confirmed' : 'partial',
    reason: `Observed in analyzer receipt proof for ${proof.receipt_id}.`,
  }))
}

function busToolExecuted(decision: BusReceiptProof['decision']): boolean {
  return decision === 'allow' || decision === 'transform'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function stringField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function optionalString(value: string | null | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

export function summarizeEvidenceSignature(signedEvidencePacket: string): EvidenceSignatureSummary {
  let parsed: unknown
  try {
    parsed = JSON.parse(signedEvidencePacket)
  } catch {
    return {
      status: 'malformed',
      label: 'Malformed evidence packet',
      algorithm: 'unknown',
      reason: 'signed_evidence_packet is not valid JSON',
    }
  }

  const signature = isRecord(parsed) ? parsed.export_signature : undefined
  if (!isRecord(signature)) {
    return {
      status: 'missing',
      label: 'No export signature',
      algorithm: 'unknown',
      reason: 'export_signature missing from evidence packet',
    }
  }

  const algorithm = stringField(signature, 'algorithm') ?? 'unknown'
  const digest = stringField(signature, 'payload_digest') ?? stringField(signature, 'digest')
  const reason = stringField(signature, 'reason')
  const keyId = stringField(signature, 'key_id') ?? stringField(signature, 'keyId')
  const status = stringField(signature, 'status')

  if (status === 'signed') {
    return {
      status,
      label: 'Deployment-managed signature',
      algorithm,
      keyId,
      digest,
      reason,
    }
  }

  if (status === 'unsigned-local-digest') {
    return {
      status,
      label: 'Unsigned local digest',
      algorithm,
      digest,
      reason,
    }
  }

  return {
    status: 'malformed',
    label: 'Unrecognized signature status',
    algorithm,
    digest,
    reason: reason ?? 'export_signature.status is missing or unsupported',
  }
}

export function normalizeBusReceiptProof(proof: BusReceiptProof): ReceiptProofPacket {
  const decision = proof.decision
  const outcome = outcomeFromBusDecision(decision)
  const action = actionNameFromBusProof(proof)
  const decisionEvent = proof.events.find((event) => event.kind === 'decision')
  const signedEvidencePacket = proof.signed_evidence_packet
  const firstTraceEvent = proof.events.find((event) => optionalString(event.phoenix_trace_id))
  const firstSpanEvent = proof.events.find((event) => optionalString(event.phoenix_span_id))
  const firstParentSpanEvent = proof.events.find((event) =>
    optionalString(event.phoenix_parent_span_id),
  )
  const phoenixTraceId =
    optionalString(proof.phoenix_trace_id) ??
    optionalString(proof.trace.phoenix_trace_id) ??
    optionalString(firstTraceEvent?.phoenix_trace_id)
  const phoenixSpanId =
    optionalString(proof.phoenix_span_id) ??
    optionalString(proof.trace.phoenix_span_id) ??
    optionalString(firstSpanEvent?.phoenix_span_id)
  const phoenixParentSpanId =
    optionalString(proof.phoenix_parent_span_id) ??
    optionalString(proof.trace.phoenix_parent_span_id) ??
    optionalString(firstParentSpanEvent?.phoenix_parent_span_id)
  return {
    receiptId: proof.receipt_id,
    receiptHash: proof.receipt_hash,
    traceId: proof.correlation_id,
    phoenixTraceId,
    phoenixSpanId,
    phoenixParentSpanId,
    replayCommand: `agent-bus-analyzer receipt --receipt ${proof.receipt_id} --trace ${proof.correlation_id}`,
    auditEventId: decisionEvent?.event_id ?? proof.receipt_id,
    signedEvidencePacket,
    evidenceSignature: summarizeEvidenceSignature(signedEvidencePacket),
    hashChainVerified: proof.hash_chain_verified,
    policyPath: proof.policy_path.join(' → '),
    toolExecuted: busToolExecuted(decision),
    action: {
      id: `bus-${proof.receipt_id}`,
      agent: decisionEvent?.source_agent ?? proof.events[0]?.source_agent ?? 'agent-bus',
      action,
      target: proof.correlation_id,
      attemptedAt: proof.trace.started_at,
      outcome,
      plainReason: `${proof.integrity_status} bus trace with ${proof.events.length} event(s); receipt proof is ${proof.hash_chain_verified ? 'hash-chain verified' : 'not hash-chain verified'}.`,
      receiptId: proof.receipt_id,
      receiptHash: proof.receipt_hash,
      traceId: proof.correlation_id,
      replayCommand: `agent-bus-analyzer receipt --receipt ${proof.receipt_id} --trace ${proof.correlation_id}`,
      auditEventId: decisionEvent?.event_id ?? proof.receipt_id,
      checks: busChecks(proof),
      before: JSON.stringify(
        {
          correlation_id: proof.correlation_id,
          phoenix_trace_id: phoenixTraceId,
          phoenix_span_id: phoenixSpanId,
          phoenix_parent_span_id: phoenixParentSpanId,
          payload_refs: proof.events.map((event) => event.payload_ref),
        },
        null,
        2,
      ),
      after: JSON.stringify(
        {
          decision,
          integrity_status: proof.integrity_status,
          hash_chain_verified: proof.hash_chain_verified,
          phoenix_trace_id: phoenixTraceId,
          phoenix_span_id: phoenixSpanId,
          phoenix_parent_span_id: phoenixParentSpanId,
          tool_executed: busToolExecuted(decision),
        },
        null,
        2,
      ),
    },
  }
}

export function useActionProof(receiptId: string) {
  return useQuery({
    queryKey: ['action-proof', receiptId],
    enabled: receiptId.length > 0,
    queryFn: () => {
      const live = () => api.bus.getReceiptProof(receiptId).then(normalizeBusReceiptProof)
      const fallback = () =>
        import('../mocks/data/actions').then((m) => {
          const proof = m.getGovernedActionProof(receiptId)
          if (proof) return proof
          throw new ApiError(404, `/api/v1/actions/${receiptId}/proof`, 'proof not in fixtures')
        })
      return import.meta.env.DEV ? withFixtureFallback(live, fallback) : live()
    },
    ...SNAPSHOT,
  })
}

export function useTestAction() {
  return useMutation({
    mutationFn: api.actions.test,
  })
}

export function useOverview() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['overview'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.overview.get, () =>
            import('../mocks/data/overview').then((m) => m.OVERVIEW_SUMMARY),
          )
      : api.overview.get,
    ...busHealth,
  })
}

export function useMaci() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['maci'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.maci.get, () =>
            import('../mocks/data/maci').then((m) => m.MACI_LANES),
          )
      : api.maci.get,
    ...busHealth,
  })
}

export function useDeliberations() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['deliberations'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.deliberations.list, () =>
            import('../mocks/data/deliberations').then((m) => m.DELIBERATIONS),
          )
      : api.deliberations.list,
    ...busHealth,
  })
}

export function useIncidents() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['incidents'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.incidents.list, () =>
            import('../mocks/data/incidents').then((m) => m.INCIDENTS),
          )
      : api.incidents.list,
    ...busHealth,
  })
}

export function usePolicies() {
  const busHealth = useBusHealth('slow')
  return useQuery({
    queryKey: ['policies'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.policies.list, () =>
            import('../mocks/data/policies').then((m) => m.POLICIES),
          )
      : api.policies.list,
    ...busHealth,
  })
}

export function useCompileDraft() {
  const busHealth = useBusHealth('slow')
  return useQuery({
    queryKey: ['compile-draft'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.compile.draft, () =>
            import('../mocks/data/compile').then((m) => m.COMPILE_DRAFT),
          )
      : api.compile.draft,
    ...busHealth,
  })
}

export function useReplayCompile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.compile.replay,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['compile-draft'] })
      void queryClient.invalidateQueries({ queryKey: ['console-summary'] })
    },
  })
}

export function usePromoteCompile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.compile.promote,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['compile-draft'] })
      void queryClient.invalidateQueries({ queryKey: ['console-summary'] })
    },
  })
}

export function useAudit() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['audit'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.audit.list, () =>
            import('../mocks/data/audit').then((m) => m.AUDIT_EVENTS),
          )
      : api.audit.list,
    ...busHealth,
  })
}

export function useEvaluationEvidence(status: EvaluationEvidenceStatus = 'passed') {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['evaluation-evidence', status],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(
            () => api.evaluationEvidence.list(status),
            () =>
              import('../mocks/data/audit').then((m) =>
                m.AUDIT_EVENTS.flatMap((event) =>
                  event.evaluationEvidence && event.evaluationEvidence.status === status
                    ? [event.evaluationEvidence]
                    : [],
                ),
              ),
          )
      : () => api.evaluationEvidence.list(status),
    ...busHealth,
  })
}

export function useSettings() {
  const busHealth = useBusHealth('slow')
  return useQuery({
    queryKey: ['settings'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.settings.get, () =>
            import('../mocks/data/settings').then((m) => m.SETTING_SECTIONS),
          )
      : api.settings.get,
    ...busHealth,
  })
}

export function useTenants() {
  const busHealth = useBusHealth('slow')
  return useQuery({
    queryKey: ['tenants'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.tenants.list, () =>
            import('../mocks/data/tenants').then((m) => m.TENANTS),
          )
      : api.tenants.list,
    ...busHealth,
  })
}

export function useAccount() {
  const busHealth = useBusHealth('slow')
  return useQuery({
    queryKey: ['account'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.account.get, () =>
            import('../mocks/data/account').then((m) => m.ACCOUNT_VIEW),
          )
      : api.account.get,
    ...busHealth,
  })
}

export function useBusTraceList() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['bus-traces'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(
            () => api.bus.listTraces(),
            () => import('../mocks/data/bus-analysis').then((m) => m.BUS_TRACE_LIST),
          )
      : () => api.bus.listTraces(),
    ...busHealth,
  })
}

export function useSingleTrace(correlationId: string | null) {
  return useQuery({
    queryKey: ['bus-trace', correlationId],
    enabled: correlationId !== null,
    queryFn: () => {
      const id = correlationId as string
      const live = () => api.bus.getTrace(id)
      const fallback = () =>
        import('../mocks/data/bus-analysis').then((m) => {
          const found = m.getSingleTraceFixture(id)
          if (found) return found
          throw new ApiError(404, `/api/bus/traces/${id}`, 'trace not in fixture set')
        })
      return import.meta.env.DEV ? withFixtureFallback(live, fallback) : live()
    },
    ...SNAPSHOT,
  })
}

export function useBusDefects() {
  const busHealth = useBusHealth('live')
  return useQuery({
    queryKey: ['bus-defects'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(
            () => api.bus.listDefects(),
            () => import('../mocks/data/bus-analysis').then((m) => m.BUS_DEFECT_LIST),
          )
      : () => api.bus.listDefects(),
    ...busHealth,
  })
}
