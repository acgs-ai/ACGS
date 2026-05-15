import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import {
  BusApiError,
  busAnalysis,
  type EventStatus,
  type Expired,
  type IntegrityStatus,
  type SingleTrace,
  type TraceEvent,
  type TraceListItem,
} from '../../lib/bus-analysis-client'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

const LIVE = { staleTime: 5_000, refetchInterval: 10_000 } as const

function canUseFixtureFallback(): boolean {
  if (import.meta.env.PROD) return false
  return import.meta.env.VITE_USE_MOCKS === 'true'
}

async function withBusFixtureFallback<T>(
  request: () => Promise<T>,
  fallback: () => Promise<T>,
): Promise<T> {
  try {
    return await request()
  } catch (error) {
    if (error instanceof BusApiError || !canUseFixtureFallback()) {
      throw error
    }
    console.warn('Bus analyzer unavailable; rendering fixture-backed traces.', error)
    return fallback()
  }
}

export function useBusTraceList() {
  return useQuery({
    queryKey: ['bus-traces'],
    queryFn: import.meta.env.DEV
      ? () =>
          withBusFixtureFallback(
            () => busAnalysis.listTraces(),
            () => import('../../mocks/data/bus-analysis').then((m) => m.BUS_TRACE_LIST),
          )
      : () => busAnalysis.listTraces(),
    ...LIVE,
  })
}

export function useSingleTrace(correlationId: string | null) {
  return useQuery({
    queryKey: ['bus-trace', correlationId],
    enabled: correlationId !== null,
    queryFn: () => {
      if (correlationId === null) {
        // enabled guards the call; keeps the type narrow.
        return Promise.reject(new Error('useSingleTrace called with null correlation_id'))
      }
      const live = () => busAnalysis.getTrace(correlationId)
      const fallback = () =>
        import('../../mocks/data/bus-analysis').then((m) => {
          const found = m.getSingleTraceFixture(correlationId)
          if (found) return found as SingleTrace | Expired
          throw new BusApiError(404, `/api/bus/traces/${correlationId}`, 'trace not in fixture set')
        })
      return import.meta.env.DEV ? withBusFixtureFallback(live, fallback) : live()
    },
    ...LIVE,
  })
}

// EventStatus → posture pill semantics. Posture vocabulary lives in
// DESIGN.md §3.2 — risk-confirmed for clean, risk-blocked for hard
// failures, risk-partial for ambiguity / observability gaps.
const STATUS_POSTURE: Record<EventStatus, 'confirmed' | 'partial' | 'blocked'> = {
  completed: 'confirmed',
  'policy-violation': 'blocked',
  'dispatch-failure': 'blocked',
  'unwired-handler': 'partial',
  'orphan-response': 'partial',
  'incomplete-pair': 'partial',
  'ingest-gap': 'partial',
}

const INTEGRITY_POSTURE: Record<IntegrityStatus, 'confirmed' | 'partial' | 'blocked'> = {
  intact: 'confirmed',
  tampered: 'blocked',
  unknown: 'partial',
}

const STATUS_LABEL: Record<EventStatus, string> = {
  completed: 'Completed',
  'policy-violation': 'Policy violation',
  'dispatch-failure': 'Dispatch failure',
  'unwired-handler': 'Unwired handler',
  'orphan-response': 'Orphan response',
  'incomplete-pair': 'Incomplete pair',
  'ingest-gap': 'Ingest gap',
}

const INTEGRITY_LABEL: Record<IntegrityStatus, string> = {
  intact: 'Intact',
  tampered: 'Tampered',
  unknown: 'Unknown',
}

const KIND_LABEL: Record<TraceEvent['kind'], string> = {
  dispatch: 'Dispatch',
  response: 'Response',
  decision: 'Decision',
}

function shortHash(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 16)}…` : hash
}

function shortId(uuid: string): string {
  const head = uuid.split('-')[0] ?? uuid
  return head.length > 8 ? `${head.slice(0, 8)}…` : head
}

const listFields = (t: TraceListItem) => [
  t.correlation_id,
  t.constitutional_hash,
  t.worst_event_status,
  t.integrity_status,
  STATUS_LABEL[t.worst_event_status],
  INTEGRITY_LABEL[t.integrity_status],
]

function decisionPostureFor(decision: TraceEvent['decision']): 'confirmed' | 'partial' | 'blocked' {
  switch (decision) {
    case 'allow':
      return 'confirmed'
    case 'deny':
      return 'blocked'
    case 'transform':
    case 'escalate':
      return 'partial'
    default:
      return 'partial'
  }
}

function TraceRowList({
  items,
  selectedId,
  onSelect,
}: {
  items: readonly TraceListItem[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div className="audit-list">
      {items.map((t) => (
        <button
          key={t.correlation_id}
          type="button"
          className="bus-trace-row"
          aria-current={selectedId === t.correlation_id ? 'true' : undefined}
          onClick={() => onSelect(t.correlation_id)}
        >
          <span className="ts">{t.started_at}</span>
          <span className={`pill ${STATUS_POSTURE[t.worst_event_status]}`}>
            {STATUS_LABEL[t.worst_event_status]}
          </span>
          <span className={`pill ${INTEGRITY_POSTURE[t.integrity_status]}`}>
            {INTEGRITY_LABEL[t.integrity_status]}
          </span>
          <span className="ev">
            <span className="bus-trace-corr">{shortId(t.correlation_id)}</span>
            <span className="src">
              {t.event_count} event{t.event_count === 1 ? '' : 's'}
              {t.completed_at ? '' : ' · in progress'}
            </span>
          </span>
          <span className="hash-col">
            <strong>{shortHash(t.constitutional_hash)}</strong>
            <span> · constitutional</span>
          </span>
        </button>
      ))}
    </div>
  )
}

function EventRow({ event }: { event: TraceEvent }) {
  const isIngestGap = event.status === 'ingest-gap'
  return (
    <div className="bus-event-row">
      <span className="bus-event-causal">#{event.causal_index}</span>
      <span className={`pill ${STATUS_POSTURE[event.status]}`}>{STATUS_LABEL[event.status]}</span>
      <span className="bus-event-kind">{KIND_LABEL[event.kind]}</span>
      <span className="bus-event-summary">
        <strong>
          {event.source_agent}
          {event.target_handler_resolved
            ? ` → ${event.target_handler_resolved}`
            : event.target_handler_declared
              ? ` → ${event.target_handler_declared} (unresolved)`
              : ''}
        </strong>
        {event.decision && (
          <span className={`pill ${decisionPostureFor(event.decision)} bus-event-decision`}>
            {event.decision}
          </span>
        )}
        {event.flagged_rule && (
          <span className="bus-event-rule">flagged · {event.flagged_rule}</span>
        )}
        {isIngestGap && (
          <span className="bus-event-rule">
            gap · {event.gap_started_at} → {event.gap_ended_at}
          </span>
        )}
        <span className="src">
          {event.recorded_at}
          {event.audit_receipt_hash ? ` · audit ${shortHash(event.audit_receipt_hash)}` : ''}
        </span>
      </span>
      <span className="hash-col">
        <strong>{shortHash(event.event_hash)}</strong>
        <span>
          {' · '}
          {event.prev_hash ? `prev ${shortHash(event.prev_hash)}` : 'genesis'}
        </span>
      </span>
    </div>
  )
}

function TraceInspector({ data, onBack }: { data: SingleTrace | Expired; onBack: () => void }) {
  if (data.kind === 'expired') {
    return (
      <div>
        <button type="button" className="bus-back" onClick={onBack}>
          ← back to traces
        </button>
        <div className="bus-inspector-banner partial" role="status">
          <strong>Expired.</strong> This trace was purged under the{' '}
          {data.retention_policy.max_age_days}-day retention policy at{' '}
          {data.retention_policy.purged_at}. Correlation {data.correlation_id}.
        </div>
      </div>
    )
  }

  const { trace, events, integrity_status, rotation_at_index } = data
  return (
    <div>
      <button type="button" className="bus-back" onClick={onBack}>
        ← back to traces
      </button>
      <div className="bus-inspector-header">
        <div>
          <div className="c-meta">Correlation</div>
          <div className="bus-inspector-id">{trace.correlation_id}</div>
        </div>
        <div className="bus-inspector-meta">
          <span className={`pill ${INTEGRITY_POSTURE[integrity_status]}`}>
            {INTEGRITY_LABEL[integrity_status]}
          </span>
          <span className="hash-col">
            <strong>{shortHash(trace.constitutional_hash)}</strong>
            <span> · constitutional</span>
          </span>
        </div>
      </div>

      {integrity_status !== 'intact' && (
        <div className={`bus-inspector-banner ${INTEGRITY_POSTURE[integrity_status]}`} role="alert">
          <strong>Integrity {integrity_status}.</strong> This trace cannot be presented as clean.
          Treat any decision recorded below as unverified until the chain is re-anchored.
        </div>
      )}

      {typeof rotation_at_index === 'number' && (
        <div className="bus-inspector-banner partial" role="note">
          <strong>Constitutional rotation</strong> recorded mid-trace at causal index{' '}
          {rotation_at_index}.
        </div>
      )}

      <div className="bus-event-list">
        {events.map((event) => (
          <EventRow key={event.event_id} event={event} />
        ))}
      </div>

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Read-only · every event is hash-chained to its predecessor · this view is a window onto
        the bus, not the bus
      </p>
    </div>
  )
}

export function BusAnalysis() {
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const list = useBusTraceList()
  const single = useSingleTrace(selectedId)
  const filtered = useTextFilter(list.data?.items, query, listFields)

  if (selectedId !== null) {
    if (single.isLoading || !single.data) {
      if (single.isError) {
        return <ConsoleError onRetry={() => single.refetch()} />
      }
      return <ConsoleLoading label="Loading trace …" />
    }
    return <TraceInspector data={single.data} onBack={() => setSelectedId(null)} />
  }

  if (list.isLoading) {
    return <ConsoleLoading />
  }

  if (list.isError || !list.data) {
    return <ConsoleError onRetry={() => list.refetch()} />
  }

  const total = list.data.items.length
  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Filter by correlation, status, integrity, hash…"
        ariaLabel="Filter traces"
        meta={`${filtered.length} of ${total} visible · UTC · read-only`}
      />

      {filtered.length === 0 ? (
        <EmptyState query={query} label="traces" onClear={() => setQuery('')} />
      ) : (
        <TraceRowList items={filtered} selectedId={selectedId} onSelect={setSelectedId} />
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Observer-only · capture is read-only on the agent bus · trace inspection never alters a
        recorded run
      </p>
    </div>
  )
}
