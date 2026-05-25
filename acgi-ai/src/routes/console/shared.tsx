import { type ReactNode, useMemo, useRef } from 'react'
import type { AppError } from '../../lib/errors'

export const CONSTITUTION_HASH = '608508a9bd224290'

export type EmptyMeans = 'fresh-tenant' | 'awaiting-bus' | 'audit-drift'
export type EnvIndicatorMode = 'Live' | 'Stubbed' | 'Fixture' | 'Offline'

type ConsoleStateKind =
  | 'loading'
  | 'empty'
  | 'error'
  | 'partial-bus'
  | 'stale-while-revalidating'
  | 'retry-in-flight'
  | 'conflicted-mutation'
  | 'permission-denied'
  | 'rate-limited'
  | 'optimistic-pending'
  | 'expired-session'

type StateTone = 'info' | 'warning' | 'danger' | 'success'

export type LocalReceipt = {
  title: string
  body: string
  meta: string
}

export const EMPTY_STATE_COPY: Record<EmptyMeans, { title: string; body: string; fix: string }> = {
  'fresh-tenant': {
    title: 'No tenant evidence yet.',
    body: 'This can be normal for a new or filtered tenant. The console keeps the shell visible while the bus has no matching records.',
    fix: 'Clear filters or wait for the first governed bus event.',
  },
  'awaiting-bus': {
    title: 'Waiting for governed bus evidence.',
    body: 'The page is connected to the console shell, but the upstream bus has not returned matching records for this view.',
    fix: 'Check bus health, retry, or confirm that the current matter should have records.',
  },
  'audit-drift': {
    title: 'No audit-aligned records found.',
    body: 'An empty audit-facing view can indicate drift between the bus, receipt store, or local filters.',
    fix: 'Clear local filters first; if the view stays empty, page the audit owner before relying on the absence of evidence.',
  },
}

export function normalizeQuery(value: string): string {
  return value.trim().toLowerCase()
}

export function useTextFilter<T>(
  items: readonly T[] | undefined,
  query: string,
  getFields: (item: T) => readonly (number | string | null | undefined)[],
): T[] {
  const getFieldsRef = useRef(getFields)
  getFieldsRef.current = getFields

  return useMemo(() => {
    const source = items ?? []
    const q = normalizeQuery(query)
    if (!q) return [...source]
    return source.filter((item) =>
      getFieldsRef.current(item).some((field) =>
        String(field ?? '')
          .toLowerCase()
          .includes(q),
      ),
    )
  }, [items, query])
}

export function renderEmphasis(title: string, emphasis: string): ReactNode {
  const idx = title.toLowerCase().indexOf(emphasis.toLowerCase())
  if (idx === -1) return title
  return (
    <>
      {title.slice(0, idx)}
      <em>{title.slice(idx, idx + emphasis.length)}</em>
      {title.slice(idx + emphasis.length)}
    </>
  )
}

export function SearchToolbar({
  value,
  onChange,
  placeholder,
  ariaLabel,
  meta,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  ariaLabel: string
  meta: ReactNode
}) {
  return (
    <div className="c-toolbar">
      <input
        className="c-search"
        placeholder={placeholder}
        aria-label={ariaLabel}
        value={value}
        onChange={(e) => onChange(e.currentTarget.value)}
      />
      <span className="c-meta">{meta}</span>
    </div>
  )
}

function StateCard({
  stateKind,
  tone = 'info',
  title,
  body,
  action,
  meta,
  appErrorKind,
}: {
  stateKind: ConsoleStateKind
  tone?: StateTone
  title: ReactNode
  body: ReactNode
  action?: ReactNode
  meta?: ReactNode
  appErrorKind?: AppError['kind']
}) {
  return (
    <div
      className={`c-state-card ${tone}`}
      role="status"
      aria-live="polite"
      data-state-kind={stateKind}
      data-app-error-kind={appErrorKind}
    >
      <div>
        <strong>{title}</strong>
        <p>{body}</p>
      </div>
      {meta ? <span className="c-state-meta">{meta}</span> : null}
      {action ? <div className="c-state-action">{action}</div> : null}
    </div>
  )
}

export function ConsoleLoading({ label = 'Polling governed bus evidence…' }: { label?: string }) {
  return (
    <StateCard
      stateKind="loading"
      title="Loading console evidence"
      body={label}
      meta="loading · structural shell retained"
    />
  )
}

export function ConsoleError({ onRetry, appError }: { onRetry: () => void; appError?: AppError }) {
  return (
    <StateCard
      stateKind="error"
      tone="danger"
      title={appError?.title ?? 'Could not reach the governed bus'}
      body={
        appError ? (
          <span className="c-error-detail">
            <span>
              <strong>Cause:</strong> {appError.cause}
            </span>
            <span>
              <strong>Fix:</strong> {appError.fix}
            </span>
            <span>
              <strong>Trace ID:</strong> <code>{appError.traceId}</code>
            </span>
          </span>
        ) : (
          'The console is fail-closed until the API boundary returns usable evidence.'
        )
      }
      meta={
        appError
          ? `error · ${appError.kind} · Trace ID ${appError.traceId}`
          : 'error · retry available'
      }
      appErrorKind={appError?.kind}
      action={
        <button type="button" className="m-text-link" onClick={onRetry}>
          Retry
        </button>
      }
    />
  )
}

export function EmptyState({
  query,
  label,
  emptyMeans,
  onClear,
}: {
  query: string
  label: string
  emptyMeans: EmptyMeans
  onClear: () => void
}) {
  const copy = EMPTY_STATE_COPY[emptyMeans]
  return (
    <div className="c-empty" role="status" aria-live="polite" data-state-kind="empty">
      <strong>{query ? `No ${label} match the current filter.` : copy.title}</strong>
      <span>{query ? copy.body : `${copy.body} ${copy.fix}`}</span>
      {query ? (
        <span>
          Query <code>{query}</code> is local to this browser session and has not reached the bus.
          {` ${copy.fix}`}
        </span>
      ) : null}
      <button type="button" className="btn btn-secondary btn-sm" onClick={onClear}>
        Clear search
      </button>
    </div>
  )
}

export function PartialBus({ affectedModule }: { affectedModule: string }) {
  return (
    <StateCard
      stateKind="partial-bus"
      tone="warning"
      title="Partial bus evidence"
      body={`${affectedModule} returned stale or incomplete evidence while the rest of the console stayed readable.`}
      meta="partial-bus · per-card staleness"
    />
  )
}

export function StaleWhileRevalidating({ lastUpdated }: { lastUpdated: string }) {
  return (
    <StateCard
      stateKind="stale-while-revalidating"
      title="Showing last verified evidence"
      body="A background poll is refreshing this view; existing receipts stay visible until the bus response changes."
      meta={`stale-while-revalidating · ${lastUpdated}`}
    />
  )
}

export function RetryInFlight({ attempt }: { attempt: number }) {
  return (
    <StateCard
      stateKind="retry-in-flight"
      title="Retry in flight"
      body="The console has queued a bounded retry and is holding the current evidence steady."
      meta={`retry-in-flight · attempt ${attempt}`}
    />
  )
}

export function Conflict({ resource }: { resource: string }) {
  return (
    <StateCard
      stateKind="conflicted-mutation"
      tone="warning"
      title="Mutation conflict detected"
      body={`${resource} changed upstream before the local action could be committed.`}
      meta="conflicted-mutation · reload required"
    />
  )
}

export function PermissionDenied({ policy }: { policy: string }) {
  return (
    <StateCard
      stateKind="permission-denied"
      tone="danger"
      title="Permission denied"
      body={`The governed bus refused this action under ${policy}.`}
      meta="permission-denied · no side effect ran"
    />
  )
}

export function RateLimited({ retryAfter }: { retryAfter: string }) {
  return (
    <StateCard
      stateKind="rate-limited"
      tone="warning"
      title="Rate limit active"
      body="The bus asked this console to slow down instead of hammering the evidence path."
      meta={`rate-limited · retry after ${retryAfter}`}
    />
  )
}

export function OptimisticPending({ action }: { action: string }) {
  return (
    <StateCard
      stateKind="optimistic-pending"
      tone="success"
      title="Action pending receipt"
      body={`${action} is visible locally while the receipt finalizes; the side effect is not claimed complete yet.`}
      meta="optimistic-pending · awaiting receipt"
    />
  )
}

export function ExpiredSession({ onSignIn }: { onSignIn: () => void }) {
  return (
    <StateCard
      stateKind="expired-session"
      tone="danger"
      title="Session expired"
      body="The console discarded privileged state and will not render bus evidence until a fresh server session exists."
      meta="expired-session · fail closed"
      action={
        <button type="button" className="m-text-link" onClick={onSignIn}>
          Return to sign in
        </button>
      }
    />
  )
}

export function EnvIndicator({
  mode,
  timestamp,
  affectedModules,
}: {
  mode: EnvIndicatorMode
  timestamp: string
  affectedModules: readonly string[]
}) {
  if (import.meta.env.PROD) return null

  return (
    <div className="c-env-indicator" role="status" aria-live="polite">
      <strong>{mode}</strong>
      <span>{timestamp}</span>
      <span>{affectedModules.join(' · ')}</span>
    </div>
  )
}

export function StateFooter({
  stateKind,
  children,
}: {
  stateKind: ConsoleStateKind
  children: ReactNode
}) {
  return (
    <footer className="c-state-footer" data-state-kind={stateKind}>
      {children}
    </footer>
  )
}

export function Receipt({ receipt }: { receipt: LocalReceipt | null }) {
  if (!receipt) return null
  return (
    <div className="c-receipt" role="status" aria-live="polite">
      <strong>{receipt.title}</strong>
      <span>{receipt.body}</span>
      <code>{receipt.meta}</code>
    </div>
  )
}
