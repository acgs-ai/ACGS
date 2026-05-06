import { type ReactNode, useMemo, useRef } from 'react'

export const CONSTITUTION_HASH = '608508a9bd224290'

export type LocalReceipt = {
  title: string
  body: string
  meta: string
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

export function ConsoleLoading({ label = 'Polling …' }: { label?: string }) {
  return (
    <div className="c-toolbar">
      <span className="c-meta">⁂ {label}</span>
    </div>
  )
}

export function ConsoleError({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="c-toolbar">
      <span className="c-meta">
        ⁂ Could not reach the bus.{' '}
        <button type="button" className="m-text-link" onClick={onRetry}>
          Retry
        </button>
      </span>
    </div>
  )
}

export function EmptyState({
  query,
  label,
  onClear,
}: {
  query: string
  label: string
  onClear: () => void
}) {
  return (
    <div className="c-empty" role="status">
      <strong>No {label} match the current filter.</strong>
      <span>
        Query <code>{query}</code> is local to this browser session and has not reached the bus.
      </span>
      <button type="button" className="btn btn-secondary btn-sm" onClick={onClear}>
        Clear search
      </button>
    </div>
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
