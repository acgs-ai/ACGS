import { useState } from 'react'
import { useDeliberations } from '../../api/hooks'
import type { Deliberation } from '../../api/types'
import {
  CONSTITUTION_HASH,
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  type LocalReceipt,
  Receipt,
  renderEmphasis,
  SearchToolbar,
  useTextFilter,
} from './shared'

const deliberationFields = (d: Deliberation) => [
  d.id,
  d.matter,
  d.title,
  d.citation,
  d.body,
  d.posture,
  d.opened,
  d.due,
]

export function Deliberations() {
  const [query, setQuery] = useState('')
  const [receipt, setReceipt] = useState<LocalReceipt | null>(null)
  const { data, isLoading, isError, refetch } = useDeliberations()
  const filtered = useTextFilter(data, query, deliberationFields)

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const record = (
    action: 'approved' | 'held' | 'refused',
    id: string,
    matter: string,
    cite: string,
  ) => {
    setReceipt({
      title: `Local deliberation receipt · ${action}`,
      body: `${id} for ${matter} recorded in this browser only; backend attestation is still required before dispatch.`,
      meta: `${CONSTITUTION_HASH} · ${cite} · ${new Date().toISOString()}`,
    })
  }

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search by matter, citation, posture…"
        ariaLabel="Search deliberations"
        meta={`${filtered.length} of ${data.length} open · oldest 13:32 UTC · SLA 8h`}
      />
      <Receipt receipt={receipt} />

      {filtered.length === 0 ? (
        <EmptyState query={query} label="deliberations" onClear={() => setQuery('')} />
      ) : (
        <div className="delib-list">
          {filtered.map((d) => (
            <article className="delib-card" key={d.id}>
              <div>
                <h4>{renderEmphasis(d.title, d.emphasis)}</h4>
                <div className="meta">
                  <span>{d.id}</span>
                  <span>{d.matter}</span>
                  <span>{d.citation}</span>
                  <span>opened {d.opened.split(' ')[1]}</span>
                  <span>due {d.due.split(' ')[1]}</span>
                </div>
                <p className="body">{d.body}</p>
                <div className="u-row-mt-md">
                  <span className={`pill ${d.posture}`}>
                    {d.posture === 'privileged' ? 'Privileged' : d.posture}
                  </span>
                  <span className="u-mono-cap">608508a9 · attest required</span>
                </div>
              </div>
              <div className="delib-card-actions">
                <button
                  className="btn btn-rust"
                  type="button"
                  onClick={() => record('approved', d.id, d.matter, d.citation)}
                >
                  Approve
                </button>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => record('held', d.id, d.matter, d.citation)}
                >
                  Hold
                </button>
                <button
                  className="btn btn-ghost"
                  type="button"
                  onClick={() => record('refused', d.id, d.matter, d.citation)}
                >
                  Refuse
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}
