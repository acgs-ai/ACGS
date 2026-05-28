import { useState } from 'react'
import { useIncidents } from '../../api/hooks'
import type { Incident } from '../../api/types'
import {
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  renderEmphasis,
  SearchToolbar,
  useTextFilter,
} from './shared'

const incidentFields = (i: Incident) => [i.id, i.ts, i.posture, i.title, i.src, i.body, i.hash]

export function Incidents() {
  const [query, setQuery] = useState('')
  const { data, isLoading, isError, refetch } = useIncidents()
  const filtered = useTextFilter(data, query, incidentFields)

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search by source, citation, hash…"
        ariaLabel="Search incidents"
        meta={`${filtered.length} of ${data.length} open · 2 blocked · oldest 6h ago`}
      />

      {filtered.length === 0 ? (
        <EmptyState
          emptyMeans="fresh-tenant"
          query={query}
          label="incidents"
          onClear={() => setQuery('')}
        />
      ) : (
        <div className="incidents-list">
          {filtered.map((i) => (
            <article className="incident-row" key={i.id}>
              <span className="ts">{i.ts}</span>
              <span className={`pill ${i.posture}`}>
                {i.posture === 'privileged' ? 'Privileged' : i.posture}
              </span>
              <div>
                <div className="title">{renderEmphasis(i.title, i.emphasis)}</div>
                <span className="src">
                  {i.id} · {i.src}
                </span>
                <p>{i.body}</p>
              </div>
              <span className="view">{i.hash}</span>
            </article>
          ))}
        </div>
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Incidents are escalations off the audit trail · every entry here is also signed into the
        ledger at the same hash
      </p>
    </div>
  )
}
