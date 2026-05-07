import { useState } from 'react'
import { useAudit } from '../../api/hooks'
import type { AuditEvent } from '../../api/types'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

const auditFields = (e: AuditEvent) => [e.ts, e.ev, e.src, e.hash, e.matter, e.posture]

export function Audit() {
  const [query, setQuery] = useState('')
  const { data, isLoading, isError, refetch } = useAudit()
  const filtered = useTextFilter(data, query, auditFields)

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
        placeholder="Search by matter, citation, agent, hash…"
        ariaLabel="Search audit"
        meta={`${filtered.length} of ${data.length} visible · UTC · append-only`}
      />

      {filtered.length === 0 ? (
        <EmptyState query={query} label="audit events" onClear={() => setQuery('')} />
      ) : (
        <div className="audit-list">
          {filtered.map((e) => (
            <div className="audit-row" key={e.ts}>
              <span className="ts">{e.ts}</span>
              <span className={`pill ${e.posture}`}>
                {e.posture === 'privileged' ? 'Privileged' : e.posture}
              </span>
              <span className="ev">
                {e.ev}
                <span className="src">
                  {e.src}
                  {e.matter ? ` · ${e.matter}` : ''}
                </span>
              </span>
              <span className="hash-col">
                <strong>{e.hash.split(' · ')[0]}</strong>
                <span> · {e.hash.split(' · ')[1]}</span>
              </span>
            </div>
          ))}
        </div>
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Append-only · every entry is countersigned by the constitutional hash 608508a9bd224290 ·
        this view is a window onto the ledger, not the ledger
      </p>
    </div>
  )
}
