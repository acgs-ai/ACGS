import type { ReactNode } from 'react'
import { useIncidents } from '../../api/hooks'

function renderTitle(title: string, emphasis: string): ReactNode {
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

export function Incidents() {
  const { data, isLoading, isError, refetch } = useIncidents()

  if (isLoading) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">⁂ Polling …</span>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">
          ⁂ Could not reach the bus.{' '}
          <button type="button" className="m-text-link" onClick={() => refetch()}>
            Retry
          </button>
        </span>
      </div>
    )
  }

  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search by source, citation, hash…"
          aria-label="Search incidents"
        />
        <span className="c-meta">5 open · 2 blocked · oldest 6h ago</span>
      </div>

      <div className="incidents-list">
        {data.map((i) => (
          <article className="incident-row" key={i.id}>
            <span className="ts">{i.ts}</span>
            <span className={`pill ${i.posture}`}>
              {i.posture === 'privileged' ? 'Privileged' : i.posture}
            </span>
            <div>
              <div className="title">{renderTitle(i.title, i.emphasis)}</div>
              <span className="src">
                {i.id} · {i.src}
              </span>
              <p>{i.body}</p>
            </div>
            <span className="view">{i.hash}</span>
          </article>
        ))}
      </div>

      <p
        style={{
          marginTop: 24,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ Incidents are escalations off the audit trail · every entry here is also signed into the
        ledger at the same hash
      </p>
    </div>
  )
}
