import { useAudit } from '../../api/hooks'

export function Audit() {
  const { data, isLoading, isError, refetch } = useAudit()

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
          placeholder="Search by matter, citation, agent, hash…"
          aria-label="Search audit"
        />
        <span className="c-meta">UTC · append-only · 8,402 events today</span>
      </div>

      <div className="audit-list">
        {data.map((e) => (
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

      <p
        style={{
          marginTop: 24,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ Append-only · every entry is countersigned by the constitutional hash 608508a9bd224290 ·
        this view is a window onto the ledger, not the ledger
      </p>
    </div>
  )
}
