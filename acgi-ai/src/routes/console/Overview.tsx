import { useOverview } from '../../api/hooks'

export function Overview() {
  const { data, isLoading, isError, refetch } = useOverview()

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
      <p className="overview-intro">
        Twelve agents are bound to constitution <span className="mono">608508a9bd224290</span>. Four
        operating MACI lanes are clear. Three matters are in human deliberation. Drift across the
        bus, the gateway, and the worker is zero bytes; the constitution that compiled at 09:14 UTC
        is the same constitution serving traffic at this moment.
      </p>

      <div className="overview-stats">
        {data.stats.map((s) => (
          <Stat key={s.label} label={s.label} value={s.value} sub={s.sub} />
        ))}
      </div>

      <section className="overview-section" aria-labelledby="active-governance-cases">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="active-governance-cases">
            Active governance cases
          </h2>
          <span className="c-meta">Auto-refresh · 2s</span>
        </div>
        <table className="c-table c-table-dense">
          <thead>
            <tr>
              <th>Case</th>
              <th>Stage</th>
              <th>Lane</th>
              <th>Age / Turn</th>
              <th>Evidence</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {data.activeCases.map((c) => (
              <tr key={c.name}>
                <td className="mono">{c.name}</td>
                <td>
                  <span className={`pill ${c.posture}`}>{c.stage}</span>
                </td>
                <td className="mono">{c.lane}</td>
                <td className="num">{c.age}</td>
                <td className="mono muted">{c.evidence}</td>
                <td>{c.event}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="overview-section" aria-labelledby="queue-health">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="queue-health">
            Queue health
          </h2>
          <span className="c-meta">Backoff · review · audit</span>
        </div>
        <div className="queue-grid">
          {data.queues.map((q) => (
            <div className="queue-row" key={q.label}>
              <span className="queue-label">{q.label}</span>
              <span className={`queue-value ${q.posture === 'confirmed' ? 'ok' : ''}`}>
                {q.value}
              </span>
              <span className="queue-detail">{q.detail}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="overview-section" aria-labelledby="refusals-by-article">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="refusals-by-article">
            Today&apos;s refusals by article
          </h2>
          <span className="c-meta">UTC · live</span>
        </div>
        <table className="c-table">
          <thead>
            <tr>
              <th>Article</th>
              <th>Citation</th>
              <th className="align-right">Refusals · 24h</th>
              <th>Trend</th>
              <th>Posture</th>
            </tr>
          </thead>
          <tbody>
            {data.refusalsByArticle.map((r) => (
              <tr key={r.article}>
                <td className="mono">Art. {r.article}</td>
                <td className="mono muted">{r.citation}</td>
                <td className="num align-right">{r.refusals.toLocaleString()}</td>
                <td className="num muted">{r.trend}</td>
                <td>
                  <span className={`pill ${r.posture}`}>{r.posture}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="overview-stat">
      <div className="overview-stat-label">{label}</div>
      <div className="overview-stat-value">{value}</div>
      <div className="overview-stat-sub">{sub}</div>
    </div>
  )
}
