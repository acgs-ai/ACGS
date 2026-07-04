import { useOverview } from '../../api/hooks'
import { navigate } from '../../lib/navigate'
import { ConsoleError, ConsoleLoading } from './shared'

export function Overview() {
  const { data, isLoading, isError, refetch } = useOverview()

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  return (
    <div>
      <p className="overview-intro">
        Twelve agents are bound to constitution <span className="mono">608508a9bd224290</span>. Four
        operating MACI lanes are clear. Three matters are in human deliberation. Drift across the
        bus, the gateway, and the worker is zero bytes; the constitution that compiled at 09:14 UTC
        is the same constitution serving traffic at this moment.
      </p>

      <section
        className="overview-section action-entry"
        aria-labelledby="getting-started"
        data-first-run="getting-started"
      >
        <div>
          <h2 className="overview-section-title" id="getting-started">
            Getting started
          </h2>
          <p>
            New to this console? The numbers above come from local fixtures. Bind your own runtime
            and prove one gated action end to end before you trust any populated view. These are
            local readiness steps, not production certification.
          </p>
        </div>
        <ol>
          <li>
            Connect a runtime to the same-origin governed bus, then open{' '}
            <span className="mono">/console/bus</span> to watch traces propagate.
          </li>
          <li>
            Run the one-command smoke proof:{' '}
            <span className="mono">uv run --package gove-zone gove-zone smoke</span>.
          </li>
          <li>
            Replay the receipt-gated demo so a denied or unreceipted action stays blocked:{' '}
            <span className="mono">
              uv run --package gove-zone python
              packages/gove-zone/examples/receipt-gated-execution/demo.py
            </span>
            .
          </li>
        </ol>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => navigate('/console/bus')}
        >
          Open bus traces
        </button>
      </section>

      <div className="overview-stats">
        {data.stats.map((s) => (
          <Stat key={s.label} label={s.label} value={s.value} sub={s.sub} />
        ))}
      </div>

      <section className="overview-section action-entry" aria-labelledby="verify-agent-action">
        <div>
          <h2 className="overview-section-title" id="verify-agent-action">
            Verify an agent action
          </h2>
          <p>
            Start here when a non-technical reviewer asks whether an agent action was safe. The
            action control room shows the attempted tool call, decision, reason, receipt, replay
            command, and audit anchor in one path.
          </p>
        </div>
        <ol>
          <li>See what the agent tried to do.</li>
          <li>Read whether it was allowed, denied, transformed, or escalated.</li>
          <li>Check the receipt, trace, and replay command.</li>
          <li>Confirm that unsafe actions did not execute silently.</li>
        </ol>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => navigate('/console/actions')}
        >
          Open action control
        </button>
      </section>

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
