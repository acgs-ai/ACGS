const STATS = [
  ['Decisions today', '8,402', '+612 vs. 7d median'],
  ['Refused', '1,402', '16.7% of total'],
  ['Promoted', '312', 'P-1190 -> P-1502'],
]

const ACTIVE_CASES = [
  [
    'Matter-9821',
    'Human review',
    'MACI-3',
    '18m / T-42',
    '4 receipts',
    'human review requested',
    'partial',
  ],
  [
    'Policy P-1502',
    'Promotion',
    'Registry',
    '07m / T-11',
    'Dafny replay',
    'policy check completed',
    'confirmed',
  ],
  [
    'Appeal A-118',
    'Counsel vote',
    'Deliberation',
    '41m / T-07',
    '2 opinions',
    'appeal queue advanced',
    'partial',
  ],
  [
    'Audit 608508a9',
    'Seal',
    'Audit',
    '18s / T-03',
    'anchor:18s',
    'audit record sealed',
    'confirmed',
  ],
]

const QUEUES = [
  ['Human review queue', '3', 'oldest 41m', 'partial'],
  ['Appeal queue', '1', 'counsel vote open', 'partial'],
  ['Enforcement retry/backoff', '0', 'No queued retries', 'confirmed'],
  ['Audit backlog', '4', 'anchor due in 18s', 'confirmed'],
]

export function Overview() {
  return (
    <div>
      <p className="overview-intro">
        Twelve agents are bound to constitution <span className="mono">608508a9bd224290</span>. Four
        operating MACI lanes are clear. Three matters are in human deliberation. Drift across the
        bus, the gateway, and the worker is zero bytes; the constitution that compiled at 09:14 UTC
        is the same constitution serving traffic at this moment.
      </p>

      <div className="overview-stats">
        {STATS.map(([label, value, sub]) => (
          <Stat key={label} label={label} value={value} sub={sub} />
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
            {ACTIVE_CASES.map(([name, stage, lane, age, evidence, event, posture]) => (
              <tr key={name}>
                <td className="mono">{name}</td>
                <td>
                  <span className={`pill ${posture}`}>{stage}</span>
                </td>
                <td className="mono">{lane}</td>
                <td className="num">{age}</td>
                <td className="mono muted">{evidence}</td>
                <td>{event}</td>
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
          {QUEUES.map(([label, value, detail, posture]) => (
            <div className="queue-row" key={label}>
              <span className="queue-label">{label}</span>
              <span className={`queue-value ${posture === 'confirmed' ? 'ok' : ''}`}>{value}</span>
              <span className="queue-detail">{detail}</span>
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
            {[
              ['IV', '§164.502(b)', '702', '+18%', 'confirmed'],
              ['VII', 'EU AI Act §15(4)', '441', '+4%', 'confirmed'],
              ['II', 'SR 11-7 §V', '128', '-9%', 'partial'],
              ['IX', 'GDPR Art. 22', '88', '+22%', 'partial'],
              ['XI', 'Internal §3.4', '43', '+11%', 'blocked'],
            ].map(([art, cite, n, trend, posture]) => (
              <tr key={art}>
                <td className="mono">Art. {art}</td>
                <td className="mono muted">{cite}</td>
                <td className="num align-right">{n}</td>
                <td className="num muted">{trend}</td>
                <td>
                  <span className={`pill ${posture}`}>{posture}</span>
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
