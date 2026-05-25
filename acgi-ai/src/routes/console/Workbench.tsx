import { navigate } from '../../lib/navigate'

const workbenchStages = [
  {
    step: '01',
    title: 'Work queue',
    signal: 'Owner, risk, and next reversible action are visible first.',
    posture: 'partial',
    route: '/console/actions',
    cta: 'Open actions',
  },
  {
    step: '02',
    title: 'Trace graph',
    signal: 'Model calls, tools, handoffs, and guardrails read as one path.',
    posture: 'confirmed',
    route: '/console/bus',
    cta: 'Inspect traces',
  },
  {
    step: '03',
    title: 'Evaluation panel',
    signal: 'Dataset checks, AI review, and human labels sit beside the trace.',
    posture: 'partial',
    route: '/console/policies',
    cta: 'Review policy',
  },
  {
    step: '04',
    title: 'Human release gate',
    signal: 'Reviewer sees policy citations and gaps before privilege moves.',
    posture: 'blocked',
    route: '/console/deliberations',
    cta: 'Open reviews',
  },
  {
    step: '05',
    title: 'Evidence room',
    signal: 'Receipts, hashes, snapshots, and replay refs export with boundaries.',
    posture: 'confirmed',
    route: '/console/audit',
    cta: 'Open audit',
  },
] as const

const caseCards = [
  ['GOV-214', 'Claim launch copy', 'Needs legal claim matrix', 'blocked'],
  ['BUS-087', 'Trace regression', 'One orphan response under review', 'partial'],
  ['REL-031', 'Buyer proof packet', 'Hosted Storybook proof pending', 'partial'],
] as const

const evidenceRows = [
  ['Receipt', 'rcpt_608508a9', 'hash-chained'],
  ['Policy', 'EU AI Act Art. 14', 'human oversight'],
  ['Eval', 'offline regression set', '2 failures held'],
  ['Release', 'operator approval', 'not production proof'],
] as const

export function Workbench() {
  return (
    <div>
      <p className="overview-intro">
        A single operator path for governed agent work: queue the case, inspect the trace, compare
        evaluation signals, route human release, then export only bounded evidence. This is a local
        console blueprint for easier use, not production assurance.
      </p>

      <section className="overview-section workbench-console" aria-labelledby="workbench-map-h">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-map-h">
            Visual operator map
          </h2>
          <span className="c-meta">Blueprint · same console UI · no new dependency</span>
        </div>

        <ol className="workbench-console-map" aria-label="Governed agent workbench flow">
          {workbenchStages.map((stage) => (
            <li className="workbench-console-stage" key={stage.step}>
              <div className="workbench-console-step">
                <span className="c-meta">{stage.step}</span>
                <span className={`pill ${stage.posture}`}>{stage.title}</span>
              </div>
              <p>{stage.signal}</p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(stage.route)}
              >
                {stage.cta}
              </button>
            </li>
          ))}
        </ol>
      </section>

      <section className="overview-section" aria-labelledby="workbench-board-h">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-board-h">
            One screen for the next safe action
          </h2>
          <span className="c-meta">Queue → Trace → Evidence</span>
        </div>

        <div className="workbench-board">
          <div className="workbench-board-column">
            <span className="c-meta">Work queue</span>
            {caseCards.map(([id, title, detail, posture]) => (
              <article className="workbench-case" key={id}>
                <div>
                  <strong>{id}</strong>
                  <span className={`pill ${posture}`}>{posture}</span>
                </div>
                <h3>{title}</h3>
                <p>{detail}</p>
              </article>
            ))}
          </div>

          <div className="workbench-trace">
            <span className="c-meta" id="workbench-trace-h">
              Trace graph
            </span>
            {['Goal', 'Model call', 'Tool guardrail', 'Policy decision', 'Receipt'].map(
              (node, index) => (
                <div className="workbench-trace-node" key={node}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <strong>{node}</strong>
                </div>
              ),
            )}
          </div>

          <div className="workbench-board-column">
            <span className="c-meta">Evidence panel</span>
            <table className="c-table c-table-dense workbench-evidence">
              <tbody>
                {evidenceRows.map(([label, value, state]) => (
                  <tr key={label}>
                    <th>{label}</th>
                    <td className="mono">{value}</td>
                    <td>{state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="c-receipt">
              <strong>Claim boundary</strong>
              <span>
                Local UX blueprint only. Production deploy, hosted Storybook, legal, pentest, and
                manual accessibility proof remain external gates.
              </span>
              <code>platform-blueprint-ui-local</code>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
