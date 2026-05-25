import { useHashScroll } from '../../lib/hashScroll'
import { navigate } from '../../lib/navigate'
import {
  CASE_CARDS,
  EVIDENCE_ROWS,
  LAUNCH_PROOF_LANES,
  OPERATOR_CHECKLIST,
  WORKBENCH_DECISION_RAIL,
  WORKBENCH_GUIDED_PATH,
  WORKBENCH_STAGES,
} from '../workbench-content'

export function Workbench() {
  useHashScroll()

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
          {WORKBENCH_STAGES.map((stage) => (
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
            {CASE_CARDS.map(({ id, title, detail, posture }) => (
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
                {EVIDENCE_ROWS.map(({ label, value, state }) => (
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

      <section
        className="overview-section"
        id="guided-review-path"
        aria-labelledby="workbench-guided-h"
      >
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-guided-h">
            Guided review path
          </h2>
          <span className="c-meta">Choose → Trace → Check → Export</span>
        </div>

        <div className="workbench-guided-path">
          {WORKBENCH_GUIDED_PATH.map((item) => (
            <article className="workbench-guided" key={item.title}>
              <div>
                <span className="workbench-guided-step">{item.step}</span>
                <code>{item.proof}</code>
              </div>
              <h3>{item.title}</h3>
              <p>{item.instruction}</p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(item.route)}
              >
                {item.cta}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section
        className="overview-section"
        id="operator-decision-rail"
        aria-labelledby="workbench-decision-h"
      >
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-decision-h">
            Operator decision rail
          </h2>
          <span className="c-meta">Pick → Inspect → Decide</span>
        </div>

        <div className="workbench-decision-rail">
          {WORKBENCH_DECISION_RAIL.map((item) => (
            <article className="workbench-decision" key={item.title}>
              <div>
                <span className="workbench-decision-step">{item.step}</span>
                <span className="c-meta">{item.proof}</span>
              </div>
              <h3>{item.title}</h3>
              <p>{item.prompt}</p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(item.route)}
              >
                {item.cta}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section className="overview-section" aria-labelledby="workbench-checklist-h">
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-checklist-h">
            Operator quick start
          </h2>
          <span className="c-meta">Start here → Hold release → Export proof</span>
        </div>

        <div className="workbench-checklist">
          {OPERATOR_CHECKLIST.map((item) => (
            <article className="workbench-check" key={item.label}>
              <div>
                <span className="c-meta">{item.label}</span>
                <code>{item.proof}</code>
              </div>
              <p>{item.body}</p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(item.route)}
              >
                {item.cta}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section
        className="overview-section"
        id="launch-proof-ladder"
        aria-labelledby="workbench-proof-h"
      >
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-proof-h">
            Launch proof ladder
          </h2>
          <span className="c-meta">Local → Live → Assured</span>
        </div>

        <div className="workbench-proof-ladder">
          {LAUNCH_PROOF_LANES.map((lane) => (
            <article className="workbench-proof" key={lane.title}>
              <div>
                <span className="c-meta">{lane.title}</span>
                <strong>{lane.state}</strong>
                <code>{lane.proof}</code>
              </div>
              <p>{lane.body}</p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(lane.route)}
              >
                {lane.cta}
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}
