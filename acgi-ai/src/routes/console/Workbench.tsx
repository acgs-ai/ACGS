import { useHashScroll } from '../../lib/hashScroll'
import { navigate } from '../../lib/navigate'
import {
  ASSURANCE_INTAKE_LANES,
  CASE_CARDS,
  EVIDENCE_ROWS,
  FRAMEWORK_INTEGRATION_RAIL,
  LAUNCH_PROOF_LANES,
  LIVE_VERIFIER_BLOCKER_LANES,
  OPERATOR_CHECKLIST,
  PLATFORM_REQUIREMENT_LANES,
  PRODUCTION_COMMAND_RAIL,
  PRODUCTION_CUTOVER_LANES,
  RELEASE_BLOCKER_QUEUE,
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

      <section
        className="overview-section"
        id="platform-requirements"
        aria-labelledby="workbench-requirements-h"
      >
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-requirements-h">
            Platform requirements
          </h2>
          <span className="c-meta">Framework → control → proof</span>
        </div>

        <div className="workbench-requirement-grid">
          {PLATFORM_REQUIREMENT_LANES.map((lane) => (
            <article className="workbench-requirement" key={lane.pillar}>
              <div>
                <span className="workbench-requirement-pillar">{lane.pillar}</span>
                <span className="c-meta">{lane.source}</span>
              </div>
              <h3>{lane.title}</h3>
              <p>
                <strong>{lane.question}</strong>
                <span>{lane.visual}</span>
              </p>
              <code>{lane.proof}</code>
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

      <section
        className="overview-section"
        id="framework-integration-rail"
        aria-labelledby="workbench-framework-h"
      >
        <div className="c-toolbar">
          <h2 className="overview-section-title" id="workbench-framework-h">
            Framework integration rail
          </h2>
          <span className="c-meta">Normalize → Gate → Receipt → Adopt</span>
        </div>

        <div className="workbench-framework-rail">
          {FRAMEWORK_INTEGRATION_RAIL.map((item) => (
            <article className="workbench-framework" key={item.title}>
              <div>
                <span className="workbench-framework-step">{item.step}</span>
                <span className="c-meta">{item.source}</span>
              </div>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
              <code>{item.proof}</code>
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

        <section className="workbench-cutover-summary" aria-labelledby="workbench-cutover-h">
          <div>
            <span className="c-meta" id="workbench-cutover-h">
              Current saved cutover state
            </span>
            <strong>safeToClaimProduction=false</strong>
            <p>
              Saved live verifier: 2 pass, 6 fail, cutoverDelta=blocked-live-cutover. Treat these
              lanes as the next operator checklist, not production proof.
            </p>
          </div>
          <div className="workbench-cutover-lanes">
            {PRODUCTION_CUTOVER_LANES.map((lane) => (
              <article className="workbench-cutover" key={lane.title}>
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

        <section
          className="workbench-blocker-summary"
          id="release-blocker-queue"
          aria-labelledby="workbench-release-blockers-h"
        >
          <div>
            <span className="c-meta" id="workbench-release-blockers-h">
              Release blocker queue
            </span>
            <strong>Every external blocker has an owner, artifact, and unblock command.</strong>
            <p>
              This queue turns the blocked preflight into an operator handoff. It does not clear
              production, legal, security, accessibility, or hosted proof until the named artifact
              is attached and verified.
            </p>
          </div>
          <div className="workbench-blocker-lanes">
            {RELEASE_BLOCKER_QUEUE.map((blocker) => (
              <article className="workbench-release-blocker" key={blocker.blockerId}>
                <div>
                  <span className="c-meta">{blocker.owner}</span>
                  <strong>{blocker.blockerId}</strong>
                  <code>{blocker.proof}</code>
                </div>
                <h3>{blocker.title}</h3>
                <p>{blocker.action}</p>
                <small>{blocker.artifact}</small>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => navigate(blocker.route)}
                >
                  {blocker.cta}
                </button>
              </article>
            ))}
          </div>
        </section>

        <section
          className="workbench-live-summary"
          id="live-verifier-blocker-map"
          aria-labelledby="workbench-live-blockers-h"
        >
          <div>
            <span className="c-meta" id="workbench-live-blockers-h">
              Live verifier blocker map
            </span>
            <strong>Every failed live check stays visible until verified.</strong>
            <p>
              These blocker ids come from the saved production preflight. They are deploy actions,
              not local proof, and must clear before the production evidence validator can pass.
            </p>
          </div>
          <div className="workbench-live-lanes">
            {LIVE_VERIFIER_BLOCKER_LANES.map((lane) => (
              <article className="workbench-live-blocker" key={lane.blockerId}>
                <div>
                  <span className="c-meta">{lane.title}</span>
                  <strong>{lane.blockerId}</strong>
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

        <section
          className="workbench-command-summary"
          id="production-command-rail"
          aria-labelledby="workbench-command-rail-h"
        >
          <div>
            <span className="c-meta" id="workbench-command-rail-h">
              Production command rail
            </span>
            <strong>Run the proof commands in order, then attach the artifacts.</strong>
            <p>
              These commands are local or read-only verification steps. They do not deploy, mutate
              DNS, approve claims, or create external assurance proof.
            </p>
          </div>
          <div className="workbench-command-lanes">
            {PRODUCTION_COMMAND_RAIL.map((item) => (
              <article className="workbench-command" key={item.title}>
                <div>
                  <span className="c-meta">{item.title}</span>
                  <code>{item.command}</code>
                  <small>{item.artifact}</small>
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
          className="workbench-assurance-summary"
          id="assurance-proof-intake"
          aria-labelledby="workbench-assurance-h"
        >
          <div>
            <span className="c-meta" id="workbench-assurance-h">
              Assurance proof intake
            </span>
            <strong>External blockers need attached proof, not local promises.</strong>
            <p>
              These are the proof packets required before production, compliance, accessibility, or
              hosted buyer-evidence claims can replace blockers.
            </p>
          </div>
          <div className="workbench-assurance-lanes">
            {ASSURANCE_INTAKE_LANES.map((lane) => (
              <article className="workbench-assurance" key={lane.title}>
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
      </section>
    </div>
  )
}
