import { ArrowRight, Menu, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useHashScroll } from '../lib/hashScroll'
import { navigate } from '../lib/navigate'
import {
  AGENT_FRAMEWORK_STARTER_KITS,
  ASSURANCE_INTAKE_LANES,
  FRAMEWORK_INTEGRATION_RAIL,
  HOSTED_STORYBOOK_RUNWAY,
  LAUNCH_PROOF_LANES,
  LIVE_VERIFIER_BLOCKER_LANES,
  OPERATOR_CHECKLIST,
  PLATFORM_REQUIREMENT_LANES,
  PRODUCTION_COMMAND_RAIL,
  PRODUCTION_CUTOVER_LANES,
  RELEASE_BLOCKER_QUEUE,
  RESEARCH_INPUTS,
  WORKBENCH_DECISION_RAIL,
  WORKBENCH_GUIDED_PATH,
  WORKBENCH_STAGES,
} from './workbench-content'

const ASTERISM = '⁂'

const capabilities = [
  {
    n: '01',
    title: 'Receipt gate before side effects',
    body:
      'An agent proposes an action; gove-zone evaluates a deterministic rule-set policy ' +
      'and issues a Decision Receipt. Executors run only when that specific receipt verifies.',
  },
  {
    n: '02',
    title: 'Tamper-evident receipts',
    body:
      'Every allow, denial, and transform is recorded before execution in a hash-chained ' +
      'audit log, so readers can detect edits, reordering, or truncation of the local chain.',
  },
  {
    n: '03',
    title: 'Replayable, bounded proof',
    body:
      'Replay verifies the recorded receipt, policy binding, and audit chain. It is local ' +
      'runtime evidence, not production approval, tool sandboxing, or certification.',
  },
]

const coverage = [
  ['allowed_action_executed', 'Valid ALLOW receipt lets the safe action execute.', 'pass'],
  ['denied_action_blocked', 'Denied action is blocked before the side effect.', 'pass'],
  ['transformed_action_executed', 'TRANSFORM runs only with approved arguments.', 'pass'],
  ['missing_receipt_blocked', 'No receipt means no execution.', 'pass'],
  ['tampered_receipt_blocked', 'Receipt tampering is refused at the gate.', 'pass'],
  ['audit_chain_verified', 'The emitted local audit chain verifies.', 'pass'],
]

const launchDockets = [
  {
    tag: 'Package',
    name: 'gove-zone alpha',
    state: 'source workspace',
    feat: false,
    bullets: [
      'Developed as a local workspace package',
      'Not yet published to PyPI',
      'Kernel modules: decision → receipt → audit → replay',
      'Deterministic policy bundles / rule-set policy',
      'Operators provide the tool sandbox',
    ],
    cta: 'Read the spec',
  },
  {
    tag: 'Evidence',
    name: 'Proof pack',
    state: 'local pass',
    feat: true,
    bullets: [
      'Safe action executes after valid receipt',
      'Denied, missing, and tampered receipts block',
      'Transformed arguments bind exactly',
      'Hash-chained local audit verifies',
      'Proof is local runtime evidence only',
    ],
    cta: 'Inspect the proof',
  },
  {
    tag: 'Release',
    name: 'Public gates',
    state: 'blocked until true',
    feat: false,
    bullets: [
      'Publish to PyPI or document from-source install',
      'Re-run proofpack on the release commit',
      'Re-run the full gove-zone and CaLegal suites',
      'Attach the proofpack bundle as release evidence',
      'Keep Ed25519 and MACI caveats with the claims',
    ],
    cta: 'Review gates',
  },
]

export function Marketing() {
  const [navOpen, setNavOpen] = useState(false)
  const closeNav = () => setNavOpen(false)

  useHashScroll()

  useEffect(() => {
    if (typeof window === 'undefined') return
    const close = () => setNavOpen(false)
    window.addEventListener('hashchange', close)
    return () => window.removeEventListener('hashchange', close)
  }, [])

  return (
    <div className="marketing">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <div className="shell">
        <nav className={`m-nav${navOpen ? ' is-open' : ''}`} aria-label="Primary">
          <a className="m-brand" href="/" aria-label="ACGS home">
            <span>acgs</span>
            <span className="folio" aria-hidden>
              {ASTERISM}
            </span>
          </a>
          <button
            type="button"
            className="m-nav-toggle"
            aria-expanded={navOpen}
            aria-controls="m-nav-links"
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            onClick={() => setNavOpen((v) => !v)}
          >
            {navOpen ? <X size={18} strokeWidth={1.8} /> : <Menu size={18} strokeWidth={1.8} />}
          </button>
          <div className="m-nav-links" id="m-nav-links">
            <a href="#capabilities">Platform</a>
            <a href="#workbench">Workbench</a>
            <a href="#coverage">Coverage</a>
            <a
              href="/products"
              onClick={(e) => {
                e.preventDefault()
                closeNav()
                navigate('/products')
              }}
            >
              Products
            </a>
            <a href="#pricing">Release gates</a>
            <a
              href="/console"
              onClick={(e) => {
                e.preventDefault()
                closeNav()
                navigate('/console')
              }}
            >
              Console
            </a>
            <a
              href="/login"
              onClick={(e) => {
                e.preventDefault()
                closeNav()
                navigate('/login')
              }}
            >
              Sign in
            </a>
          </div>
          <a className="m-nav-cta" href="#book">
            Review proof <ArrowRight size={14} strokeWidth={1.75} />
          </a>
        </nav>

        <main id="main-content" tabIndex={-1}>
          <header className="m-hero">
            <div>
              <span className="m-eyebrow">
                <span className="asterism" aria-hidden>
                  {ASTERISM}
                </span>
                ACGS launch thesis · gove-zone alpha package
              </span>
              <h1>
                Agents can reason freely. They cannot <em>execute</em> freely.
              </h1>
              <p className="m-hero-lede">
                ACGS is the umbrella project. gove-zone is its alpha runtime governance package for
                receipt-gated agent execution: no valid Decision Receipt, no side effect. It sits
                immediately before tools run; operators still own the sandbox, deployment controls,
                key custody, and external assurance.
              </p>
              <div className="m-hero-actions">
                <a className="btn btn-primary" href="#coverage">
                  Inspect the proofpack <ArrowRight size={16} strokeWidth={1.8} />
                </a>
                <a
                  className="btn btn-secondary"
                  href="/console/agents"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/console/agents')
                  }}
                >
                  Open the console
                </a>
              </div>
            </div>

            <aside className="m-hero-aside">
              <figure className="m-code">
                <figcaption className="m-code-head">
                  <span>gove-zone proofpack · local run</span>
                  <span>status: pass</span>
                </figcaption>
                <pre>
                  <span className="c">{'// Release evidence, not certification'}</span>
                  {'\n'}
                  {'{'}
                  {'\n'}
                  {'  '}
                  <span className="k">"status"</span>
                  {': '}
                  <span className="s">"pass"</span>
                  {','}
                  {'\n'}
                  {'  '}
                  <span className="k">"allowed_action_executed"</span>
                  {': true,'}
                  {'\n'}
                  {'  '}
                  <span className="k">"denied_action_blocked"</span>
                  {': true,'}
                  {'\n'}
                  {'  '}
                  <span className="k">"missing_receipt_blocked"</span>
                  {': true,'}
                  {'\n'}
                  {'  '}
                  <span className="k">"tampered_receipt_blocked"</span>
                  {': true,'}
                  {'\n'}
                  {'  '}
                  <span className="k">"audit_chain_verified"</span>
                  {': true'}
                  {'\n'}
                  {'}'}
                </pre>
              </figure>
              <blockquote className="m-pull">
                The claim is narrow by design: a receipt gate before side effects, with local
                proofpack evidence and explicit limits. It is not a production, compliance, or
                third-party assurance claim.
                <cite>— gove-zone security boundary</cite>
              </blockquote>
            </aside>
          </header>

          <div className="m-break" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          {/* Capabilities */}
          <section id="capabilities" aria-labelledby="cap-h">
            <p className="m-product-definition">
              ACGS leads externally; gove-zone is the package you run. The present-tense claim is
              deliberately narrow: an alpha runtime governance plane for receipt-gated agent
              execution.
            </p>
            <div className="m-sec-head">
              <span className="num">I · Platform</span>
              <h2 id="cap-h">
                A <em>receipt gate</em> before agent side effects.
              </h2>
            </div>

            <div className="m-cards">
              {capabilities.map((c) => (
                <article className="m-card" key={c.n}>
                  <span className="folio-no">№ {c.n}</span>
                  <h3>{c.title}</h3>
                  <p>{c.body}</p>
                </article>
              ))}
            </div>
          </section>

          <div className="m-break" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          {/* Workbench blueprint */}
          <section id="workbench" aria-labelledby="workbench-h">
            <div className="m-sec-head">
              <span className="num">II · Workbench</span>
              <h2 id="workbench-h">
                Visualized <em>work</em>, not another wall of settings.
              </h2>
            </div>
            <div className="m-workbench">
              <ol className="m-workbench-map" aria-label="Visualized operator workflow">
                {WORKBENCH_STAGES.map((stage) => (
                  <li className="m-workbench-stage" key={stage.step}>
                    <span className="stage-step">{stage.step}</span>
                    <h3>{stage.title}</h3>
                    <p className="stage-signal">{stage.signal}</p>
                    <p>{stage.body}</p>
                  </li>
                ))}
              </ol>

              <aside className="m-workbench-panel" aria-label="Research-backed UI inputs">
                <span className="folio-no">Research inputs</span>
                <h3>What a leading agent-governance platform should make easy.</h3>
                <p>
                  The UI should make risky work inspectable in one pass: queue, trace, evaluation,
                  release, and export. The claim is a product blueprint, not certification or live
                  assurance.
                </p>
                <ul>
                  {RESEARCH_INPUTS.map(({ source, cue }) => (
                    <li key={source}>
                      <strong>{source}</strong>
                      <span>{cue}</span>
                    </li>
                  ))}
                </ul>
                <section
                  className="m-workbench-requirements"
                  aria-labelledby="marketing-platform-requirements-h"
                >
                  <span className="folio-no" id="marketing-platform-requirements-h">
                    Platform requirements
                  </span>
                  <ol>
                    {PLATFORM_REQUIREMENT_LANES.map(({ pillar, title, proof, source }) => (
                      <li key={pillar}>
                        <strong>{pillar}</strong>
                        <span>{title}</span>
                        <code>{proof}</code>
                        <small>{source}</small>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-framework"
                  aria-labelledby="marketing-framework-rail-h"
                >
                  <span className="folio-no" id="marketing-framework-rail-h">
                    Framework integration rail
                  </span>
                  <p>
                    Agent-framework adoption should be visible as normalize, gate, receipt, and
                    adopt steps before anyone treats local adapter proof as live integration proof.
                  </p>
                  <ol>
                    {FRAMEWORK_INTEGRATION_RAIL.map(({ step, title, source, proof }) => (
                      <li key={title}>
                        <strong>{step}</strong>
                        <span>{title}</span>
                        <small>{source}</small>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-starters"
                  aria-labelledby="marketing-framework-starters-h"
                >
                  <span className="folio-no" id="marketing-framework-starters-h">
                    Agent framework starter kits
                  </span>
                  <p>
                    Adoption starts from a concrete payload, local gate command, and receipt proof
                    before anyone claims live framework deployment.
                  </p>
                  <ol>
                    {AGENT_FRAMEWORK_STARTER_KITS.map(({ framework, entry, command, proof }) => (
                      <li key={framework}>
                        <strong>{framework}</strong>
                        <span>{entry}</span>
                        <code>{proof}</code>
                        <small>{command}</small>
                      </li>
                    ))}
                  </ol>
                </section>
                <section className="m-workbench-guided" aria-labelledby="marketing-guided-path-h">
                  <span className="folio-no" id="marketing-guided-path-h">
                    Guided review path
                  </span>
                  <ol>
                    {WORKBENCH_GUIDED_PATH.map(({ step, title, instruction, proof }) => (
                      <li key={title}>
                        <strong>{step}</strong>
                        <span>{title}</span>
                        <p>{instruction}</p>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-decision"
                  aria-labelledby="marketing-decision-rail-h"
                >
                  <span className="folio-no" id="marketing-decision-rail-h">
                    Operator decision rail
                  </span>
                  <ol>
                    {WORKBENCH_DECISION_RAIL.map(({ step, title, prompt, proof }) => (
                      <li key={title}>
                        <strong>{step}</strong>
                        <span>{title}</span>
                        <p>{prompt}</p>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-checklist"
                  aria-labelledby="marketing-operator-start-h"
                >
                  <span className="folio-no" id="marketing-operator-start-h">
                    Operator quick start
                  </span>
                  <ol>
                    {OPERATOR_CHECKLIST.map(({ label, cue }) => (
                      <li key={label}>
                        <strong>{label}</strong>
                        <span>{cue}</span>
                      </li>
                    ))}
                  </ol>
                </section>
                <section className="m-workbench-proof" aria-labelledby="marketing-proof-ladder-h">
                  <span className="folio-no" id="marketing-proof-ladder-h">
                    Launch proof ladder
                  </span>
                  <ol>
                    {LAUNCH_PROOF_LANES.map(({ title, state, proof, cue }) => (
                      <li key={title}>
                        <strong>{title}</strong>
                        <code>{proof}</code>
                        <span>{state}</span>
                        <span>{cue}</span>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-cutover"
                  aria-labelledby="marketing-cutover-state-h"
                >
                  <span className="folio-no" id="marketing-cutover-state-h">
                    Current saved cutover state
                  </span>
                  <p>
                    safeToClaimProduction=false · saved live verifier: 2 pass, 6 fail · local state
                    is not production proof.
                  </p>
                  <ol>
                    {PRODUCTION_CUTOVER_LANES.map(({ title, state, proof }) => (
                      <li key={title}>
                        <strong>{title}</strong>
                        <span>{state}</span>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-blockers"
                  aria-labelledby="marketing-release-blockers-h"
                >
                  <span className="folio-no" id="marketing-release-blockers-h">
                    Release blocker queue
                  </span>
                  <p>
                    The launch path stays easy to act on by pairing every external blocker with an
                    owner, artifact, and unblock command before any stronger claim is made.
                  </p>
                  <ol>
                    {RELEASE_BLOCKER_QUEUE.map(({ blockerId, owner, artifact, proof }) => (
                      <li key={blockerId}>
                        <strong>{owner}</strong>
                        <span>{blockerId}</span>
                        <code>{proof}</code>
                        <small>{artifact}</small>
                      </li>
                    ))}
                  </ol>
                </section>
                <section className="m-workbench-live" aria-labelledby="marketing-live-blockers-h">
                  <span className="folio-no" id="marketing-live-blockers-h">
                    Live verifier blocker map
                  </span>
                  <p>
                    The saved production preflight names each live DNS, service, header, HTTPS, and
                    hosted manifest blocker before any launch claim changes.
                  </p>
                  <ol>
                    {LIVE_VERIFIER_BLOCKER_LANES.map(({ title, blockerId, proof }) => (
                      <li key={blockerId}>
                        <strong>{title}</strong>
                        <span>{blockerId}</span>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
                <section className="m-workbench-command" aria-labelledby="marketing-command-rail-h">
                  <span className="folio-no" id="marketing-command-rail-h">
                    Production command rail
                  </span>
                  <p>
                    The launch path should show the local and read-only commands that refresh
                    blocker evidence before operators attach external proof.
                  </p>
                  <ol>
                    {PRODUCTION_COMMAND_RAIL.map(({ title, command, artifact }) => (
                      <li key={title}>
                        <strong>{title}</strong>
                        <code>{command}</code>
                        <span>{artifact}</span>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-storybook-runway"
                  aria-labelledby="marketing-storybook-runway-h"
                >
                  <span className="folio-no" id="marketing-storybook-runway-h">
                    Hosted Storybook runway
                  </span>
                  <p>
                    Buyer-evidence publication stays visible as build local gallery, enable Pages,
                    verify live Storybook, and attach hosted proof before the hosted blocker clears.
                  </p>
                  <ol>
                    {HOSTED_STORYBOOK_RUNWAY.map(({ step, title, command, proof }) => (
                      <li key={title}>
                        <strong>{step}</strong>
                        <span>{title}</span>
                        <code>{proof}</code>
                        <small>{command}</small>
                      </li>
                    ))}
                  </ol>
                </section>
                <section
                  className="m-workbench-assurance"
                  aria-labelledby="marketing-assurance-intake-h"
                >
                  <span className="folio-no" id="marketing-assurance-intake-h">
                    Assurance proof intake
                  </span>
                  <p>
                    External blockers need attached proof before production, compliance,
                    accessibility, or hosted buyer-evidence claims.
                  </p>
                  <ol>
                    {ASSURANCE_INTAKE_LANES.map(({ title, state, proof }) => (
                      <li key={title}>
                        <strong>{title}</strong>
                        <span>{state}</span>
                        <code>{proof}</code>
                      </li>
                    ))}
                  </ol>
                </section>
              </aside>
            </div>
          </section>

          <div className="m-break" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          {/* Coverage */}
          <section id="coverage" aria-labelledby="cov-h">
            <div className="m-sec-head">
              <span className="num">III · Proof pack</span>
              <h2 id="cov-h">
                Local proof says <em>pass</em>, with boundaries attached.
              </h2>
            </div>
            <div className="m-coverage">
              <table>
                <thead>
                  <tr>
                    <th>Check</th>
                    <th>What it demonstrates</th>
                    <th>Current result</th>
                  </tr>
                </thead>
                <tbody>
                  {coverage.map((row) => (
                    <tr key={row[0]}>
                      <td>{row[0]}</td>
                      <td>{row[1]}</td>
                      <td>{row[2]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="m-break" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          {/* Release gates */}
          <section id="pricing" aria-labelledby="pricing-h">
            <div className="m-sec-head">
              <span className="num">IV · Release gates</span>
              <h2 id="pricing-h">
                Ship the <em>evidence</em>, not an adjective.
              </h2>
            </div>
            <div className="m-pricing">
              {launchDockets.map((t) => (
                <article className={`m-tier ${t.feat ? 'feat' : ''}`} key={t.name}>
                  <span className="t-tag">{t.tag}</span>
                  <h3 className="t-name">{t.name}</h3>
                  <div className="t-price">
                    <span className="t-price-num">{t.state}</span>
                  </div>
                  <hr />
                  <ul>
                    {t.bullets.map((b) => (
                      <li key={b}>{b}</li>
                    ))}
                  </ul>
                  <a className="btn btn-primary" href="#book">
                    {t.cta} <ArrowRight size={15} strokeWidth={1.8} />
                  </a>
                </article>
              ))}
            </div>
          </section>

          <div className="m-break" id="book" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          <section aria-labelledby="book-h">
            <div className="m-sec-head">
              <span className="num">V · Conversation</span>
              <h2 id="book-h">
                Review the <em>receipt path</em> before the launch.
              </h2>
            </div>
            <div className="m-conversation">
              <p>
                Bring the commit, proofpack bundle, and claims map. The review should name exactly
                which side effects are receipt-gated today, which caveats travel with the claim, and
                which release gates remain blocked before stronger public wording ships.
              </p>
              <p className="m-conversation-follow">
                Mail{' '}
                <a className="m-text-link" href="mailto:matters@acgs.ai">
                  matters@acgs.ai
                </a>{' '}
                with a subject line that begins <code>[matter]</code>.
              </p>
            </div>
          </section>
        </main>
      </div>

      <footer className="m-foot">
        <div className="m-foot-inner">
          <div>
            <div className="m-foot-mark">
              acgs <em>{ASTERISM}</em>
            </div>
            <div className="m-foot-addr">
              {`ACGS / gove-zone
Alpha runtime governance plane.

No valid Decision Receipt,
no side effect.`}
            </div>
          </div>
          <div>
            <h4>Platform</h4>
            <ul>
              <li>
                <a href="#capabilities">Capabilities</a>
              </li>
              <li>
                <a href="#coverage">Coverage</a>
              </li>
              <li>
                <a href="#pricing">Release gates</a>
              </li>
              <li>
                <a
                  href="/products"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/products')
                  }}
                >
                  Product atlas
                </a>
              </li>
              <li>
                <a
                  href="/console/agents"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/console/agents')
                  }}
                >
                  Console
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4>Dockets</h4>
            <ul>
              <li>gove-zone alpha</li>
              <li>Proof pack</li>
              <li>Release gates</li>
              <li>CaLegal companion</li>
              <li>Legal claim review</li>
            </ul>
          </div>
          <div>
            <h4>Reading room</h4>
            <ul>
              <li>
                <a
                  href="/privacy"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/privacy')
                  }}
                >
                  Privacy &amp; subprocessors
                </a>
              </li>
              <li>
                <a
                  href="/trust"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/trust')
                  }}
                >
                  Trust center
                </a>
              </li>
              <li>
                <a
                  href="/security"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/security')
                  }}
                >
                  Security
                </a>
              </li>
              <li>
                <a
                  href="/console/audit"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/console/audit')
                  }}
                >
                  Audit trail
                </a>
              </li>
              <li>
                <a
                  href="/console/compile"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/console/compile')
                  }}
                >
                  Change history
                </a>
              </li>
              <li>
                <a href="#coverage">Statute index</a>
              </li>
              <li>
                <a href="/static/fonts/OFL.txt" target="_blank" rel="noopener">
                  Font licenses
                </a>
              </li>
              <li>
                <a
                  href="/login"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/login')
                  }}
                >
                  Sign in
                </a>
              </li>
            </ul>
          </div>
        </div>
        <div className="shell">
          <div className="m-foot-bar">
            <span>v3.1.0 · Vol. I · MMXXVI</span>
            <span>
              hash <span className="hash">608508a9bd224290</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  )
}
