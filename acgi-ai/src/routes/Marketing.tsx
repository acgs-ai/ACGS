import { ArrowRight } from 'lucide-react'
import { navigate } from '../lib/navigate'

const ASTERISM = '⁂'

const capabilities = [
  {
    n: '01',
    title: 'Constitutions that compile',
    body:
      'Author the rules in plain prose with citations to primary sources. ' +
      'The compiler emits an enforceable runtime artifact, signed by hash, ' +
      'that the bus refuses to load if it has drifted by a single byte.',
  },
  {
    n: '02',
    title: 'Separation of powers',
    body:
      'Proposer, Validator, and Executor are distinct lanes. No agent ' +
      'validates its own output; no model is trusted to mark its own work. ' +
      'MACI separation is structural, not advisory.',
  },
  {
    n: '03',
    title: 'Fail closed',
    body:
      'When the policy engine cannot reach a decision, the action is denied. ' +
      'There is no fail-open branch in the bus, the gateway, or the worker. ' +
      'Every refusal is recorded with a citation and a hash.',
  },
]

const coverage = [
  ['EU AI Act', 'Art. 9 risk · Art. 14 oversight · Art. 15(4) accuracy', 'v1.0'],
  ['SR 11-7', '§V model risk · §VII validation · §VIII development', 'v2011'],
  ['HIPAA', '§164.502 minimum necessary · §164.514 de-identification', 'v2024'],
  ['GDPR', 'Art. 22 automated decisions · Art. 25 by-design', 'v2018'],
  ['SOC 2', 'CC6 logical access · CC7 system operations', 'v2017'],
  ['ISO/IEC 42001', 'Cl. 8 operations · Cl. 9 evaluation', 'v2023'],
]

const tiers = [
  {
    tag: 'Open',
    name: 'Foundation',
    price: '0',
    unit: '/ self-hosted',
    feat: false,
    bullets: [
      'acgs-lite SDK, full source',
      'Constitution compiler + audit log',
      'MACI separation primitives',
      'Single-tenant, single environment',
      'Community channel support',
    ],
    cta: 'Read the spec',
  },
  {
    tag: 'Team',
    name: 'Governed',
    price: '4,800',
    unit: '/ month',
    feat: true,
    bullets: [
      'Hosted enhanced agent bus',
      'Five governed agents, two custodial roles',
      'EU AI Act + SR 11-7 + HIPAA modules',
      'Constitutional hash attestation',
      'Eight-hour incident response SLA',
    ],
    cta: 'Schedule a review',
  },
  {
    tag: 'Enterprise',
    name: 'Sovereign',
    price: 'On request',
    unit: '',
    feat: false,
    bullets: [
      'Federated bus across regions',
      'Air-gapped deployment supported',
      'Dafny / MACI proof artifacts',
      'Privilege-boundary attestation',
      'Named architect + 24/7 paging',
    ],
    cta: 'Schedule a review',
  },
]

export function Marketing() {
  return (
    <div className="marketing">
      <div className="shell">
        <nav className="m-nav" aria-label="Primary">
          <a className="m-brand" href="/" aria-label="ACGS home">
            <span>acgs</span>
            <span className="folio" aria-hidden>
              {ASTERISM}
            </span>
          </a>
          <div className="m-nav-links">
            <a href="#capabilities">Platform</a>
            <a href="#coverage">Coverage</a>
            <a href="#pricing">Pricing</a>
            <a
              href="/console"
              onClick={(e) => {
                e.preventDefault()
                navigate('/console')
              }}
            >
              Console
            </a>
            <a
              href="/login"
              onClick={(e) => {
                e.preventDefault()
                navigate('/login')
              }}
            >
              Sign in
            </a>
          </div>
          <a className="m-nav-cta" href="#book">
            Schedule a review <ArrowRight size={14} strokeWidth={1.75} />
          </a>
        </nav>

        <header className="m-hero">
          <div>
            <span className="m-eyebrow">
              <span className="asterism" aria-hidden>
                {ASTERISM}
              </span>
              Vol. I · Constitutional governance for AI agents
            </span>
            <h1>
              The publishing house that ships <em>governance</em>.
            </h1>
            <p className="m-hero-lede">
              ACGS turns regulatory prose — the EU AI Act, SR 11-7, HIPAA, GDPR — into runtime
              artifacts your agent cannot ignore. Constitutions are authored, compiled, hashed, and
              enforced. Every refusal carries a citation. Every approval carries a signature.
            </p>
            <div className="m-hero-actions">
              <a className="btn btn-primary" href="#book">
                Schedule a review <ArrowRight size={16} strokeWidth={1.8} />
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
                <span>constitution.acgs · v3.1.0</span>
                <span>608508a9bd224290</span>
              </figcaption>
              <pre>
                <span className="c">{'// Article IV — Privileged work product'}</span>
                {'\n'}
                <span className="k">rule</span> <span className="s">"matter.disclosure"</span> {'{'}
                {'\n'}
                {'  '}
                <span className="k">when</span>
                {'  agent.role == '}
                <span className="s">"public"</span>
                {'\n'}
                {'  '}
                <span className="k">when</span>
                {'  payload.contains('}
                <span className="s">"matter_id"</span>
                {')'}
                {'\n'}
                {'  '}
                <span className="k">deny</span>
                {'  '}
                <span className="s">"privilege boundary"</span>
                {'\n'}
                {'  '}
                <span className="k">cite</span>
                {'  '}
                <span className="s">"§164.502(b)"</span>
                {'\n'}
                {'}'}
              </pre>
            </figure>
            <blockquote className="m-pull">
              The page is a poster, not a document. Every refusal we emit is countersigned by a
              section number from a primary source.
              <cite>— ACGS, Decisions Log §3</cite>
            </blockquote>
          </aside>
        </header>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* Capabilities */}
        <section id="capabilities" aria-labelledby="cap-h">
          <p className="m-product-definition">
            ACGS is a policy compiler and enforcement layer for regulated AI agents, binding
            citations, roles, and refusal rules into the runtime path.
          </p>
          <div className="m-sec-head">
            <span className="num">I · Platform</span>
            <h2 id="cap-h">
              An <em>operating constitution</em> for systems that decide on behalf of people.
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

        {/* Coverage */}
        <section id="coverage" aria-labelledby="cov-h">
          <div className="m-sec-head">
            <span className="num">II · Coverage</span>
            <h2 id="cov-h">
              <em>Cited</em>, not claimed.
            </h2>
          </div>
          <div className="m-coverage">
            <table>
              <thead>
                <tr>
                  <th>Framework</th>
                  <th>Sections enforced</th>
                  <th>Version</th>
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

        {/* Pricing */}
        <section id="pricing" aria-labelledby="pricing-h">
          <div className="m-sec-head">
            <span className="num">III · Pricing</span>
            <h2 id="pricing-h">
              Three editions. <em>One</em> constitutional hash.
            </h2>
          </div>
          <div className="m-pricing">
            {tiers.map((t) => (
              <article className={`m-tier ${t.feat ? 'feat' : ''}`} key={t.name}>
                <span className="t-tag">{t.tag}</span>
                <h3 className="t-name">{t.name}</h3>
                <div className="t-price">
                  <span className="t-price-num">
                    {t.price.startsWith('On') ? t.price : `$${t.price}`}
                  </span>
                  <span className="t-price-unit">{t.unit}</span>
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
            <span className="num">IV · Conversation</span>
            <h2 id="book-h">
              We schedule by <em>matter</em>, not by funnel stage.
            </h2>
          </div>
          <div className="m-conversation">
            <p>
              Tell us what you are deploying, which framework you answer to, and which decisions an
              agent has to make on your behalf. We will send back a one-page reading that names the
              rules we would compile and the refusals we would emit. No deck. No funnel.
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
      </div>

      <footer className="m-foot">
        <div className="m-foot-inner">
          <div>
            <div className="m-foot-mark">
              acgs <em>{ASTERISM}</em>
            </div>
            <div className="m-foot-addr">
              {`Anthropic Constitutional Governance System
A monograph that runs in production.

Filed under: AI safety, regulated AI,
legal technology vertical.`}
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
                <a href="#pricing">Pricing</a>
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
            <h4>Editions</h4>
            <ul>
              <li>Foundation (open)</li>
              <li>Governed (team)</li>
              <li>Sovereign (enterprise)</li>
              <li>LegalGuard (vertical)</li>
              <li>ClinicalGuard (vertical)</li>
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
