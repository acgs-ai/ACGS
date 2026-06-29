import { navigate } from '../lib/navigate'
import './EvalMvp.css'

const ASTERISM = '⁂'

const GATES = [
  {
    number: '01',
    name: 'Dispatch gate',
    role: 'Policy check before dispatch',
    description:
      'Every agent action is evaluated against the active policy set before it can reach any tool. The gate checks actor identity, action type, arguments, and risk level. Only ALLOW decisions proceed.',
    detail: 'tool calls · cloud ops · code execution',
  },
  {
    number: '02',
    name: 'Audit gate',
    role: 'Decision Receipt emission',
    description:
      'A cryptographically signed Decision Receipt is emitted before the action executes. The receipt binds actor, action, arguments, policy snapshot, and timestamp into an append-only JSONL trail.',
    detail: 'Ed25519 signature · JSONL audit chain',
  },
  {
    number: '03',
    name: 'Consume gate',
    role: 'Single-use enforcement',
    description:
      'Each receipt is consumed exactly once. A persistent ledger with TTL pruning prevents replay. A reused or forged receipt produces DENY without retrying the policy check.',
    detail: 'replay detection · TTL prune · persistent ledger',
  },
]

const BENTO = [
  {
    cls: 'ev-bento-a',
    label: 'Fail closed',
    body: 'Execution aborts without a valid signed receipt. No receipt, no side effect — the gap is never papered over.',
  },
  {
    cls: 'ev-bento-b',
    label: 'Zero runtime deps',
    body: 'Core depends only on stdlib. Signing is an optional crypto extra.',
  },
  {
    cls: 'ev-bento-c',
    label: 'Audit before action',
    body: 'Every decision is logged before the action runs — not after, not on success.',
  },
  {
    cls: 'ev-bento-d',
    label: 'Anti-replay',
    body: 'Persistent consumption ledger prevents replayed or forged receipts from re-executing.',
  },
  {
    cls: 'ev-bento-e',
    label: 'Framework neutral',
    body: 'Works as a standalone decorator or via a governed MCP server — no framework lock-in.',
  },
  {
    cls: 'ev-bento-f',
    label: 'Observable',
    body: 'JSONL audit trail is machine-readable and designed for structured export and analysis.',
  },
]

const INTEGRATIONS = [
  { name: 'LangChain', note: 'via governed MCP server' },
  { name: 'AutoGPT', note: 'via tool-call wrapper' },
  { name: 'OpenAI Swarm', note: 'via executor decorator' },
  { name: 'Custom agents', note: 'via direct Python API' },
]

const PROOF_POINTS = [
  {
    state: 'shipped' as const,
    label: 'Dispatch → Audit → Consume pipeline',
    detail: '322 passing tests · ruff clean · mypy strict',
  },
  {
    state: 'shipped' as const,
    label: 'Ed25519 signed Decision Receipts',
    detail: 'Signing on by default; optional cryptography extra',
  },
  {
    state: 'shipped' as const,
    label: 'Single-use consumption ledger',
    detail: 'Persistent JSONL · TTL prune · replay detection',
  },
  {
    state: 'shipped' as const,
    label: 'Offline proof-pack verifier',
    detail: 'Verifies receipt chain without runtime access',
  },
  {
    state: 'gate' as const,
    label: 'Production deployment',
    detail: 'Pending: live Cloud Run + Cloudflare Pages deploy secrets',
  },
  {
    state: 'gate' as const,
    label: 'Independent security review',
    detail: 'Pending: third-party pentest before SOC 2 roadmap claims',
  },
]

/* ── SVG pipeline diagram ──────────────────────────────────────────────── */
function EvalPipeline() {
  return (
    <svg
      className="ev-pipeline-svg"
      viewBox="0 0 140 220"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      focusable="false"
    >
      {/* connector lines */}
      <path className="ev-pipe-line ev-pipe-line-1" pathLength={1} d="M 70 64 L 70 82" />
      <path className="ev-pipe-line ev-pipe-line-2" pathLength={1} d="M 70 130 L 70 148" />
      <path className="ev-pipe-line ev-pipe-line-3" pathLength={1} d="M 70 196 L 70 214" />

      {/* arrowheads */}
      <polygon className="ev-pipe-arrowhead ev-pipe-arrow-1" points="65,78 75,78 70,86" />
      <polygon className="ev-pipe-arrowhead ev-pipe-arrow-2" points="65,144 75,144 70,152" />
      <polygon className="ev-pipe-arrowhead ev-pipe-arrow-3" points="65,210 75,210 70,218" />

      {/* gate 01 — dispatch */}
      <rect className="ev-pipe-rect" x="12" y="20" width="116" height="44" rx="6" />
      <text className="ev-pipe-num" x="70" y="40" textAnchor="middle">
        01
      </text>
      <text className="ev-pipe-label" x="70" y="55" textAnchor="middle">
        dispatch gate
      </text>

      {/* gate 02 — audit */}
      <rect className="ev-pipe-rect" x="12" y="86" width="116" height="44" rx="6" />
      <text className="ev-pipe-num" x="70" y="106" textAnchor="middle">
        02
      </text>
      <text className="ev-pipe-label" x="70" y="121" textAnchor="middle">
        audit gate
      </text>

      {/* gate 03 — consume */}
      <rect className="ev-pipe-rect" x="12" y="152" width="116" height="44" rx="6" />
      <text className="ev-pipe-num" x="70" y="172" textAnchor="middle">
        03
      </text>
      <text className="ev-pipe-label" x="70" y="187" textAnchor="middle">
        consume gate
      </text>
    </svg>
  )
}

/* ── JSONL receipt code block ──────────────────────────────────────────── */
function ReceiptBlock() {
  return (
    <div className="ev-code-wrap">
      <div className="ev-code-header">
        <span className="ev-code-header-label ev-kw">receipt</span>
        <span className="ev-code-header-label ev-comment">{'// audit.jsonl'}</span>
      </div>
      <pre className="ev-code-block">
        <code>
          {'{\n'}
          {'  '}
          <span className="ev-kw">"decision"</span>
          {': '}
          <span className="ev-str">"ALLOW"</span>
          {',\n'}
          {'  '}
          <span className="ev-kw">"actor"</span>
          {'   : '}
          <span className="ev-str">"agent-1"</span>
          {',\n'}
          {'  '}
          <span className="ev-kw">"action"</span>
          {'  : '}
          <span className="ev-str">"write_file"</span>
          {',\n'}
          {'  '}
          <span className="ev-kw">"args"</span>
          {'    : { '}
          <span className="ev-kw">"path"</span>
          {': '}
          <span className="ev-str">"/tmp/out"</span>
          {' },\n'}
          {'  '}
          <span className="ev-kw">"policy"</span>
          {'  : '}
          <span className="ev-str">"v1.2.0-sha256-abc…"</span>
          {',\n'}
          {'  '}
          <span className="ev-kw">"issued_at"</span>
          {': '}
          <span className="ev-str">"2026-06-27T00:00Z"</span>
          {',\n'}
          {'  '}
          <span className="ev-kw">"sig"</span>
          {'     : '}
          <span className="ev-str">"ed25519:k7xQ…"</span>
          {'\n}'}
        </code>
      </pre>
    </div>
  )
}

/* ── guard() decorator code block ─────────────────────────────────────── */
function GuardBlock() {
  return (
    <div className="ev-code-wrap">
      <div className="ev-code-header">
        <span className="ev-code-header-label ev-kw">guard()</span>
        <span className="ev-code-header-label ev-comment">{'// decorator'}</span>
      </div>
      <pre className="ev-code-block">
        <code>
          <span className="ev-kw">from </span>
          <span className="ev-ident">acgs_governance_eval_mvp</span>
          <span className="ev-kw"> import </span>
          <span className="ev-ident">guard</span>
          {'\n\n'}
          <span className="ev-comment">@guard</span>
          {'\n'}
          <span className="ev-kw">async def </span>
          <span className="ev-ident">write_file</span>
          {'(path: str) -> None:\n'}
          {'    '}
          <span className="ev-comment"># blocked without valid receipt</span>
          {'\n'}
          {'    '}
          <span className="ev-kw">await </span>
          <span className="ev-ident">_unsafe_write</span>
          {'(path, content)\n\n'}
          <span className="ev-comment"># TOCTOU: check-then-act gap closed</span>
          {'\n'}
          <span className="ev-comment"># by binding policy at receipt time,</span>
          {'\n'}
          <span className="ev-comment"># not at evaluation time.</span>
        </code>
      </pre>
    </div>
  )
}

/* ── Main component ────────────────────────────────────────────────────── */
export function EvalMvp() {
  return (
    <div className="marketing ev-page">
      <a className="skip-link" href="#main-content">
        Skip to eval MVP content
      </a>

      {/* Nav */}
      <div className="shell">
        <nav className="m-nav" aria-label="Primary">
          <a
            className="m-brand"
            href="/"
            aria-label="ACGS home"
            onClick={(e) => {
              e.preventDefault()
              navigate('/')
            }}
          >
            <span>acgs</span>
            <span className="folio" aria-hidden>
              {ASTERISM}
            </span>
          </a>
          <div className="m-nav-links">
            <a
              href="/governance-patterns"
              onClick={(e) => {
                e.preventDefault()
                navigate('/governance-patterns')
              }}
            >
              Patterns
            </a>
            <a
              href="/products"
              onClick={(e) => {
                e.preventDefault()
                navigate('/products')
              }}
            >
              Products
            </a>
            <a
              href="/trust"
              onClick={(e) => {
                e.preventDefault()
                navigate('/trust')
              }}
            >
              Trust
            </a>
          </div>
          <a
            className="m-nav-cta"
            href="/products"
            onClick={(e) => {
              e.preventDefault()
              navigate('/products')
            }}
          >
            Explore products
          </a>
        </nav>
      </div>

      <main id="main-content" tabIndex={-1}>
        {/* ── Section 1: Hero ─────────────────────────────────────────── */}
        <div className="shell">
          <section className="ev-hero" aria-labelledby="ev-h1">
            <div className="ev-hero-copy">
              <div className="m-eyebrow">
                <span className="asterism">{ASTERISM}</span>
                <span>governance-eval-mvp · v0.1.0</span>
              </div>
              <h1 id="ev-h1" className="ev-h1">
                Three gates. <em className="u-em-rust">One receipt.</em> No trust violations.
              </h1>
              <p className="ev-lede">
                acgs-governance-eval-mvp evaluates every agent action through a sequential dispatch
                → audit → consume pipeline before it reaches your tools. Execution fails closed
                without a valid, signed Decision Receipt.
              </p>
              <div className="ev-hero-actions">
                <a
                  className="btn btn-primary"
                  href="/products"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/products')
                  }}
                >
                  Explore products
                </a>
                <span className="ev-install-pill">pip install acgs-governance-eval-mvp</span>
              </div>
            </div>
            <div className="ev-hero-diagram" aria-hidden="true">
              <EvalPipeline />
            </div>
          </section>
        </div>

        {/* ── Section 2: Three Sequential Gates ───────────────────────── */}
        <section className="ev-gates-section" aria-labelledby="ev-gates-h2">
          <div className="shell">
            <h2 id="ev-gates-h2" className="ev-section-h2">
              Three sequential gates
            </h2>
            <div className="ev-gates-grid">
              {GATES.map((gate) => (
                <article className="ev-gate" key={gate.number}>
                  <div className="ev-gate-number">{gate.number}</div>
                  <h3 className="ev-gate-name">{gate.name}</h3>
                  <div className="ev-gate-role">{gate.role}</div>
                  <p className="ev-gate-desc">{gate.description}</p>
                  <code className="ev-gate-detail">{gate.detail}</code>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* ── Section 3: Audit Chain ───────────────────────────────────── */}
        <div className="shell">
          <section className="ev-audit-section" aria-labelledby="ev-audit-h2">
            <div className="ev-audit-inner">
              <div className="ev-audit-copy">
                <div className="m-eyebrow">
                  <span>Audit chain</span>
                </div>
                <h2 id="ev-audit-h2" className="ev-section-h2">
                  Every decision is a record
                </h2>
                <p>
                  The audit gate emits a signed JSONL Decision Receipt before execution. The receipt
                  binds actor identity, action, policy snapshot, and timestamp — creating a
                  tamper-evident, append-only chain that survives environment restarts.
                </p>
                <ul className="ev-audit-facts">
                  <li>Ed25519 signature required by default</li>
                  <li>Receipt emitted before the action runs</li>
                  <li>JSONL append-only, portable across environments</li>
                  <li>Offline-verifiable via the proof-pack verifier</li>
                </ul>
              </div>
              <ReceiptBlock />
            </div>
          </section>
        </div>

        {/* ── Section 4: TOCTOU + guard() API ─────────────────────────── */}
        <section className="ev-toctou-section" aria-labelledby="ev-toctou-h2">
          <div className="shell">
            <div className="ev-toctou-inner">
              <div className="ev-toctou-copy">
                <div className="m-eyebrow">
                  <span>TOCTOU protection</span>
                </div>
                <h2 id="ev-toctou-h2" className="ev-section-h2">
                  Check-then-act <em className="u-em-rust">gap closed</em>
                </h2>
                <p>
                  Traditional permission checks suffer from time-of-check / time-of-use (TOCTOU)
                  races: policy is evaluated once, then action runs later under potentially
                  different conditions.
                </p>
                <p>
                  The <code className="ev-install-pill">@guard</code> decorator binds policy at
                  receipt time and ties execution to that specific receipt. A receipt cannot be used
                  twice, preventing drift between check and act.
                </p>
              </div>
              <GuardBlock />
            </div>
          </div>
        </section>

        {/* ── Section 5: Differentiators bento ────────────────────────── */}
        <div className="shell">
          <section className="ev-bento-section" aria-labelledby="ev-bento-h2">
            <h2 id="ev-bento-h2" className="ev-section-h2">
              Why it is different
            </h2>
            <div className="ev-bento-grid">
              {BENTO.map((cell) => (
                <div className={`ev-bento-cell ${cell.cls}`} key={cell.cls}>
                  <div className="ev-bento-cell-label">{cell.label}</div>
                  <p className="ev-bento-cell-body">{cell.body}</p>
                </div>
              ))}
            </div>
          </section>

          {/* ── Section 6: Integrations strip ───────────────────────── */}
          <section className="ev-integrations-section" aria-label="Framework integrations">
            <div className="ev-integrations-label">works with</div>
            <div className="ev-integrations-rail">
              {INTEGRATIONS.map((item) => (
                <div className="ev-integration-item" key={item.name}>
                  <span className="ev-integration-name">{item.name}</span>
                  <span className="ev-integration-note">{item.note}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* ── Section 7: Honest proof points ──────────────────────────── */}
        <section className="ev-proof-section" aria-labelledby="ev-proof-h2">
          <div className="shell">
            <h2 id="ev-proof-h2" className="ev-section-h2">
              What is shipped vs what is gated
            </h2>
            <p className="ev-proof-intro">
              This page names explicit evidence gates. Claims only move from ROADMAP to SHIPPED when
              independent proof exists.
            </p>
            <div className="ev-proof-grid">
              {PROOF_POINTS.map((item) => (
                <div className="ev-proof-item" key={item.label}>
                  <div
                    className={`ev-proof-badge ${
                      item.state === 'shipped' ? 'ev-proof-badge-shipped' : 'ev-proof-badge-gate'
                    }`}
                  >
                    {item.state === 'shipped' ? 'shipped' : 'gate pending'}
                  </div>
                  <div className="ev-proof-label">{item.label}</div>
                  <div className="ev-proof-detail">{item.detail}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Section 8: Install CTA ───────────────────────────────────── */}
        <section className="ev-cta-section" aria-labelledby="ev-cta-h2">
          <div className="shell">
            <h2 id="ev-cta-h2" className="ev-section-h2">
              Start evaluating agent actions
            </h2>
            <p className="ev-cta-intro">
              acgs-governance-eval-mvp is a source-installable Python package — PyPI release is on
              the roadmap. Add the governed MCP server to your agent framework, or decorate
              individual tool-call functions directly.
            </p>
            <div className="ev-install-cmd-block">
              <span className="ev-install-cmd-prefix">$</span>
              <code>pip install acgs-governance-eval-mvp</code>
            </div>
            <div className="ev-cta-actions">
              <a
                className="btn btn-primary"
                href="/products"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/products')
                }}
              >
                View all products
              </a>
              <a
                href="/governance-patterns"
                className="btn"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/governance-patterns')
                }}
              >
                Read governance patterns
              </a>
            </div>
          </div>
        </section>
      </main>

      <footer className="m-foot">
        <div className="m-foot-inner">
          <div>
            <div className="m-foot-mark">
              governance <em>{ASTERISM}</em> eval
            </div>
            <p className="m-foot-addr">
              {`acgs-governance-eval-mvp v0.1.0
Three gates. One receipt.
No trust violations.`}
            </p>
          </div>
          <div>
            <h4>Evaluate</h4>
            <ul>
              <li>
                <a href="/products">Products</a>
              </li>
              <li>
                <a
                  href="/governance-patterns"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/governance-patterns')
                  }}
                >
                  Governance patterns
                </a>
              </li>
              <li>
                <a
                  href="/failure-modes"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/failure-modes')
                  }}
                >
                  Failure modes
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4>Governance</h4>
            <ul>
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
                  href="/privacy"
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('/privacy')
                  }}
                >
                  Privacy
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4>Boundaries</h4>
            <ul>
              <li>v0.1.0 · evaluation MVP</li>
              <li>Not production-ready</li>
              <li>No compliance certification</li>
              <li>Fail closed by design</li>
            </ul>
          </div>
        </div>
        <div className="m-foot-inner m-foot-bar">
          <span>governance-eval · MMXXVI</span>
          <span>
            acgs <span className="hash">{ASTERISM}</span> hub
          </span>
        </div>
      </footer>
    </div>
  )
}
