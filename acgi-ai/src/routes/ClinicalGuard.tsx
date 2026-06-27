import { ArrowRight } from 'lucide-react'
import { navigate } from '../lib/navigate'

export function ClinicalGuard() {
  return (
    <div className="product-surface">
      <a className="skip-link" href="#cg-main">
        Skip to ClinicalGuard content
      </a>
      <div className="product-shell">
        {/* § 1 — Standalone product nav */}
        <nav className="product-nav" aria-label="ClinicalGuard page navigation">
          <a
            className="cg-nav-brand"
            href="/"
            onClick={(e) => {
              e.preventDefault()
              navigate('/')
            }}
          >
            acgs <span className="cg-nav-asterism">⁂</span>
          </a>
          <div>
            <button type="button" onClick={() => navigate('/products')}>
              ← Products
            </button>
          </div>
        </nav>

        <main id="cg-main" tabIndex={-1}>
          {/* § 2 — Hero */}
          <header className="product-hero">
            <div className="product-hero-detail">
              {/* Left — editorial */}
              <div>
                <p className="product-eyebrow">
                  <span>⁂</span>
                  Clinical governance · Rule 01 of 04
                </p>
                <h1>
                  Clinical <em>decisions</em> need receipts
                </h1>
                <p>
                  ClinicalGuard enforces HIPAA-aligned policy before any PHI-adjacent agent action
                  executes. No valid Decision Receipt — no side effect. Every PHI access is gated,
                  audited, and traceable to a named approver.
                </p>
                <div className="product-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => navigate('/ask')}
                  >
                    Ask a governance question
                    <ArrowRight size={14} strokeWidth={1.75} />
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => navigate('/products')}
                  >
                    All products
                  </button>
                </div>
              </div>
              {/* Right — product docket */}
              <aside className="product-docket" aria-label="Clinical policy reference">
                <div className="cg-docket-head">
                  <span className="product-folio">clinicalguard v1.0</span>
                  <span className="cg-status-pill cg-status-pill--confirmed">CONFIRMED</span>
                </div>
                <dl>
                  <div>
                    <dt>Reference</dt>
                    <dd className="tabular">CG-2026-001</dd>
                  </div>
                  <div>
                    <dt>Constitutional hash</dt>
                    <dd className="tabular">cgv1:a7f3d8e2b5c09f14</dd>
                  </div>
                  <div>
                    <dt>Route</dt>
                    <dd>/products/clinicalguard</dd>
                  </div>
                  <div>
                    <dt>Audit ID</dt>
                    <dd className="tabular">audit:cg-2026-001-phi-check</dd>
                  </div>
                </dl>
              </aside>
            </div>
          </header>

          {/* § 3 — Stat cards */}
          <div className="cg-section">
            <div className="product-stat-grid">
              <article className="product-stat">
                <span className="product-folio">policy rules</span>
                <strong className="tabular">20</strong>
                <p>
                  HIPAA-aligned decision rules active across PHI access, storage, and transmission
                  actions.
                </p>
              </article>
              <article className="product-stat">
                <span className="product-folio">phi identifiers</span>
                <strong className="tabular">10 / 18</strong>
                <p>
                  Ten of the eighteen HIPAA Safe Harbor identifiers recognized and gated at the
                  input layer.
                </p>
              </article>
              <article className="product-stat">
                <span className="product-folio">confidence threshold</span>
                <strong className="tabular">0.90 / 0.65</strong>
                <p>
                  Hard approve at 0.90; conditional at 0.65. Below 0.65 the action is rejected
                  outright.
                </p>
              </article>
            </div>
          </div>

          {/* § 4 — Two-layer architecture */}
          <section className="cg-section" aria-labelledby="cg-arch-h2">
            <h2 id="cg-arch-h2" className="cg-section-h2">
              Two-layer decision architecture
            </h2>
            <div className="cg-two-col">
              <div className="cg-body-col">
                <p>
                  ClinicalGuard operates as an execution membrane below agent reasoning. The{' '}
                  <strong>classification layer</strong> identifies PHI-adjacent content using a rule
                  set aligned to the HIPAA Privacy Rule. The <strong>policy layer</strong> applies a
                  governance decision — approve, conditionally approve, or reject — before any
                  downstream action may execute.
                </p>
                <p>
                  No PHI-adjacent executor may run without a cryptographically signed Decision
                  Receipt issued by the policy layer. Receipts are written to an append-only audit
                  log keyed on a stable <span className="cg-mono-inline">audit_event_hash</span>.
                </p>
                <p>
                  The layers are stateless and composable. Operators may supply their own rule
                  overlays without modifying the core engine. The constitutional hash is recomputed
                  on each overlay merge and verified at runtime startup.
                </p>
              </div>
              <aside className="cg-aside-panel" aria-label="Architecture decision note">
                <p className="cg-aside-label">Architecture note</p>
                <p>
                  Classification and policy are separated by design. A misclassification does not
                  bypass policy; a policy override does not alter classification output. Both layers
                  must independently pass before a receipt is issued.
                </p>
                <p>
                  Executor fail-close is not a configuration option. An executor missing its receipt
                  cannot be overridden at the call site without modifying the kernel — a change that
                  invalidates the constitutional hash.
                </p>
              </aside>
            </div>
          </section>

          {/* § 5 — Decision Outcomes */}
          <section className="cg-section" aria-labelledby="cg-verdict-h2">
            <h2 id="cg-verdict-h2" className="cg-section-h2">
              Decision outcomes
            </h2>
            <div className="cg-verdict-grid">
              <article className="cg-verdict-card" data-verdict="approved">
                <div className="cg-verdict-badge">APPROVED</div>
                <p className="cg-verdict-rule">
                  Confidence ≥ 0.90 and all required PHI consents present.
                </p>
                <p>
                  A signed receipt is issued. The executor runs. The receipt is written to the
                  append-only audit log and cannot be revoked after execution.
                </p>
              </article>
              <article className="cg-verdict-card" data-verdict="conditional">
                <div className="cg-verdict-badge">CONDITIONALLY APPROVED</div>
                <p className="cg-verdict-rule">
                  Confidence 0.65–0.89 or a secondary consent flag is pending.
                </p>
                <p>
                  A receipt is issued with a <span className="cg-mono-inline">conditions</span>{' '}
                  block. The executor may run only if every condition is resolved by a named
                  approver before the receipt TTL expires.
                </p>
              </article>
              <article className="cg-verdict-card" data-verdict="rejected">
                <div className="cg-verdict-badge">REJECTED</div>
                <p className="cg-verdict-rule">
                  Confidence below 0.65, missing consent, or rule veto raised.
                </p>
                <p>
                  No receipt is issued. The executor fails closed. A rejection record is written to
                  the audit log so the refusal is traceable and reviewable.
                </p>
              </article>
            </div>
          </section>

          {/* § 6 — Severity classification grid */}
          <section className="cg-section" aria-labelledby="cg-severity-h2">
            <h2 id="cg-severity-h2" className="cg-section-h2">
              Severity classification
            </h2>
            <div className="cg-severity-grid">
              <article className="cg-severity-cell" data-tier="critical">
                <span className="cg-severity-tier">CRITICAL</span>
                <p>
                  Direct PHI disclosure or system-level record mutation without consent. Automatic
                  rejection; incident ticket opened.
                </p>
                <span className="cg-mono-inline">veto: phi.direct_disclosure</span>
              </article>
              <article className="cg-severity-cell" data-tier="high">
                <span className="cg-severity-tier">HIGH</span>
                <p>
                  Indirect PHI exposure via aggregation or inference. Requires named approver before
                  a conditional receipt is honoured.
                </p>
                <span className="cg-mono-inline">flag: phi.indirect_exposure</span>
              </article>
              <article className="cg-severity-cell" data-tier="medium">
                <span className="cg-severity-tier">MEDIUM</span>
                <p>
                  PHI-adjacent context included in a non-clinical prompt. Routed to human review
                  queue with a 24 h SLA.
                </p>
                <span className="cg-mono-inline">flag: phi.adjacent_context</span>
              </article>
              <article className="cg-severity-cell" data-tier="low">
                <span className="cg-severity-tier">LOW</span>
                <p>
                  Statistical or aggregate output with no individual re-identification risk. Logged,
                  not blocked.
                </p>
                <span className="cg-mono-inline">log: phi.statistical_output</span>
              </article>
            </div>
          </section>

          {/* § 7 — MACI separation of powers */}
          <section className="cg-section" aria-labelledby="cg-maci-h2">
            <h2 id="cg-maci-h2" className="cg-section-h2">
              MACI separation of powers
            </h2>
            <div className="cg-maci-grid">
              <div className="cg-maci-body">
                <p>
                  ClinicalGuard enforces the <strong>Multi-Agent Constitutional Isolation</strong>{' '}
                  (MACI) principle: the agent that proposes an action cannot also validate or
                  approve it. This separation prevents a compromised agent from self-authorizing
                  PHI-adjacent side effects.
                </p>
                <p>
                  In a MACI-compliant deployment, three roles are distinct and non-overlapping:{' '}
                  <strong>Proposer</strong> constructs the action request,{' '}
                  <strong>Validator</strong> runs the policy check and issues or denies the receipt,
                  and <strong>Approver</strong> provides the out-of-band human or privileged-agent
                  sign-off required for conditional verdicts.
                </p>
                <p>
                  ClinicalGuard is the Validator layer. It does not schedule, propose, or execute
                  actions. Its only output is a signed receipt or a rejection record.
                </p>
              </div>
              <aside className="cg-maci-diagram" aria-label="MACI flow diagram">
                <pre className="cg-pre">{`PROPOSER
  ↓ action request
VALIDATOR
  (ClinicalGuard)
  ↓ signed receipt
    or rejection
APPROVER
  ↓ resolves conditions
EXECUTOR
  ↓ runs with receipt`}</pre>
              </aside>
            </div>
          </section>

          {/* § 8 — Audit Trail */}
          <section className="cg-section" aria-labelledby="cg-audit-h2">
            <p className="product-eyebrow cg-section-eyebrow">
              <span>⁂</span>
              Audit trail · Rule 02 of 04
            </p>
            <h2 id="cg-audit-h2" className="cg-section-h2">
              Immutable audit evidence
            </h2>
            <div className="cg-two-col">
              <div className="cg-body-col">
                <p>
                  Every ClinicalGuard decision — approve, conditional, or reject — is written to an
                  append-only JSONL audit log. Entries are keyed on a stable{' '}
                  <span className="cg-mono-inline">audit_event_hash</span> derived from the action
                  fingerprint, policy version, and actor identity.
                </p>
                <p>
                  The log is tamper-evident. Each entry includes the policy rules evaluated, the PHI
                  flags raised, the confidence score, the receipt hash (if issued), and the
                  wall-clock timestamp. Entries cannot be deleted or overwritten; corrections are
                  additive amendment records.
                </p>
                <p>
                  Audit entries are readable by the operator via the{' '}
                  <span className="cg-mono-inline">audit read</span> CLI subcommand. No proprietary
                  export format is required; the log is plain JSONL, importable into any SIEM.
                </p>
              </div>
              <aside className="cg-aside-panel" aria-label="Audit log evidence panel">
                <p className="cg-aside-label">Evidence record</p>
                <dl className="cg-evidence-dl">
                  <div>
                    <dt>Log format</dt>
                    <dd>Append-only JSONL · one event per line</dd>
                  </div>
                  <div>
                    <dt>Entry key</dt>
                    <dd className="tabular">audit_event_hash (SHA-256)</dd>
                  </div>
                  <div>
                    <dt>Retention</dt>
                    <dd>Operator-defined · default 90 days</dd>
                  </div>
                  <div>
                    <dt>Export</dt>
                    <dd>Plain JSONL · no proprietary format</dd>
                  </div>
                </dl>
              </aside>
            </div>
          </section>

          {/* § 9 — PHI + HIPAA */}
          <section className="cg-section" aria-labelledby="cg-phi-h2">
            <p className="product-eyebrow cg-section-eyebrow">
              <span>⁂</span>
              PHI classification · Rule 03 of 04
            </p>
            <h2 id="cg-phi-h2" className="cg-section-h2">
              PHI coverage and HIPAA alignment
            </h2>
            <div className="cg-two-col">
              <div className="cg-phi-list-col">
                <p className="cg-phi-intro">
                  ClinicalGuard recognizes ten of the eighteen HIPAA Safe Harbor identifiers. The
                  remaining eight require operator-supplied classifiers; the kernel accepts them as
                  rule overlays without modifying the base engine.
                </p>
                <ul className="cg-phi-list" aria-label="Covered PHI identifiers">
                  <li>Names (patient, provider, relative)</li>
                  <li>Geographic data below state level</li>
                  <li>Dates (except year) related to an individual</li>
                  <li>Telephone numbers</li>
                  <li>Email addresses</li>
                  <li>Social Security numbers</li>
                  <li>Medical record numbers</li>
                  <li>Health plan beneficiary numbers</li>
                  <li>Account numbers</li>
                  <li>Certificate / license numbers</li>
                </ul>
              </div>
              <aside className="cg-parchment" aria-label="Scope caveat">
                <p className="cg-parchment-label">Scope caveat</p>
                <p>
                  ClinicalGuard is an engineering governance layer, not a legal compliance tool.
                  Operators are responsible for confirming that their own HIPAA obligations are met
                  through appropriate legal review, BAAs, and organizational controls.
                </p>
                <p>
                  The ten identifier types above reflect the current rule set. Coverage is a
                  function of the active rule overlay, not a compliance claim. Do not represent
                  ClinicalGuard coverage as equivalent to a HIPAA audit.
                </p>
              </aside>
            </div>
          </section>

          {/* § 10 — Graceful degradation + A2A */}
          <section className="cg-section" aria-labelledby="cg-degradation-h2">
            <h2 id="cg-degradation-h2" className="cg-section-h2">
              Graceful degradation and A2A compatibility
            </h2>
            <div className="cg-degradation-strip">
              <div>
                <h3 className="cg-strip-h3">Graceful degradation</h3>
                <p>
                  If the ClinicalGuard validator is unavailable, executors fail closed by default.
                  An optional <span className="cg-mono-inline">allow_degraded</span> flag permits
                  degraded execution with a mandatory human-review annotation appended to the audit
                  record.
                </p>
              </div>
              <div>
                <h3 className="cg-strip-h3">A2A protocol compatibility</h3>
                <p>
                  ClinicalGuard operates as an Agent-to-Agent (A2A) policy node. Proposer agents
                  submit action requests via the JSON receipt API; the validator response is a
                  signed receipt or a structured rejection payload. No session state is required
                  between calls.
                </p>
              </div>
            </div>
          </section>

          {/* § 11 — Asterism break */}
          <div className="cg-asterism-break" aria-hidden="true">
            <hr className="cg-asterism-rule" />
            <span>⁂</span>
            <hr className="cg-asterism-rule" />
          </div>

          {/* § 12 — Evidence definition list + install strip */}
          <section className="cg-section" aria-labelledby="cg-evidence-h2">
            <p className="product-eyebrow cg-section-eyebrow">
              <span>⁂</span>
              Evidence · Rule 04 of 04
            </p>
            <h2 id="cg-evidence-h2" className="cg-section-h2">
              Provable, inspectable, operator-owned
            </h2>
            <dl className="cg-evidence-def-list">
              <div>
                <dt>Receipt issuance</dt>
                <dd>
                  Every approve verdict produces a signed Decision Receipt. The signature is
                  verifiable offline using the operator's public key.
                </dd>
              </div>
              <div>
                <dt>Constitutional hash</dt>
                <dd>
                  The rule set is hashed at build time. Any rule modification invalidates the hash,
                  failing runtime startup before any PHI action is attempted.
                </dd>
              </div>
              <div>
                <dt>Append-only audit log</dt>
                <dd>
                  Rejections and approvals are co-equal log citizens. You cannot have a receipt
                  without an audit entry, and you cannot delete an audit entry without breaking the
                  hash chain.
                </dd>
              </div>
              <div>
                <dt>Operator key ownership</dt>
                <dd>
                  Signing keys are operator-managed. ACGS has no access to private keys and cannot
                  forge receipts on an operator's behalf.
                </dd>
              </div>
            </dl>
            <div className="cg-install-strip">
              <div className="cg-install-label">
                <span className="product-folio">install</span>
                <p>
                  Requires acgs-lite ≥ 2.10.0 with the{' '}
                  <span className="cg-mono-inline">clinicalguard</span> extra.
                </p>
              </div>
              <pre className="cg-install-block">
                <code>{`pip install "acgs-lite[clinicalguard]"`}</code>
              </pre>
            </div>
          </section>
        </main>
      </div>
    </div>
  )
}
