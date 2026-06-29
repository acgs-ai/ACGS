import { MarketingFrame } from './Marketing'

/* ============================================================================
 * acgs-lite showcase page — /acgs-lite
 * Warm-paper design system: Instrument Serif display, token-only CSS.
 * Motion: CSS @keyframes al-fade-up with nth-child stagger (no motion/react —
 * keeps the marketing bundle within the 200 KiB gzip budget).
 * Copy discipline: MACI is advisory-by-default; opt-in via enforce_maci=True.
 * No version pinned in pip snippet — see HTML comment below.
 * ============================================================================ */

interface Feature {
  title: string
  body: string
}

const FEATURES: Feature[] = [
  {
    title: 'Deny before the side effect',
    body: 'Unsafe tool calls are refused before anything runs — fail-closed on missing, malformed, or tampered receipts, and on DENY or ESCALATE outcomes.',
  },
  {
    title: 'Argument binding',
    body: 'A receipt authorises a specific tool with specific arguments. A valid receipt for write_file(path="/tmp/safe") cannot authorise write_file(path="/etc/shadow").',
  },
  {
    title: 'Tamper-evident audit',
    body: 'The audit log is an append-only hash chain. Any edit, reorder, or truncation fails verify_chain(). Decisions are replayable against policy via receipt and audit-chain verification.',
  },
  {
    title: 'Tool-format normalisation',
    body: 'Bridges Claude, Codex, MCP, OpenAI, and LangChain tool-call formats via integration.py — one enforcement layer across multiple agent runtimes.',
  },
  {
    title: 'Policy bundles',
    body: 'Decisions are driven by rule-set policy bundles, each tenant- and boundary-bound. No shared global policy table; isolation is structural.',
  },
  {
    title: 'Ed25519 signing (opt-in)',
    body: "Optional cryptographic receipt signatures close the recomputed-receipt residual. Unsigned by default; key management is the operator's responsibility.",
  },
]

interface ProofCheck {
  check: string
  result: string
}

const PROOF_CHECKS: ProofCheck[] = [
  { check: 'allowed_action_executed', result: 'pass' },
  { check: 'denied_action_blocked', result: 'pass' },
  { check: 'transformed_action_executed', result: 'pass' },
  { check: 'missing_receipt_blocked', result: 'pass' },
  { check: 'tampered_receipt_blocked', result: 'pass' },
  { check: 'audit_chain_verified', result: 'pass' },
]

const LIMITS: string[] = [
  'Alpha — a production-shaped foundation, not production-, compliance-, or regulator-certified.',
  "No PKI, CA, trust chain, key custody, or revocation. Signing is point-to-point; key management is the operator's responsibility.",
  'No side-effect sandboxing. acgs-lite decides whether and with which arguments an action runs; it does not contain the blast radius of the tool you register.',
  'No durable off-host audit sink (WORM / SIEM) by default; the chain is local JSONL. Audit locking is Unix-only (fcntl); Windows support is deferred.',
  'Not a guarantee against full host compromise — an attacker controlling host + issuer + audit file can forge a locally consistent chain.',
]

/* pip install snippet — no version pinned intentionally */
const INSTALL_LINE = 'pip install acgs-lite'
/* see PyPI for the latest published release */

const CODE_EXAMPLE = `from acgs_lite import GovernedExecutor, PolicyBundle

policy = PolicyBundle.from_file("policy.yaml")
executor = GovernedExecutor(policy=policy)

# The gate verifies the receipt, checks policy,
# appends to the audit chain, then calls the tool —
# or raises GovernanceError before anything runs.
result = await executor.run(
    action="write_file",
    arguments={"path": "/tmp/report.csv", "content": data},
    receipt=receipt,          # Decision Receipt from your agent
    actor="pipeline/etl-v2",
)`.trim()

const PROOF_CMD = `# from the monorepo root
uv run --package gove-zone gove-zone proofpack
# → {"status": "pass", "checks": 6, "failures": 0}`.trim()

export function AcgsLite() {
  return (
    <MarketingFrame>
      {/* ── Hero ─────────────────────────────────────────────────── */}
      <section className="al-hero m-page-hero" aria-labelledby="al-h">
        <div className="al-hero-eyebrow m-eyebrow">
          <span className="al-badge">PyPI</span>
          <span>acgs-lite · governance receipts for Python agents</span>
        </div>
        <h1 id="al-h" className="al-hero-h1 al-animate-hero-1">
          No valid receipt,
          <br />
          <em>no side effect.</em>
        </h1>
        <p className="al-hero-lede al-animate-hero-2">
          acgs-lite is a fail-closed governance gate for AI agent side effects. It sits between an
          agent&apos;s decision and the tool call that acts on the world — enforcing a verifiable
          Decision Receipt before execution. No valid receipt, no side effect. Enforced, not
          advisory.
        </p>
        <div className="al-install-row al-animate-hero-3">
          <code className="al-install-cmd">{INSTALL_LINE}</code>
          {/* no version pinned — consult PyPI for the current release */}
        </div>
        <div className="al-hero-actions al-animate-hero-4">
          <a
            className="btn btn-rust"
            href="https://pypi.org/project/acgs-lite/"
            target="_blank"
            rel="noopener noreferrer"
          >
            View on PyPI
          </a>
          <a
            className="btn btn-ghost"
            href="https://github.com/dislovelhl/ACGS"
            target="_blank"
            rel="noopener noreferrer"
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* ── Signal strip ─────────────────────────────────────────── */}
      <section className="al-signals" aria-label="Package facts">
        <ul className="al-signal-list">
          {(
            [
              { label: 'Platform', value: 'Python ≥ 3.10' },
              { label: 'License', value: 'MIT' },
              { label: 'Enforcement', value: 'Fail-closed' },
              { label: 'Audit log', value: 'Hash-chained JSONL' },
            ] as const
          ).map(({ label, value }) => (
            <li key={label} className="al-signal-item">
              <span className="al-signal-label">{label}</span>
              <span className="al-signal-value">{value}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* ── Feature grid ─────────────────────────────────────────── */}
      <section className="al-features" aria-labelledby="al-features-h">
        <h2 id="al-features-h" className="al-section-h2 al-animate-in">
          What the gate enforces
        </h2>
        <ul className="al-feature-grid">
          {FEATURES.map((f, i) => (
            <li key={f.title} className={`al-feature-card al-stagger-${i}`}>
              <strong className="al-feature-title">{f.title}</strong>
              <p className="al-feature-body">{f.body}</p>
            </li>
          ))}
        </ul>
      </section>

      {/* ── Code example ─────────────────────────────────────────── */}
      <section className="al-code-section" aria-labelledby="al-code-h">
        <div className="al-code-inner al-animate-in">
          <h2 id="al-code-h" className="al-section-h2">
            Receipt-gated execution
          </h2>
          <p className="al-code-lede">
            One call wraps any tool. acgs-lite verifies the receipt, checks policy, appends to the
            audit chain, and executes — or raises <code>GovernanceError</code> before the side
            effect can run.
          </p>
          <pre className="al-code-block">
            <code>{CODE_EXAMPLE}</code>
          </pre>
        </div>
      </section>

      {/* ── MACI role separation ──────────────────────────────────── */}
      <section className="al-maci" aria-labelledby="al-maci-h">
        <div className="al-maci-inner al-animate-in">
          <h2 id="al-maci-h" className="al-section-h2">
            Role separation <em>(MACI)</em>
          </h2>
          <p className="al-maci-lede">
            A receipt binds two distinct principals — the <strong>proposer</strong> (the agent that
            asked) and the <strong>validator</strong> (the authority that approved). The kernel
            refuses to mint a self-validated receipt: an agent can propose an action but can never
            validate its own authority to execute it.
          </p>
          <div className="al-maci-callout">
            <span className="al-maci-callout-label">Default behaviour</span>
            <p>
              MACI is <strong>advisory-by-default.</strong> Role-separation checks run on every
              receipt but do not block execution unless you explicitly opt in via{' '}
              <code>enforce_maci=True</code>. This lets you observe violations in existing pipelines
              before enforcing them.
            </p>
          </div>
          <p className="al-maci-note">
            Broader MACI phases — cross-boundary federation, external validator registries — are
            roadmap. See <code>MACI-ROADMAP.md</code>.
          </p>
        </div>
      </section>

      {/* ── Proof panel ──────────────────────────────────────────── */}
      <section className="al-proof" aria-labelledby="al-proof-h">
        <div className="al-proof-inner al-animate-in">
          <h2 id="al-proof-h" className="al-section-h2">
            Proof, not adjectives
          </h2>
          <p className="al-proof-lede">
            Run the proof pack yourself. Six conformance checks, reproducible artifacts, no badge
            required. The whole pitch is that you <em>don&apos;t</em> have to take the headline on
            trust.
          </p>
          <pre className="al-code-block al-proof-cmd-block">
            <code>{PROOF_CMD}</code>
          </pre>
          <div className="al-proof-table-wrap">
            <table className="al-proof-table">
              <thead>
                <tr>
                  <th>Conformance check</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {PROOF_CHECKS.map(({ check, result }, i) => (
                  <tr key={check} className={`al-stagger-${i}`}>
                    <td>
                      <code>{check}</code>
                    </td>
                    <td className="al-proof-pass">{result}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ── Honest limits ────────────────────────────────────────── */}
      <section className="al-limits" aria-labelledby="al-limits-h">
        <div className="al-limits-inner al-animate-in">
          <h2 id="al-limits-h" className="al-section-h2">
            What it does <em>not</em> do
          </h2>
          <p className="al-limits-intro">
            Honest positioning. These are stated up front, not in footnotes.
          </p>
          <ul className="al-limits-list">
            {LIMITS.map((limit) => (
              <li key={limit}>{limit}</li>
            ))}
          </ul>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────── */}
      <section className="al-cta" aria-labelledby="al-cta-h">
        <div className="al-cta-inner al-animate-in">
          <h2 id="al-cta-h" className="al-cta-h2">
            Ready to gate your agents?
          </h2>
          <p className="al-cta-lede">
            Install acgs-lite, run the proof pack, and observe the first governed receipt in your
            pipeline. No external infrastructure required.
          </p>
          <div className="al-cta-actions">
            <a
              className="btn btn-rust"
              href="https://pypi.org/project/acgs-lite/"
              target="_blank"
              rel="noopener noreferrer"
            >
              Get acgs-lite on PyPI
            </a>
            <a className="btn btn-secondary" href="/#interview">
              Start governance interview
            </a>
          </div>
        </div>
      </section>
    </MarketingFrame>
  )
}
