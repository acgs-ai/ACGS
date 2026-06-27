import { ArrowRight } from 'lucide-react'
import { navigate } from '../lib/navigate'
import { MarketingFrame } from './Marketing'

const ASTERISM = '⁂'

interface Capability {
  title: string
  body: string
}

interface Step {
  title: string
  body: string
}

interface RiskTier {
  level: string
  cls: string
  title: string
  body: string
  examples: string[]
}

const CAPABILITIES: Capability[] = [
  {
    title: 'Policy-IO bridge',
    body: 'Declarative YAML policy files bind agent intent to execution scope. Every operation declares action, target, and evidence before the infrastructure layer proceeds.',
  },
  {
    title: 'Decision Receipts',
    body: 'Each evaluation emits a signed, tamper-evident receipt. Executors must present a valid receipt or halt. No receipt, no side effect.',
  },
  {
    title: 'Risk classification',
    body: 'Operations are scored LOW, PARTIAL, or HIGH based on blast radius, reversibility, and required authority. Thresholds are configurable per environment.',
  },
  {
    title: 'Audit trail',
    body: 'Every evaluation appends an immutable JSONL audit record covering decision, evidence hash, actor identity, and timestamp. Append-only by design.',
  },
  {
    title: 'Fail-closed executor',
    body: 'The executor calls receipt verification before any infrastructure write. A missing, expired, or tampered receipt produces an immediate halt, not a warning.',
  },
  {
    title: 'CLI verifier',
    body: 'The standalone verify-proofpack command lets operators inspect, diff, and audit proof packs outside the running system. Portable and dependency-light.',
  },
]

const STEPS: Step[] = [
  {
    title: 'Declare policy',
    body: 'Write a YAML policy file that names permitted actions, required evidence, and scope limits. Bind it to the environment at init time.',
  },
  {
    title: 'Agent requests execution',
    body: 'The agent submits an action request with intent, actor identity, and arguments. The pack evaluates against policy synchronously.',
  },
  {
    title: 'Pack evaluates and emits receipt',
    body: 'Policy rules run in priority order. The outcome is written to a signed Decision Receipt containing a cryptographic hash of the evaluation.',
  },
  {
    title: 'Executor verifies before acting',
    body: 'The infrastructure executor presents the receipt to the verification gate. Any hash or signature deviation causes a fail-closed halt with a full audit record.',
  },
]

const SAMPLE_RECEIPT = `{
  "receipt_id": "rec_01j3xv7p8q2kzmn4r5...",
  "decision":   "ALLOW",
  "action":     "deploy:cloud-run:staging",
  "actor":      "agent/deploy-bot@acgs.ai",
  "risk_level": "LOW",
  "policy_ref": "infra-staging-v1.yaml",
  "audit_hash": "sha256:a3f9b1c4d2e7...",
  "issued_at":  "2026-06-27T14:22:04Z",
  "expires_at": "2026-06-27T14:27:04Z",
  "signature":  "ed25519:7d3e2f1a9b8c..."
}`

const RISK_TIERS: RiskTier[] = [
  {
    level: 'LOW',
    cls: 'confirmed',
    title: 'Proceed with logging',
    body: 'Low blast radius, fully reversible, no privileged credentials. The receipt is issued immediately; execution continues with a full audit record.',
    examples: ['Read-only describe', 'Preview plans', 'Staging deploys'],
  },
  {
    level: 'PARTIAL',
    cls: 'partial',
    title: 'Proceed with approval flag',
    body: 'Moderate scope or partial reversibility. A REVIEW flag is attached to the receipt. The operator may require a human acknowledgment before the executor runs.',
    examples: ['Config changes', 'Service restarts', 'Quota modifications'],
  },
  {
    level: 'HIGH',
    cls: 'blocked',
    title: 'Halt until escalated',
    body: 'Wide blast radius, irreversible, or privileged credentials required. Execution is blocked until an explicit human approval is recorded in the audit trail.',
    examples: ['Production deploys', 'IAM mutations', 'Data deletions'],
  },
]

export function CftPack() {
  return (
    <MarketingFrame>
      {/* §1 Hero */}
      <section className="m-page-hero cft-hero" aria-labelledby="cft-h">
        <span className="m-eyebrow">
          <span className="asterism" aria-hidden>
            {ASTERISM}
          </span>
          CFT Governance Pack
          <span className="cft-badge">Python · MIT</span>
        </span>
        <h1 id="cft-h">
          Governed infrastructure for every AI <em>action</em>.
        </h1>
        <p className="m-hero-lede">
          A Python library that attaches policy evaluation and verifiable Decision Receipts to
          infrastructure operations before any side effect runs. Agents declare intent; the pack
          decides; the executor verifies the receipt or halts.
        </p>
        <div className="m-hero-actions">
          <a
            className="btn btn-rust"
            href="/products"
            onClick={(event) => {
              event.preventDefault()
              navigate('/products')
            }}
          >
            View all products <ArrowRight size={14} strokeWidth={1.75} />
          </a>
          <a
            className="btn btn-secondary"
            href="https://pypi.org/project/acgs-cft-governance-pack/"
            target="_blank"
            rel="noopener noreferrer"
          >
            pip install
          </a>
        </div>
      </section>

      {/* §2 Capabilities */}
      <section className="cft-section" aria-labelledby="cft-ships-h">
        <div className="m-sec-head">
          <span className="num">01 · capabilities</span>
          <h2 id="cft-ships-h">
            Everything the pack <em>ships</em>.
          </h2>
        </div>
        <div className="m-cards cft-caps-grid">
          {CAPABILITIES.map((cap, i) => (
            <article className="m-card" key={cap.title}>
              <span className="folio-no">{String(i + 1).padStart(2, '0')}</span>
              <h3>{cap.title}</h3>
              <p>{cap.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* §3 Execution flow */}
      <section className="cft-section" aria-labelledby="cft-flow-h">
        <div className="m-sec-head">
          <span className="num">02 · execution flow</span>
          <h2 id="cft-flow-h">
            Policy before <em>action</em>, always.
          </h2>
        </div>
        <ol className="cft-steps" aria-label="Execution flow steps">
          {STEPS.map((step, i) => (
            <li className="cft-step" key={step.title}>
              <span className="cft-step-n" aria-hidden>
                {String(i + 1).padStart(2, '0')}
              </span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* §4 Sample receipt */}
      <section className="cft-section m-agent-output" aria-labelledby="cft-receipt-h">
        <div className="m-sec-head">
          <span className="num">03 · sample output</span>
          <h2 id="cft-receipt-h">
            A receipt you can <em>verify</em>.
          </h2>
        </div>
        <pre>{SAMPLE_RECEIPT}</pre>
      </section>

      {/* §5 Risk tiers */}
      <section className="cft-section" aria-labelledby="cft-risk-h">
        <div className="m-sec-head">
          <span className="num">04 · risk tiers</span>
          <h2 id="cft-risk-h">
            Three tiers, one <em>boundary</em>.
          </h2>
        </div>
        <div className="cft-risk-tiers">
          {RISK_TIERS.map((tier) => (
            <article className="cft-risk-card" key={tier.level}>
              <span className={`pill ${tier.cls}`}>{tier.level}</span>
              <h3>{tier.title}</h3>
              <p>{tier.body}</p>
              <ul aria-label={`${tier.level} examples`}>
                {tier.examples.map((ex) => (
                  <li key={ex}>{ex}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      {/* §6 Get started */}
      <section className="cft-section cft-cta" aria-labelledby="cft-cta-h">
        <div className="cft-cta-inner">
          <span className="m-eyebrow">
            <span className="asterism" aria-hidden>
              {ASTERISM}
            </span>
            Get started
          </span>
          <h2 id="cft-cta-h">
            Attach governance before the first <em>deploy</em>.
          </h2>
          <p className="m-hero-lede">
            One pip install. Zero infrastructure changes. Policy runs inline with your existing IaC
            pipeline.
          </p>
          <div className="m-hero-actions">
            <a
              className="btn btn-rust"
              href="https://pypi.org/project/acgs-cft-governance-pack/"
              target="_blank"
              rel="noopener noreferrer"
            >
              pip install acgs-cft-governance-pack
            </a>
            <a
              className="btn btn-secondary"
              href="/products"
              onClick={(event) => {
                event.preventDefault()
                navigate('/products')
              }}
            >
              All products
            </a>
          </div>
        </div>
      </section>
    </MarketingFrame>
  )
}
