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
    body: 'Declarative YAML policy files name permitted resource shapes, required labels, and forbidden actions. The pack loads and evaluates them against Terraform plans before any apply gate runs.',
  },
  {
    title: 'Evidence records',
    body: 'Each evaluation emits one JSONL evidence record. The record contains the decision, a SHA-256 plan hash, a Merkle root over every evaluated control, actor identity, and timestamp. No evidence record, no apply gate passes.',
  },
  {
    title: 'Control severity levels',
    body: 'Each policy control carries a severity (high, medium, or low). A single high-severity violation denies the plan and halts the CI pipeline at the apply gate before any infrastructure change runs.',
  },
  {
    title: 'Audit trail',
    body: 'Every evaluation appends one event to a JSONL file. The file is append-only by convention. Each event includes the full decision, plan hash, Merkle root, actor, and control-level reasons.',
  },
  {
    title: 'Fail-closed evaluation',
    body: 'Denied plans exit with code 2. Your CI pipeline can treat any non-zero exit as a hard block. There is no degraded mode: a governance failure is always a pipeline failure.',
  },
  {
    title: 'Evaluate CLI',
    body: 'The acgs-cft-govern evaluate command takes a Terraform plan JSON, a policy directory, and an actor identity, and writes the evidence JSONL. It is a standalone binary with no runtime infrastructure dependency.',
  },
]

const STEPS: Step[] = [
  {
    title: 'Declare policy',
    body: 'Write a YAML policy file that names permitted resource types, required labels, forbidden IAM roles, and other controls. Point the CLI at the policy directory.',
  },
  {
    title: 'Generate a Terraform plan',
    body: 'Run terraform plan -out tfplan.binary and terraform show -json to produce the plan JSON. Pass that file to the acgs-cft-govern evaluate command along with actor identity.',
  },
  {
    title: 'Pack evaluates and emits evidence',
    body: 'Controls run in policy order. The outcome is written to a JSONL evidence record containing the decision, a SHA-256 plan hash, and a Merkle root over all evaluated controls.',
  },
  {
    title: 'CI gate blocks on denial',
    body: 'The evaluate command exits 2 on any denial. Your CI workflow treats exit 2 as a hard block on the apply step. The evidence JSONL is uploaded as a CI artifact for audit.',
  },
]

const SAMPLE_RECEIPT = `{
  "schema":      "acgs.cft.evidence.v1",
  "event_type":  "terraform_plan_evaluation",
  "decision":    "allow",
  "plan_hash":   "sha256:a3f9b1c4d2e7...",
  "actor":       { "id": "platform-ci", "role": "validator" },
  "reason":      "All 5 governance controls passed",
  "merkle_root": "sha256:7d3e2f1a9b8c...",
  "timestamp":   "2026-06-27T14:22:04Z"
}`

const RISK_TIERS: RiskTier[] = [
  {
    level: 'LOW',
    cls: 'confirmed',
    title: 'Informational control',
    body: 'A low-severity violation is logged in the evidence record but does not deny the plan. Use for advisory checks such as recommended label conventions.',
    examples: ['Recommended tags', 'Preferred naming', 'Optional logging'],
  },
  {
    level: 'MEDIUM',
    cls: 'partial',
    title: 'Warning control',
    body: 'A medium-severity violation records a reason in the evidence record. Your policy configuration determines whether medium violations deny the plan or pass with a warning.',
    examples: ['Subnet flow logs', 'Release channel', 'OIDC hardening'],
  },
  {
    level: 'HIGH',
    cls: 'blocked',
    title: 'Blocking control',
    body: 'A high-severity violation denies the plan immediately. The evaluate command exits 2, the evidence record captures the full reason, and the CI apply step is blocked.',
    examples: ['Public ingress', 'Broad IAM roles', 'Service account keys'],
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
          A Python library that evaluates Terraform plans against YAML governance policies and emits
          a verifiable evidence record before any apply gate runs. Declare the policy; the pack
          evaluates; the CI pipeline blocks on any denial.
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
            An evidence record you can <em>inspect</em>.
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
