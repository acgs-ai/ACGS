import { ArrowRight } from 'lucide-react'
import type { FeatureStatus } from '../components/governance/FeatureStatusBadge'
import { FeatureStatusBadge } from '../components/governance/FeatureStatusBadge'
import { GovernedClaim } from '../components/governance/GovernedClaim'
import { navigate } from '../lib/navigate'

const STATUS_MAP: Record<string, FeatureStatus> = {
  CONFIRMED: 'verified',
  PARTIAL: 'partial',
  BLOCKED: 'not-supported',
  PRIVILEGED: 'roadmap',
}

function toFeatureStatus(raw: string): FeatureStatus {
  return STATUS_MAP[raw] ?? 'unverified'
}

const ASTERISM = '⁂'

type ProductCard = {
  label: string
  value: string
  note: string
}

type ProductRoute = {
  slug: string
  folio: string
  eyebrow: string
  title: string
  emphasis: string
  deck: string
  source: string
  status: string
  primaryCta: string
  secondaryCta?: string
  cards: ProductCard[]
  sections: Array<{
    heading: string
    body: string
    bullets: string[]
  }>
  evidence: string[]
}

const products: ProductRoute[] = [
  {
    slug: 'legalguard',
    folio: 'I',
    eyebrow: 'LegalGuard · Port A / Port B',
    title: 'Legal AI that knows when to',
    emphasis: 'stop',
    deck: 'A legal-information vertical where privilege, citation, conflict, evidence, and audit checks run before any draft leaves the matter boundary.',
    source: 'packages/legalguard/landing.html · chat.html · workbench.html',
    status: 'PRIVILEGED',
    primaryCta: 'Open assistant reference',
    secondaryCta: 'Review Port A boundary',
    cards: [
      { label: 'Hash', value: '608508a9bd224290', note: 'shared constitutional furniture' },
      { label: 'Ports', value: 'A / B', note: 'licensed workbench separated from public client' },
      { label: 'Skills', value: '5', note: 'privilege, citation, conflict, evidence, audit' },
    ],
    sections: [
      {
        heading: 'The disclaimer is structural.',
        body: 'The public assistant is framed as source-backed information and risk screening, not legal advice. Skill selection and natural-language prompts both return citations and mandatory disclosure language.',
        bullets: [
          'Not-legal-advice notice at the top edge',
          'Skill-aware routing for privilege and conflict questions',
          'Server settings kept explicit for prototype inspection',
        ],
      },
      {
        heading: 'Port A is matter-bearing.',
        body: 'The internal workbench keeps actor, organization, matter, document upload, and reviewer actions inside the privileged surface. Evidence downloads happen after a seven-field analysis is generated.',
        bullets: [
          'Parchment privilege boundary',
          'Reviewer-mapped identity path',
          'Matter and source IDs visible before analysis',
        ],
      },
    ],
    evidence: [
      'Privilege boundary',
      'Citation validation',
      'Conflict screening',
      'Evidence package',
      'Audit trail',
    ],
  },
  {
    slug: 'governance-eval',
    folio: 'II',
    eyebrow: 'Governance Eval · Business Panel',
    title: 'Evaluation is the product',
    emphasis: 'surface',
    deck: 'Authority, policy recall, governance recall, replay, and business-readiness views are rendered as one buyer-readable evidence command center.',
    source: 'acgs_governance_eval_mvp/ACGS Governance Eval Console.html · ACGS Business Panel.html',
    status: 'CONFIRMED',
    primaryCta: 'Inspect gate chain',
    secondaryCta: 'Open business narrative',
    cards: [
      { label: 'Gate path', value: '3', note: 'authority + policy recall + governance recall' },
      { label: 'Cases', value: '4', note: 'sample ActionRequest evaluations' },
      { label: 'Bridge', value: 'v0', note: 'governed action evidence packet' },
    ],
    sections: [
      {
        heading: 'Runtime decisions are pre-execution records.',
        body: 'The console treats a missing mandatory gate or a prior deny as a block. Rows expose actor role, action type, resource, reason codes, rule IDs, and event-hash preview.',
        bullets: [
          'Conjunctive gate-chain model',
          'Deny policy override path',
          'Replay stability against role and policy versions',
        ],
      },
      {
        heading: 'Buyer framing stays evidence-scoped.',
        body: 'The business panel translates internal packages into a GovernZone story: Hermes emits governed events, the eval MVP verifies and replays them, and acgi-ai becomes the durable inspection UI.',
        bullets: [
          'Portfolio command center',
          'Founder/operator operating signal',
          'Next-build line centered on evidence packets',
        ],
      },
    ],
    evidence: [
      'AuthorityGate.allow',
      'PolicyRecallGate.allow',
      'GovernanceRecallGate.allow',
      'Replay audit',
      'Export packet',
    ],
  },
  {
    slug: 'acgs-lite',
    folio: 'III',
    eyebrow: 'ACGS Lite · Integration dashboard',
    title: 'The SDK surface proves its',
    emphasis: 'coverage',
    deck: 'A package-level integration matrix for provider wrappers, framework adapters, protocols, middleware, observability, and compliance workflows.',
    source: 'acgs-lite/docs/integration-dashboard.html',
    status: 'PARTIAL',
    primaryCta: 'Review integration map',
    cards: [
      {
        label: 'Integrations',
        value: '23',
        note: 'provider, framework, protocol, DevOps surfaces',
      },
      { label: 'Ready', value: '21', note: 'locally verified entries in the snapshot' },
      { label: 'Tests', value: '~3,630', note: 'fixture-reported test functions' },
    ],
    sections: [
      {
        heading: 'Provider wrappers become governed clients.',
        body: 'OpenAI, Anthropic, Gemini, xAI, LiteLLM, and local-model paths are framed as governance wrappers rather than one-off SDK forks.',
        bullets: [
          'GovernedOpenAI and GovernedAnthropic production lanes',
          'LiteLLM as the broad provider bridge',
          'Indirect local and Mistral coverage through LiteLLM',
        ],
      },
      {
        heading: 'Framework adapters keep the policy seam stable.',
        body: 'LangChain, LlamaIndex, AG2, CrewAI, DSPy, Haystack, middleware, MCP, A2A, telemetry, and CI entries are grouped by integration contract.',
        bullets: [
          'Runnable, engine, agent, pipeline patterns',
          'ASGI and WSGI middleware entry points',
          'Prometheus and cloud logging exporters',
        ],
      },
    ],
    evidence: [
      'LLM wrappers',
      'Framework adapters',
      'MCP server',
      'A2A protocol',
      'Cloud Run server',
    ],
  },
  {
    slug: 'acgs',
    folio: 'IV',
    eyebrow: 'ACGS · Runtime bridge',
    title: 'Governance before every',
    emphasis: 'tool call',
    deck: 'A local runtime kernel that normalizes agent-framework tool-call shapes into pre-execution decisions, receipts, and replayable audit chains.',
    source:
      'packages/gove-zone/src/gove_zone/integration.py · smoke.py · tests/test_integration_hook.py',
    status: 'CONFIRMED',
    primaryCta: 'Review runtime bridge',
    secondaryCta: 'Open local smoke proof',
    cards: [
      {
        label: 'Shapes',
        value: '7',
        note: 'Claude/Codex, MCP, function_call, Responses, Chat, LangChain, generic',
      },
      { label: 'Gate modes', value: '2', note: 'observe by default, enforce fail-closed' },
      { label: 'Proof', value: 'smoke', note: 'allow, deny, and audit-chain verification' },
    ],
    sections: [
      {
        heading: 'Frameworks meet one policy seam.',
        body: 'The adapter accepts Claude/Codex-style hooks, MCP tools/call payloads, function-call events, OpenAI Responses output items, OpenAI Chat tool_calls, LangChain-style tool_calls, and generic bridge payloads without importing those SDKs.',
        bullets: [
          'One normalized ToolCall before side effects',
          'Batch expansion so one denied child cannot hide in a multi-call event',
          'Malformed recognized batches fail closed as runtime.malformed_batch',
        ],
      },
      {
        heading: 'The first proof is local and repeatable.',
        body: 'New adopters can run gove-zone smoke from the monorepo to see one safe write allowed, one secret-path write denied, and the resulting audit chain verified without a live agent host.',
        bullets: [
          'uv run --package gove-zone gove-zone smoke',
          'Optional retained JSONL audit evidence',
          'Local runtime evidence only, not hosted or third-party assurance proof',
        ],
      },
    ],
    evidence: [
      'OpenAI Responses',
      'OpenAI Chat tool_calls',
      'LangChain tool_calls',
      'MCP tools/call',
      'Fail-closed audit chain',
    ],
  },
  {
    slug: 'hermes',
    folio: 'V',
    eyebrow: 'Hermes · Governed evidence panel',
    title: 'Evidence, not',
    emphasis: 'logs',
    deck: 'A Hermes runtime review panel for hook decisions, policy snapshots, replay labs, human-release gates, hash-chain verification, and export review.',
    source: 'hermes_acgs_bundle/ACGS Governed Evidence Panel.html',
    status: 'CONFIRMED',
    primaryCta: 'Open trace review',
    cards: [
      { label: 'Chain', value: 'Verified', note: 'latest prev_hash resolves to the tail' },
      { label: 'Queue', value: '3', note: 'human releases pending review' },
      { label: 'Drift', value: '1 gap', note: 'policy snapshot mismatch surfaced' },
    ],
    sections: [
      {
        heading: 'Hooks carry governed evidence.',
        body: 'Pre-tool, post-tool, and final-answer hooks produce event hashes, previous-hash links, policy IDs, verifier states, and exportable evidence bundles.',
        bullets: [
          'Append-only JSONL evidence',
          'Trace reconstruction from hash-chain links',
          'Export packets for review',
        ],
      },
      {
        heading: 'Replay highlights drift without rewriting history.',
        body: 'The replay lab compares original policy IDs to the current constitution snapshot, then surfaces missing review inputs and current status without mutating the record.',
        bullets: [
          'Tool allowlist policy snapshot',
          'Write-operation release gate',
          'High-risk final answer hold',
        ],
      },
    ],
    evidence: ['Governed traces', 'Policy snapshot', 'Replay lab', 'Review queue', 'Audit exports'],
  },
  {
    slug: 'eu-ai-act',
    folio: 'VI',
    eyebrow: 'EU AI Act · Countdown',
    title: 'Compliance before the',
    emphasis: 'deadline',
    deck: 'A public countdown and command-line compliance scan narrative for high-risk AI provisions, auditor-oriented evidence reports, and framework coverage.',
    source: 'ACGS/docs/eu-ai-act-countdown/index.html',
    status: 'PARTIAL',
    primaryCta: 'Review compliance scan',
    cards: [
      { label: 'Date', value: 'Aug 2 2026', note: 'high-risk provisions enforcement milestone' },
      { label: 'Penalty', value: '€35M', note: 'maximum fine called out in the reference' },
      { label: 'Scan', value: '72 / 100', note: 'sample high-risk healthcare report' },
    ],
    sections: [
      {
        heading: 'The product story starts at build time.',
        body: 'The reference page positions acgs-lite as a two-command compliance scan that names article-level pass/fail findings before deployment.',
        bullets: [
          'Art. 9 risk management pass',
          'Art. 11 documentation fail',
          'Art. 13 transparency fail',
        ],
      },
      {
        heading: 'Regulatory coverage remains concrete.',
        body: 'The page anchors coverage in EU AI Act, GDPR, NIST AI RMF, SOC 2, HIPAA, ISO 42001, CCPA, and FDA SaMD rather than generic trust claims.',
        bullets: [
          'Framework count surfaced as a product metric',
          'Nanosecond latency claim retained as reference copy',
          'PDF reporting described as auditor-facing draft output',
        ],
      },
    ],
    evidence: [
      'Article checklist',
      'Compliance score',
      'Report command',
      'Framework coverage',
      'Deadline clock',
    ],
  },
  {
    slug: 'vault-demo',
    folio: 'VII',
    eyebrow: 'Hackathon demo · Auth0 Token Vault',
    title: 'No token before the',
    emphasis: 'constitution',
    deck: 'A governed-agent vault demo where MACI role, connection, and scope checks happen before any external API token is issued.',
    source: 'ACGS/hackathon-demo/static/index.html',
    status: 'BLOCKED',
    primaryCta: 'Review demo policy',
    cards: [
      { label: 'Roles', value: '3', note: 'executive, judicial, implementer' },
      { label: 'Connections', value: '3', note: 'GitHub, Google, Slack' },
      { label: 'Mode', value: 'Validate / execute', note: 'decision before token exchange' },
    ],
    sections: [
      {
        heading: 'The architecture is a refusal path first.',
        body: 'Agent requests pass through the ACGS constitution before Token Vault exchange. A failed MACI role or scope boundary denies the token and emits audit evidence.',
        bullets: [
          'Validate MACI role and scopes',
          'Deny plus audit on failure',
          'No external API call before pass',
        ],
      },
      {
        heading: 'Demo scenarios stay inspectable.',
        body: 'The reference includes scenario selection, custom request fields, governance decision output, audit trail, and constitutional policy display in one page.',
        bullets: [
          'Scenario-driven validation',
          'Custom scopes as comma-separated input',
          'Constitutional policy visible beside results',
        ],
      },
    ],
    evidence: ['MACI role', 'Token vault', 'Scope boundary', 'Governance decision', 'Audit trail'],
  },
]

function getProduct(path: string): ProductRoute | null {
  const slug = path.replace('/products/', '')
  return products.find((product) => product.slug === slug) ?? null
}

function ProductNav({ current }: { current?: string }) {
  return (
    <nav className="product-nav" aria-label="Product references">
      <button type="button" onClick={() => navigate('/')}>
        acgs <span>{ASTERISM}</span>
      </button>
      <div>
        <button
          type="button"
          onClick={() => navigate('/products')}
          className={!current ? 'active' : ''}
        >
          Index
        </button>
        {products.map((product) => (
          <button
            type="button"
            onClick={() => navigate(`/products/${product.slug}`)}
            className={current === product.slug ? 'active' : ''}
            key={product.slug}
          >
            {product.folio}
          </button>
        ))}
      </div>
    </nav>
  )
}

export function ProductIndex() {
  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to product content
      </a>
      <main id="main-content" className="product-surface" tabIndex={-1} data-theme="control-plane">
        <div className="product-shell">
          <ProductNav />
          <header className="product-hero">
            <p className="product-eyebrow">
              <span>{ASTERISM}</span> Product reference atlas
            </p>
            <h1>
              Standalone HTML, rebuilt as <em>native</em> React surfaces.
            </h1>
            <p>
              This atlas turns the LegalGuard, governance-evaluation, ACGS Lite, Hermes, EU AI Act,
              ACGS runtime bridge, and Auth0 vault references into routeable product pages without
              iframe drops or new dependencies.
            </p>
          </header>

          <section className="product-grid" aria-label="Product routes">
            {products.map((product) => (
              <article className="product-card" key={product.slug}>
                <span className="product-folio">Vol. {product.folio}</span>
                <h2>
                  {product.title} <em>{product.emphasis}</em>.
                </h2>
                <p>{product.deck}</p>
                <button
                  type="button"
                  className="product-link"
                  onClick={() => navigate(`/products/${product.slug}`)}
                >
                  Read reference <ArrowRight size={14} strokeWidth={1.7} />
                </button>
              </article>
            ))}
          </section>
        </div>
      </main>
    </>
  )
}

export function ProductSurface({ path }: { path: string }) {
  const product = getProduct(path)

  if (!product) return <ProductIndex />

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to product content
      </a>
      <main id="main-content" className="product-surface" tabIndex={-1} data-theme="control-plane">
        <div className="product-shell">
          <ProductNav current={product.slug} />
          <header className="product-hero product-hero-detail">
            <div>
              <p className="product-eyebrow">
                <span>{ASTERISM}</span> {product.eyebrow}
              </p>
              <h1>
                {product.title} <em>{product.emphasis}</em>.
              </h1>
              <p>{product.deck}</p>
              <div className="product-actions">
                <a className="btn btn-primary" href="#evidence">
                  {product.primaryCta} <ArrowRight size={16} strokeWidth={1.8} />
                </a>
                {product.secondaryCta && (
                  <a className="btn btn-secondary" href="#reference">
                    {product.secondaryCta}
                  </a>
                )}
              </div>
            </div>
            <aside className="product-docket" aria-label="Reference docket">
              <FeatureStatusBadge status={toFeatureStatus(product.status)}>
                {product.status}
              </FeatureStatusBadge>
              <dl>
                <div>
                  <dt>Reference</dt>
                  <dd>{product.source}</dd>
                </div>
                <div>
                  <dt>Hash</dt>
                  <dd>608508a9bd224290</dd>
                </div>
                <div>
                  <dt>Route</dt>
                  <dd>/products/{product.slug}</dd>
                </div>
              </dl>
            </aside>
          </header>

          <section className="product-stat-grid" aria-label={`${product.eyebrow} product signals`}>
            {product.cards.map((card) => (
              <article className="product-stat" key={card.label}>
                <span>{card.label}</span>
                <strong>{card.value}</strong>
                <p>{card.note}</p>
              </article>
            ))}
          </section>

          <div className="m-break" aria-hidden>
            {ASTERISM} {ASTERISM} {ASTERISM}
          </div>

          <section className="product-brief" id="reference" aria-label="Reference interpretation">
            {product.sections.map((section) => (
              <article key={section.heading}>
                <h2>{section.heading}</h2>
                <p>{section.body}</p>
                <ul>
                  {section.bullets.map((bullet) => (
                    <li key={bullet}>{bullet}</li>
                  ))}
                </ul>
              </article>
            ))}
          </section>

          <section className="product-evidence" id="evidence" aria-labelledby="evidence-h">
            <div className="m-sec-head">
              <span className="num">Vol. {product.folio} · Evidence</span>
              <h2 id="evidence-h">
                Product cues preserved as <em>routeable</em> evidence.
              </h2>
            </div>
            <div className="product-evidence-list">
              {product.evidence.map((item, index) => (
                <article key={item}>
                  <span>0{index + 1}</span>
                  <p>{item}</p>
                </article>
              ))}
            </div>
            {product.evidence.length > 0 && (
              <div className="product-evidence-claims">
                <GovernedClaim
                  claim={product.deck}
                  status={toFeatureStatus(product.status)}
                  proofType="docs"
                  proofUrl={`/products/${product.slug}`}
                  version={`Vol. ${product.folio}`}
                />
              </div>
            )}
          </section>
        </div>
      </main>
    </>
  )
}
