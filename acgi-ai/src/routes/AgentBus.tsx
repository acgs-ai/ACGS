import type { ReactNode } from 'react'
import { navigate } from '../lib/navigate'
import { MarketingFrame } from './Marketing'

// ── Data ─────────────────────────────────────────────────────────────────────

const SAMPLE_RECEIPT = [
  { label: 'event_id', value: 'evt_7f3a9b1c…' },
  { label: 'actor', value: 'agent/planner-1' },
  { label: 'action', value: 'file.write' },
  { label: 'args_hash', value: 'sha256:e3b0c4…' },
  { label: 'policy', value: 'ALLOW' },
  { label: 'signed', value: 'ed25519 ✓' },
  { label: 'issued_at', value: '2026-06-27T14:22:11Z' },
]

const PROOF_FACTS = [
  { folio: '01', stat: 'Every event', sub: 'signed before emission' },
  { folio: '02', stat: 'Receipt first', sub: 'action blocked without one' },
  { folio: '03', stat: 'Replay-safe', sub: 'ledger with TTL prune' },
]

const CAPABILITIES = [
  {
    title: 'Event capture',
    body: 'Every agent action — file write, API call, approval request — emits a structured event before execution proceeds.',
  },
  {
    title: 'Signed receipts',
    body: 'Each event is signed with ed25519. Receipts carry actor, action, arguments hash, policy verdict, and timestamp.',
  },
  {
    title: 'Replay audit',
    body: 'The ledger is append-only and replayable. Any audit trace can be reconstructed from the signed receipt stream.',
  },
  {
    title: 'Schema versioning',
    body: 'X-ACGS-Schema-Version propagates through every bus hop so consumers detect schema drift at the wire layer.',
  },
]

const RECEIPT_ANATOMY = [
  { field: 'event_id', type: 'uuid', note: 'Globally unique per emission' },
  { field: 'actor', type: 'string', note: 'Agent identity — verified by executor gate' },
  { field: 'action', type: 'string', note: 'Verb.noun canonical form' },
  { field: 'args_hash', type: 'sha256', note: 'Argument fingerprint — replay-safe' },
  { field: 'policy_verdict', type: 'enum', note: 'ALLOW | DENY | ESCALATE | TRANSFORM' },
  { field: 'issued_at', type: 'RFC 3339', note: 'Monotonic wall clock at gate' },
  { field: 'signature', type: 'ed25519', note: 'Over canonical JSON bytes' },
]

const API_ENDPOINTS: {
  method: string
  path: string
  description: string
  status: 'confirmed' | 'partial'
}[] = [
  {
    method: 'POST',
    path: '/api/v1/events',
    description: 'Emit signed event to the bus',
    status: 'confirmed',
  },
  {
    method: 'GET',
    path: '/api/v1/events/{id}',
    description: 'Retrieve event with receipt',
    status: 'confirmed',
  },
  {
    method: 'GET',
    path: '/api/v1/receipts/{hash}',
    description: 'Verify receipt by content hash',
    status: 'confirmed',
  },
  {
    method: 'POST',
    path: '/api/v1/replay',
    description: 'Replay event stream for audit',
    status: 'partial',
  },
  {
    method: 'GET',
    path: '/api/v1/health',
    description: 'Bus health and schema version',
    status: 'confirmed',
  },
]

const RELATED_LINKS: {
  href: string
  label: string
  status: 'confirmed' | 'partial'
  note: string
}[] = [
  {
    href: '/failure-modes',
    label: 'Failure catalogue',
    status: 'confirmed',
    note: 'Bus handles these failure classes',
  },
  {
    href: '/governance-patterns',
    label: 'Governance patterns',
    status: 'confirmed',
    note: 'No-valid-receipt, no-action pattern',
  },
  {
    href: '/products',
    label: 'ACGS products',
    status: 'confirmed',
    note: 'Full runtime governance suite',
  },
  {
    href: '/trust',
    label: 'Trust center',
    status: 'partial',
    note: 'Evidence in engineering draft',
  },
  {
    href: '/agent-readable',
    label: 'Agent-readable rules',
    status: 'confirmed',
    note: 'Rules agents must follow on this bus',
  },
]

// ── Primitives ────────────────────────────────────────────────────────────────

function StatusPill({
  status,
  label,
}: {
  status: 'confirmed' | 'partial' | 'blocked'
  label?: string
}) {
  return <span className={`pill ${status}`}>{label ?? status}</span>
}

function Section({
  folio,
  title,
  children,
}: {
  folio: string
  title: string
  children: ReactNode
}) {
  return (
    <section className="privacy-section">
      <div className="m-sec-head">
        <div className="num">{folio}</div>
        <h2>{title}</h2>
      </div>
      <div className="privacy-section-body">{children}</div>
    </section>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function AgentBus() {
  return (
    <MarketingFrame>
      <div className="ab-page">
        {/* §1 — Hero: asymmetric split */}
        <header className="ab-hero">
          <div className="ab-hero-main">
            <div className="m-eyebrow">
              <span className="asterism" aria-hidden="true">
                ⁂
              </span>
              <span>Agent bus · Observability layer</span>
            </div>
            <h1 className="ab-h1">
              Every action,
              <br />
              <em className="u-em-rust">signed</em> before it lands
            </h1>
            <p className="ab-lede">
              The ACGS agent bus sits between agent reasoning and real-world side effects. It
              captures, signs, and receipts every event before an executor may proceed. No valid
              receipt — no action.
            </p>
            <div className="ab-hero-actions">
              <a
                className="btn btn-primary"
                href="/console"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/console')
                }}
              >
                Open the console
              </a>
              <a
                className="btn btn-ghost"
                href="/products"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/products')
                }}
              >
                See all products
              </a>
            </div>
          </div>

          <div className="ab-hero-proof" data-theme="control-plane">
            <div className="ab-proof-widget">
              <div className="ab-proof-label">Live receipt · verified</div>
              <dl className="ab-receipt-dl">
                {SAMPLE_RECEIPT.map(({ label, value }) => (
                  <div className="ab-receipt-dl-row" key={label}>
                    <dt className="ab-receipt-dt">{label}</dt>
                    <dd className="ab-receipt-dd">{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="ab-proof-sig">
                <StatusPill status="confirmed" label="signature valid" />
              </div>
            </div>
          </div>
        </header>

        {/* §2 — Proof strip: three key facts */}
        <div className="ab-proof-strip">
          {PROOF_FACTS.map(({ folio, stat, sub }) => (
            <div className="ab-proof-item" key={folio}>
              <div className="ab-proof-folio">{folio}</div>
              <div className="ab-proof-stat">{stat}</div>
              <div className="ab-proof-sub">{sub}</div>
            </div>
          ))}
        </div>

        {/* §3 — Observer principle: full-width dark panel */}
        <section className="ab-observer" data-theme="control-plane" aria-labelledby="ab-observer-h">
          <div className="ab-observer-inner">
            <div className="m-eyebrow">
              <span className="asterism" aria-hidden="true">
                ⁂
              </span>
              <span>Core principle</span>
            </div>
            <p className="ab-observer-headline" id="ab-observer-h">
              The bus sees <em className="u-em-rust">everything</em> the agent does.
            </p>
            <p className="ab-observer-body">
              Before an executor runs a tool call, writes a file, or touches an API, the event
              passes through the bus gate. The gate evaluates policy, assigns a verdict, and issues
              a signed receipt. The executor checks the receipt before proceeding — not after.
            </p>
          </div>
        </section>

        {/* §4 — Core capabilities: 2×2 bento */}
        <Section folio="No. 01" title="Core capabilities">
          <div className="ab-bento">
            {CAPABILITIES.map((cap) => (
              <article className="ab-bento-card" key={cap.title}>
                <h3 className="ab-bento-title">{cap.title}</h3>
                <p className="ab-bento-body">{cap.body}</p>
              </article>
            ))}
          </div>
        </Section>

        {/* §5 — Evidence signing: parchment receipt anatomy */}
        <Section folio="No. 02" title="Receipt anatomy">
          <div className="ab-signing">
            <p className="ab-signing-intro">
              A Decision Receipt is a canonical, signed JSON document. Every field is required; any
              missing field is a DENY at the gate.
            </p>
            <table className="m-coverage">
              <thead>
                <tr>
                  <th>Field</th>
                  <th>Type</th>
                  <th>Purpose</th>
                </tr>
              </thead>
              <tbody>
                {RECEIPT_ANATOMY.map(({ field, type, note }) => (
                  <tr key={field}>
                    <td className="ab-field-cell">{field}</td>
                    <td className="ab-type-cell tabular">{type}</td>
                    <td>{note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>

        {/* §6 — API surface table */}
        <Section folio="No. 03" title="API surface">
          <table className="m-coverage">
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Description</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {API_ENDPOINTS.map(({ method, path, description, status }) => (
                <tr key={path}>
                  <td className="ab-method tabular">{method}</td>
                  <td className="ab-path">{path}</td>
                  <td>{description}</td>
                  <td>
                    <StatusPill status={status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        {/* §7 — Cross-linking: related resources */}
        <Section folio="No. 04" title="Related resources">
          <ul className="ab-related-list">
            {RELATED_LINKS.map(({ href, label, status, note }) => (
              <li className="ab-related-item" key={href}>
                <a
                  className="ab-related-link"
                  href={href}
                  onClick={(e) => {
                    e.preventDefault()
                    navigate(href)
                  }}
                >
                  {label}
                </a>
                <StatusPill status={status} />
                <span className="ab-related-note">{note}</span>
              </li>
            ))}
          </ul>
        </Section>

        {/* §8 — CTA close */}
        <section className="ab-cta" aria-labelledby="ab-cta-h">
          <div className="ab-cta-inner">
            <div className="m-eyebrow">
              <span className="asterism" aria-hidden="true">
                ⁂
              </span>
              <span>Deploy the bus</span>
            </div>
            <h2 className="ab-cta-headline" id="ab-cta-h">
              Governed agents start <em className="u-em-rust">here</em>
            </h2>
            <p className="ab-cta-body">
              The agent bus is the first thing you wire. Every framework integration, every
              receipt-gated executor, and every audit trail flows through it.
            </p>
            <div className="ab-cta-actions">
              <a
                className="btn btn-primary"
                href="/console"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/console')
                }}
              >
                Open the console
              </a>
              <a
                className="btn btn-secondary"
                href="/governance-patterns"
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
      </div>
    </MarketingFrame>
  )
}
