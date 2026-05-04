import type { ReactNode } from 'react'

type Incident = {
  id: string
  ts: string
  posture: 'confirmed' | 'partial' | 'blocked' | 'privileged'
  title: string
  /** Single word from `title` rendered in italic-rust (DESIGN.md §2.2). */
  emphasis: string
  src: string
  body: string
  hash: string
}

const INCIDENTS: Incident[] = [
  {
    id: 'I-0431',
    ts: '2026-05-03 14:08:51',
    posture: 'blocked',
    title: 'Constitution byte-drift on the worker',
    emphasis: 'drift',
    src: 'maintainer-01 · drift sentry',
    body: 'Worker hash diverged from bus hash by 14 bytes between 14:08:11 and 14:08:51. Bus refused to dispatch four high-risk decisions during the window. Worker is now back to canon; the four refused calls have been replayed under the canonical hash.',
    hash: '608508a9 · 8b38',
  },
  {
    id: 'I-0430',
    ts: '2026-05-03 13:47:11',
    posture: 'partial',
    title: 'Validator quorum fell to one',
    emphasis: 'quorum',
    src: 'reviewer-09 · offline',
    body: 'reviewer-09 dropped a heartbeat at 13:47. Quorum sat at one for nine seconds before reviewer-02 picked up the validator lane. Two pending validations were held during the window; both have since been promoted.',
    hash: '608508a9 · 8b34',
  },
  {
    id: 'I-0429',
    ts: '2026-05-03 12:47:55',
    posture: 'blocked',
    title: 'Tool scope intersection empty on cite.lookup.private',
    emphasis: 'empty',
    src: 'executor-03 · cite.lookup.private',
    body: 'executor-03 attempted a private statute lookup outside its declared scope. The bus denied the call and surfaced an incident. No payload was emitted to the third-party tool. Suspected agent-scope drift; review the executor manifest.',
    hash: '608508a9 · 8b1f',
  },
  {
    id: 'I-0428',
    ts: '2026-05-03 09:31:02',
    posture: 'privileged',
    title: 'Custodian write to opposing-counsel recipient',
    emphasis: 'recipient',
    src: 'custodian-01 → matter.notes.append',
    body: 'custodian-01 staged a memo whose recipient list included opposing counsel. The bus held the dispatch and routed the matter into D-2031 for human deliberation. No write reached the matter store.',
    hash: '608508a9 · 8b09',
  },
  {
    id: 'I-0427',
    ts: '2026-05-03 08:14:20',
    posture: 'partial',
    title: 'Refusal SLA breached on Matter-3387',
    emphasis: 'breached',
    src: 'deliberation D-2032',
    body: 'D-2032 was opened at 14:08:22 and is approaching the 8h SLA window. Routed to on-call counsel; recommend partner attestation before the SLA expires at 18:08 UTC.',
    hash: '608508a9 · 8af2',
  },
]

function renderTitle(title: string, emphasis: string): ReactNode {
  const idx = title.toLowerCase().indexOf(emphasis.toLowerCase())
  if (idx === -1) return title
  return (
    <>
      {title.slice(0, idx)}
      <em>{title.slice(idx, idx + emphasis.length)}</em>
      {title.slice(idx + emphasis.length)}
    </>
  )
}

export function Incidents() {
  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search by source, citation, hash…"
          aria-label="Search incidents"
        />
        <span className="c-meta">5 open · 2 blocked · oldest 6h ago</span>
      </div>

      <div className="incidents-list">
        {INCIDENTS.map((i) => (
          <article className="incident-row" key={i.id}>
            <span className="ts">{i.ts}</span>
            <span className={`pill ${i.posture}`}>
              {i.posture === 'privileged' ? 'Privileged' : i.posture}
            </span>
            <div>
              <div className="title">{renderTitle(i.title, i.emphasis)}</div>
              <span className="src">
                {i.id} · {i.src}
              </span>
              <p>{i.body}</p>
            </div>
            <span className="view">{i.hash}</span>
          </article>
        ))}
      </div>

      <p
        style={{
          marginTop: 24,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ Incidents are escalations off the audit trail · every entry here is also signed into the
        ledger at the same hash
      </p>
    </div>
  )
}
