import type { ReactNode } from 'react'

type Delib = {
  id: string
  matter: string
  title: string
  /** Single word from `title` to render in italic-rust (DESIGN.md §2.2). */
  emphasis: string
  citation: string
  body: string
  opened: string
  due: string
  posture: 'confirmed' | 'partial' | 'blocked' | 'privileged'
}

const DELIBS: Delib[] = [
  {
    id: 'D-2031',
    matter: 'Matter-9821',
    title: 'Disclose drafting context to opposing counsel?',
    emphasis: 'Disclose',
    citation: '§164.502(b) · privileged',
    body: 'Custodian-01 drafted a memo whose recipient list includes opposing counsel. The bus held the dispatch and opened a deliberation. Recommend on-call partner review with attestation; refuse otherwise.',
    opened: '2026-05-03 13:32:41',
    due: '2026-05-03 17:32:00',
    posture: 'privileged',
  },
  {
    id: 'D-2032',
    matter: 'Matter-3387',
    title: 'Cross-jurisdiction citation in public reply',
    emphasis: 'public',
    citation: 'Internal §3.4',
    body: 'Analyst-04 surfaced a refusal whose draft cites a California statute on a New York matter. The cite is technically defensible but reads as venue-shopping in public; deliberation requested before the reply leaves the bus.',
    opened: '2026-05-03 14:08:22',
    due: '2026-05-03 18:08:00',
    posture: 'partial',
  },
  {
    id: 'D-2033',
    matter: 'Matter-7104',
    title: 'Promote P-1503 to canon?',
    emphasis: 'canon',
    citation: 'Internal §3.1',
    body: 'Six identical refusals of shape "matter disclosure" in the past four hours. Proposer suggests a canon escalation that routes future identical traffic directly to deliberation, bypassing the proposer lane.',
    opened: '2026-05-03 14:06:11',
    due: '2026-05-04 08:00:00',
    posture: 'confirmed',
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

export function Deliberations() {
  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search by matter, citation, posture…"
          aria-label="Search deliberations"
        />
        <span className="c-meta">3 open · oldest 13:32 UTC · SLA 8h</span>
      </div>

      <div className="delib-list">
        {DELIBS.map((d) => (
          <article className="delib-card" key={d.id}>
            <div>
              <h4>{renderTitle(d.title, d.emphasis)}</h4>
              <div className="meta">
                <span>{d.id}</span>
                <span>{d.matter}</span>
                <span>{d.citation}</span>
                <span>opened {d.opened.split(' ')[1]}</span>
                <span>due {d.due.split(' ')[1]}</span>
              </div>
              <p className="body">{d.body}</p>
              <div style={{ marginTop: 14, display: 'flex', gap: 10, alignItems: 'center' }}>
                <span className={`pill ${d.posture}`}>
                  {d.posture === 'privileged' ? 'Privileged' : d.posture}
                </span>
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    color: 'var(--muted)',
                    letterSpacing: '0.04em',
                  }}
                >
                  608508a9 · attest required
                </span>
              </div>
            </div>
            <div className="delib-card-actions">
              <button className="btn btn-rust" type="button">
                Approve
              </button>
              <button className="btn btn-secondary" type="button">
                Hold
              </button>
              <button className="btn btn-ghost" type="button">
                Refuse
              </button>
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
