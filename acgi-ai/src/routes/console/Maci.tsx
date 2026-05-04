type Card = {
  id: string
  title: string
  body: string
  agent: string
  ts: string
  posture: 'confirmed' | 'partial' | 'blocked' | 'privileged'
}

const PROPOSER: Card[] = [
  {
    id: 'P-1502',
    title: 'Refuse cross-jurisdiction citation',
    body: 'Public Q on a New York matter cited a California statute. Drafting refusal that names the venue mismatch and proposes the correct §.',
    agent: 'analyst-04',
    ts: '14:08:22',
    posture: 'partial',
  },
  {
    id: 'P-1503',
    title: 'Promote draft on §164.502(b) refusal',
    body: 'Six independent refusals of identical shape on matter disclosure. Proposing a canon entry to escalate identical future requests to deliberation.',
    agent: 'analyst-12',
    ts: '14:06:11',
    posture: 'confirmed',
  },
]

const VALIDATOR: Card[] = [
  {
    id: 'V-0892',
    title: 'Cross-validate P-1497',
    body: 'Independent re-derivation of cite §164.502(b). Replay matches; Dafny proof artifact attached. Recommending promotion.',
    agent: 'reviewer-02',
    ts: '14:07:48',
    posture: 'confirmed',
  },
  {
    id: 'V-0893',
    title: 'Hold P-1499 — drift suspected',
    body: 'Constitution byte-diff present in proposer trace; promoting to deliberations queue with hash mismatch flag. Refusing to validate.',
    agent: 'reviewer-09',
    ts: '14:05:10',
    posture: 'blocked',
  },
]

const EXECUTOR: Card[] = [
  {
    id: 'E-2210',
    title: 'Tool call · matter.notes.append',
    body: 'Custodian-attested write into Matter-9821; redactor-04 sanitised PHI before commit.',
    agent: 'executor-01',
    ts: '14:09:03',
    posture: 'privileged',
  },
  {
    id: 'E-2211',
    title: 'Tool call · cite.lookup',
    body: 'Public statute index lookup, no privileged context, no PHI; dispatched without escalation.',
    agent: 'executor-03',
    ts: '14:09:00',
    posture: 'confirmed',
  },
]

function Lane({ title, meta, cards }: { title: string; meta: string; cards: Card[] }) {
  return (
    <div className="maci-lane">
      <div className="maci-lane-head">
        <span>{title}</span>
        <span>{meta}</span>
      </div>
      {cards.map((c) => (
        <article className="maci-card" key={c.id}>
          <h4>{c.title}</h4>
          <div className="meta">
            {c.id} · {c.agent} · {c.ts}
          </div>
          <p>{c.body}</p>
          <div className="maci-card-foot">
            <span className={`pill ${c.posture}`}>
              {c.posture === 'privileged' ? 'Privileged' : c.posture}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>
              open ›
            </span>
          </div>
        </article>
      ))}
    </div>
  )
}

export function Maci() {
  return (
    <div>
      <p
        style={{
          fontFamily: 'var(--font-serif)',
          fontSize: 16,
          lineHeight: 1.6,
          color: 'var(--ink-3)',
          maxWidth: '64ch',
          marginBottom: 24,
        }}
      >
        Three lanes, no overlap. An agent that drafts cannot validate; an agent that validates
        cannot execute. The bus refuses to dispatch any action whose lane provenance is missing or
        duplicated.
      </p>
      <div className="maci-board">
        <Lane title="Proposer" meta="2 open" cards={PROPOSER} />
        <Lane title="Validator" meta="2 open · 1 hold" cards={VALIDATOR} />
        <Lane title="Executor" meta="2 dispatched" cards={EXECUTOR} />
      </div>
    </div>
  )
}
