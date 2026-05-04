import { useMaci } from '../../api/hooks'
import type { MaciCard } from '../../api/types'

function Lane({ title, meta, cards }: { title: string; meta: string; cards: MaciCard[] }) {
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
            <span className="u-mono-cap-accent">open ›</span>
          </div>
        </article>
      ))}
    </div>
  )
}

export function Maci() {
  const { data, isLoading, isError, refetch } = useMaci()

  if (isLoading) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">⁂ Polling …</span>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">
          ⁂ Could not reach the bus.{' '}
          <button type="button" className="m-text-link" onClick={() => refetch()}>
            Retry
          </button>
        </span>
      </div>
    )
  }

  return (
    <div>
      <p className="u-prose-lede">
        Three lanes, no overlap. An agent that drafts cannot validate; an agent that validates
        cannot execute. The bus refuses to dispatch any action whose lane provenance is missing or
        duplicated.
      </p>
      <div className="maci-board">
        <Lane title="Proposer" meta={`${data.proposer.length} open`} cards={data.proposer} />
        <Lane title="Validator" meta={`${data.validator.length} open`} cards={data.validator} />
        <Lane title="Executor" meta={`${data.executor.length} dispatched`} cards={data.executor} />
      </div>
    </div>
  )
}
