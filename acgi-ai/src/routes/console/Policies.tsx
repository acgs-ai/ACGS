import { useState } from 'react'
import { usePolicies } from '../../api/hooks'

export function Policies() {
  const [activeId, setActiveId] = useState<string | null>(null)
  const { data, isLoading, isError, refetch } = usePolicies()

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

  const active = data.find((r) => r.id === activeId) ?? data[0]

  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search rules, citations…"
          aria-label="Search policies"
        />
        <span className="c-meta">47 rules · 8 amended · v3.1.0</span>
      </div>

      <div className="policy-list">
        <div className="policy-rules">
          {data.map((r) => (
            <button
              key={r.id}
              type="button"
              className={`policy-rule ${r.id === active.id ? 'active' : ''}`}
              onClick={() => setActiveId(r.id)}
            >
              <div>
                <span className="rid">{r.id}</span>
                <div className="rname">{r.name}</div>
              </div>
              <span className={`pill ${r.posture}`}>
                {r.posture === 'privileged' ? 'Priv' : r.posture[0].toUpperCase()}
              </span>
            </button>
          ))}
        </div>

        <div className="policy-detail">
          <h3>
            {active.name
              .split('.')
              .flatMap((part, i) =>
                i === 0
                  ? [<span key={`${active.id}-${part}`}>{part}</span>]
                  : [
                      <em key={`${active.id}-dot-${part}`}>.</em>,
                      <span key={`${active.id}-${part}`}>{part}</span>,
                    ],
              )}
          </h3>
          <div className="policy-meta-row">
            <span>{active.id}</span>
            <span>· {active.citation}</span>
            <span>· hash 608508a9</span>
            <span style={{ marginLeft: 'auto' }}>
              <span className={`pill ${active.posture}`}>
                {active.posture === 'privileged' ? 'Privileged' : active.posture}
              </span>
            </span>
          </div>

          <div className="policy-prose">
            <blockquote>
              <span className="policy-citation">{active.citation.split(' ·')[0]}</span> — the rule
              is authored as prose first, compiled second. The compiled artifact below is what the
              bus actually loads.
            </blockquote>
            <p>{active.prose}</p>
          </div>

          <div className="policy-diff">
            <div className="policy-diff-head">
              <span>compiled · v3.1.0 · diff vs. v3.0.4</span>
              <span>{active.id}</span>
            </div>
            <pre>
              <span className="ctx">
                {' '}
                rule "{active.name}" {'{'}
              </span>
              {'\n'}
              <span className="rem">- when role == "public"</span>
              {'\n'}
              <span className="add">+ when agent.role == "public"</span>
              {'\n'}
              <span className="add">+ when agent.scope.contains("matter")</span>
              {'\n'}
              <span className="ctx"> deny "privilege boundary"</span>
              {'\n'}
              <span className="ctx"> cite "{active.citation.split(' ·')[0]}"</span>
              {'\n'}
              <span className="ctx"> {'}'}</span>
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
