import { useState } from 'react'
import { usePolicies } from '../../api/hooks'
import type { PolicyRule } from '../../api/types'
import { track } from '../../surfaces/console/telemetry'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

const policyFields = (r: PolicyRule) => [r.id, r.name, r.citation, r.posture, r.prose]

export function Policies() {
  const [activeId, setActiveId] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const { data, isLoading, isError, refetch } = usePolicies()
  const filtered = useTextFilter(data, query, policyFields)

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const active = filtered.find((r) => r.id === activeId) ?? filtered[0]

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search rules, citations…"
        ariaLabel="Search policies"
        meta={`${filtered.length} of ${data.length} rules · 8 amended · v3.1.0`}
      />

      {filtered.length === 0 || !active ? (
        <EmptyState
          emptyMeans="awaiting-bus"
          query={query}
          label="policies"
          onClear={() => setQuery('')}
        />
      ) : (
        <div className="policy-list">
          <div className="policy-rules">
            {filtered.map((r, ruleIndex) => (
              <button
                key={r.id}
                type="button"
                className={`policy-rule ${r.id === active.id ? 'active' : ''}`}
                onClick={() => {
                  // Positional index only — the rule id/name never leaves
                  // the console (design §4 payload hygiene).
                  track('policy_rule_selected', { rule_position: ruleIndex })
                  setActiveId(r.id)
                }}
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
              <span className="u-ml-auto">
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
      )}
    </div>
  )
}
