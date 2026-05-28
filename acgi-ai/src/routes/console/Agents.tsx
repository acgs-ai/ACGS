import { useState } from 'react'
import { useAgents } from '../../api/hooks'
import type { Agent } from '../../api/types'
import {
  CONSTITUTION_HASH,
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  SearchToolbar,
  useTextFilter,
} from './shared'

const agentFields = (a: Agent) => [a.id, a.name, a.role, a.lane, a.model, a.health, a.lastSeen]

export function Agents() {
  const [query, setQuery] = useState('')
  const [view, setView] = useState<'board' | 'table'>('board')
  const { data, isLoading, isError, refetch, isFetching } = useAgents()
  const filtered = useTextFilter(data, query, agentFields)

  if (isLoading) {
    return <ConsoleLoading label="Polling agent registry…" />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const total = data.length

  const meta = (
    <span className="toolbar-meta-wrapper">
      <span className="btn-group">
        <button
          type="button"
          className={`btn ${view === 'board' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setView('board')}
        >
          Board
        </button>
        <button
          type="button"
          className={`btn ${view === 'table' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setView('table')}
        >
          Table
        </button>
      </span>
      <span>
        {filtered.length} of {total} · {isFetching ? 'refreshing' : 'live'} · {CONSTITUTION_HASH}
      </span>
    </span>
  )

  const renderAgentCard = (a: Agent) => (
    <article className="agent-card" key={a.id}>
      <div className="agent-card-head">
        <h4>{a.name}</h4>
        <span className={`pill ${a.health}`}>
          {a.health === 'privileged' ? 'Privileged' : a.health}
        </span>
      </div>
      <div className="agent-card-meta">
        {a.id} · {a.model}
      </div>
      <div className="agent-card-body">
        <strong>Role:</strong> {a.role}
        <br />
        <strong>Refusals (24h):</strong> {a.refusals24h.toLocaleString()}
      </div>
      <div className="agent-card-foot">
        <span className="last-seen">Seen: {a.lastSeen}</span>
        <span className="u-mono-cap-accent">active ›</span>
      </div>
    </article>
  )

  const proposers = filtered.filter((a) => a.lane === 'Proposer')
  const validators = filtered.filter((a) => a.lane === 'Validator')
  const executors = filtered.filter((a) => a.lane === 'Executor')
  const custodians = filtered.filter((a) => a.lane === 'Custodian')

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search agents, roles, lanes…"
        ariaLabel="Search agents"
        meta={meta}
      />

      {filtered.length === 0 ? (
        <EmptyState query={query} label="agents" onClear={() => setQuery('')} />
      ) : view === 'board' ? (
        <div className="agent-board">
          <div className="agent-lane">
            <div className="agent-lane-head">
              <span>Proposer</span>
              <span>{proposers.length}</span>
            </div>
            {proposers.map(renderAgentCard)}
          </div>
          <div className="agent-lane">
            <div className="agent-lane-head">
              <span>Validator</span>
              <span>{validators.length}</span>
            </div>
            {validators.map(renderAgentCard)}
          </div>
          <div className="agent-lane">
            <div className="agent-lane-head">
              <span>Executor</span>
              <span>{executors.length}</span>
            </div>
            {executors.map(renderAgentCard)}
          </div>
          <div className="agent-lane">
            <div className="agent-lane-head">
              <span>Custodian</span>
              <span>{custodians.length}</span>
            </div>
            {custodians.map(renderAgentCard)}
          </div>
        </div>
      ) : (
        <table className="c-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Agent</th>
              <th>Role</th>
              <th>MACI lane</th>
              <th>Model</th>
              <th className="u-align-right">Refusals · 24h</th>
              <th>Posture</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.id}</td>
                <td>
                  <strong className="u-fw-600">{a.name}</strong>
                </td>
                <td className="u-color-ink-2">{a.role}</td>
                <td className="mono u-color-ink-2">{a.lane}</td>
                <td className="mono u-color-muted">{a.model}</td>
                <td className="num u-align-right">{a.refusals24h.toLocaleString()}</td>
                <td>
                  <span className={`pill ${a.health}`}>
                    {a.health === 'privileged' ? 'Privileged' : a.health}
                  </span>
                </td>
                <td className="mono u-color-muted">{a.lastSeen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
