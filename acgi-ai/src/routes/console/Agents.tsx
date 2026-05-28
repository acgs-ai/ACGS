import { useState } from 'react'
import { useAgents } from '../../api/hooks'
import type { Agent } from '../../api/types'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

const agentFields = (a: Agent) => [a.id, a.name, a.role, a.lane, a.model, a.health, a.lastSeen]

export function Agents() {
  const [query, setQuery] = useState('')
  const { data, isLoading, isError, refetch, isFetching } = useAgents()
  const filtered = useTextFilter(data, query, agentFields)

  if (isLoading) {
    return <ConsoleLoading label="Polling agent registry…" />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const total = data.length
  const meta = `${filtered.length} of ${total} · ${isFetching ? 'refreshing' : 'live'} · 608508a9bd224290`

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
        <EmptyState
          emptyMeans="awaiting-bus"
          query={query}
          label="agents"
          onClear={() => setQuery('')}
        />
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
