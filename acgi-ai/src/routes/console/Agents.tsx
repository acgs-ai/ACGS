import { useAgents } from '../../api/hooks'

export function Agents() {
  const { data, isLoading, isError, refetch, isFetching } = useAgents()

  if (isLoading) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">⁂ Polling agent registry…</span>
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

  const total = data.length
  const meta = `${total} of ${total} · ${isFetching ? 'refreshing' : 'live'} · 608508a9bd224290`

  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search agents, roles, lanes…"
          aria-label="Search agents"
        />
        <span className="c-meta">{meta}</span>
      </div>

      <table className="c-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Agent</th>
            <th>Role</th>
            <th>MACI lane</th>
            <th>Model</th>
            <th style={{ textAlign: 'right' }}>Refusals · 24h</th>
            <th>Posture</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {data.map((a) => (
            <tr key={a.id}>
              <td className="mono">{a.id}</td>
              <td>
                <strong style={{ fontWeight: 600 }}>{a.name}</strong>
              </td>
              <td style={{ color: 'var(--ink-2)' }}>{a.role}</td>
              <td className="mono" style={{ color: 'var(--ink-2)' }}>
                {a.lane}
              </td>
              <td className="mono" style={{ color: 'var(--muted)' }}>
                {a.model}
              </td>
              <td className="num" style={{ textAlign: 'right' }}>
                {a.refusals24h.toLocaleString()}
              </td>
              <td>
                <span className={`pill ${a.health}`}>
                  {a.health === 'privileged' ? 'Privileged' : a.health}
                </span>
              </td>
              <td className="mono" style={{ color: 'var(--muted)' }}>
                {a.lastSeen}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
