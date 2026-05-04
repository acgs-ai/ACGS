type Agent = {
  id: string
  name: string
  role: string
  lane: 'Proposer' | 'Validator' | 'Executor' | 'Custodian'
  model: string
  refusals24h: number
  health: 'confirmed' | 'partial' | 'blocked' | 'privileged'
  lastSeen: string
}

const AGENTS: Agent[] = [
  {
    id: 'A-01',
    name: 'analyst-04',
    role: 'Public counsel intake',
    lane: 'Proposer',
    model: 'sonnet 4.6',
    refusals24h: 184,
    health: 'confirmed',
    lastSeen: '14:09:02',
  },
  {
    id: 'A-02',
    name: 'analyst-12',
    role: 'Public counsel intake',
    lane: 'Proposer',
    model: 'sonnet 4.6',
    refusals24h: 211,
    health: 'confirmed',
    lastSeen: '14:08:51',
  },
  {
    id: 'A-03',
    name: 'reviewer-02',
    role: 'Cross-validation',
    lane: 'Validator',
    model: 'opus 4.7',
    refusals24h: 38,
    health: 'confirmed',
    lastSeen: '14:08:48',
  },
  {
    id: 'A-04',
    name: 'reviewer-09',
    role: 'Cross-validation',
    lane: 'Validator',
    model: 'opus 4.7',
    refusals24h: 41,
    health: 'confirmed',
    lastSeen: '14:09:11',
  },
  {
    id: 'A-05',
    name: 'executor-01',
    role: 'Tool dispatch',
    lane: 'Executor',
    model: 'haiku 4.5',
    refusals24h: 12,
    health: 'partial',
    lastSeen: '14:09:03',
  },
  {
    id: 'A-06',
    name: 'executor-03',
    role: 'Tool dispatch',
    lane: 'Executor',
    model: 'haiku 4.5',
    refusals24h: 18,
    health: 'confirmed',
    lastSeen: '14:09:00',
  },
  {
    id: 'A-07',
    name: 'custodian-01',
    role: 'Matter custody',
    lane: 'Custodian',
    model: 'opus 4.7',
    refusals24h: 502,
    health: 'privileged',
    lastSeen: '14:09:05',
  },
  {
    id: 'A-08',
    name: 'custodian-02',
    role: 'Matter custody',
    lane: 'Custodian',
    model: 'opus 4.7',
    refusals24h: 396,
    health: 'privileged',
    lastSeen: '14:08:58',
  },
  {
    id: 'A-09',
    name: 'redactor-04',
    role: 'PHI redaction',
    lane: 'Executor',
    model: 'haiku 4.5',
    refusals24h: 0,
    health: 'blocked',
    lastSeen: '13:42:11',
  },
  {
    id: 'A-10',
    name: 'historian-01',
    role: 'Decision-log keeper',
    lane: 'Validator',
    model: 'opus 4.7',
    refusals24h: 0,
    health: 'confirmed',
    lastSeen: '14:09:09',
  },
  {
    id: 'A-11',
    name: 'oracle-02',
    role: 'Statute lookup',
    lane: 'Proposer',
    model: 'sonnet 4.6',
    refusals24h: 0,
    health: 'confirmed',
    lastSeen: '14:09:07',
  },
  {
    id: 'A-12',
    name: 'maintainer-01',
    role: 'Constitution drift watch',
    lane: 'Custodian',
    model: 'opus 4.7',
    refusals24h: 0,
    health: 'confirmed',
    lastSeen: '14:09:10',
  },
]

export function Agents() {
  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search agents, roles, lanes…"
          aria-label="Search agents"
        />
        <span className="c-meta">12 of 12 · live · 608508a9bd224290</span>
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
          {AGENTS.map((a) => (
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
