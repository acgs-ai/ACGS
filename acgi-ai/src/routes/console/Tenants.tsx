import { useTenants } from '../../api/hooks'
import type { TenantState } from '../../api/types'

const STATE_TO_PILL: Record<TenantState, string> = {
  active: 'confirmed',
  standby: 'partial',
  sealed: 'blocked',
}

export function Tenants() {
  const { data, isLoading, isError, refetch } = useTenants()

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

  const active = data.find((t) => t.state === 'active')

  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search tenants, jurisdictions, tiers…"
          aria-label="Search tenants"
        />
        <span className="c-meta">4 tenants · 1 active · 1 sealed · custodian-01 has access</span>
      </div>

      {active && (
        <div className="tenant-active">
          <div className="tenant-active-head">
            <span className="label">Active tenancy</span>
            <span className={`pill ${STATE_TO_PILL[active.state]}`}>active</span>
          </div>
          <h3>{active.name}</h3>
          <div className="tenant-active-meta">
            <span>{active.id}</span>
            <span>tier · {active.tier}</span>
            <span>jurisdiction · {active.jurisdiction}</span>
            <span>last · {active.lastActivity}</span>
          </div>
          <div className="tenant-active-stats">
            <Stat label="Agents" value={active.agents} unit="bound" />
            <Stat label="Matters" value={active.matters} unit="custodial" />
            <Stat label="Refusals · 24h" value={active.refusals24h} unit="cited" />
          </div>
        </div>
      )}

      <div className="c-toolbar" style={{ marginTop: 32 }}>
        <strong style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 400 }}>
          All <em style={{ fontStyle: 'italic', color: 'var(--accent)' }}>tenancies</em>
        </strong>
        <span className="c-meta">switching reloads the constitution against the new tenant</span>
      </div>

      <table className="c-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Tenant</th>
            <th>Tier</th>
            <th>Jurisdiction</th>
            <th style={{ textAlign: 'right' }}>Agents</th>
            <th style={{ textAlign: 'right' }}>Matters</th>
            <th style={{ textAlign: 'right' }}>Refusals · 24h</th>
            <th>State</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {data.map((t) => (
            <tr key={t.id}>
              <td className="mono">{t.id}</td>
              <td>
                <strong style={{ fontWeight: 600 }}>{t.name}</strong>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    color: 'var(--muted)',
                    marginTop: 2,
                    letterSpacing: '0.04em',
                  }}
                >
                  last {t.lastActivity}
                </div>
              </td>
              <td className="mono" style={{ color: 'var(--ink-2)' }}>
                {t.tier}
              </td>
              <td className="mono" style={{ color: 'var(--muted)' }}>
                {t.jurisdiction}
              </td>
              <td className="num" style={{ textAlign: 'right' }}>
                {t.agents}
              </td>
              <td className="num" style={{ textAlign: 'right' }}>
                {t.matters}
              </td>
              <td className="num" style={{ textAlign: 'right' }}>
                {t.refusals24h.toLocaleString()}
              </td>
              <td>
                <span className={`pill ${STATE_TO_PILL[t.state]}`}>{t.state}</span>
              </td>
              <td>
                {t.state === 'active' ? (
                  <span className="c-meta" style={{ color: 'var(--ink-3)' }}>
                    in session
                  </span>
                ) : t.state === 'sealed' ? (
                  <span className="c-meta" style={{ color: 'var(--muted)' }}>
                    request unsealing
                  </span>
                ) : (
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ padding: '6px 12px', fontSize: 13 }}
                  >
                    Switch to →
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <p
        style={{
          marginTop: 28,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ Switching tenancy emits an audit event; sealed tenancies require a custodian + maintainer
        attestation to reopen
      </p>
    </div>
  )
}

function Stat({ label, value, unit }: { label: string; value: number; unit: string }) {
  return (
    <div className="tenant-stat">
      <div className="label">{label}</div>
      <div className="value">{value.toLocaleString()}</div>
      <div className="unit">{unit}</div>
    </div>
  )
}
