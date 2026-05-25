import { useState } from 'react'
import { useTenants } from '../../api/hooks'
import type { Tenant, TenantState } from '../../api/types'
import {
  CONSTITUTION_HASH,
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  type LocalReceipt,
  Receipt,
  SearchToolbar,
  useTextFilter,
} from './shared'

const STATE_TO_PILL: Record<TenantState, string> = {
  active: 'confirmed',
  standby: 'partial',
  sealed: 'blocked',
}

const tenantFields = (t: Tenant) => [t.id, t.name, t.tier, t.jurisdiction, t.state, t.lastActivity]

export function Tenants() {
  const [query, setQuery] = useState('')
  const [receipt, setReceipt] = useState<LocalReceipt | null>(null)
  const { data, isLoading, isError, refetch } = useTenants()
  const filtered = useTextFilter(data, query, tenantFields)

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const active = data.find((t) => t.state === 'active')
  const request = (label: string, tenantId: string) => {
    setReceipt({
      title: `Local tenancy request · ${label}`,
      body: `${tenantId} request is staged in this browser only; switching requires custodian attestation before the bus reloads constitution context.`,
      meta: `${CONSTITUTION_HASH} · tenancy · ${new Date().toISOString()}`,
    })
  }

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search tenants, jurisdictions, tiers…"
        ariaLabel="Search tenants"
        meta={`${filtered.length} of ${data.length} tenants · 1 active · 1 sealed · custodian-01 has access`}
      />
      <Receipt receipt={receipt} />

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

      <div className="c-toolbar u-mt-3xl">
        <strong className="u-display-h">
          All <em className="u-em-rust">tenancies</em>
        </strong>
        <span className="c-meta">switching reloads the constitution against the new tenant</span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          emptyMeans="fresh-tenant"
          query={query}
          label="tenants"
          onClear={() => setQuery('')}
        />
      ) : (
        <table className="c-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Tenant</th>
              <th>Tier</th>
              <th>Jurisdiction</th>
              <th className="u-align-right">Agents</th>
              <th className="u-align-right">Matters</th>
              <th className="u-align-right">Refusals · 24h</th>
              <th>State</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((t) => (
              <tr key={t.id}>
                <td className="mono">{t.id}</td>
                <td>
                  <strong className="u-fw-600">{t.name}</strong>
                  <div className="tenants-cell-meta">last {t.lastActivity}</div>
                </td>
                <td className="mono u-color-ink-2">{t.tier}</td>
                <td className="mono u-color-muted">{t.jurisdiction}</td>
                <td className="num u-align-right">{t.agents}</td>
                <td className="num u-align-right">{t.matters}</td>
                <td className="num u-align-right">{t.refusals24h.toLocaleString()}</td>
                <td>
                  <span className={`pill ${STATE_TO_PILL[t.state]}`}>{t.state}</span>
                </td>
                <td>
                  {t.state === 'active' ? (
                    <span className="c-meta u-color-ink-3">in session</span>
                  ) : t.state === 'sealed' ? (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => request('unseal', t.id)}
                    >
                      Request unsealing
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => request('switch', t.id)}
                    >
                      Switch to →
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="u-mt-xxl u-mono-cap-wide">
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
