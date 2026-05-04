import { useAccount } from '../../api/hooks'
import type { IdentitySource } from '../../api/types'
import { navigate } from '../../lib/navigate'

const SOURCE_LABEL: Record<IdentitySource, string> = {
  sso: 'SSO',
  self: 'Self',
  constitution: 'Constitution',
}

export function Account() {
  const { data, isLoading, isError, refetch } = useAccount()

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
      <p className="u-prose-lede-tight">
        Your record on the bus. The constitution decides which lanes you may operate in; you decide
        your authentication factors. Everything you do from this surface is countersigned in the
        audit trail under your name.
      </p>

      {/* Identity */}
      <div className="settings-section u-mt-3xl">
        <div className="settings-section-head">Identity</div>
        {data.identity.map((f) => (
          <div className="settings-row" key={f.key}>
            <div>
              <span className="key">{f.key}</span>
              <span className="desc">
                {f.source === 'constitution'
                  ? 'Set by the operating constitution; cannot be amended from this page.'
                  : f.source === 'sso'
                    ? 'Provided by your identity provider at sign-in.'
                    : 'Self-managed; rotate via your IdP.'}
              </span>
            </div>
            <span
              className={`tag ${f.source === 'constitution' ? 'constitution' : f.source === 'sso' ? 'operator' : 'default'}`}
            >
              {SOURCE_LABEL[f.source]}
            </span>
            <span className="val">{f.value}</span>
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              disabled={f.source === 'constitution' || f.source === 'sso'}
            >
              {f.source === 'self' ? 'Rotate' : '—'}
            </button>
          </div>
        ))}
      </div>

      {/* Active sessions */}
      <div className="settings-section">
        <div className="settings-section-head">Active sessions</div>
        <table className="c-table u-mt-sm">
          <thead>
            <tr>
              <th>ID</th>
              <th>Device</th>
              <th>IP</th>
              <th>Location</th>
              <th>Started</th>
              <th>State</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {data.sessions.map((s) => (
              <tr key={s.id}>
                <td className="mono">{s.id}</td>
                <td>{s.device}</td>
                <td className="mono u-color-ink-2">{s.ip}</td>
                <td className="mono u-color-muted">{s.location}</td>
                <td className="mono u-color-muted">{s.started}</td>
                <td>
                  {s.current ? (
                    <span className="pill confirmed">this session</span>
                  ) : (
                    <span className="pill partial">other</span>
                  )}
                </td>
                <td>
                  {s.current ? (
                    <span className="c-meta u-color-ink-3">—</span>
                  ) : (
                    <button type="button" className="btn btn-ghost btn-sm">
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Recent actions — scoped to this user */}
      <div className="settings-section">
        <div className="settings-section-head">Recent actions · last 5 by you</div>
        <div className="audit-list u-mt-sm">
          {data.recentActions.map((a) => (
            <div className="audit-row" key={a.ts}>
              <span className="ts">{a.ts}</span>
              <span className={`pill ${a.posture}`}>
                {a.posture === 'privileged' ? 'Privileged' : a.posture}
              </span>
              <span className="ev">
                {a.action}
                <span className="src">cited {a.cite}</span>
              </span>
              <span className="hash-col">
                <strong>608508a9</strong>
                <span> · attested</span>
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="account-actions">
        <button
          className="btn btn-secondary"
          type="button"
          onClick={() => navigate('/console/audit')}
        >
          Open full audit trail →
        </button>
        <button className="btn btn-ghost" type="button" onClick={() => navigate('/login')}>
          Sign out
        </button>
        <span className="account-stamp">608508a9 · attest carried · session S-9421</span>
      </div>

      <p className="u-mt-xxl u-mono-cap-wide">
        ⁂ The constitution rules you, you do not rule it · personal preferences do not override lane
        policy
      </p>
    </div>
  )
}
