import { navigate } from '../../lib/navigate'

type IdentityField = {
  key: string
  value: string
  source: 'sso' | 'self' | 'constitution'
}

type Session = {
  id: string
  device: string
  ip: string
  location: string
  started: string
  current: boolean
}

type ActionRow = {
  ts: string
  posture: 'confirmed' | 'partial' | 'blocked' | 'privileged'
  action: string
  cite: string
}

const IDENTITY: IdentityField[] = [
  { key: 'name', value: 'M. Custodian', source: 'sso' },
  { key: 'email', value: 'm.custodian@hofstra-lorenz.com', source: 'sso' },
  { key: 'role', value: 'custodian · clerk', source: 'constitution' },
  { key: 'lane.allowed', value: 'Custodian, Validator', source: 'constitution' },
  { key: 'mfa', value: 'WebAuthn · iCloud Keychain', source: 'self' },
  { key: 'attestation.cert', value: 'CERT-9821 · valid through 2026-12-01', source: 'sso' },
]

const SESSIONS: Session[] = [
  {
    id: 'S-9421',
    device: 'macOS · Safari 19',
    ip: '203.0.113.41',
    location: 'New York, NY',
    started: '2026-05-04 13:02 UTC',
    current: true,
  },
  {
    id: 'S-9407',
    device: 'iPadOS · Safari',
    ip: '203.0.113.41',
    location: 'New York, NY',
    started: '2026-05-04 09:18 UTC',
    current: false,
  },
  {
    id: 'S-9388',
    device: 'macOS · Chrome 198',
    ip: '198.51.100.7',
    location: 'Brooklyn, NY · vpn',
    started: '2026-05-03 21:54 UTC',
    current: false,
  },
]

const ACTIONS: ActionRow[] = [
  {
    ts: '2026-05-04 13:32:41',
    posture: 'privileged',
    action: 'Opened deliberation D-2031 on Matter-9821',
    cite: '§164.502(b)',
  },
  {
    ts: '2026-05-04 12:47:55',
    posture: 'confirmed',
    action: 'Approved P-1497 promotion to canon',
    cite: 'SR 11-7 §V',
  },
  {
    ts: '2026-05-04 11:14:08',
    posture: 'partial',
    action: 'Held P-1499 pending validator quorum',
    cite: 'Internal §3.1',
  },
  {
    ts: '2026-05-03 17:08:22',
    posture: 'confirmed',
    action: 'Switched tenancy to Hofstra & Lorenz',
    cite: 'Internal §3.4',
  },
  {
    ts: '2026-05-03 09:18:11',
    posture: 'confirmed',
    action: 'Sign-in via Google Workspace SSO',
    cite: 'auth · attested',
  },
]

const SOURCE_LABEL: Record<IdentityField['source'], string> = {
  sso: 'SSO',
  self: 'Self',
  constitution: 'Constitution',
}

export function Account() {
  return (
    <div>
      <p
        style={{
          fontFamily: 'var(--font-serif)',
          fontSize: 17,
          lineHeight: 1.65,
          color: 'var(--ink-2)',
          maxWidth: '64ch',
        }}
      >
        Your record on the bus. The constitution decides which lanes you may operate in; you decide
        your authentication factors. Everything you do from this surface is countersigned in the
        audit trail under your name.
      </p>

      {/* Identity */}
      <div className="settings-section" style={{ marginTop: 32 }}>
        <div className="settings-section-head">Identity</div>
        {IDENTITY.map((f) => (
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
              className="btn btn-ghost"
              type="button"
              disabled={f.source === 'constitution' || f.source === 'sso'}
              style={{
                padding: '6px 12px',
                fontSize: 13,
                opacity: f.source === 'self' ? 1 : 0.4,
                cursor: f.source === 'self' ? 'pointer' : 'not-allowed',
              }}
            >
              {f.source === 'self' ? 'Rotate' : '—'}
            </button>
          </div>
        ))}
      </div>

      {/* Active sessions */}
      <div className="settings-section">
        <div className="settings-section-head">Active sessions</div>
        <table className="c-table" style={{ marginTop: 8 }}>
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
            {SESSIONS.map((s) => (
              <tr key={s.id}>
                <td className="mono">{s.id}</td>
                <td>{s.device}</td>
                <td className="mono" style={{ color: 'var(--ink-2)' }}>
                  {s.ip}
                </td>
                <td className="mono" style={{ color: 'var(--muted)' }}>
                  {s.location}
                </td>
                <td className="mono" style={{ color: 'var(--muted)' }}>
                  {s.started}
                </td>
                <td>
                  {s.current ? (
                    <span className="pill confirmed">this session</span>
                  ) : (
                    <span className="pill partial">other</span>
                  )}
                </td>
                <td>
                  {s.current ? (
                    <span className="c-meta" style={{ color: 'var(--ink-3)' }}>
                      —
                    </span>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ padding: '6px 12px', fontSize: 13 }}
                    >
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
        <div className="audit-list" style={{ marginTop: 8 }}>
          {ACTIONS.map((a) => (
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
        <span
          style={{
            marginLeft: 'auto',
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: 'var(--muted)',
            letterSpacing: '0.04em',
          }}
        >
          608508a9 · attest carried · session S-9421
        </span>
      </div>

      <p
        style={{
          marginTop: 28,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ The constitution rules you, you do not rule it · personal preferences do not override lane
        policy
      </p>
    </div>
  )
}
