import { ArrowRight, Bell } from 'lucide-react'
import type { ReactNode } from 'react'
import { navigate } from '../lib/navigate'
import { Account } from './console/Account'
import { Agents } from './console/Agents'
import { Audit } from './console/Audit'
import { Compile } from './console/Compile'
import { Deliberations } from './console/Deliberations'
import { Incidents } from './console/Incidents'
import { Maci } from './console/Maci'
import { Overview } from './console/Overview'
import { Policies } from './console/Policies'
import { Settings } from './console/Settings'
import { Tenants } from './console/Tenants'
import { NotFound } from './NotFound'

const NAV: { section: string; items: { path: string; label: string; count?: string }[] }[] = [
  {
    section: 'Operate',
    items: [
      { path: '/console', label: 'Overview' },
      { path: '/console/agents', label: 'Agents', count: '12' },
      { path: '/console/maci', label: 'MACI lanes', count: '4' },
      { path: '/console/deliberations', label: 'Deliberations', count: '3' },
      { path: '/console/incidents', label: 'Incidents', count: '5' },
    ],
  },
  {
    section: 'Govern',
    items: [
      { path: '/console/policies', label: 'Policies', count: '47' },
      { path: '/console/compile', label: 'Compile', count: '7' },
      { path: '/console/audit', label: 'Audit trail' },
      { path: '/console/settings', label: 'Settings' },
      { path: '/console/tenants', label: 'Tenants', count: '4' },
    ],
  },
]

const PAGE_TITLES: Record<string, { crumb: string; title: ReactNode }> = {
  '/console': {
    crumb: 'I · Operate / Overview',
    title: (
      <>
        Operating <em>constitution</em>
      </>
    ),
  },
  '/console/agents': {
    crumb: 'I.II · Operate / Agents',
    title: (
      <>
        Agent <em>registry</em>
      </>
    ),
  },
  '/console/maci': {
    crumb: 'I.III · Operate / MACI lanes',
    title: (
      <>
        MACI <em>separation</em>
      </>
    ),
  },
  '/console/deliberations': {
    crumb: 'I.IV · Operate / Deliberations',
    title: (
      <>
        Human <em>deliberations</em>
      </>
    ),
  },
  '/console/incidents': {
    crumb: 'I.V · Operate / Incidents',
    title: (
      <>
        Active <em>escalations</em>
      </>
    ),
  },
  '/console/policies': {
    crumb: 'II.I · Govern / Policies',
    title: (
      <>
        Policy <em>register</em>
      </>
    ),
  },
  '/console/compile': {
    crumb: 'II.II · Govern / Compile',
    title: (
      <>
        Constitution <em>compile</em>
      </>
    ),
  },
  '/console/audit': {
    crumb: 'II.III · Govern / Audit trail',
    title: (
      <>
        Audit <em>trail</em>
      </>
    ),
  },
  '/console/settings': {
    crumb: 'II.IV · Govern / Settings',
    title: (
      <>
        Operating <em>parameters</em>
      </>
    ),
  },
  '/console/tenants': {
    crumb: 'II.V · Govern / Tenants',
    title: (
      <>
        Active <em>tenancies</em>
      </>
    ),
  },
  '/console/account': {
    crumb: 'Personal · record',
    title: (
      <>
        Your <em>record</em>
      </>
    ),
  },
}

const HEARTBEAT = [
  ['Agents', '12/12'],
  ['Checks', '84'],
  ['Runtime', '06h 14m'],
  ['Drift', '0 byte'],
  ['Audit anchor', '18s'],
  ['Next refresh', '2s'],
]

function PageBody({ path }: { path: string }) {
  switch (path) {
    case '/console':
      return <Overview />
    case '/console/agents':
      return <Agents />
    case '/console/maci':
      return <Maci />
    case '/console/deliberations':
      return <Deliberations />
    case '/console/incidents':
      return <Incidents />
    case '/console/policies':
      return <Policies />
    case '/console/compile':
      return <Compile />
    case '/console/audit':
      return <Audit />
    case '/console/settings':
      return <Settings />
    case '/console/tenants':
      return <Tenants />
    case '/console/account':
      return <Account />
    default:
      return <NotFound surface="console" path={path} />
  }
}

const NOT_FOUND_META = {
  crumb: '404 · path not enumerated',
  title: (
    <>
      Outside the <em>canon</em>
    </>
  ),
}

export function Console({ path }: { path: string }) {
  const meta = PAGE_TITLES[path] ?? (path === '/console' ? PAGE_TITLES['/console'] : NOT_FOUND_META)
  return (
    <div className="console">
      {/* Sidebar */}
      <aside className="c-side" aria-label="Console navigation">
        <a
          className="c-brand"
          href="/"
          onClick={(e) => {
            e.preventDefault()
            navigate('/')
          }}
        >
          acgs <em>⁂</em>
          <span className="v">v3.1.0 · 608508a9</span>
        </a>
        <nav>
          {NAV.map((group) => (
            <div key={group.section}>
              <div className="c-nav-section">{group.section}</div>
              <ul className="c-nav">
                {group.items.map((item) => {
                  const active =
                    path === item.path || (item.path !== '/console' && path.startsWith(item.path))
                  return (
                    <li key={item.path}>
                      <a
                        className={active ? 'active' : ''}
                        href={item.path}
                        onClick={(e) => {
                          e.preventDefault()
                          navigate(item.path)
                        }}
                      >
                        <span>{item.label}</span>
                        {item.count && <span className="count">{item.count}</span>}
                      </a>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </nav>
        <div className="c-side-foot">
          <span>Constitutional hash</span>
          <span className="hash">608508a9bd224290</span>
          <div className="c-side-user">
            <a
              className={`c-side-user-link${path === '/console/account' ? ' active' : ''}`}
              href="/console/account"
              onClick={(e) => {
                e.preventDefault()
                navigate('/console/account')
              }}
            >
              custodian-01 · clerk
            </a>
            <a
              className="c-side-user-signout"
              href="/login"
              onClick={(e) => {
                e.preventDefault()
                navigate('/login')
              }}
            >
              sign out →
            </a>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="c-main">
        <div className="c-banner" role="note">
          <span>⁂ Privilege boundary enforced · session attests to no advice</span>
          <span>608508a9bd224290</span>
        </div>

        <div className="c-topbar">
          <div>
            <div className="crumb">{meta.crumb}</div>
            <h1>{meta.title}</h1>
          </div>
          <div className="c-topbar-actions">
            <button
              className="btn btn-secondary"
              type="button"
              aria-label="Open incidents"
              onClick={() => navigate('/console/incidents')}
            >
              <Bell size={15} strokeWidth={1.8} /> 3 events
            </button>
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => navigate('/console/compile')}
            >
              Compile constitution <ArrowRight size={15} strokeWidth={1.8} />
            </button>
          </div>
        </div>

        <div className="c-heartbeat">
          <span className="c-heartbeat-live">Live</span>
          {HEARTBEAT.map(([label, value]) => (
            <div className="c-heartbeat-item" key={label}>
              <span className="c-heartbeat-label">{label}</span>
              <span className="c-heartbeat-value">{value}</span>
            </div>
          ))}
        </div>

        <div className="c-page">
          <PageBody path={path} />
        </div>
      </main>

      {/* Right rail */}
      <aside className="c-rail" aria-label="Status">
        <div className="rail-block">
          <h5>Live ledger</h5>
          <div className="rail-stats">
            <div className="rail-stat">
              <span className="label">Agents online</span>
              <span className="value">12 / 12</span>
            </div>
            <div className="rail-stat">
              <span className="label">Refusals · 24h</span>
              <span className="value">1,402</span>
            </div>
            <div className="rail-stat">
              <span className="label">Median latency</span>
              <span className="value">38 ms</span>
            </div>
            <div className="rail-stat">
              <span className="label">Constitution drift</span>
              <span className="value value-ok">0 byte</span>
            </div>
          </div>
        </div>
        <div className="rail-block">
          <h5>Queue health</h5>
          <div className="rail-stats">
            <div className="rail-stat">
              <span className="label">Human review</span>
              <span className="value">3</span>
            </div>
            <div className="rail-stat">
              <span className="label">Appeals</span>
              <span className="value">1</span>
            </div>
            <div className="rail-stat">
              <span className="label">Retry backoff</span>
              <span className="value value-ok">0</span>
            </div>
            <div className="rail-empty">No queued retries</div>
          </div>
        </div>
        <div className="rail-block">
          <h5>Recent events</h5>
          <div className="rail-event">
            Refused tool call <code>matter.fetch</code> for agent <strong>analyst-04</strong> and
            cited <em>§164.502(b)</em>.<span className="ts">14:08:22 · UTC</span>
          </div>
          <div className="rail-event">
            Validator promoted draft <strong>P-1207</strong> to canon after two independent reviews
            and a Dafny replay.
            <span className="ts">13:51:09 · UTC</span>
          </div>
          <div className="rail-event">
            Human deliberation opened on <strong>Matter-9821</strong>; routed to on-call counsel.
            <span className="ts">13:32:41 · UTC</span>
          </div>
        </div>
        <div className="rail-block">
          <h5>Coverage</h5>
          <div className="rail-stats">
            <div className="rail-stat">
              <span className="label">EU AI Act</span>
              <span className="pill confirmed">Active</span>
            </div>
            <div className="rail-stat">
              <span className="label">SR 11-7</span>
              <span className="pill confirmed">Active</span>
            </div>
            <div className="rail-stat">
              <span className="label">HIPAA</span>
              <span className="pill confirmed">Active</span>
            </div>
            <div className="rail-stat">
              <span className="label">GDPR</span>
              <span className="pill partial">Partial</span>
            </div>
          </div>
        </div>
      </aside>
    </div>
  )
}
