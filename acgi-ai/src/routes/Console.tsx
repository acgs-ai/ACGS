import { ArrowRight, Bell, Menu, X } from 'lucide-react'
import { type ReactNode, useEffect, useRef, useState } from 'react'
import {
  useAgents,
  useCompileDraft,
  useConsoleSummary,
  useDeliberations,
  useGovernedActions,
  useIncidents,
  useOverview,
  usePolicies,
  useTenants,
} from '../api/hooks'
import { navigate } from '../lib/navigate'
import { clearSession } from '../lib/session'
import { Account } from './console/Account'
import { Actions } from './console/Actions'
import { Agents } from './console/Agents'
import { Audit } from './console/Audit'
import { BusAnalysis } from './console/BusAnalysis'
import { Compile } from './console/Compile'
import { Deliberations } from './console/Deliberations'
import { Incidents } from './console/Incidents'
import { Maci } from './console/Maci'
import { Overview } from './console/Overview'
import { Policies } from './console/Policies'
import { Settings } from './console/Settings'
import { Tenants } from './console/Tenants'
import { NotFound } from './NotFound'

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
  '/console/actions': {
    crumb: 'I.III · Operate / Actions',
    title: (
      <>
        Action <em>control</em>
      </>
    ),
  },
  '/console/maci': {
    crumb: 'I.IV · Operate / MACI lanes',
    title: (
      <>
        MACI <em>separation</em>
      </>
    ),
  },
  '/console/deliberations': {
    crumb: 'I.V · Operate / Deliberations',
    title: (
      <>
        Human <em>deliberations</em>
      </>
    ),
  },
  '/console/incidents': {
    crumb: 'I.VI · Operate / Incidents',
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
  '/console/bus': {
    crumb: 'II.IV · Govern / Bus traces',
    title: (
      <>
        Bus <em>traces</em>
      </>
    ),
  },
  '/console/settings': {
    crumb: 'II.V · Govern / Settings',
    title: (
      <>
        Operating <em>parameters</em>
      </>
    ),
  },
  '/console/tenants': {
    crumb: 'II.VI · Govern / Tenants',
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

function PageBody({ path }: { path: string }) {
  switch (path) {
    case '/console':
      return <Overview />
    case '/console/agents':
      return <Agents />
    case '/console/actions':
      return <Actions />
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
    case '/console/bus':
      return <BusAnalysis />
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

const FALLBACK_EVENTS = [
  {
    id: 'fallback-tool-refusal',
    body: 'Refused tool call matter.fetch for agent analyst-04 and cited §164.502(b).',
    ts: '14:08:22 · UTC',
  },
  {
    id: 'fallback-promotion',
    body: 'Validator promoted draft P-1207 to canon after two independent reviews and a Dafny replay.',
    ts: '13:51:09 · UTC',
  },
  {
    id: 'fallback-deliberation',
    body: 'Human deliberation opened on Matter-9821; routed to on-call counsel.',
    ts: '13:32:41 · UTC',
  },
]

const FALLBACK_COVERAGE = [
  { label: 'EU AI Act', posture: 'confirmed', value: 'Active' },
  { label: 'SR 11-7', posture: 'confirmed', value: 'Active' },
  { label: 'HIPAA', posture: 'confirmed', value: 'Active' },
  { label: 'GDPR', posture: 'partial', value: 'Partial' },
] as const

function formatBytes(bytes: number): string {
  return bytes === 1 ? '1 byte' : `${bytes.toLocaleString()} bytes`
}

export function Console({ path }: { path: string }) {
  const IS_MOCK = import.meta.env.VITE_USE_MOCKS === 'true'
  const meta = PAGE_TITLES[path] ?? (path === '/console' ? PAGE_TITLES['/console'] : NOT_FOUND_META)
  const [navOpen, setNavOpen] = useState(false)
  const previousPath = useRef(path)
  const agents = useAgents()
  const deliberations = useDeliberations()
  const actions = useGovernedActions()
  const incidents = useIncidents()
  const policies = usePolicies()
  const compileDraft = useCompileDraft()
  const tenants = useTenants()
  const overview = useOverview()
  const summary = useConsoleSummary()

  const agentsOnline = summary.data?.agentsOnline ?? agents.data?.length ?? 12
  const agentsTotal = summary.data?.agentsTotal ?? agentsOnline
  const policyCount = policies.data?.length ?? 47
  const compileCount = compileDraft.data?.changes.length ?? 7
  const deliberationCount = summary.data?.humanReview ?? deliberations.data?.length ?? 3
  const incidentCount = incidents.data?.length ?? 5
  const actionCount = actions.data?.length ?? 0
  const tenantCount = tenants.data?.length ?? 4
  const refusals24h =
    summary.data?.refusals24h ??
    overview.data?.refusalsByArticle.reduce((sum, row) => sum + row.refusals, 0) ??
    1402
  const checks = summary.data?.checks ?? policyCount + compileCount + 30
  const driftBytes = summary.data?.driftBytes ?? 0
  const auditAnchorSeconds = summary.data?.auditAnchorSeconds ?? 18
  const nextRefreshSeconds = summary.data?.nextRefreshSeconds ?? 10
  const runtimeLabel = summary.data?.runtimeLabel ?? '06h 14m'
  const medianLatencyMs = summary.data?.medianLatencyMs ?? 38
  const appeals = summary.data?.appeals ?? Math.max(1, incidentCount - deliberationCount)
  const retryBackoff = summary.data?.retryBackoff ?? 0
  const recentEvents = summary.data?.recentEvents ?? FALLBACK_EVENTS
  const coverage = summary.data?.coverage ?? FALLBACK_COVERAGE
  const nav = [
    {
      section: 'Operate',
      items: [
        { path: '/console', label: 'Overview' },
        { path: '/console/agents', label: 'Agents', count: String(agentsOnline) },
        { path: '/console/actions', label: 'Actions', count: String(actionCount) },
        { path: '/console/maci', label: 'MACI lanes', count: '4' },
        {
          path: '/console/deliberations',
          label: 'Deliberations',
          count: String(deliberationCount),
        },
        { path: '/console/incidents', label: 'Incidents', count: String(incidentCount) },
      ],
    },
    {
      section: 'Govern',
      items: [
        { path: '/console/policies', label: 'Policies', count: String(policyCount) },
        { path: '/console/compile', label: 'Compile', count: String(compileCount) },
        { path: '/console/audit', label: 'Audit trail' },
        { path: '/console/bus', label: 'Bus traces' },
        { path: '/console/settings', label: 'Settings' },
        { path: '/console/tenants', label: 'Tenants', count: String(tenantCount) },
      ],
    },
  ]
  const heartbeat = [
    ['Agents', `${agentsOnline}/${agentsTotal}`],
    ['Checks', String(checks)],
    ['Runtime', runtimeLabel],
    ['Drift', formatBytes(driftBytes)],
    ['Audit anchor', `${auditAnchorSeconds}s`],
    ['Next refresh', `${nextRefreshSeconds}s`],
  ]

  // F-A1 — close the mobile drawer in the same call that navigates. We
  // collapse navigate() and setNavOpen(false) into one synchronous user
  // event so React's set-state-in-effect rule stays clean and the close
  // happens before the next render.
  const go = (to: string) => {
    setNavOpen(false)
    navigate(to)
  }

  const signOut = () => {
    clearSession()
    go('/login')
  }

  useEffect(() => {
    if (previousPath.current === path) return
    previousPath.current = path
    setNavOpen(false)
  }, [path])

  // Escape dismisses the mobile drawer. Mirrors the backdrop button so
  // keyboard users have a parity dismiss path.
  useEffect(() => {
    if (!navOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setNavOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [navOpen])

  return (
    <div className={`console${navOpen ? ' nav-open' : ''}`}>
      {/* Backdrop — visible only at <=720 when the drawer is open */}
      <button
        type="button"
        className="c-nav-backdrop"
        aria-label="Close navigation"
        onClick={() => setNavOpen(false)}
      />
      {/* Sidebar */}
      <aside id="c-side" className="c-side" aria-label="Console navigation">
        <a
          className="c-brand"
          href="/"
          onClick={(e) => {
            e.preventDefault()
            go('/')
          }}
        >
          acgs <em>⁂</em>
          <span className="v">v3.1.0 · 608508a9</span>
        </a>
        <nav>
          {nav.map((group) => (
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
                          go(item.path)
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
                go('/console/account')
              }}
            >
              custodian-01 · clerk
            </a>
            <a
              className="c-side-user-signout"
              href="/login"
              onClick={(e) => {
                e.preventDefault()
                signOut()
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
          <button
            type="button"
            className="c-nav-toggle"
            aria-expanded={navOpen}
            aria-controls="c-side"
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            onClick={() => setNavOpen((v) => !v)}
          >
            {navOpen ? <X size={16} strokeWidth={1.8} /> : <Menu size={16} strokeWidth={1.8} />}
          </button>
          <div>
            <div className="crumb">{meta.crumb}</div>
            <h1>{meta.title}</h1>
          </div>
          <div className="c-topbar-actions">
            <button
              className="btn btn-secondary"
              type="button"
              aria-label="Open incidents"
              onClick={() => go('/console/incidents')}
            >
              <Bell size={15} strokeWidth={1.8} /> {incidentCount} events
            </button>
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => go('/console/compile')}
            >
              Compile constitution <ArrowRight size={15} strokeWidth={1.8} />
            </button>
          </div>
        </div>

        <div className="c-heartbeat">
          <span className={`c-heartbeat-live${IS_MOCK ? ' mock' : ''}`}>
            {IS_MOCK ? 'Mock' : summary.data != null ? 'Live' : 'Fallback'}
          </span>
          {heartbeat.map(([label, value]) => (
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
              <span className="value">
                {agentsOnline} / {agentsTotal}
              </span>
            </div>
            <div className="rail-stat">
              <span className="label">Refusals · 24h</span>
              <span className="value">{refusals24h.toLocaleString()}</span>
            </div>
            <div className="rail-stat">
              <span className="label">Median latency</span>
              <span className="value">{medianLatencyMs} ms</span>
            </div>
            <div className="rail-stat">
              <span className="label">Constitution drift</span>
              <span className="value value-ok">{formatBytes(driftBytes)}</span>
            </div>
          </div>
        </div>
        <div className="rail-block">
          <h5>Queue health</h5>
          <div className="rail-stats">
            <div className="rail-stat">
              <span className="label">Human review</span>
              <span className="value">{deliberationCount}</span>
            </div>
            <div className="rail-stat">
              <span className="label">Appeals</span>
              <span className="value">{appeals}</span>
            </div>
            <div className="rail-stat">
              <span className="label">Retry backoff</span>
              <span className="value value-ok">{retryBackoff}</span>
            </div>
            <div className="rail-empty">
              {retryBackoff === 0 ? 'No queued retries' : 'Retries queued under backoff'}
            </div>
          </div>
        </div>
        <div className="rail-block">
          <h5>Recent events</h5>
          {recentEvents.map((event) => (
            <div className="rail-event" key={event.id}>
              {event.body}
              <span className="ts">{event.ts}</span>
            </div>
          ))}
        </div>
        <div className="rail-block">
          <h5>Coverage</h5>
          <div className="rail-stats">
            {coverage.map((item) => (
              <div className="rail-stat" key={item.label}>
                <span className="label">{item.label}</span>
                <span className={`pill ${item.posture}`}>{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </aside>
    </div>
  )
}
