type Source = 'constitution' | 'operator' | 'default'

type Setting = {
  key: string
  desc: string
  value: string
  source: Source
}

type Section = {
  title: string
  settings: Setting[]
}

const SECTIONS: Section[] = [
  {
    title: 'Deliberation',
    settings: [
      {
        key: 'deliberation.sla.hours',
        desc: 'Maximum time a high-risk decision may sit in the human-in-the-loop queue before the bus auto-refuses.',
        value: '8',
        source: 'constitution',
      },
      {
        key: 'deliberation.queue.max',
        desc: 'Soft cap on open deliberations; over this, new escalations route to the on-call partner directly.',
        value: '24',
        source: 'operator',
      },
      {
        key: 'deliberation.escalation.chain',
        desc: 'Ordered roles consulted when a deliberation breaches its SLA.',
        value: 'counsel → maintainer → partner',
        source: 'default',
      },
    ],
  },
  {
    title: 'MACI lanes',
    settings: [
      {
        key: 'maci.proposer.parallelism',
        desc: 'Concurrent proposers permitted to draft against the same matter.',
        value: '4',
        source: 'operator',
      },
      {
        key: 'maci.validator.quorum',
        desc: 'Independent validators required before a draft may be promoted to canon.',
        value: '2',
        source: 'constitution',
      },
      {
        key: 'maci.executor.scope.policy',
        desc: 'How tightly the bus checks scope intersection between the executor and its tool.',
        value: 'strict',
        source: 'constitution',
      },
    ],
  },
  {
    title: 'Bus',
    settings: [
      {
        key: 'bus.drift.tolerance.bytes',
        desc: 'Tolerated byte difference between the compiled constitution and the runtime constitution.',
        value: '0',
        source: 'constitution',
      },
      {
        key: 'bus.retry.policy',
        desc: 'Backoff policy on a transient bus refusal (not on a constitutional refusal).',
        value: 'exponential · 3 attempts · 5s base',
        source: 'operator',
      },
      {
        key: 'bus.hash.refresh.seconds',
        desc: 'How often the bus, gateway, and worker recompute and compare the constitutional hash.',
        value: '30',
        source: 'default',
      },
    ],
  },
  {
    title: 'Notifications',
    settings: [
      {
        key: 'notify.event.email',
        desc: 'Where the bus mails a refusal digest at the end of each UTC day.',
        value: 'sec-ops@acgs.ai',
        source: 'operator',
      },
      {
        key: 'notify.webhook.url',
        desc: 'Streaming subscription endpoint for the live ledger.',
        value: 'wss://bus.internal/observe',
        source: 'operator',
      },
      {
        key: 'notify.severity.threshold',
        desc: 'Minimum posture at which a refusal is paged out of band.',
        value: 'partial',
        source: 'operator',
      },
    ],
  },
]

const SOURCE_LABEL: Record<Source, string> = {
  constitution: 'Constitution',
  operator: 'Operator',
  default: 'Default',
}

export function Settings() {
  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search keys, sections, sources…"
          aria-label="Search settings"
        />
        <span className="c-meta">12 keys · 4 sections · v3.1.0</span>
      </div>

      <p
        style={{
          fontFamily: 'var(--font-serif)',
          fontSize: 16,
          lineHeight: 1.6,
          color: 'var(--ink-3)',
          maxWidth: '64ch',
          marginBottom: 24,
        }}
      >
        Operator overrides are themselves audited. A value with the
        <span className="tag constitution" style={{ margin: '0 6px' }}>
          Constitution
        </span>
        tag cannot be edited from this page; amend the rule first, then compile.
      </p>

      {SECTIONS.map((section) => (
        <div className="settings-section" key={section.title}>
          <div className="settings-section-head">{section.title}</div>
          {section.settings.map((s) => (
            <div className="settings-row" key={s.key}>
              <div>
                <span className="key">{s.key}</span>
                <span className="desc">{s.desc}</span>
              </div>
              <span className={`tag ${s.source}`}>{SOURCE_LABEL[s.source]}</span>
              <span className="val">{s.value}</span>
              <button
                className="btn btn-ghost"
                type="button"
                disabled={s.source === 'constitution'}
                style={{
                  padding: '6px 12px',
                  fontSize: 13,
                  opacity: s.source === 'constitution' ? 0.4 : 1,
                  cursor: s.source === 'constitution' ? 'not-allowed' : 'pointer',
                }}
              >
                Edit
              </button>
            </div>
          ))}
        </div>
      ))}

      <p
        style={{
          marginTop: 28,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ Every edit on this page lands in the audit trail · the bus does not silently re-read its
        own configuration
      </p>
    </div>
  )
}
