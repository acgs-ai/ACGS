import { useSettings } from '../../api/hooks'
import type { SettingSource } from '../../api/types'

const SOURCE_LABEL: Record<SettingSource, string> = {
  constitution: 'Constitution',
  operator: 'Operator',
  default: 'Default',
}

export function Settings() {
  const { data, isLoading, isError, refetch } = useSettings()

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
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search keys, sections, sources…"
          aria-label="Search settings"
        />
        <span className="c-meta">12 keys · 4 sections · v3.1.0</span>
      </div>

      <p className="u-prose-lede">
        Operator overrides are themselves audited. A value with the
        <span className="tag constitution u-tag-inline">Constitution</span>
        tag cannot be edited from this page; amend the rule first, then compile.
      </p>

      {data.map((section) => (
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
                className="btn btn-ghost btn-sm"
                type="button"
                disabled={s.source === 'constitution'}
              >
                Edit
              </button>
            </div>
          ))}
        </div>
      ))}

      <p className="u-mt-xxl u-mono-cap-wide">
        ⁂ Every edit on this page lands in the audit trail · the bus does not silently re-read its
        own configuration
      </p>
    </div>
  )
}
