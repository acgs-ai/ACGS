import { useMemo, useState } from 'react'
import { useSettings } from '../../api/hooks'
import type { SettingSection, SettingSource } from '../../api/types'
import {
  CONSTITUTION_HASH,
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  type LocalReceipt,
  normalizeQuery,
  Receipt,
  SearchToolbar,
} from './shared'

const SOURCE_LABEL: Record<SettingSource, string> = {
  constitution: 'Constitution',
  operator: 'Operator',
  default: 'Default',
}

export function Settings() {
  const [query, setQuery] = useState('')
  const [draftKey, setDraftKey] = useState<string | null>(null)
  const [receipt, setReceipt] = useState<LocalReceipt | null>(null)
  const { data, isLoading, isError, refetch } = useSettings()
  const filtered = useMemo<SettingSection[]>(() => {
    const q = normalizeQuery(query)
    if (!data) return []
    if (!q) return data
    return data
      .map((section) => {
        const sectionMatches = section.title.toLowerCase().includes(q)
        return {
          ...section,
          settings: sectionMatches
            ? section.settings
            : section.settings.filter((s) =>
                [s.key, s.desc, s.value, s.source].some((field) => field.toLowerCase().includes(q)),
              ),
        }
      })
      .filter((section) => section.settings.length > 0)
  }, [data, query])

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const total = data.reduce((sum, section) => sum + section.settings.length, 0)
  const visible = filtered.reduce((sum, section) => sum + section.settings.length, 0)
  const stageEdit = (key: string, value: string) => {
    setReceipt({
      title: 'Local setting draft staged',
      body: `${key} remains ${value}; no operator override is persisted until a mutation endpoint signs it.`,
      meta: `${CONSTITUTION_HASH} · operator draft · ${new Date().toISOString()}`,
    })
    setDraftKey(null)
  }

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search keys, sections, sources…"
        ariaLabel="Search settings"
        meta={`${visible} of ${total} keys · ${filtered.length} sections · v3.1.0`}
      />
      <Receipt receipt={receipt} />

      <p className="u-prose-lede">
        Operator overrides are themselves audited. A value with the
        <span className="tag constitution u-tag-inline">Constitution</span>
        tag cannot be edited from this page; amend the rule first, then compile.
      </p>

      {filtered.length === 0 ? (
        <EmptyState
          emptyMeans="fresh-tenant"
          query={query}
          label="settings"
          onClear={() => setQuery('')}
        />
      ) : (
        filtered.map((section) => (
          <div className="settings-section" key={section.title}>
            <div className="settings-section-head">{section.title}</div>
            {section.settings.map((s) => (
              <div className="settings-item" key={s.key}>
                <div className="settings-row">
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
                    onClick={() => setDraftKey(s.key)}
                  >
                    Edit
                  </button>
                </div>
                {draftKey === s.key && (
                  <div className="settings-draft-row">
                    <span>
                      Local draft only · current value <code>{s.value}</code> remains active on the
                      bus.
                    </span>
                    <button
                      className="btn btn-secondary btn-sm"
                      type="button"
                      onClick={() => stageEdit(s.key, s.value)}
                    >
                      Stage receipt
                    </button>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => setDraftKey(null)}
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        ))
      )}

      <p className="u-mt-xxl u-mono-cap-wide">
        ⁂ Every edit on this page lands in the audit trail · the bus does not silently re-read its
        own configuration
      </p>
    </div>
  )
}
