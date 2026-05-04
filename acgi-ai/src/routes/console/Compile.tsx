import { useCompileDraft } from '../../api/hooks'
import type { PolicyChangeKind } from '../../api/types'

export function Compile() {
  const { data, isLoading, isError, refetch } = useCompileDraft()

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

  const COUNTS: Record<PolicyChangeKind, number> = { added: 0, amended: 0, removed: 0 }
  for (const c of data.changes) COUNTS[c.change] += 1

  return (
    <div>
      <p className="compile-prose">
        Seven proposed amendments are staged against the canon. Promotion compiles a new
        constitution, signs it with a fresh hash, and replays the SR 11-7 conformance set before any
        agent on the bus is allowed to dispatch under the new rule.
      </p>

      <div className="compile-counts-grid">
        <Stat label="Added" value={COUNTS.added} marker="added" />
        <Stat label="Amended" value={COUNTS.amended} marker="amended" />
        <Stat label="Removed" value={COUNTS.removed} marker="removed" />
      </div>

      <div className="compile-hash">
        <div className="col">
          <span className="label">Canon · v3.1.0</span>
          <span className="hash">{data.currentHash}</span>
          <span className="label compile-hash-meta">
            signed 2026-04-29 · 1,402 refusals carried
          </span>
        </div>
        <span className="arrow" aria-hidden>
          →
        </span>
        <div className="col">
          <span className="label">Proposed · v3.2.0-rc</span>
          <span className="hash">{data.proposedHash}</span>
          <span className="label compile-hash-meta">
            unsigned · awaits Validator-attested replay
          </span>
        </div>
      </div>

      <div className="compile-changes">
        <div className="c-toolbar">
          <strong className="u-display-h">
            Pending <em className="u-em-rust">amendments</em>
          </strong>
          <span className="c-meta">7 changes · 5 articles touched</span>
        </div>
        <table className="c-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Rule</th>
              <th>Citation</th>
              <th>Change</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {data.changes.map((c) => (
              <tr key={c.id}>
                <td className="mono">{c.id}</td>
                <td>
                  <strong className="u-fw-600">{c.name}</strong>
                </td>
                <td className="mono u-color-ink-2">{c.citation}</td>
                <td>
                  <span className={`change-marker ${c.change}`}>{c.change}</span>
                </td>
                <td className="compile-note-cell">{c.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="compile-actions">
        <button className="btn btn-rust" type="button">
          Promote to canon
        </button>
        <button className="btn btn-secondary" type="button">
          Replay conformance set
        </button>
        <button className="btn btn-ghost" type="button">
          Discard
        </button>
        <span className="attest">
          {data.proposedHash} · attest required · two reviewers, one custodian
        </span>
      </div>

      <p className="u-mt-xxl u-mono-cap-wide">
        ⁂ No compile ships without a Validator-attested replay · the bus refuses to load a
        constitution whose hash it cannot verify against the maintainer signature
      </p>
    </div>
  )
}

function Stat({
  label,
  value,
  marker,
}: {
  label: string
  value: number
  marker: PolicyChangeKind
}) {
  return (
    <div className="compile-count-cell">
      <div className={`change-marker ${marker}`}>{label}</div>
      <div className="compile-count-value">{value}</div>
      <div className="compile-count-foot">rules · v3.2.0-rc</div>
    </div>
  )
}
