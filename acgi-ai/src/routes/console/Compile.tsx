import { useState } from 'react'
import { useCompileDraft, usePromoteCompile, useReplayCompile } from '../../api/hooks'
import type { PolicyChangeKind } from '../../api/types'
import { track } from '../../surfaces/console/telemetry'
import {
  CONSTITUTION_HASH,
  ConsoleError,
  ConsoleLoading,
  type LocalReceipt,
  Receipt,
} from './shared'

export function Compile() {
  const [replayComplete, setReplayComplete] = useState(false)
  const [receipt, setReceipt] = useState<LocalReceipt | null>(null)
  const { data, isLoading, isError, refetch } = useCompileDraft()
  const replayCompile = useReplayCompile()
  const promoteCompile = usePromoteCompile()

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const COUNTS: Record<PolicyChangeKind, number> = { added: 0, amended: 0, removed: 0 }
  for (const c of data.changes) COUNTS[c.change] += 1
  const actionRequest = {
    currentHash: data.currentHash,
    proposedHash: data.proposedHash,
  }
  const replay = () => {
    track('constitution_replay_started')
    replayCompile.mutate(actionRequest, {
      onSuccess: (apiReceipt) => {
        setReplayComplete(true)
        setReceipt(apiReceipt)
      },
      onError: () => {
        setReplayComplete(false)
        setReceipt({
          title: 'Replay endpoint unavailable',
          body: 'The replay request could not reach the bus; no local promotion gate was opened.',
          meta: `${data.proposedHash} · ${CONSTITUTION_HASH} · ${new Date().toISOString()}`,
        })
      },
    })
  }
  const promote = () => {
    promoteCompile.mutate(actionRequest, {
      onSuccess: (apiReceipt) => {
        track('constitution_promoted')
        setReceipt(apiReceipt)
      },
      onError: () => {
        setReceipt({
          title: 'Promotion endpoint unavailable',
          body: 'The promotion request could not reach the bus; the runtime canon was not changed.',
          meta: `${data.proposedHash} · two reviewers + one custodian pending`,
        })
      },
    })
  }
  const discard = () => {
    track('constitution_compile_discarded')
    setReplayComplete(false)
    setReceipt({
      title: 'Local compile state cleared',
      body: 'Replay and promotion receipts were cleared in this browser; fetched draft data is unchanged.',
      meta: `${CONSTITUTION_HASH} · local discard · ${new Date().toISOString()}`,
    })
  }

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
        <button
          className="btn btn-rust"
          type="button"
          disabled={!replayComplete || promoteCompile.isPending}
          onClick={promote}
        >
          Promote to canon
        </button>
        <button
          className="btn btn-secondary"
          type="button"
          disabled={replayCompile.isPending}
          onClick={replay}
        >
          {replayCompile.isPending ? 'Replaying…' : 'Replay conformance set'}
        </button>
        <button className="btn btn-ghost" type="button" onClick={discard}>
          Discard
        </button>
        <span className="attest">
          {data.proposedHash} · {replayComplete ? 'replay receipt local' : 'replay required'} · two
          reviewers, one custodian
        </span>
      </div>
      <Receipt receipt={receipt} />

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
