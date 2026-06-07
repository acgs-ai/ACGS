import { type Decision, DecisionBadge } from './DecisionBadge'

export type ReceiptCardData = {
  receipt_id: string
  actor: string
  capability: string
  decision: Decision
  policy_id: string
  reason: string
  previous_hash: string
  receipt_hash: string
  side_effect_executed?: boolean
  replayable?: boolean
}

/**
 * ReceiptCard — the core product object: a Decision Receipt with actor,
 * capability, decision, policy, reason, hash chain, and replay/export actions.
 * Actions are optional; an absent handler hides nothing but does nothing — the
 * card never fabricates a side effect.
 */
export function ReceiptCard({
  receipt,
  onOpen,
  onReplay,
  onExport,
}: {
  receipt: ReceiptCardData
  onOpen?: () => void
  onReplay?: () => void
  onExport?: () => void
}) {
  return (
    <article className="gz-rcard">
      <header className="gz-rcard-head">
        <span className="gz-rcard-id tabular">{receipt.receipt_id}</span>
        <DecisionBadge decision={receipt.decision} />
      </header>
      <dl className="gz-rcard-body">
        <div className="gz-rcard-field">
          <dt>Actor</dt>
          <dd className="mono">{receipt.actor}</dd>
        </div>
        <div className="gz-rcard-field">
          <dt>Capability</dt>
          <dd className="mono">{receipt.capability}</dd>
        </div>
        <div className="gz-rcard-field">
          <dt>Policy</dt>
          <dd className="mono">{receipt.policy_id}</dd>
        </div>
        <div className="gz-rcard-field">
          <dt>Side effect executed</dt>
          <dd>{receipt.side_effect_executed ? 'Yes' : 'No'}</dd>
        </div>
        <div className="gz-rcard-field full">
          <dt>Reason</dt>
          <dd className="gz-rcard-reason">{receipt.reason}</dd>
        </div>
        <div className="gz-rcard-field">
          <dt>Previous hash</dt>
          <dd className="mono tabular">{receipt.previous_hash}</dd>
        </div>
        <div className="gz-rcard-field">
          <dt>Receipt hash</dt>
          <dd className="mono tabular">{receipt.receipt_hash}</dd>
        </div>
      </dl>
      <footer className="gz-rcard-foot">
        <button type="button" className="gz-rcard-act primary" onClick={onOpen}>
          Open
        </button>
        <button
          type="button"
          className="gz-rcard-act"
          onClick={onReplay}
          disabled={!receipt.replayable}
        >
          {receipt.replayable ? 'Replay' : 'Not replayable'}
        </button>
        <button type="button" className="gz-rcard-act" onClick={onExport}>
          Export
        </button>
      </footer>
    </article>
  )
}
