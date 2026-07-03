import { ArrowDown } from 'lucide-react'

export type ChainStatus = 'verified' | 'broken' | 'incomplete' | 'unavailable'

const STATUS_LABEL: Record<ChainStatus, string> = {
  verified: 'Verified',
  broken: 'Broken',
  incomplete: 'Incomplete',
  unavailable: 'Not available',
}

/**
 * HashChainViewer — previous → current → next links with chain verification.
 * A broken chain fails closed: it states that the surrounding evidence bundle
 * must be marked invalid rather than rendering as trustworthy.
 */
export function HashChainViewer({
  previousHash,
  receiptHash,
  nextHash,
  status = 'verified',
}: {
  previousHash?: string
  receiptHash?: string
  nextHash?: string
  status?: ChainStatus
}) {
  return (
    <div className="gz-chain">
      <div className="gz-chain-head">
        <span className="title">Audit chain</span>
        <span className={`gz-chain-status ${status}`}>{STATUS_LABEL[status]}</span>
      </div>
      <div className="gz-chain-link">
        <span className="role">Previous</span>
        <span className="hash tabular">{previousHash ?? '—'}</span>
      </div>
      <div className="gz-chain-connector" aria-hidden>
        <ArrowDown size={14} strokeWidth={1.6} />
      </div>
      <div className="gz-chain-link current">
        <span className="role">Current</span>
        <span className="hash tabular">{receiptHash ?? '—'}</span>
      </div>
      <div className="gz-chain-connector" aria-hidden>
        <ArrowDown size={14} strokeWidth={1.6} />
      </div>
      <div className="gz-chain-link">
        <span className="role">Next</span>
        <span className="hash tabular">{nextHash ?? 'pending'}</span>
      </div>
      {status === 'broken' ? (
        <p className="gz-chain-broken-note">
          Chain verification failed. Mark this evidence bundle invalid — fail closed.
        </p>
      ) : null}
    </div>
  )
}
