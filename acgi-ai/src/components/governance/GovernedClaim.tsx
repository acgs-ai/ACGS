import { type FeatureStatus, FeatureStatusBadge } from './FeatureStatusBadge'
import { ProofChip, type ProofType } from './ProofChip'

/**
 * GovernedClaim — renders a product claim through the claim → evidence contract.
 * No proof, no verified styling: a `verified`/`partial` claim shows its proof
 * artifact; everything else fails closed to the unproven state. Deprecated /
 * not-supported claims render visibly muted.
 */
export function GovernedClaim({
  claim,
  status = 'unverified',
  proofType = 'receipt',
  proofUrl,
  lastVerified,
  version,
}: {
  claim: string
  status?: FeatureStatus
  proofType?: ProofType
  proofUrl?: string
  lastVerified?: string
  version?: string
}) {
  const muted = status === 'deprecated' || status === 'not-supported'
  const proofHref = status === 'verified' || status === 'partial' ? proofUrl : undefined
  return (
    <article className={`gz-claim${muted ? ' gz-claim--muted' : ''}`}>
      <div className="gz-claim-top">
        <span className="gz-claim-text">{claim}</span>
        <FeatureStatusBadge status={status} />
      </div>
      <div className="gz-claim-meta">
        <ProofChip proofType={proofType} href={proofHref} lastVerified={lastVerified} />
        {version ? (
          <span className="m">
            version <b>{version}</b>
          </span>
        ) : null}
        <span className="m">
          last verified <b>{lastVerified ?? 'n/a'}</b>
        </span>
      </div>
    </article>
  )
}
