import { ArrowUpRight } from 'lucide-react'

export type ProofType = 'receipt' | 'test' | 'audit_chain' | 'roadmap' | 'docs'

const TYPE_LABEL: Record<ProofType, string> = {
  receipt: 'Receipt',
  test: 'Test',
  audit_chain: 'Audit chain',
  roadmap: 'Roadmap',
  docs: 'Docs',
}

/**
 * ProofChip — a link to the artifact that backs a claim. When `href` is absent
 * it renders the fail-closed "no proof artifact" state instead of a trust
 * signal: no proof, no verified claim.
 */
export function ProofChip({
  proofType = 'receipt',
  href,
  lastVerified,
  label,
}: {
  proofType?: ProofType
  href?: string
  lastVerified?: string
  label?: string
}) {
  if (!href) {
    return <span className="gz-proofchip gz-proofchip--missing">No proof artifact</span>
  }
  return (
    <a className="gz-proofchip" href={href} target="_blank" rel="noopener noreferrer">
      <span className="ptype">{label ?? TYPE_LABEL[proofType]}</span>
      {lastVerified ? (
        <>
          <span className="psep">·</span>
          <span className="pverified">verified {lastVerified}</span>
        </>
      ) : null}
      <span className="parrow" aria-hidden>
        <ArrowUpRight size={13} strokeWidth={1.8} />
      </span>
    </a>
  )
}
