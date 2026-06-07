import type { ReactNode } from 'react'

export type FeatureStatus =
  | 'verified'
  | 'partial'
  | 'in-progress'
  | 'roadmap'
  | 'unverified'
  | 'needs-review'
  | 'not-supported'
  | 'deprecated'

const MAP: Record<FeatureStatus, { v: string; label: string }> = {
  verified: { v: 'verified', label: 'Verified' },
  partial: { v: 'partial', label: 'Partial' },
  'in-progress': { v: 'inprogress', label: 'In progress' },
  roadmap: { v: 'roadmap', label: 'Roadmap' },
  unverified: { v: 'unverified', label: 'Unverified' },
  'needs-review': { v: 'review', label: 'Needs review' },
  'not-supported': { v: 'notsupported', label: 'Not supported' },
  deprecated: { v: 'deprecated', label: 'Deprecated' },
}

/**
 * FeatureStatusBadge — maturity of a feature or claim. Use it everywhere a
 * feature is mentioned so a roadmap / unverified item never reads as an active,
 * verified capability (the UI half of the runtime's fail-closed law).
 */
export function FeatureStatusBadge({
  status = 'unverified',
  children,
}: {
  status?: FeatureStatus
  children?: ReactNode
}) {
  const m = MAP[status] ?? MAP.unverified
  return <span className={`gz-fstatus gz-fstatus--${m.v}`}>{children ?? m.label}</span>
}
