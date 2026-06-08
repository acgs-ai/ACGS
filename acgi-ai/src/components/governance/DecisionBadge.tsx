import type { ReactNode } from 'react'

export type Decision = 'ALLOW' | 'DENY' | 'REVIEW_REQUIRED' | 'TRANSFORM' | 'ERROR'

const LABEL: Record<Decision, string> = {
  ALLOW: 'Allow',
  DENY: 'Deny',
  REVIEW_REQUIRED: 'Review',
  TRANSFORM: 'Transform',
  ERROR: 'Error',
}

const VARIANT: Record<Decision, string> = {
  ALLOW: 'allow',
  DENY: 'deny',
  REVIEW_REQUIRED: 'review',
  TRANSFORM: 'transform',
  ERROR: 'error',
}

/**
 * DecisionBadge — the runtime decision for a governed action: one of
 * ALLOW / DENY / REVIEW_REQUIRED / TRANSFORM / ERROR. Colour is signal: the
 * badge reads `color: var(--allow|--deny|…)` with a low-alpha fill, so it adapts
 * to the editorial (paper) and control-plane (dark) registers automatically.
 */
export function DecisionBadge({
  decision = 'ALLOW',
  size = 'md',
  children,
}: {
  decision?: Decision
  size?: 'sm' | 'md'
  children?: ReactNode
}) {
  const variant = VARIANT[decision] ?? 'error'
  const label = LABEL[decision] ?? 'Error'
  const cls = ['gz-badge', `gz-badge--${variant}`]
  if (size === 'sm') cls.push('gz-badge--sm')
  return <span className={cls.join(' ')}>{children ?? label}</span>
}
