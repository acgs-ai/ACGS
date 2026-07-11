import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DecisionBadge, type Decision } from '../../src/components/governance/DecisionBadge'
import { ProofChip } from '../../src/components/governance/ProofChip'
import { ReceiptCard, type ReceiptCardData } from '../../src/components/governance/ReceiptCard'
import { ProductSurface } from '../../src/routes/ProductSurfaces'

const receipt: ReceiptCardData = {
  receipt_id: 'rcpt-1',
  actor: 'demo-agent',
  capability: 'runtime.file.write',
  decision: 'ALLOW',
  policy_id: 'policy/v1',
  reason: 'allowed',
  previous_hash: '',
  receipt_hash: 'abc123',
  replayable: true,
}

describe('governance presentation components', () => {
  it('falls back gracefully for unexpected decision values', () => {
    render(<DecisionBadge decision={'UNEXPECTED' as Decision} />)

    const badge = screen.getByText('Error')
    expect(badge).toHaveClass('gz-badge--error')
    expect(badge.className).not.toContain('undefined')
  })

  it('renders a placeholder hash and hides missing actions', () => {
    render(<ReceiptCard receipt={receipt} />)

    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Replay' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Export' })).not.toBeInTheDocument()
  })

  it('renders only action buttons with handlers', () => {
    render(<ReceiptCard receipt={receipt} onOpen={vi.fn()} />)

    expect(screen.getByRole('button', { name: 'Open' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Replay' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Export' })).not.toBeInTheDocument()
  })

  it('opens proof artifacts safely in a new tab', () => {
    render(<ProofChip proofType="audit_chain" href="https://example.test/proof" />)

    const link = screen.getByRole('link', { name: /audit chain/i })
    expect(link).toHaveAttribute('href', 'https://example.test/proof')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('resolves the acgs product alias to the canonical gove-zone route', () => {
    render(<ProductSurface path="/products/acgs" />)

    expect(screen.getByText('ACGS · Runtime bridge')).toBeInTheDocument()
    expect(screen.getByText('/products/gove-zone')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /receipt/i })).toHaveAttribute('href', '/console/audit')
    expect(screen.getByRole('link', { name: /audit chain/i })).toHaveAttribute(
      'href',
      '/console/audit',
    )
  })
})
