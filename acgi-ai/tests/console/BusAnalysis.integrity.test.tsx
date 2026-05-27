// T051 — Tampered trace integrity contract.
//
// The single-trace inspector must surface integrity status. When the
// analyzer reports `integrity_status: "tampered"`, the inspector must:
//   - render a "Tampered" pill
//   - NOT render an "Intact" pill
//   - render an alert-role banner whose copy treats the trace as unverified

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { HttpResponse, http } from 'msw'
import { describe, expect, test } from 'vitest'
import { server } from '../../src/mocks/server'
import { BusAnalysis } from '../../src/routes/console/BusAnalysis'
import { renderWithProviders } from './render'

const CONST_HASH = '608508a9bd224290'
const TAMPERED_ID = '99999999-9999-7999-8999-999999999999'

const TAMPERED_LIST = {
  kind: 'trace-list',
  items: [
    {
      correlation_id: TAMPERED_ID,
      started_at: '2026-05-14T15:00:00.000Z',
      completed_at: '2026-05-14T15:00:00.500Z',
      event_count: 2,
      worst_event_status: 'policy-violation' as const,
      integrity_status: 'tampered' as const,
      constitutional_hash: CONST_HASH,
    },
  ],
  next_cursor: null,
}

const TAMPERED_TRACE = {
  kind: 'single-trace',
  trace: TAMPERED_LIST.items[0],
  integrity_status: 'tampered' as const,
  rotation_at_index: null,
  events: [
    {
      event_id: 'tamper-0001',
      correlation_id: TAMPERED_ID,
      causal_index: 0,
      kind: 'dispatch' as const,
      source_agent: 'claude:worker-99',
      target_handler_declared: 'matter.fetch',
      target_handler_resolved: null,
      payload_ref: 'sha256:' + '0'.repeat(64),
      recorded_at: '2026-05-14T15:00:00.011Z',
      event_hash: 'd1' + '0'.repeat(62),
      prev_hash: null,
      status: 'completed' as const,
      decision: null,
      flagged_rule: null,
      audit_receipt_hash: null,
      constitutional_hash: CONST_HASH,
      gap_started_at: null,
      gap_ended_at: null,
      phoenix_trace_id: null,
      phoenix_span_id: null,
      phoenix_parent_span_id: null,
    },
    {
      event_id: 'tamper-0002',
      correlation_id: TAMPERED_ID,
      causal_index: 1,
      kind: 'decision' as const,
      source_agent: 'gove-zone:kernel',
      target_handler_declared: 'matter.fetch',
      target_handler_resolved: 'matter.fetch',
      payload_ref: 'sha256:' + '1'.repeat(64),
      recorded_at: '2026-05-14T15:00:00.042Z',
      // Intentionally inconsistent prev_hash — the chain is "tampered".
      event_hash: 'd2' + '0'.repeat(62),
      prev_hash: 'cafebabe' + '0'.repeat(56),
      status: 'policy-violation' as const,
      decision: 'deny' as const,
      flagged_rule: 'integrity.chain-break',
      audit_receipt_hash: null,
      constitutional_hash: CONST_HASH,
      gap_started_at: null,
      gap_ended_at: null,
      phoenix_trace_id: null,
      phoenix_span_id: null,
      phoenix_parent_span_id: null,
    },
  ],
}

describe('BusAnalysis integrity (T051)', () => {
  test('tampered trace renders a Tampered pill, no Intact pill, and an alert banner', async () => {
    server.use(
      http.get('/api/bus/traces', () => HttpResponse.json(TAMPERED_LIST)),
      http.get('/api/bus/traces/:correlationId', () => HttpResponse.json(TAMPERED_TRACE)),
    )

    const user = userEvent.setup()
    renderWithProviders(<BusAnalysis />)

    // Wait for the list to populate, then click into the tampered trace.
    await waitFor(() => {
      expect(screen.getByText(/1 of 1 visible/i)).toBeInTheDocument()
    })

    // The list row already shows the tampered pill.
    const tamperedPills = screen.getAllByText('Tampered')
    expect(tamperedPills.length).toBeGreaterThan(0)
    expect(screen.queryByText('Intact')).toBeNull()

    // Click into the inspector.
    const rowButtons = screen.getAllByRole('button')
    const row = rowButtons.find((el) => el.textContent?.includes(TAMPERED_ID.slice(0, 8)))
    if (!row) throw new Error('No row found for tampered correlation id')
    await user.click(row)

    // Inspector confirms tampered pill + alert banner with unverified copy.
    await screen.findByText(TAMPERED_ID)
    expect(screen.getAllByText('Tampered').length).toBeGreaterThan(0)
    expect(screen.queryByText('Intact')).toBeNull()

    const alert = await screen.findByRole('alert')
    expect(alert).toBeInTheDocument()
    expect(alert.textContent?.toLowerCase()).toContain('unverified')
  })
})
