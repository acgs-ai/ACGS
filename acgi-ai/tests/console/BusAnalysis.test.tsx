// T019 — BusAnalysis list + inspector contract tests.
//
// Covers the happy path of the agent-bus-analyzer console route:
//   - the trace list renders rows for each item returned by /api/bus/traces
//   - clicking a row opens the single-trace inspector for that correlation_id
//   - inspector events render in causal_index order
//   - "back to traces" returns to the list view
//   - the search toolbar filters by text fields
//
// MSW handlers are the ones registered in src/mocks/handlers.ts (loaded by
// the global setup in tests/setup.ts), so we hit the same fixture set the
// dev/mock console uses.

import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test } from 'vitest'
import { BusAnalysis } from '../../src/routes/console/BusAnalysis'
import { renderWithProviders } from './render'

const TRACE_A = '11111111-1111-7111-8111-111111111111'
const TRACE_B = '22222222-2222-7222-8222-222222222222'
const TRACE_C = '33333333-3333-7333-8333-333333333333'

async function waitForListLoaded() {
  // The list view shows one row per fixture trace. Wait until the toolbar
  // visibility-count reflects the loaded fixture set.
  await waitFor(() => {
    expect(screen.getByText(/\d+ of \d+ visible/i)).toBeInTheDocument()
  })
}

function findRowByCorrelation(correlationId: string): HTMLElement {
  const short = correlationId.slice(0, 8)
  // Row buttons render the shortened correlation id; click that row.
  const candidates = screen.getAllByRole('button')
  const match = candidates.find((el) => el.textContent?.includes(short))
  if (!match) throw new Error(`No trace row contained correlation prefix ${short}`)
  return match
}

describe('BusAnalysis (T019)', () => {
  test('renders the list with one row per fixture trace', async () => {
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    expect(findRowByCorrelation(TRACE_A)).toBeInTheDocument()
    expect(findRowByCorrelation(TRACE_B)).toBeInTheDocument()
    expect(findRowByCorrelation(TRACE_C)).toBeInTheDocument()

    // The toolbar should report "3 of 3 visible" since no filter is set.
    expect(screen.getByText(/3 of 3 visible/i)).toBeInTheDocument()
  })

  test('renders status and integrity pills on each row', async () => {
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    const completedRow = findRowByCorrelation(TRACE_A)
    expect(within(completedRow).getByText('Completed')).toBeInTheDocument()
    expect(within(completedRow).getByText('Intact')).toBeInTheDocument()

    const violationRow = findRowByCorrelation(TRACE_B)
    expect(within(violationRow).getByText('Policy violation')).toBeInTheDocument()
  })

  test('clicking a row opens the inspector for that correlation id', async () => {
    const user = userEvent.setup()
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    await user.click(findRowByCorrelation(TRACE_A))

    // The inspector renders the full correlation_id verbatim.
    expect(await screen.findByText(TRACE_A)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /back to traces/i })).toBeInTheDocument()
  })

  test('inspector renders events in causal_index order', async () => {
    const user = userEvent.setup()
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    await user.click(findRowByCorrelation(TRACE_A))
    await screen.findByText(TRACE_A)

    // TRACE_A has three events with causal_index 0, 1, 2.
    const rendered = await screen.findAllByText(/^#\d+$/)
    const order = rendered.map((el) => el.textContent)
    expect(order).toEqual(['#0', '#1', '#2'])
  })

  test('"back to traces" returns to the list view', async () => {
    const user = userEvent.setup()
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    await user.click(findRowByCorrelation(TRACE_A))
    await screen.findByText(TRACE_A)

    await user.click(screen.getByRole('button', { name: /back to traces/i }))

    // List shell is back.
    await waitFor(() => {
      expect(screen.getByText(/3 of 3 visible/i)).toBeInTheDocument()
    })
  })

  test('search toolbar filters the list', async () => {
    const user = userEvent.setup()
    renderWithProviders(<BusAnalysis />)
    await waitForListLoaded()

    const input = screen.getByLabelText('Filter traces')
    await user.type(input, 'policy violation')

    await waitFor(() => {
      expect(screen.getByText(/1 of 3 visible/i)).toBeInTheDocument()
    })
    expect(findRowByCorrelation(TRACE_B)).toBeInTheDocument()
  })
})
