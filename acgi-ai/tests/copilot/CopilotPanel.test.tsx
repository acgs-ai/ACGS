import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CopilotPanel } from '../../src/copilot/CopilotPanel'

const send = vi.fn()

vi.mock('../../src/copilot/transport', () => ({
  createTransport: () => ({ send }),
}))

describe('CopilotPanel', () => {
  beforeEach(() => {
    send.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('rolls back the optimistic message when transport send fails', async () => {
    send.mockRejectedValueOnce(new Error('runtime down'))

    render(<CopilotPanel />)
    fireEvent.click(screen.getByRole('button', { name: /ask the governed copilot/i }))
    fireEvent.change(screen.getByLabelText(/message the governed copilot/i), {
      target: { value: 'write a file' },
    })
    fireEvent.click(screen.getByRole('button', { name: /send/i }))

    expect(screen.getByText('write a file')).toBeTruthy()

    await waitFor(() => {
      expect(screen.getByRole('alert').textContent).toContain('runtime down')
    })
    expect(screen.queryByText('write a file')).toBeNull()
  })
})
