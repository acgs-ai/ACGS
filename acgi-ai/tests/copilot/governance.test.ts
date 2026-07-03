import { afterEach, describe, expect, it, vi } from 'vitest'
import { admitAction } from '../../src/copilot/governance'

describe('admitAction', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('fails closed when the governance bridge hangs past the timeout', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init?: RequestInit) => {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        })
      }),
    )

    const result = admitAction('runtime.file.write', { path: 'evidence/report.json' })
    await vi.advanceTimersByTimeAsync(5000)

    await expect(result).resolves.toMatchObject({ decision: 'deny' })
  })
})
