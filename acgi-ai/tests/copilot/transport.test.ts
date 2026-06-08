import { beforeEach, describe, expect, it, vi } from 'vitest'

const instances: MockHttpAgent[] = []

class MockHttpAgent {
  messages: Array<{ id: string; role: string; content: string }> = []

  constructor(_opts: { url: string }) {
    instances.push(this)
  }

  addMessage(message: { id: string; role: string; content: string }) {
    this.messages.push(message)
  }

  async runAgent() {
    if (instances.indexOf(this) === 0) {
      throw new Error('runtime failed')
    }
    this.messages.push({ id: 'assistant-1', role: 'assistant', content: 'ok' })
  }
}

vi.mock('@ag-ui/client', () => ({
  HttpAgent: MockHttpAgent,
}))

describe('createTransport', () => {
  beforeEach(() => {
    instances.length = 0
  })

  it('recreates the AG-UI agent after a failed run so retries have clean history', async () => {
    const { createTransport } = await import('../../src/copilot/transport')
    const transport = createTransport()

    await expect(transport.send('first')).rejects.toThrow('runtime failed')
    await expect(transport.send('second')).resolves.toEqual([
      expect.objectContaining({ role: 'user', content: 'second' }),
      { id: 'assistant-1', role: 'assistant', content: 'ok' },
    ])

    expect(instances).toHaveLength(2)
    expect(instances[1].messages.map((message) => message.content)).toEqual(['second', 'ok'])
  })
})
