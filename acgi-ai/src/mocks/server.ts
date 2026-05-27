import { setupServer } from 'msw/node'
import { handlers } from './handlers'

export const server = setupServer(...handlers)

export function startMswNodeServer(): typeof server {
  server.listen({ onUnhandledRequest: 'error' })
  return server
}

export function resetMswNodeServer(): void {
  server.resetHandlers()
}

export function stopMswNodeServer(): void {
  server.close()
}
