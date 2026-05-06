const SESSION_KEY = 'acgs.console.session'
export const SESSION_CHANGE_EVENT = 'acgs-session-change'

type ConsoleSession = {
  createdAt: string
  nonce: string
}

function getSessionStorage(): Storage | null {
  if (typeof window === 'undefined') return null
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

function createNonce(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
}

function emitSessionChange(): void {
  if (typeof window === 'undefined') return
  window.dispatchEvent(new Event(SESSION_CHANGE_EVENT))
}

export function createSession(): void {
  const storage = getSessionStorage()
  if (!storage) return
  const session: ConsoleSession = {
    createdAt: new Date().toISOString(),
    nonce: createNonce(),
  }
  try {
    storage.setItem(SESSION_KEY, JSON.stringify(session))
    emitSessionChange()
  } catch {
    clearSession()
  }
}

export function clearSession(): void {
  const storage = getSessionStorage()
  if (!storage) return
  try {
    storage.removeItem(SESSION_KEY)
    emitSessionChange()
  } catch {
    // A failed clear should not trap a user inside the privileged surface.
    emitSessionChange()
  }
}

export function hasSession(): boolean {
  const storage = getSessionStorage()
  if (!storage) return false
  try {
    const raw = storage.getItem(SESSION_KEY)
    if (!raw) return false
    const parsed = JSON.parse(raw) as Partial<ConsoleSession>
    return typeof parsed.createdAt === 'string' && typeof parsed.nonce === 'string'
  } catch {
    clearSession()
    return false
  }
}
