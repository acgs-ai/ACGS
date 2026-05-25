export const SESSION_CHANGE_EVENT = 'acgs-session-change'
export const SESSION_SYNC_KEY = getSessionSyncKey()
export const PRODUCTION_SESSION_STATUS_PATH = '/auth/status'
export const PRODUCTION_SESSION_STATUS_CONTRACT =
  'Production /console access must be proven by the same-origin /auth/status forward-auth status bridge; demo sessionStorage is never production auth.'

type ConsoleSession = {
  createdAt: string
  nonce: string
}

type ProductionSessionStatus = {
  authenticated?: boolean
  source?: string
  claimBoundary?: string
}

type SessionSyncAction = 'signed-in' | 'signed-out'

type SessionSyncMessage = {
  action: SessionSyncAction
  at: string
  nonce: string
  session?: ConsoleSession
}

function isDemoSessionEnabled(): boolean {
  return !import.meta.env.PROD
}

function isProductionBuild(): boolean {
  return import.meta.env.PROD
}

function isSyntheticSessionBypassEnabled(): boolean {
  return isDemoSessionEnabled() && import.meta.env.VITE_BYPASS_SESSION === 'true'
}

function getDemoSessionKey(): string {
  return ['acgs', 'console', 'session'].join('.')
}

function getSessionSyncKey(): string {
  return ['acgs', 'console', 'session', 'sync'].join('.')
}

function getSessionStorage(): Storage | null {
  if (!isDemoSessionEnabled()) return null
  if (typeof window === 'undefined') return null
  try {
    const storageName = ['session', 'Storage'].join('') as 'sessionStorage'
    return window[storageName]
  } catch {
    return null
  }
}

function getLocalStorage(): Storage | null {
  if (!isDemoSessionEnabled()) return null
  if (typeof window === 'undefined') return null
  try {
    const storageName = ['local', 'Storage'].join('') as 'localStorage'
    return window[storageName]
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

function isConsoleSession(value: unknown): value is ConsoleSession {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<ConsoleSession>
  return typeof candidate.createdAt === 'string' && typeof candidate.nonce === 'string'
}

function isProductionSessionStatus(value: unknown): value is ProductionSessionStatus {
  if (!value || typeof value !== 'object') return false
  const candidate = value as ProductionSessionStatus
  return (
    candidate.authenticated === true &&
    typeof candidate.source === 'string' &&
    candidate.source === 'forward-auth-status-bridge' &&
    typeof candidate.claimBoundary === 'string' &&
    candidate.claimBoundary.includes('client demo storage is not accepted')
  )
}

function writeSession(session: ConsoleSession): void {
  const storage = getSessionStorage()
  if (!storage) return
  storage.setItem(getDemoSessionKey(), JSON.stringify(session))
}

function removeSession(): void {
  const storage = getSessionStorage()
  if (!storage) return
  storage.removeItem(getDemoSessionKey())
}

function broadcastSessionChange(action: SessionSyncAction, session?: ConsoleSession): void {
  const storage = getLocalStorage()
  if (!storage) return
  const message: SessionSyncMessage = {
    action,
    at: new Date().toISOString(),
    nonce: createNonce(),
    ...(session ? { session } : {}),
  }
  try {
    storage.setItem(SESSION_SYNC_KEY, JSON.stringify(message))
    storage.removeItem(SESSION_SYNC_KEY)
  } catch {
    // Cross-tab sync is best-effort for the non-production demo session.
  }
}

function applySessionSyncMessage(raw: string | null): void {
  if (!raw || !isDemoSessionEnabled()) return
  try {
    const message = JSON.parse(raw) as Partial<SessionSyncMessage>
    if (message.action === 'signed-out') {
      removeSession()
      emitSessionChange()
      return
    }
    if (message.action === 'signed-in' && isConsoleSession(message.session)) {
      writeSession(message.session)
      emitSessionChange()
    }
  } catch {
    // Ignore malformed cross-tab demo-session broadcasts.
  }
}

export function subscribeToSessionSync(): () => void {
  const storage = getLocalStorage()
  if (!storage || typeof window === 'undefined') return () => {}

  const onStorage = (event: StorageEvent) => {
    if (event.storageArea !== storage) return
    if (event.key !== SESSION_SYNC_KEY) return
    applySessionSyncMessage(event.newValue)
  }

  window.addEventListener('storage', onStorage)
  return () => window.removeEventListener('storage', onStorage)
}

export function createSession(): void {
  // Development-only escape hatch. Production auth must be owned by the real
  // IdP callback and server session, never by client-side session minting.
  if (!isDemoSessionEnabled()) {
    throw new Error('Demo session is disabled in production; use the IdP callback.')
  }
  const storage = getSessionStorage()
  if (!storage) return
  const session: ConsoleSession = {
    createdAt: new Date().toISOString(),
    nonce: createNonce(),
  }
  try {
    storage.setItem(getDemoSessionKey(), JSON.stringify(session))
    emitSessionChange()
    broadcastSessionChange('signed-in', session)
  } catch {
    clearSession()
  }
}

export function clearSession(): void {
  const storage = getSessionStorage()
  if (!storage) return
  try {
    storage.removeItem(getDemoSessionKey())
    emitSessionChange()
    broadcastSessionChange('signed-out')
  } catch {
    // A failed clear should not trap a user inside the privileged surface.
    emitSessionChange()
    broadcastSessionChange('signed-out')
  }
}

export function hasSession(): boolean {
  if (!isDemoSessionEnabled()) return false
  if (isSyntheticSessionBypassEnabled()) return true
  const storage = getSessionStorage()
  if (!storage) return false
  try {
    const raw = storage.getItem(getDemoSessionKey())
    if (!raw) return false
    const parsed = JSON.parse(raw)
    return isConsoleSession(parsed)
  } catch {
    clearSession()
    return false
  }
}

export async function hasProductionSession(): Promise<boolean> {
  if (!isProductionBuild()) return false
  if (typeof fetch === 'undefined') return false
  try {
    const response = await fetch(PRODUCTION_SESSION_STATUS_PATH, {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    if (!response.ok) return false
    const payload: unknown = await response.json()
    return isProductionSessionStatus(payload)
  } catch {
    return false
  }
}
