import { useEffect, useState } from 'react'
import './App.css'
import { hasSession, SESSION_CHANGE_EVENT } from './lib/session'
import { Console } from './routes/Console'
import { Login } from './routes/Login'
import { Marketing } from './routes/Marketing'
import { NotFound } from './routes/NotFound'
import { Privacy } from './routes/Privacy'
import { ProductIndex, ProductSurface } from './routes/ProductSurfaces'

function normalizePath(p: string): string {
  const canonical = p.length > 1 && p.endsWith('/') ? p.replace(/\/+$/, '') : p
  // The sidebar label "Overview" lives at `/console`, but the URL pattern
  // for every other Operate/Govern page is `/console/<name>`. A user
  // typing `/console/overview` would otherwise land on the canonical 404.
  if (canonical === '/console/overview') {
    if (typeof window !== 'undefined') {
      window.history.replaceState({}, '', '/console')
    }
    return '/console'
  }
  if (canonical !== p && typeof window !== 'undefined') {
    window.history.replaceState({}, '', canonical)
  }
  return canonical
}

function getPath(): string {
  if (typeof window === 'undefined') return '/'
  return normalizePath(window.location.pathname || '/')
}

const MARKETING_PATHS = new Set(['/'])

function isConsolePath(path: string): boolean {
  return path === '/console' || path.startsWith('/console/')
}

function loginPathFor(nextPath: string): string {
  return `/login?next=${encodeURIComponent(nextPath)}`
}

function App() {
  const [path, setPath] = useState<string>(getPath())
  const [sessionVersion, setSessionVersion] = useState(0)

  useEffect(() => {
    const onPop = () => setPath(getPath())
    const onSessionChange = () => setSessionVersion((version) => version + 1)
    window.addEventListener('popstate', onPop)
    window.addEventListener(SESSION_CHANGE_EVENT, onSessionChange)
    return () => {
      window.removeEventListener('popstate', onPop)
      window.removeEventListener(SESSION_CHANGE_EVENT, onSessionChange)
    }
  }, [])

  const hasConsoleSession = sessionVersion >= 0 ? hasSession() : false
  const needsConsoleSession = isConsolePath(path) && !hasConsoleSession

  useEffect(() => {
    if (!needsConsoleSession || typeof window === 'undefined') return
    const loginPath = loginPathFor(path)
    if (`${window.location.pathname}${window.location.search}` !== loginPath) {
      window.history.replaceState({}, '', loginPath)
    }
  }, [needsConsoleSession, path])

  if (needsConsoleSession) return <Login nextPath={path} />

  if (path === '/login') return <Login />
  if (path === '/privacy') return <Privacy />
  if (path === '/products') return <ProductIndex />
  if (path.startsWith('/products/')) return <ProductSurface path={path} />
  if (isConsolePath(path)) return <Console path={path} />
  if (MARKETING_PATHS.has(path)) return <Marketing />
  return <NotFound surface="marketing" path={path} />
}

export default App
