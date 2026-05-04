import { useEffect, useState } from 'react'
import './App.css'
import { Console } from './routes/Console'
import { Login } from './routes/Login'
import { Marketing } from './routes/Marketing'
import { NotFound } from './routes/NotFound'
import { Privacy } from './routes/Privacy'

function normalizePath(p: string): string {
  // The sidebar label "Overview" lives at `/console`, but the URL pattern
  // for every other Operate/Govern page is `/console/<name>`. A user
  // typing `/console/overview` would otherwise land on the canonical 404.
  if (p === '/console/overview') {
    if (typeof window !== 'undefined') {
      window.history.replaceState({}, '', '/console')
    }
    return '/console'
  }
  return p
}

function getPath(): string {
  if (typeof window === 'undefined') return '/'
  return normalizePath(window.location.pathname || '/')
}

const MARKETING_PATHS = new Set(['/'])

function App() {
  const [path, setPath] = useState<string>(getPath())

  useEffect(() => {
    const onPop = () => setPath(getPath())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  if (path === '/login') return <Login />
  if (path === '/privacy') return <Privacy />
  if (path.startsWith('/console')) return <Console path={path} />
  if (MARKETING_PATHS.has(path)) return <Marketing />
  return <NotFound surface="marketing" path={path} />
}

export default App
