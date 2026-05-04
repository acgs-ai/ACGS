import { useEffect, useState } from 'react'
import './App.css'
import { Console } from './routes/Console'
import { Login } from './routes/Login'
import { Marketing } from './routes/Marketing'
import { NotFound } from './routes/NotFound'
import { Privacy } from './routes/Privacy'

function getPath(): string {
  if (typeof window === 'undefined') return '/'
  return window.location.pathname || '/'
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
