import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
  redirect,
} from '@tanstack/react-router'
import { useEffect } from 'react'
import {
  hasProductionSession,
  hasSession,
  SESSION_CHANGE_EVENT,
  subscribeToSessionSync,
} from '../../lib/session'
import { Console } from '../../routes/Console'
import { Login } from '../../routes/Login'
import { NotFound } from '../../routes/NotFound'

type LoginSearch = {
  next?: string
}

type RouterLocation = {
  pathname: string
  searchStr?: string
}

function safeConsoleNext(path: string): string {
  return path.startsWith('/console') ? path : '/console'
}

function locationNext(location: RouterLocation): string {
  return safeConsoleNext(`${location.pathname}${location.searchStr ?? ''}`)
}

async function requireConsoleSession(location: RouterLocation): Promise<void> {
  if (hasSession()) return
  if (await hasProductionSession()) return
  throw redirect({ to: '/login', search: { next: locationNext(location) } })
}

function ConsoleRoot() {
  useEffect(() => {
    const onSessionChange = () => {
      void router.invalidate()
    }
    const unsubscribeSessionSync = subscribeToSessionSync()
    window.addEventListener(SESSION_CHANGE_EVENT, onSessionChange)
    return () => {
      unsubscribeSessionSync()
      window.removeEventListener(SESSION_CHANGE_EVENT, onSessionChange)
    }
  }, [])

  return <Outlet />
}

const rootRoute = createRootRoute({
  component: ConsoleRoot,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: (search: Record<string, unknown>): LoginSearch => {
    const next = typeof search.next === 'string' ? safeConsoleNext(search.next) : undefined
    return next ? { next } : {}
  },
  component: LoginRoute,
})

function LoginRoute() {
  const { next } = loginRoute.useSearch()
  return <Login nextPath={next} />
}

const consoleIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console',
  beforeLoad: ({ location }) => requireConsoleSession(location),
  component: () => <Console path="/console" />,
})

const consoleOverviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console/overview',
  beforeLoad: () => {
    throw redirect({ to: '/console' })
  },
})

const consoleSectionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console/$section',
  beforeLoad: ({ location }) => requireConsoleSession(location),
  component: ConsoleSectionRoute,
})

const consoleAuditReceiptRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console/audit/$receiptId',
  beforeLoad: ({ location }) => requireConsoleSession(location),
  component: ConsoleAuditReceiptRoute,
})

function ConsoleSectionRoute() {
  const { section } = consoleSectionRoute.useParams()
  return <Console path={`/console/${section}`} />
}

function ConsoleAuditReceiptRoute() {
  const { receiptId } = consoleAuditReceiptRoute.useParams()
  return <Console path={`/console/audit/${receiptId}`} />
}

const notFoundRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '$',
  component: ConsoleNotFoundRoute,
})

function ConsoleNotFoundRoute() {
  const { _splat } = notFoundRoute.useParams()
  return <NotFound surface="console" path={_splat ? `/${_splat}` : '/'} />
}

const routeTree = rootRoute.addChildren([
  loginRoute,
  consoleIndexRoute,
  consoleOverviewRoute,
  consoleAuditReceiptRoute,
  consoleSectionRoute,
  notFoundRoute,
])

const router = createRouter({ routeTree })

function App() {
  return <RouterProvider router={router} />
}

export default App
