import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router'
import { lazy, Suspense, useEffect } from 'react'
import { AcgsLite } from '../../routes/AcgsLite'
import { Ask } from '../../routes/Ask'
import { ClinicalGuard } from '../../routes/ClinicalGuard'
import {
  AgentReadable,
  FailureModesPage,
  FounderNarrative,
  GovernancePatternsPage,
  Marketing,
} from '../../routes/Marketing'
import { NotFound } from '../../routes/NotFound'
import { Privacy } from '../../routes/Privacy'
import { ProductIndex, ProductSurface } from '../../routes/ProductSurfaces'
import { Security } from '../../routes/Security'
import { Swarm } from '../../routes/Swarm'
import { Trust } from '../../routes/Trust'

function consoleOrigin(): string {
  return import.meta.env.VITE_CONSOLE_ORIGIN || 'https://console.acgs.ai'
}

function targetConsoleUrl(path: string): string {
  const origin = consoleOrigin().replace(/\/+$/, '')
  const targetPath = path === '/login' ? '/login' : path
  const search = typeof window !== 'undefined' ? window.location.search : ''
  return `${origin}${targetPath}${search}`
}

function PrivilegedRedirect({ path }: { path: string }) {
  const target = targetConsoleUrl(path)

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.location.assign(target)
    }
  }, [target])

  return (
    <div className="marketing">
      <div className="shell">
        <section className="notfound" role="status" aria-live="polite">
          <div className="notfound-eyebrow">
            <span className="asterism">⁂</span>
            <span>Privilege boundary · redirecting</span>
          </div>
          <h1 className="notfound-h1">
            Cross to the <em>console</em>
          </h1>
          <p className="notfound-lede">
            Privileged pages are served from the console origin. This public marketing artifact does
            not embed the console route tree.
          </p>
          <div className="notfound-actions">
            <a className="btn btn-primary" href={target}>
              Continue to console
            </a>
          </div>
        </section>
      </div>
    </div>
  )
}

const rootRoute = createRootRoute({
  component: Outlet,
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: Marketing,
})

const askRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/ask',
  component: Ask,
})

const privacyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/privacy',
  component: Privacy,
})

const founderRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/founder',
  component: FounderNarrative,
})

const failureModesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/failure-modes',
  component: FailureModesPage,
})

const governancePatternsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/governance-patterns',
  component: GovernancePatternsPage,
})

const agentReadableRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/agent-readable',
  component: AgentReadable,
})

const acgsLiteRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/acgs-lite',
  component: AcgsLite,
})

const trustRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/trust',
  component: Trust,
})

const securityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/security',
  component: Security,
})

const swarmRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/swarm',
  component: Swarm,
})

const clinicalguardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/clinicalguard',
  component: ClinicalGuard,
})

const productIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/products',
  component: ProductIndex,
})

const productRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/products/$slug',
  component: ProductRoute,
})

function ProductRoute() {
  const { slug } = productRoute.useParams()
  return <ProductSurface path={`/products/${slug}`} />
}

const privilegedLoginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: () => <PrivilegedRedirect path="/login" />,
})

const privilegedConsoleRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console',
  component: () => <PrivilegedRedirect path="/console" />,
})

const privilegedConsoleSplatRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console/$',
  component: PrivilegedConsoleSplatRoute,
})

function PrivilegedConsoleSplatRoute() {
  const { _splat } = privilegedConsoleSplatRoute.useParams()
  const path = _splat ? `/console/${_splat}` : '/console'
  return <PrivilegedRedirect path={path} />
}

const notFoundRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '$',
  component: MarketingNotFoundRoute,
})

function MarketingNotFoundRoute() {
  const { _splat } = notFoundRoute.useParams()
  return <NotFound surface="marketing" path={_splat ? `/${_splat}` : '/'} />
}

const routeTree = rootRoute.addChildren([
  indexRoute,
  askRoute,
  privacyRoute,
  founderRoute,
  failureModesRoute,
  governancePatternsRoute,
  agentReadableRoute,
  acgsLiteRoute,
  trustRoute,
  securityRoute,
  swarmRoute,
  clinicalguardRoute,
  productIndexRoute,
  productRoute,
  privilegedLoginRoute,
  privilegedConsoleRoute,
  privilegedConsoleSplatRoute,
  notFoundRoute,
])

const router = createRouter({ routeTree })

// Lazy + flag-gated: the copilot tree (panel + @ag-ui/client) is a separate
// chunk. The flag gates runtime MOUNT only — the chunk is still emitted by the
// build and counts toward the 200 KiB marketing budget (+44.5 KiB → 174.1/200);
// it is just not downloaded until mounted. See docs/COPILOTKIT_FRONTEND_PLAN.md.
const CopilotMount = lazy(() => import('../../copilot/CopilotMount'))
const copilotEnabled = import.meta.env.VITE_COPILOT_ENABLED === 'true'

function App() {
  return (
    <>
      <RouterProvider router={router} />
      {copilotEnabled && (
        <Suspense fallback={null}>
          <CopilotMount />
        </Suspense>
      )}
    </>
  )
}

export default App
