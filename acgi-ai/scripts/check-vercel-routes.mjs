import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []
const internalDocPaths = [
  '/AGENTS.md',
  '/CLAUDE.md',
  '/DESIGN.md',
  '/DEPLOY.md',
  '/nested/AGENTS.md',
  '/nested/deeper/CLAUDE.md',
  '/nested/DESIGN.md',
  '/nested/deeper/DEPLOY.md',
]

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readIfExists(relativePath) {
  const path = resolve(root, relativePath)
  return existsSync(path) ? readFileSync(path, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function routeRegex(route) {
  return new RegExp(`^${route.src}$`)
}

function routeFor(routes, path) {
  return routes.find((route) => routeRegex(route).test(path))
}

function routeIndex(routes, predicate) {
  return routes.findIndex(predicate)
}

const vercelJson = JSON.parse(read('vercel.json'))
const packageJson = JSON.parse(read('package.json'))
const securityInvariants = read('scripts/check-security-invariants.mjs')
const deployDocs = read('DEPLOY.md')
const architecture = readIfExists('ARCHITECTURE.md')
const readinessMap = readIfExists('../docs/integration-readiness-task-map.md')
const routes = Array.isArray(vercelJson.routes) ? vercelJson.routes : []

const denyIndex = routeIndex(
  routes,
  (route) => route.status === 404 && /AGENTS\|CLAUDE\|DESIGN\|DEPLOY/.test(route.src ?? ''),
)
const consoleExactIndex = routeIndex(
  routes,
  (route) => route.src === '/console' && route.status === 308,
)
const consoleWildcardIndex = routeIndex(
  routes,
  (route) => route.src === '/console/(.*)' && route.status === 308,
)
const fallbackIndex = routeIndex(routes, (route) => route.src === '/(.*)' && route.dest === '/')

check(vercelJson.buildCommand === 'pnpm build:marketing', 'vercel.json must build marketing only.')
check(
  vercelJson.outputDirectory === 'dist',
  'vercel.json must publish the marketing dist directory.',
)
check(routes.length > 0, 'vercel.json must use an ordered routes table for edge routing.')
check(denyIndex === 0, 'internal-doc 404 route must be first in vercel.json routes.')
check(
  consoleExactIndex > denyIndex,
  'exact /console redirect must follow the internal-doc deny route.',
)
check(
  consoleWildcardIndex > consoleExactIndex,
  '/console/(.*) redirect must follow the exact /console redirect.',
)
check(
  fallbackIndex === routes.length - 1,
  'SPA fallback route must be the final vercel.json route.',
)
check(
  denyIndex >= 0 && consoleExactIndex >= 0 && consoleWildcardIndex >= 0 && fallbackIndex >= 0,
  'vercel.json routes must include internal-doc deny, /console redirect, /console/(.*) redirect, and SPA fallback.',
)

const consoleExact = routes[consoleExactIndex] ?? {}
const consoleWildcard = routes[consoleWildcardIndex] ?? {}
check(
  consoleExact.headers?.Location === 'https://console.acgs.ai/console',
  '/console must 308 redirect to https://console.acgs.ai/console.',
)
check(
  consoleWildcard.headers?.Location === 'https://console.acgs.ai/console/$1',
  '/console/(.*) must 308 redirect to https://console.acgs.ai/console/$1.',
)
check(
  !Array.isArray(vercelJson.rewrites) || vercelJson.rewrites.length === 0,
  'vercel.json must not use rewrites for the privileged /console boundary; use explicit 308 routes.',
)

for (const path of internalDocPaths) {
  const route = routeFor(routes, path)
  check(route?.status === 404, `${path} must resolve to the internal-doc 404 route.`)
}
for (const [path, location] of [
  ['/console', 'https://console.acgs.ai/console'],
  ['/console/actions', 'https://console.acgs.ai/console/$1'],
  ['/console/policies/P-1207', 'https://console.acgs.ai/console/$1'],
]) {
  const route = routeFor(routes, path)
  check(route?.status === 308, `${path} must resolve to a 308 console-origin redirect.`)
  check(
    route?.headers?.Location === location,
    `${path} must use the expected console Location template.`,
  )
}
check(
  routeFor(routes, '/ordinary-marketing-route')?.dest === '/',
  'marketing SPA paths must fall back to /.',
)
check(
  routeFor(routes, '/products/runtime-kernel')?.dest === '/',
  'product detail paths must fall back to /.',
)
check(
  routeFor(routes, '/consolefoo')?.dest === '/',
  '/consolefoo must remain a marketing SPA path, not a console redirect.',
)

// Agent-readable static governance surface (W2). Each must resolve to its own
// static-file route, NOT the SPA fallback, and sit after the console redirects
// but before the fallback so an ordinary marketing path still falls through.
const agentAssetRoutes = [
  ['/llms.txt', '/llms.txt'],
  ['/governance-framework.txt', '/governance-framework.txt'],
]
for (const [path, dest] of agentAssetRoutes) {
  const route = routeFor(routes, path)
  check(Boolean(route), `${path} must resolve to an explicit Vercel route.`)
  check(
    route?.dest === dest,
    `${path} must serve the static file ${dest}, not rewrite to the SPA.`,
  )
  check(route?.dest !== '/', `${path} must not resolve to the SPA fallback rewrite.`)
  const index = routeIndex(routes, (candidate) => routeRegex(candidate).test(path))
  check(
    index > consoleWildcardIndex,
    `${path} route must come after the console redirects.`,
  )
  check(index < fallbackIndex, `${path} route must come before the SPA fallback.`)
  check(
    route?.headers?.['Content-Type'] === 'text/plain; charset=utf-8',
    `${path} must pin Content-Type: text/plain; charset=utf-8.`,
  )
}

check(
  packageJson.scripts?.['test:vercel-routes'] === 'node scripts/check-vercel-routes.mjs',
  'package.json must expose test:vercel-routes for marketing edge route verification.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:vercel-routes'),
  'package.json test:all must include test:vercel-routes.',
)
check(
  securityInvariants.includes('check-vercel-routes.mjs') &&
    securityInvariants.includes('test:vercel-routes') &&
    securityInvariants.includes('https://console.acgs.ai/console'),
  'security invariant check must guard the Vercel route verifier and console-origin redirect contract.',
)
check(
  /"routes"/.test(deployDocs) &&
    /"src": "\/console"/.test(deployDocs) &&
    /"status": 308/.test(deployDocs) &&
    /https:\/\/console\.acgs\.ai\/console/.test(deployDocs) &&
    !/"rewrites"\s*:\s*\[/.test(deployDocs),
  'DEPLOY.md must document the current routes-based Vercel redirect/deny contract, not stale rewrites.',
)
check(
  /marketing privileged redirect/.test(architecture) && /console\.acgs\.ai/.test(architecture),
  'ARCHITECTURE.md must document the marketing-to-console origin boundary.',
)
check(
  /Vercel marketing edge routing/.test(readinessMap) && /test:vercel-routes/.test(readinessMap),
  'docs/integration-readiness-task-map.md must map Vercel route readiness to its gate.',
)

if (failures.length > 0) {
  console.error('Vercel route contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Vercel route contract check passed.')
