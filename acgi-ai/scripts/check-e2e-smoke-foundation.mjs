import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readRepo(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function mustContain(source, needle, label) {
  check(source.includes(needle), `${label} must include ${JSON.stringify(needle)}.`)
}

export const E2E_VIEWPORTS = [360, 768, 834, 1024, 1440]

export const E2E_SMOKE_ROUTES = [
  {
    name: 'marketing landing',
    path: '/',
    surface: 'marketing',
    assertions: ['loads at all five viewports', 'no console fixture sentinels'],
  },
  {
    name: 'product hero legalguard',
    path: '/products/legalguard',
    surface: 'marketing',
    assertions: ['resolves product detail route', 'keeps public-only shell'],
  },
  {
    name: 'product hero governance-eval',
    path: '/products/governance-eval',
    surface: 'marketing',
    assertions: ['resolves product detail route', 'keeps public-only shell'],
  },
  {
    name: 'login privilege handoff',
    path: '/login',
    surface: 'console',
    assertions: ['renders SSO options', 'preserves next search parameter'],
  },
  {
    name: 'console unauth redirect',
    path: '/console',
    surface: 'console',
    assertions: ['redirects to /login without session', 'no fixture wall in production'],
  },
  {
    name: 'console synthetic session',
    path: '/console',
    surface: 'console',
    env: 'VITE_BYPASS_SESSION=true',
    assertions: ['loads shell in dev only', 'renders privilege banner'],
  },
]

export const CONSOLE_SIDEBAR_ROUTES = [
  '/console',
  '/console/workbench',
  '/console/agents',
  '/console/actions',
  '/console/maci',
  '/console/deliberations',
  '/console/incidents',
  '/console/policies',
  '/console/compile',
  '/console/audit',
  '/console/bus',
  '/console/process',
  '/console/settings',
  '/console/tenants',
  '/console/account',
]

export const E2E_FAILURE_MODE_MANIFEST = [
  'marketing /console redirect is not rendered from marketing bundle',
  'unauthenticated console deep link redirects with next=',
  'synthetic console session is dev-only with VITE_BYPASS_SESSION=true',
  'every in-scope sidebar route navigates without throwing',
  'privilege banner remains visible before browser mutation tests exist',
  'CSP violation and network logs remain future Playwright assertions',
]

const packageJson = JSON.parse(read('package.json'))
const e2eHttpPath = 'scripts/smoke-e2e-http-shells.mjs'
const e2eHttp = existsSync(resolve(root, e2eHttpPath)) ? read(e2eHttpPath) : ''
const productSurfaces = read('src/routes/ProductSurfaces.tsx')
const wireDecisions = read('src/routes/console/wire-decisions.ts')
const plan = read('PLAN.md')
const architecture = read('ARCHITECTURE.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(
  packageJson.scripts?.['test:e2e'] === 'node scripts/check-e2e-smoke-foundation.mjs',
  'package.json must expose test:e2e for this manifest gate only.',
)
check(
  packageJson.scripts?.['test:e2e-http'] === 'node scripts/smoke-e2e-http-shells.mjs',
  'package.json must expose test:e2e-http for the local E2E HTTP shell smoke.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:test-surface') &&
    packageJson.scripts['test:all'].includes('pnpm run test:e2e-http'),
  'package.json test:all must run the test surface manifest gate and local E2E HTTP shell smoke.',
)

check(existsSync(resolve(root, e2eHttpPath)), `${e2eHttpPath} must exist.`)

for (const viewport of E2E_VIEWPORTS) {
  check([360, 768, 834, 1024, 1440].includes(viewport), `unexpected viewport ${viewport}.`)
}
check(E2E_VIEWPORTS.length === 5, 'E2E smoke manifest must keep the five PLAN.md viewports.')

for (const path of ['/products/legalguard', '/products/governance-eval', '/products/acgs']) {
  const slug = path.replace('/products/', '')
  check(productSurfaces.includes(`slug: '${slug}'`), `ProductSurfaces.tsx must define ${path}.`)
}

for (const route of CONSOLE_SIDEBAR_ROUTES) {
  mustContain(wireDecisions, `path: '${route}'`, 'src/routes/console/wire-decisions.ts')
  mustContain(e2eHttp, route, e2eHttpPath)
}

for (const needle of [
  'E2E_HTTP_SHELL_ROUTES',
  'VITE_BYPASS_SESSION=true',
  'VITE_USE_MOCKS=true',
  'pnpm run dev:mock',
  'browser Playwright execution remains Phase 2 work',
]) {
  mustContain(e2eHttp, needle, e2eHttpPath)
}

for (const needle of [
  'Add **Playwright** smoke pack',
  'marketing landing loads at 360/768/834/1024/1440',
  'every in-scope sidebar link navigates without throwing',
  'Local HTTP shell smoke: `pnpm run test:e2e-http`',
  'test:e2e',
  'Local static foundation: `pnpm run test:test-surface`',
]) {
  mustContain(plan, needle, 'PLAN.md')
}
for (const needle of [
  'Test surface foundation',
  'test:e2e',
  'manifest gate',
  'browser proof remains external',
]) {
  mustContain(architecture, needle, 'ARCHITECTURE.md')
}
for (const needle of ['Test surface script foundation', 'pnpm -F acgi-ai run test:e2e']) {
  mustContain(readiness, needle, 'docs/integration-readiness-task-map.md')
}

if (failures.length > 0) {
  console.error('E2E smoke foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('E2E smoke foundation check passed.')
console.log(`- manifest gate only: ${E2E_SMOKE_ROUTES.length} smoke route groups`)
console.log(`- console sidebar routes: ${CONSOLE_SIDEBAR_ROUTES.length}`)
console.log('- browser Playwright execution remains Phase 2 work')
