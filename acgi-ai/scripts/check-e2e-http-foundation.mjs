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

function maybeRead(relativePath) {
  const absolute = resolve(root, relativePath)
  return existsSync(absolute) ? readFileSync(absolute, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function mustContain(source, needle, label) {
  check(source.includes(needle), `${label} must include ${JSON.stringify(needle)}.`)
}

const packageJson = JSON.parse(read('package.json'))
const smokePath = 'scripts/smoke-e2e-http-shells.mjs'
const smoke = maybeRead(smokePath)
const e2e = read('scripts/check-e2e-smoke-foundation.mjs')
const testSurface = read('scripts/check-test-surface-foundation.mjs')
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const gettingStarted = read('GETTING_STARTED.md')
const plan = read('PLAN.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(existsSync(resolve(root, smokePath)), `${smokePath} must exist.`)
check(
  packageJson.scripts?.['test:e2e-http'] === 'node scripts/smoke-e2e-http-shells.mjs',
  'package.json must expose test:e2e-http for the local E2E HTTP shell smoke.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:e2e-http'),
  'package.json test:all must include test:e2e-http.',
)

for (const needle of [
  'E2E_HTTP_SHELL_ROUTES',
  'CONSOLE_SIDEBAR_ROUTES',
  'VITE_BYPASS_SESSION=true',
  'VITE_USE_MOCKS=true',
  'pnpm run dev:mock',
  '<div id="root">',
  'browser Playwright execution remains Phase 2 work',
]) {
  mustContain(smoke, needle, smokePath)
}

for (const route of [
  '/',
  '/products/legalguard',
  '/products/governance-eval',
  '/products/gove-zone',
  '/login?next=%2Fconsole%2Fagents',
  '/console/workbench',
  '/console/agents',
  '/console/audit',
  '/console/account',
]) {
  mustContain(smoke, route, smokePath)
}

for (const needle of ['test:e2e-http', 'smoke-e2e-http-shells.mjs']) {
  mustContain(e2e, needle, 'scripts/check-e2e-smoke-foundation.mjs')
  mustContain(testSurface, needle, 'scripts/check-test-surface-foundation.mjs')
  mustContain(security, needle, 'scripts/check-security-invariants.mjs')
  mustContain(ciGates, needle, 'scripts/check-ci-readiness-gates.mjs')
}

check(
  /Local HTTP shell smoke: `pnpm run test:e2e-http`/.test(plan) &&
    /browser Playwright execution remains Phase 2 work/.test(plan),
  'PLAN.md must record the bounded local E2E HTTP shell smoke without closing Playwright work.',
)
check(
  /E2E HTTP shell smoke/.test(architecture) &&
    /test:e2e-http/.test(architecture) &&
    /browser Playwright execution remains Phase 2 work/.test(architecture),
  'ARCHITECTURE.md must document the bounded E2E HTTP shell smoke and Playwright gap.',
)
check(
  /pnpm -F acgi-ai run test:e2e-http/.test(gettingStarted),
  'GETTING_STARTED.md must list the local E2E HTTP shell smoke command.',
)
check(
  /E2E HTTP shell smoke/.test(readiness) &&
    /pnpm -F acgi-ai run test:e2e-http/.test(readiness),
  'integration readiness map must record the E2E HTTP shell smoke and command.',
)

if (failures.length > 0) {
  console.error('E2E HTTP shell foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('E2E HTTP shell foundation check passed.')
console.log('- runtime: Vite mock dev server HTTP shell smoke')
console.log('- scope: local route shell responses; browser Playwright execution remains Phase 2 work')
