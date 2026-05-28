import { existsSync, readdirSync, readFileSync } from 'node:fs'
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

const packageJson = JSON.parse(read('package.json'))
const sharedPath = 'src/routes/console/shared.tsx'
const shared = read(sharedPath)
const consoleShell = read('src/routes/Console.tsx')
const appCss = read('src/App.css')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')

const requiredStatePrimitives = [
  ['ConsoleLoading', 'loading'],
  ['EmptyState', 'empty'],
  ['ConsoleError', 'error'],
  ['PartialBus', 'partial-bus'],
  ['StaleWhileRevalidating', 'stale-while-revalidating'],
  ['RetryInFlight', 'retry-in-flight'],
  ['Conflict', 'conflicted-mutation'],
  ['PermissionDenied', 'permission-denied'],
  ['RateLimited', 'rate-limited'],
  ['OptimisticPending', 'optimistic-pending'],
  ['ExpiredSession', 'expired-session'],
]

for (const [component, stateName] of requiredStatePrimitives) {
  check(
    new RegExp(`export function ${component}\\b`).test(shared),
    `${sharedPath} must export ${component} for the ${stateName} console state.`,
  )
  check(
    shared.includes(stateName),
    `${sharedPath} must name the ${stateName} state for static/audit evidence.`,
  )
}

check(/export type EmptyMeans/.test(shared), `${sharedPath} must export EmptyMeans.`)
for (const emptyMeans of ['fresh-tenant', 'awaiting-bus', 'audit-drift']) {
  check(
    shared.includes(`'${emptyMeans}'`),
    `${sharedPath} must include emptyMeans discriminator ${emptyMeans}.`,
  )
}
check(
  /emptyMeans[?:]/.test(shared) && /EMPTY_STATE_COPY/.test(shared),
  'EmptyState must require an emptyMeans taxonomy and copy map.',
)
check(/export function EnvIndicator\b/.test(shared), `${sharedPath} must export EnvIndicator.`)
check(
  /aria-live="polite"/.test(shared),
  `${sharedPath} state components must expose polite live regions.`,
)
check(
  /data-state-kind/.test(shared),
  `${sharedPath} state components must expose data-state-kind evidence.`,
)

const consoleRouteDir = resolve(root, 'src/routes/console')
const routeFiles = readdirSync(consoleRouteDir)
  .filter((name) => name.endsWith('.tsx') && name !== 'shared.tsx')
  .sort()
for (const file of routeFiles) {
  const source = read(`src/routes/console/${file}`)
  for (const match of source.matchAll(/<EmptyState\b[\s\S]*?\/>/g)) {
    check(match[0].includes('emptyMeans='), `${file} EmptyState usage must pass emptyMeans.`)
  }
}

for (const file of ['Overview.tsx', 'Maci.tsx']) {
  const source = read(`src/routes/console/${file}`)
  check(
    /ConsoleLoading/.test(source) && /ConsoleError/.test(source),
    `${file} must use shared ConsoleLoading and ConsoleError primitives, not bespoke loading/error chrome.`,
  )
  check(
    !/Could not reach the bus/.test(source),
    `${file} must not duplicate raw bus-error copy outside shared ConsoleError.`,
  )
}

check(
  /EnvIndicator/.test(consoleShell) &&
    /mode=/.test(consoleShell) &&
    /affectedModules=/.test(consoleShell),
  'Console shell must render the non-dismissable EnvIndicator with mode and affected modules.',
)
check(
  /c-state-card/.test(appCss) && /c-env-indicator/.test(appCss),
  'src/App.css must style console state primitives and the env indicator without inline styles.',
)
check(
  packageJson.scripts?.['test:state-coverage'] === 'node scripts/check-console-state-coverage.mjs',
  'package.json must expose test:state-coverage.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:state-coverage'),
  'package.json test:all must include test:state-coverage.',
)
check(
  /check-console-state-coverage\.mjs/.test(security) && /test:state-coverage/.test(security),
  'security invariant check must guard console state coverage wiring.',
)
check(
  /test:state-coverage/.test(ciGates),
  'CI readiness gate check must include console state coverage as part of the readiness contract.',
)
check(
  /Console state coverage/.test(architecture) && /test:state-coverage/.test(architecture),
  'ARCHITECTURE.md must document the console state coverage gate.',
)
check(
  /Console state coverage gate/.test(deploy) && /test:state-coverage/.test(deploy),
  'DEPLOY.md must document the console state coverage gate.',
)
check(
  /Console state coverage foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:state-coverage/.test(readiness),
  'integration readiness map must record the console state coverage foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Console state coverage check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Console state coverage check passed.')
console.log(`- state primitives: ${requiredStatePrimitives.map(([name]) => name).join(', ')}`)
console.log(`- route files scanned: ${routeFiles.length}`)
