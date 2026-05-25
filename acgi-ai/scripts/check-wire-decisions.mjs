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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function recordSlice(source, path) {
  const marker = `path: '${path}'`
  const start = source.indexOf(marker)
  if (start < 0) return ''
  const rest = source.slice(start)
  const next = rest.slice(marker.length).search(/\n\s*{\n\s*path:\s*'/)
  return next >= 0 ? rest.slice(0, marker.length + next) : rest
}

const expectedRoutes = [
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
  '/console/settings',
  '/console/tenants',
  '/console/account',
]

const requiredFields = [
  'crumb',
  'titleLead',
  'titleEmphasis',
  'headerAnatomy',
  'primaryAction',
  'secondaryActions',
  'density',
  'filterPlacement',
  'pagination',
  'rightRailPurpose',
  'receiptLifetime',
  'destructiveConfirmation',
]

const registryPath = resolve(root, 'src/routes/console/wire-decisions.ts')
const registry = existsSync(registryPath) ? readFileSync(registryPath, 'utf8') : ''
const consoleShell = read('src/routes/Console.tsx')
const packageJson = JSON.parse(read('package.json'))
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const design = read('DESIGN.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''

check(existsSync(registryPath), 'src/routes/console/wire-decisions.ts must exist.')
check(
  /export const CONSOLE_WIRE_DECISIONS/.test(registry) &&
    /satisfies readonly ConsoleWireDecision\[\]/.test(registry),
  'wire decision registry must export a typed CONSOLE_WIRE_DECISIONS array.',
)
check(
  /getConsoleWireDecision/.test(registry) && /ConsoleWireDecision/.test(registry),
  'wire decision registry must expose lookup and type helpers.',
)

for (const route of expectedRoutes) {
  const slice = recordSlice(registry, route)
  check(slice.length > 0, `wire decision registry must include ${route}.`)
  for (const field of requiredFields) {
    check(
      new RegExp(`${field}\\s*:\\s*['"\`][^'"\`]{4,}['"\`]`).test(slice),
      `${route} wire decision must define non-empty ${field}.`,
    )
  }
  check(
    new RegExp(`case\\s+['"]${escapeRegExp(route)}['"]`).test(consoleShell) || route === '/console',
    `Console.tsx PageBody switch must still route ${route}.`,
  )
  check(design.includes(`| \`${route}\``), `DESIGN.md A7 appendix must document ${route}.`)
}

check(
  /getConsoleWireDecision/.test(consoleShell) &&
    /data-wire-route/.test(consoleShell) &&
    /data-wire-decision-card/.test(consoleShell) &&
    /data-right-rail-purpose/.test(consoleShell),
  'Console.tsx must consume the wire decision registry for shell metadata and right-rail evidence.',
)
check(
  /Route-by-route wire decisions \(A7\)/.test(design) &&
    /Header anatomy/.test(design) &&
    /Receipt lifetime/.test(design) &&
    /Destructive confirmation/.test(design),
  'DESIGN.md must include the A7 route-by-route appendix with required decision columns.',
)
check(
  packageJson.scripts?.['test:wire-decisions'] === 'node scripts/check-wire-decisions.mjs',
  'package.json must expose test:wire-decisions.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:wire-decisions'),
  'package.json test:all must include test:wire-decisions.',
)
check(
  /check-wire-decisions\.mjs/.test(security) && /test:wire-decisions/.test(security),
  'security invariant check must guard wire decision wiring.',
)
check(/test:wire-decisions/.test(ciGates), 'CI readiness gate must include wire decisions.')
check(
  /Wire decisions/.test(architecture) && /test:wire-decisions/.test(architecture),
  'ARCHITECTURE.md must document the wire decision gate.',
)
check(
  /Wire decisions gate/.test(deploy) && /test:wire-decisions/.test(deploy),
  'DEPLOY.md must document the wire decisions gate.',
)
check(
  /Wire decisions foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:wire-decisions/.test(readiness),
  'integration readiness map must record the wire decisions foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Wire decisions check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Wire decisions check passed.')
console.log(`- routes covered: ${expectedRoutes.length}`)
console.log(
  '- fields: header, actions, density, filters, pagination, right rail, receipts, destructive confirmations',
)
