import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
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
const claude = read('CLAUDE.md')
const agents = read('AGENTS.md')
const readiness = read('../docs/integration-readiness-task-map.md')
const securityCheck = read('scripts/check-security-invariants.mjs')
const architecture = maybeRead('ARCHITECTURE.md')
const integrating = maybeRead('INTEGRATING.md')
const gettingStarted = maybeRead('GETTING_STARTED.md')
const hello = maybeRead('scripts/hello.mjs')
const helloWorld = maybeRead('scripts/hello-world.sh')

check(
  existsSync(resolve(root, 'ARCHITECTURE.md')),
  'ARCHITECTURE.md must exist at the acgi-ai package root.',
)
check(
  existsSync(resolve(root, 'INTEGRATING.md')),
  'INTEGRATING.md must exist at the acgi-ai package root.',
)
check(
  existsSync(resolve(root, 'GETTING_STARTED.md')),
  'GETTING_STARTED.md must exist at the acgi-ai package root.',
)
check(
  existsSync(resolve(root, 'scripts/hello.mjs')),
  'scripts/hello.mjs must exist for a fast onboarding smoke.',
)
check(
  existsSync(resolve(root, 'scripts/hello-world.sh')),
  'scripts/hello-world.sh must exist for the TTHW foundation smoke.',
)

for (const [label, source] of [
  ['ARCHITECTURE.md', architecture],
  ['INTEGRATING.md', integrating],
  ['GETTING_STARTED.md', gettingStarted],
]) {
  check(
    !/production[- ]validated|production[- ]ready|SOC 2 certified|WCAG 2\.2 AA conformant/i.test(
      source,
    ),
    `${label} must not overclaim production/compliance status.`,
  )
  check(
    !/TODO|TBD|coming soon|placeholder/i.test(source),
    `${label} must not contain TODO/TBD/placeholder language.`,
  )
}

mustContain(architecture, '@surface/App', 'ARCHITECTURE.md')
mustContain(architecture, 'src/surfaces/marketing/App.tsx', 'ARCHITECTURE.md')
mustContain(architecture, 'src/surfaces/console/App.tsx', 'ARCHITECTURE.md')
mustContain(architecture, 'TanStack Router route trees', 'ARCHITECTURE.md')
mustContain(architecture, 'BUS_UPSTREAM', 'ARCHITECTURE.md')
mustContain(architecture, 'OIDC or server-cookie auth remains a production gate', 'ARCHITECTURE.md')
mustContain(architecture, 'claim-matrix.json', 'ARCHITECTURE.md')
mustContain(
  architecture,
  'Trust/security pages are engineering-draft publication scaffolding',
  'ARCHITECTURE.md',
)

const endpointNeedles = [
  '/api/v1/console-summary',
  '/api/v1/agents',
  '/api/v1/actions/test',
  '/api/v1/compile/replay',
  '/api/v1/compile/promote',
  '/api/bus/traces',
  '/api/bus/traces/{correlation_id}',
]
for (const endpoint of endpointNeedles) mustContain(integrating, endpoint, 'INTEGRATING.md')
mustContain(integrating, 'X-ACGS-Schema-Version', 'INTEGRATING.md')
mustContain(integrating, 'ApiError', 'INTEGRATING.md')
mustContain(integrating, 'credentials: same-origin', 'INTEGRATING.md')
mustContain(integrating, 'VITE_USE_MOCKS=true', 'INTEGRATING.md')
mustContain(integrating, 'Known unstable fields', 'INTEGRATING.md')
mustContain(integrating, 'BUS_UPSTREAM', 'INTEGRATING.md')

mustContain(gettingStarted, 'Node >=24 <25', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'pnpm 9.15.4', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'pnpm -F acgi-ai run hello', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'pnpm -F acgi-ai run test:tthw', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'pnpm -F acgi-ai run hello:world:local', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'pnpm -F acgi-ai run test:all', 'GETTING_STARTED.md')
mustContain(gettingStarted, 'make verify', 'GETTING_STARTED.md')
mustContain(
  gettingStarted,
  'local verification does not equal production deployment',
  'GETTING_STARTED.md',
)

mustContain(hello, 'ACGI DX hello', 'scripts/hello.mjs')
mustContain(hello, 'ARCHITECTURE.md', 'scripts/hello.mjs')
mustContain(hello, 'INTEGRATING.md', 'scripts/hello.mjs')
mustContain(hello, 'GETTING_STARTED.md', 'scripts/hello.mjs')
mustContain(helloWorld, 'ACGI_TTHW_BUDGET_SECONDS', 'scripts/hello-world.sh')
mustContain(helloWorld, 'pnpm run dev:mock', 'scripts/hello-world.sh')
mustContain(helloWorld, 'CHOKIDAR_USEPOLLING', 'scripts/hello-world.sh')
mustContain(helloWorld, 'headless browser proof remains external', 'scripts/hello-world.sh')

check(packageJson.scripts?.hello === 'node scripts/hello.mjs', 'package.json must expose hello.')
check(
  packageJson.scripts?.['hello:world'] === 'bash scripts/hello-world.sh',
  'package.json must expose hello:world.',
)
check(
  packageJson.scripts?.['hello:world:local'] ===
    'bash scripts/hello-world.sh --skip-install --allow-node-drift --http-only',
  'package.json must expose hello:world:local.',
)
check(
  packageJson.scripts?.['dev:mock'] === 'VITE_USE_MOCKS=true vite',
  'package.json must expose dev:mock.',
)
check(
  packageJson.scripts?.['dev:live'] === 'VITE_USE_MOCKS=false vite',
  'package.json must expose dev:live.',
)
check(
  packageJson.scripts?.test === 'pnpm run test:all',
  'package.json must expose test as the full local gate.',
)
check(
  packageJson.scripts?.['test:contract'] ===
    'pnpm run test:bus-schema && pnpm run test:bus-proxy && pnpm run test:cloudrun-templates && pnpm run test:cloudrun-renderer && pnpm run test:production-deploy-contract && pnpm run test:auth-boundary',
  'package.json must expose test:contract for integration/deploy and production deploy fail-closed contracts.',
)
check(
  packageJson.scripts?.['audit:eval'] ===
    'pnpm run test:claim-matrix && pnpm run test:trust-surface && pnpm run test:platform-blueprint',
  'package.json must expose audit:eval for public claim/trust evidence checks.',
)
check(
  packageJson.scripts?.['test:docs-scaffold'] === 'node scripts/check-dx-scaffold.mjs',
  'package.json must expose test:docs-scaffold.',
)
check(
  packageJson.scripts?.['test:tthw'] === 'node scripts/check-tthw-foundation.mjs',
  'package.json must expose test:tthw.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:docs-scaffold') &&
    packageJson.scripts['test:all'].includes('pnpm run test:tthw'),
  'package.json test:all must include test:docs-scaffold and test:tthw.',
)

mustContain(claude, 'ARCHITECTURE.md', 'CLAUDE.md')
mustContain(claude, 'INTEGRATING.md', 'CLAUDE.md')
mustContain(claude, 'pnpm hello', 'CLAUDE.md')
check(
  !/as a single bundle/i.test(claude),
  'CLAUDE.md must not describe the app as a single bundle after the surface split.',
)
check(!/There is no API client/i.test(claude), 'CLAUDE.md must not claim there is no API client.')

mustContain(agents, 'ARCHITECTURE.md', 'AGENTS.md')
mustContain(agents, 'INTEGRATING.md', 'AGENTS.md')
mustContain(agents, 'test:docs-scaffold', 'AGENTS.md')

mustContain(securityCheck, 'check-dx-scaffold.mjs', 'security invariant check')
mustContain(securityCheck, 'test:docs-scaffold', 'security invariant check')
mustContain(securityCheck, 'check-tthw-foundation.mjs', 'security invariant check')
mustContain(securityCheck, 'test:tthw', 'security invariant check')
mustContain(securityCheck, 'hello-world.sh', 'security invariant check')
mustContain(readiness, 'DX scaffolding docs', 'integration readiness map')
mustContain(readiness, 'TTHW foundation', 'integration readiness map')
mustContain(readiness, 'pnpm -F acgi-ai run test:docs-scaffold', 'integration readiness map')
mustContain(readiness, 'pnpm -F acgi-ai run test:tthw', 'integration readiness map')

if (failures.length) {
  console.error('DX scaffold check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('DX scaffold check passed.')
