import { existsSync, readFileSync, statSync } from 'node:fs'
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

const packageJson = JSON.parse(read('package.json'))
const helloWorldPath = resolve(root, 'scripts/hello-world.sh')
const helloWorld = existsSync(helloWorldPath) ? readFileSync(helloWorldPath, 'utf8') : ''
const workflowPath = resolve(repoRoot, '.github/workflows/tthw.yml')
const workflow = existsSync(workflowPath) ? readFileSync(workflowPath, 'utf8') : ''
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const dxScaffold = read('scripts/check-dx-scaffold.mjs')
const gettingStarted = read('GETTING_STARTED.md')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const plan = read('PLAN.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(existsSync(helloWorldPath), 'scripts/hello-world.sh must exist.')
if (existsSync(helloWorldPath)) {
  check((statSync(helloWorldPath).mode & 0o111) !== 0, 'scripts/hello-world.sh must be executable.')
}
check(existsSync(workflowPath), '.github/workflows/tthw.yml must exist for scheduled clean-runner TTHW measurement.')

check(
  packageJson.scripts?.['hello:world'] === 'bash scripts/hello-world.sh',
  'package.json must expose hello:world as the full TTHW runner.',
)
check(
  packageJson.scripts?.['hello:world:local'] ===
    'bash scripts/hello-world.sh --skip-install --allow-node-drift --http-only',
  'package.json must expose hello:world:local as the bounded local HTTP-shell smoke.',
)
check(
  packageJson.scripts?.['test:tthw'] === 'node scripts/check-tthw-foundation.mjs',
  'package.json must expose test:tthw for the static TTHW foundation gate.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:tthw'),
  'package.json test:all must include test:tthw.',
)

for (const needle of [
  'ACGI_TTHW_BUDGET_SECONDS',
  'pnpm install --frozen-lockfile --ignore-workspace',
  'pnpm run dev:mock',
  'CHOKIDAR_USEPOLLING',
  'VITE_BYPASS_SESSION=true',
  'http://127.0.0.1',
  '/console',
  'HTTP shell foundation',
  'headless browser proof remains external',
]) {
  mustContain(helloWorld, needle, 'scripts/hello-world.sh')
}

for (const needle of [
  'schedule:',
  'workflow_dispatch:',
  "node-version: '24'",
  'bash acgi-ai/scripts/hello-world.sh',
  'ACGI_TTHW_BUDGET_SECONDS: 300',
]) {
  mustContain(workflow, needle, '.github/workflows/tthw.yml')
}

for (const needle of ['test:tthw', 'hello-world.sh', 'tthw.yml']) {
  mustContain(security, needle, 'scripts/check-security-invariants.mjs')
  mustContain(ciGates, needle, 'scripts/check-ci-readiness-gates.mjs')
}
mustContain(dxScaffold, 'hello-world.sh', 'scripts/check-dx-scaffold.mjs')

check(
  /TTHW foundation/.test(architecture) &&
    /hello:world/.test(architecture) &&
    /test:tthw/.test(architecture) &&
    /headless browser proof remains external/.test(architecture),
  'ARCHITECTURE.md must document the bounded TTHW foundation and external browser-proof gap.',
)
check(
  /TTHW foundation gate/.test(deploy) &&
    /hello-world\.sh/.test(deploy) &&
    /tthw\.yml/.test(deploy) &&
    /not a production deployment proof/.test(deploy),
  'DEPLOY.md must document the TTHW foundation gate without claiming production deployment proof.',
)
check(
  /TTHW foundation/.test(gettingStarted) &&
    /pnpm -F acgi-ai run hello:world:local/.test(gettingStarted) &&
    /pnpm -F acgi-ai run test:tthw/.test(gettingStarted),
  'GETTING_STARTED.md must document local TTHW foundation commands.',
)
check(
  /Local static foundation: `pnpm run test:tthw`/.test(plan) &&
    /clean-runner scheduled TTHW/.test(plan),
  'PLAN.md must bound the A4/TTHW local foundation and scheduled clean-runner proof.',
)
check(
  /TTHW foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:tthw/.test(readiness) &&
    /pnpm -F acgi-ai run hello:world:local/.test(readiness),
  'integration readiness map must record the TTHW foundation and commands.',
)

if (failures.length > 0) {
  console.error('TTHW foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('TTHW foundation check passed.')
console.log('- script: scripts/hello-world.sh')
console.log('- workflow: .github/workflows/tthw.yml')
console.log('- scope: HTTP shell foundation; headless browser proof remains external')
