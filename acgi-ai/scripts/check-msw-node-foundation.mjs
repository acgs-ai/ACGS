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
const nodeServerPath = 'src/mocks/server.ts'
const policyPath = 'src/mocks/policy.ts'
const nodeServer = maybeRead(nodeServerPath)
const policy = maybeRead(policyPath)
const browser = read('src/mocks/browser.ts')
const handlers = read('src/mocks/handlers.ts')
const main = read('src/main.tsx')
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const plan = read('PLAN.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(existsSync(resolve(root, nodeServerPath)), `${nodeServerPath} must exist.`)
check(existsSync(resolve(root, policyPath)), `${policyPath} must exist.`)

for (const needle of [
  "from 'msw/node'",
  'setupServer(...handlers)',
  "onUnhandledRequest: 'error'",
  'server.resetHandlers()',
  'server.close()',
]) {
  mustContain(nodeServer, needle, nodeServerPath)
}

for (const needle of [
  'MswUnhandledRequestPolicy',
  "return 'error'",
  "return 'bypass'",
  'isEvalMode',
]) {
  mustContain(policy, needle, policyPath)
}

mustContain(browser, 'setupWorker(...handlers)', 'src/mocks/browser.ts')
mustContain(handlers, 'export const handlers', 'src/mocks/handlers.ts')
mustContain(main, 'getMswUnhandledRequestPolicy', 'src/main.tsx')
mustContain(main, 'onUnhandledRequest: getMswUnhandledRequestPolicy()', 'src/main.tsx')

check(
  packageJson.scripts?.['test:msw-node'] === 'node scripts/check-msw-node-foundation.mjs',
  'package.json must expose test:msw-node.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:msw-node'),
  'package.json test:all must include test:msw-node.',
)

for (const needle of ['test:msw-node', 'check-msw-node-foundation.mjs', 'src/mocks/server.ts']) {
  mustContain(security, needle, 'scripts/check-security-invariants.mjs')
  mustContain(ciGates, needle, 'scripts/check-ci-readiness-gates.mjs')
}

check(
  /MSW node-mode foundation/.test(architecture) &&
    /test:msw-node/.test(architecture) &&
    /onUnhandledRequest: 'error'/.test(architecture) &&
    /hook tests remain Phase 2 work/.test(architecture),
  'ARCHITECTURE.md must document the bounded MSW node-mode foundation.',
)
check(
  /Add \*\*MSW node-mode\*\* test setup/.test(plan) &&
    /Local static foundation: `pnpm run test:msw-node`/.test(plan),
  'PLAN.md must record the local MSW node-mode foundation without closing hook-test work.',
)
check(
  /MSW node-mode foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:msw-node/.test(readiness),
  'integration readiness map must record the MSW node-mode foundation and command.',
)

if (failures.length > 0) {
  console.error('MSW node-mode foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('MSW node-mode foundation check passed.')
console.log('- server: src/mocks/server.ts')
console.log("- strict unhandled policy: onUnhandledRequest: 'error'")
console.log('- scope: node-mode setup foundation; hook tests remain Phase 2 work')
