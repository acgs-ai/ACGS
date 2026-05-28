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

const packageJson = JSON.parse(read('package.json'))
const e2ePath = 'scripts/check-e2e-smoke-foundation.mjs'
const e2eHttpPath = 'scripts/smoke-e2e-http-shells.mjs'
const visualPath = 'scripts/check-visual-baseline-foundation.mjs'
const e2e = existsSync(resolve(root, e2ePath)) ? read(e2ePath) : ''
const e2eHttp = existsSync(resolve(root, e2eHttpPath)) ? read(e2eHttpPath) : ''
const visual = existsSync(resolve(root, visualPath)) ? read(visualPath) : ''
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const plan = read('PLAN.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(
  packageJson.scripts?.['test:test-surface'] ===
    'node scripts/check-test-surface-foundation.mjs',
  'package.json must expose test:test-surface.',
)
check(
  packageJson.scripts?.['test:e2e'] === 'node scripts/check-e2e-smoke-foundation.mjs',
  'package.json must expose test:e2e as the local e2e smoke manifest gate.',
)
check(
  packageJson.scripts?.['test:e2e-http'] === 'node scripts/smoke-e2e-http-shells.mjs',
  'package.json must expose test:e2e-http as the local E2E HTTP shell smoke.',
)
check(
  packageJson.scripts?.['test:visual'] ===
    'node scripts/check-visual-baseline-foundation.mjs',
  'package.json must expose test:visual as the local visual baseline manifest gate.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:test-surface'),
  'package.json test:all must include test:test-surface.',
)

check(existsSync(resolve(root, e2ePath)), `${e2ePath} must exist.`)
check(existsSync(resolve(root, e2eHttpPath)), `${e2eHttpPath} must exist.`)
check(existsSync(resolve(root, visualPath)), `${visualPath} must exist.`)

for (const [label, source, needles] of [
  [
    e2ePath,
    e2e,
    [
      'E2E_SMOKE_ROUTES',
      'CONSOLE_SIDEBAR_ROUTES',
      'marketing landing',
      '/products/legalguard',
      '/products/governance-eval',
      'VITE_BYPASS_SESSION=true',
      'test:e2e',
      'manifest gate only',
    ],
  ],
  [
    e2eHttpPath,
    e2eHttp,
    [
      'E2E_HTTP_SHELL_ROUTES',
      'CONSOLE_SIDEBAR_ROUTES',
      '/products/legalguard',
      '/products/governance-eval',
      'VITE_BYPASS_SESSION=true',
      'VITE_USE_MOCKS=true',
      'pnpm run dev:mock',
      'test:e2e-http',
      'browser Playwright execution remains Phase 2 work',
    ],
  ],
  [
    visualPath,
    visual,
    [
      'VISUAL_VIEWPORTS',
      'VISUAL_BASELINE_TARGETS',
      'console agents permission-denied',
      'compile receipt failure',
      '0.1%',
      'test:visual',
      'manifest gate only',
    ],
  ],
]) {
  for (const needle of needles) mustContain(source, needle, label)
}

for (const needle of ['test:test-surface', 'test:e2e', 'test:e2e-http', 'test:visual']) {
  mustContain(security, needle, 'scripts/check-security-invariants.mjs')
  mustContain(ciGates, needle, 'scripts/check-ci-readiness-gates.mjs')
}
for (const needle of [
  'check-test-surface-foundation.mjs',
  'check-e2e-smoke-foundation.mjs',
  'smoke-e2e-http-shells.mjs',
  'check-visual-baseline-foundation.mjs',
]) {
  mustContain(security, needle, 'scripts/check-security-invariants.mjs')
}

check(
  /Test surface foundation/.test(architecture) &&
    /test:test-surface/.test(architecture) &&
    /test:e2e/.test(architecture) &&
    /test:e2e-http/.test(architecture) &&
    /test:visual/.test(architecture) &&
    /manifest gate/.test(architecture) &&
    /browser proof remains external/.test(architecture),
  'ARCHITECTURE.md must document the bounded Test surface foundation and external browser-proof gap.',
)
check(
  /Test surface foundation gate/.test(deploy) &&
    /test:test-surface/.test(deploy) &&
    /test:e2e/.test(deploy) &&
    /test:visual/.test(deploy) &&
    /not Playwright execution/.test(deploy),
  'DEPLOY.md must document the Test surface foundation gate without claiming Playwright execution.',
)
check(
  /Test surface script foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:test-surface/.test(readiness) &&
    /pnpm -F acgi-ai run test:e2e/.test(readiness) &&
    /pnpm -F acgi-ai run test:e2e-http/.test(readiness) &&
    /pnpm -F acgi-ai run test:visual/.test(readiness),
  'integration readiness map must record the Test surface script foundation and commands.',
)
check(
  /Local static foundation: `pnpm run test:test-surface`/.test(plan) &&
    /Local HTTP shell smoke: `pnpm run test:e2e-http`/.test(plan) &&
    /browser Playwright and visual-diff execution remains Phase 2 work/.test(plan),
  'PLAN.md must bound A15/Phase 2 test script foundation without closing browser execution work.',
)

if (failures.length > 0) {
  console.error('Test surface foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Test surface foundation check passed.')
console.log('- scripts: test:test-surface, test:e2e, test:e2e-http, test:visual')
console.log('- scope: static manifest gates only; browser Playwright/visual proof remains external')
