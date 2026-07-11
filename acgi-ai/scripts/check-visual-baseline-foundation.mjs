import { readFileSync } from 'node:fs'
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

export const VISUAL_VIEWPORTS = [360, 768, 834, 1024, 1440]

export const VISUAL_BASELINE_TARGETS = [
  'marketing hero',
  'marketing legalguard hero slug',
  'marketing governance-eval hero slug',
  'login',
  'login interstitial',
  'console overview',
  'console agents filled',
  'console agents empty',
  'console agents error',
  'console agents stale',
  'console agents permission-denied',
  'console agents long-content',
  'compile receipt success',
  'compile receipt failure',
]

export const VISUAL_BASELINE_CONTRACT = {
  threshold: '0.1%',
  scope: 'manifest gate only',
  // One console-overview 1440 baseline now executes in the browser-checks CI job
  // (tests/e2e/visual-overview.spec.ts, non-blocking). The full five-viewport
  // matrix and the remaining VISUAL_BASELINE_TARGETS stay Phase 3 browser work.
  externalProof:
    'Full-matrix Playwright screenshot capture and the remaining pixel-diff targets remain Phase 3 browser work.',
}

const packageJson = JSON.parse(read('package.json'))
const plan = read('PLAN.md')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(
  packageJson.scripts?.['test:visual'] ===
    'node scripts/check-visual-baseline-foundation.mjs',
  'package.json must expose test:visual for this manifest gate only.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:test-surface'),
  'package.json test:all must run the test surface manifest gate.',
)
check(
  VISUAL_VIEWPORTS.join(',') === '360,768,834,1024,1440',
  'VISUAL_VIEWPORTS must match the PLAN.md visual baseline viewport set.',
)
for (const target of [
  'marketing hero',
  'login interstitial',
  'console agents permission-denied',
  'compile receipt failure',
]) {
  check(VISUAL_BASELINE_TARGETS.includes(target), `visual manifest must include ${target}.`)
}

for (const needle of [
  'Add a **visual-diff** baseline pass',
  '360, 768, 834, 1024, 1440',
  'console agents (filled + empty + error + stale + permission-denied + long-content)',
  'Diff threshold 0.1%',
  'test:visual',
  'The full viewport matrix and remaining visual targets remain Phase 3 work',
]) {
  mustContain(plan, needle, 'PLAN.md')
}
for (const needle of ['Test surface foundation', 'test:visual', 'manifest gate', 'browser proof remains external']) {
  mustContain(architecture, needle, 'ARCHITECTURE.md')
}
for (const needle of ['Test surface foundation gate', 'test:visual', 'not Playwright execution']) {
  mustContain(deploy, needle, 'DEPLOY.md')
}
for (const needle of ['Test surface script foundation', 'pnpm -F acgi-ai run test:visual']) {
  mustContain(readiness, needle, 'docs/integration-readiness-task-map.md')
}

if (failures.length > 0) {
  console.error('Visual baseline foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Visual baseline foundation check passed.')
console.log(`- manifest gate only: ${VISUAL_BASELINE_TARGETS.length} visual targets`)
console.log(`- viewports: ${VISUAL_VIEWPORTS.join(', ')}`)
console.log('- one console-overview 1440 baseline executes in browser-checks CI (non-blocking)')
console.log('- the full matrix + remaining targets remain Phase 3 browser work')
