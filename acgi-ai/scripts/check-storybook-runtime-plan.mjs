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

const planPath = 'storybook-runtime.plan.json'
const checkerPath = 'scripts/check-storybook-runtime-plan.mjs'

check(existsSync(resolve(root, planPath)), `${planPath} must exist.`)
check(existsSync(resolve(root, checkerPath)), `${checkerPath} must exist.`)

const planText = read(planPath)
const plan = JSON.parse(planText)
const packageJson = JSON.parse(read('package.json'))
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const releaseEvidenceTests = readRepo('tests/test_release_evidence_bundle.py')
const readinessTests = readRepo('tests/test_platform_readiness_report.py')
const ciGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const securityCheck = read('scripts/check-security-invariants.mjs')

check(plan.schemaVersion === 1, 'storybook runtime plan schemaVersion must be 1.')
check(plan.artifactKind === 'storybook-runtime-plan', 'artifactKind must be storybook-runtime-plan.')
check(
  plan.status === 'pending-dependency-authority',
  'storybook runtime plan must stay pending-dependency-authority until dependencies are approved.',
)

for (const needle of [
  'not official Storybook runtime proof',
  'not hosted Storybook proof',
  'not production deployment proof',
  'no dependencies are installed by this plan',
  'pending-external',
]) {
  mustContain(plan.claimBoundary ?? '', needle, 'storybook runtime plan claimBoundary')
  mustContain(planText, needle, planPath)
}

const approvalIds = new Set((plan.requiredApprovals ?? []).map((approval) => approval.id))
for (const id of ['dependency-owner-approval', 'release-owner-approval']) {
  check(approvalIds.has(id), `requiredApprovals must include ${id}.`)
}

for (const needle of [
  'pending-external:dependency-owner-approval',
  'pending-external:storybook-version-pins',
  'pending-external:official-storybook-build-output',
  'pending-external:storybook-pages-proof',
  'npm create storybook@latest',
  'npx storybook@latest init',
  '@storybook/react-vite',
  'storybook build --output-dir storybook-static',
  'storybook',
  '.storybook/main.ts',
  '.storybook/preview.ts',
  'receipt-proof-journey',
  'bus-owned-proof-source',
  'claim-safe-trust-surface',
  'visual-governance-workbench',
  'operator-decision-rail',
  'guided-review-path',
  'launch-proof-ladder',
  'deploy-readiness-boundary',
  'storybook:build',
  'pnpm run evidence:build',
]) {
  mustContain(planText, needle, planPath)
}

check(
  packageJson.scripts?.['test:storybook-runtime-plan'] ===
    'node scripts/check-storybook-runtime-plan.mjs',
  'package.json must expose test:storybook-runtime-plan.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:storybook-runtime-plan'),
  'package.json test:all must include storybook runtime plan verification.',
)
const testAll = packageJson.scripts?.['test:all'] ?? ''
const idxBuyerEvidence = testAll.indexOf('pnpm run test:buyer-evidence')
const idxRuntimePlan = testAll.indexOf('pnpm run test:storybook-runtime-plan')
const idxPublication = testAll.indexOf('pnpm run test:storybook-publication')

check(
  idxBuyerEvidence !== -1 && idxRuntimePlan !== -1 && idxBuyerEvidence < idxRuntimePlan,
  'test:all must check buyer evidence before the Storybook runtime plan.',
)
check(
  idxRuntimePlan !== -1 && idxPublication !== -1 && idxRuntimePlan < idxPublication,
  'test:all must check the Storybook runtime plan before publication wiring.',
)
check(
  packageJson.scripts?.['storybook:build'] === 'pnpm run evidence:build',
  'storybook:build must remain the dependency-free buyer-evidence shim until approval.',
)

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['release evidence tests', releaseEvidenceTests],
  ['platform readiness tests', readinessTests],
  ['CI readiness gate', ciGateCheck],
  ['security invariants', securityCheck],
]) {
  mustContain(source, 'storybook-runtime.plan.json', label)
  mustContain(source, 'test:storybook-runtime-plan', label)
  mustContain(source, 'pending-external:dependency-owner-approval', label)
  mustContain(source, 'not official Storybook runtime proof', label)
}

if (failures.length > 0) {
  console.error('Storybook runtime plan check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Storybook runtime plan check passed.')
