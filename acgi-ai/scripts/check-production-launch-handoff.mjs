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
const handoffPath = 'PRODUCTION-LAUNCH.md'
const deploy = read('DEPLOY.md')
const handoff = read(handoffPath)
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const productionEvidenceTemplate = read('production-evidence.example.json')
const productionEvidenceTemplateCheck = read('scripts/check-production-evidence-template.mjs')
const productionLiveVerifierCheck = read('scripts/check-production-live-verifier.mjs')
const productionBlockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const productionEvidenceValidatorCheck = read('scripts/check-production-evidence-validator.mjs')
const productionEvidenceDraftCheck = read('scripts/check-production-evidence-draft.mjs')
const consoleWorkflow = readRepo('.github/workflows/console.yml')
const marketingWorkflow = readRepo('.github/workflows/marketing.yml')

check(existsSync(resolve(root, handoffPath)), `${handoffPath} must exist.`)
check(
  packageJson.scripts?.['test:production-launch-handoff'] ===
    'node scripts/check-production-launch-handoff.mjs',
  'package.json must expose test:production-launch-handoff.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-launch-handoff'),
  'package.json test:all must include production launch handoff verification.',
)
check(
  packageJson.scripts?.['validate:production-evidence'] ===
    'node scripts/validate-production-evidence.mjs',
  'package.json must expose validate:production-evidence.',
)
check(
  packageJson.scripts?.['test:production-evidence-validator'] ===
    'node scripts/check-production-evidence-validator.mjs',
  'package.json must expose test:production-evidence-validator.',
)
check(
  packageJson.scripts?.['build:production-cutover-plan'] ===
    'node scripts/build-production-cutover-plan.mjs',
  'package.json must expose build:production-cutover-plan.',
)
check(
  packageJson.scripts?.['test:production-cutover-plan'] ===
    'node scripts/check-production-cutover-plan.mjs',
  'package.json must expose test:production-cutover-plan.',
)
check(
  packageJson.scripts?.['build:production-evidence-draft'] ===
    'node scripts/build-production-evidence-draft.mjs',
  'package.json must expose build:production-evidence-draft.',
)
check(
  packageJson.scripts?.['test:production-evidence-draft'] ===
    'node scripts/check-production-evidence-draft.mjs',
  'package.json must expose test:production-evidence-draft.',
)
check(
  packageJson.scripts?.['build:production-blocker-report'] ===
    'node scripts/build-production-blocker-report.mjs',
  'package.json must expose build:production-blocker-report.',
)
check(
  packageJson.scripts?.['test:production-blocker-report'] ===
    'node scripts/check-production-blocker-report.mjs',
  'package.json must expose test:production-blocker-report.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-blocker-report'),
  'package.json test:all must include production blocker report verification.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-validator'),
  'package.json test:all must include production evidence validator verification.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-cutover-plan'),
  'package.json test:all must include production cutover plan verification.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-draft'),
  'package.json test:all must include production evidence draft verification.',
)

for (const needle of [
  'Local readiness is not production deployment proof',
  'Do not claim production deployment until',
  'No stronger claims until live proof is attached',
  'make verify-js-node24',
  'make platform-readiness',
  'make release-evidence',
  'pnpm -F acgi-ai run test:production-deploy-contract',
  'pnpm -F acgi-ai run test:production-launch-handoff',
  'pnpm -F acgi-ai run test:production-evidence-template',
  'pnpm -F acgi-ai run test:production-live-verifier',
  'pnpm -F acgi-ai run test:production-blocker-report',
  'pnpm -F acgi-ai run test:production-evidence-validator',
  'pnpm -F acgi-ai run test:production-cutover-plan',
  'pnpm -F acgi-ai run test:production-evidence-draft',
  'pnpm -F acgi-ai run verify:production-live -- --json',
  'pnpm -F acgi-ai run build:production-blocker-report -- --live-output',
  'pnpm -F acgi-ai run build:production-cutover-plan -- --live-output',
  'pnpm -F acgi-ai run build:production-evidence-draft -- --live-output',
  'pnpm -F acgi-ai run validate:production-evidence -- --manifest',
  'production-evidence.example.json',
  'productionLiveStatus',
  'productionLiveBlockers',
  'production-blocker-report',
  'production-cutover-plan',
  'production-evidence-draft',
  'production-evidence.deployment-blocked.json',
  'copyIntoProductionEvidence',
  'productionEvidenceValidationCommand',
  'productionEvidenceValidationOutputRef',
  'validatedProductionEvidence',
  'pending-external',
  'not live production proof',
  'pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai',
  'dist-release-evidence/manifest.json',
  'dist-release-evidence/platform-readiness.json',
  'Completed production evidence manifest',
  'buyer-evidence-gallery',
  'console-dist',
  'GitHub Actions run URL',
  'Vercel deployment URL',
  'Cloud Run revision URL',
  'EXPECTED_BUILD_ID',
  '/healthz',
  'served_hash',
  'build_id',
  'scripts/postdeploy-verify.sh',
  'JSON output from `pnpm -F acgi-ai run verify:production-live -- --json`',
  'JSON output from `pnpm -F acgi-ai run build:production-blocker-report',
  'JSON output from `pnpm -F acgi-ai run build:production-cutover-plan',
  'JSON output from `pnpm -F acgi-ai run build:production-evidence-draft',
  'JSON output from `pnpm -F acgi-ai run validate:production-evidence',
]) {
  mustContain(handoff, needle, handoffPath)
}

for (const secret of [
  'VERCEL_TOKEN',
  'VERCEL_ORG_ID',
  'VERCEL_PROJECT_ID',
  'GCP_PROJECT_ID',
  'GCP_REGION',
  'GCP_WORKLOAD_IDENTITY_PROVIDER',
  'GCP_SERVICE_ACCOUNT',
  'GCP_ARTIFACT_REGISTRY',
  'CONSOLE_AUTH_UPSTREAM',
  'CONSOLE_BUS_UPSTREAM',
  'STORYBOOK_PAGES_ENABLED=true',
]) {
  mustContain(handoff, secret, handoffPath)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
]) {
  mustContain(source, 'test:production-launch-handoff', label)
  mustContain(source, 'production launch handoff', label)
  mustContain(source, 'test:production-evidence-template', label)
  mustContain(source, 'test:production-live-verifier', label)
  mustContain(source, 'test:production-blocker-report', label)
  mustContain(source, 'test:production-evidence-validator', label)
  mustContain(source, 'test:production-cutover-plan', label)
  mustContain(source, 'test:production-evidence-draft', label)
  mustContain(source, 'verify:production-live', label)
  mustContain(source, 'build:production-blocker-report', label)
  mustContain(source, 'build:production-cutover-plan', label)
  mustContain(source, 'build:production-evidence-draft', label)
  mustContain(source, 'validate:production-evidence', label)
  mustContain(source, 'production-blocker-report', label)
  mustContain(source, 'production-cutover-plan', label)
  mustContain(source, 'production-evidence-draft', label)
  mustContain(source, 'copyIntoProductionEvidence', label)
  mustContain(source, 'production-evidence.example.json', label)
}

for (const [label, source] of [
  ['production-evidence.example.json', productionEvidenceTemplate],
  ['production evidence template checker', productionEvidenceTemplateCheck],
  ['production live verifier checker', productionLiveVerifierCheck],
  ['production blocker report checker', productionBlockerReportCheck],
  ['production evidence validator checker', productionEvidenceValidatorCheck],
  ['production evidence draft checker', productionEvidenceDraftCheck],
]) {
  mustContain(source, 'not live production proof', label)
  mustContain(source, 'pending-external', label)
  mustContain(source, 'validate:production-evidence', label)
  mustContain(source, 'productionLiveBlockers', label)
  mustContain(source, 'validatedProductionEvidence', label)
}

mustContain(productionEvidenceDraftCheck, 'test:production-evidence-draft', 'production evidence draft checker')

for (const [label, workflow] of [
  ['console.yml', consoleWorkflow],
  ['marketing.yml', marketingWorkflow],
]) {
  mustContain(workflow, 'pnpm test:all', label)
  mustContain(workflow, "node-version: '24'", label)
}

if (failures.length > 0) {
  console.error('Production launch handoff check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production launch handoff check passed.')
