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

function mustNotContain(source, needle, label) {
  check(!source.includes(needle), `${label} must not include ${JSON.stringify(needle)}.`)
}

const packageJson = JSON.parse(read('package.json'))
const marketingWorkflowPath = '.github/workflows/marketing.yml'
const consoleWorkflowPath = '.github/workflows/console.yml'
const productionDeployCheckPath = 'scripts/check-production-deploy-contract.mjs'
const marketingWorkflow = readRepo(marketingWorkflowPath)
const consoleWorkflow = readRepo(consoleWorkflowPath)
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')

check(existsSync(resolve(repoRoot, marketingWorkflowPath)), `${marketingWorkflowPath} must exist.`)
check(existsSync(resolve(repoRoot, consoleWorkflowPath)), `${consoleWorkflowPath} must exist.`)
check(
  existsSync(resolve(root, productionDeployCheckPath)),
  `${productionDeployCheckPath} must exist.`,
)

check(
  packageJson.scripts?.['test:production-deploy-contract'] ===
    'node scripts/check-production-deploy-contract.mjs',
  'package.json must expose test:production-deploy-contract.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-deploy-contract'),
  'package.json test:all must include production deploy contract verification.',
)
check(
  packageJson.scripts?.['test:contract']?.includes('pnpm run test:production-deploy-contract'),
  'package.json test:contract must include production deploy contract verification.',
)

for (const needle of [
  'name: marketing',
  'if: github.event_name ==',
  'Check Vercel secrets present',
  'HAVE_TOKEN',
  'HAVE_ORG',
  'HAVE_PROJECT',
  'available=true',
  '::error::Vercel production deploy blocked',
  'not production deployment proof',
  'exit 1',
  'Install Vercel CLI',
  'vercel pull --yes',
  'vercel build --prod',
  'vercel deploy --prebuilt --prod',
]) {
  mustContain(marketingWorkflow, needle, marketingWorkflowPath)
}

for (const needle of ['::warning::Vercel deploy skipped', 'available=false']) {
  mustNotContain(marketingWorkflow, needle, marketingWorkflowPath)
}

for (const [stepName, command] of [
  ['Install Vercel CLI', 'pnpm add -g vercel@latest'],
  ['Pull Vercel environment', 'vercel pull --yes'],
  ['Build for Vercel', 'vercel build --prod'],
  ['Deploy', 'vercel deploy --prebuilt --prod'],
]) {
  const stepPattern = new RegExp(
    `name:\\s+${stepName}[\\s\\S]*if: github\\.event_name == 'push' && steps\\.vercel_auth\\.outputs\\.available == 'true'[\\s\\S]*${command.replaceAll(
      ' ',
      '\\s+',
    )}`,
  )
  check(stepPattern.test(marketingWorkflow), `${marketingWorkflowPath} must gate ${stepName}.`)
}

for (const needle of [
  'name: console',
  'google-github-actions/auth@v2',
  'GCP_WORKLOAD_IDENTITY_PROVIDER',
  'GCP_SERVICE_ACCOUNT',
  'CONSOLE_AUTH_UPSTREAM',
  'CONSOLE_BUS_UPSTREAM',
  'node scripts/render-cloudrun-service.mjs',
  'gcloud run services replace',
  'scripts/postdeploy-verify.sh',
]) {
  mustContain(consoleWorkflow, needle, consoleWorkflowPath)
}

for (const source of [deploy, readiness, platformReadiness, releaseEvidence]) {
  mustContain(source, 'test:production-deploy-contract', 'production deploy contract docs')
  mustContain(source, 'production deploy fail-closed', 'production deploy contract docs')
}

if (failures.length > 0) {
  console.error('Production deploy contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production deploy contract check passed.')
