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
const marketingCfWorkflowPath = '.github/workflows/marketing-cloudflare.yml'
const consoleWorkflowPath = '.github/workflows/console.yml'
const productionDeployCheckPath = 'scripts/check-production-deploy-contract.mjs'
const marketingWorkflow = readRepo(marketingWorkflowPath)
const marketingCfWorkflow = readRepo(marketingCfWorkflowPath)
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

// Marketing PRODUCTION deploy moved from Vercel (marketing.yml) to Cloudflare Pages
// (marketing-cloudflare.yml). The fail-closed contract now lives in the Cloudflare
// workflow; marketing.yml is reduced to a PR/verify-only gate.
check(
  existsSync(resolve(repoRoot, marketingCfWorkflowPath)),
  `${marketingCfWorkflowPath} must exist.`,
)

// marketing.yml must remain a verify gate and must NOT carry a production deploy.
for (const needle of ['name: marketing', 'not production deployment proof', 'pnpm test:all']) {
  mustContain(marketingWorkflow, needle, marketingWorkflowPath)
}
for (const needle of [
  'vercel deploy --prebuilt --prod',
  'vercel build --prod',
  'Install Vercel CLI',
]) {
  mustNotContain(marketingWorkflow, needle, marketingWorkflowPath)
}

// Cloudflare Pages production deploy must fail closed when secrets are absent.
for (const needle of [
  'name: marketing-cloudflare',
  "if: github.event_name == 'push'",
  'Check Cloudflare secrets present',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_ACCOUNT_ID',
  'HAVE_TOKEN',
  'HAVE_ACCOUNT',
  'available=true',
  '::error::Cloudflare Pages deploy blocked',
  'exit 1',
  'environment: production',
  'cloudflare/wrangler-action@v3',
  'pages deploy --branch=master',
]) {
  mustContain(marketingCfWorkflow, needle, marketingCfWorkflowPath)
}

// Must fail closed (exit 1) when secrets are missing — never silently skip.
for (const needle of ['::warning::', 'available=false']) {
  mustNotContain(marketingCfWorkflow, needle, marketingCfWorkflowPath)
}

// The Cloudflare deploy step must be gated on secret availability.
const cfDeployPattern = new RegExp(
  `name:\\s+Deploy to Cloudflare Pages[\\s\\S]*if:\\s+steps\\.cf_auth\\.outputs\\.available == 'true'[\\s\\S]*pages\\s+deploy`,
)
check(
  cfDeployPattern.test(marketingCfWorkflow),
  `${marketingCfWorkflowPath} must gate the Cloudflare deploy on secret availability.`,
)

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
