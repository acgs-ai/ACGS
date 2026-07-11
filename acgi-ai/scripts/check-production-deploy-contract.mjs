import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const failures = []

const NODE_VERSION = '24.18.0'
const PACKAGE_MANAGER =
  'pnpm@9.15.4+sha512.b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0'
const ACTIONS = Object.freeze({
  checkout: 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5',
  node: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
  upload: 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  download: 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093',
  pagesUpload: 'actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa',
  pagesDeploy: 'actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e',
  gcpAuth: 'google-github-actions/auth@c200f3691d83b41bf9bbd8638997a462592937ed',
  gcloud: 'google-github-actions/setup-gcloud@e427ad8a34f8676edf47cf7d7925499adf3eb74f',
  wrangler: 'cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd',
})

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

function assertImmutableActionPins(source, label) {
  const refs = [...source.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)\s*$/gm)].map((match) => match[1])
  check(refs.length > 0, `${label} must use at least one GitHub Action.`)
  for (const ref of refs) {
    check(/@[0-9a-f]{40}$/.test(ref), `${label} action ${ref} must use an immutable 40-hex SHA.`)
  }
}

function occurrenceCount(source, needle) {
  return source.split(needle).length - 1
}

function assertCorepackIntegritySetup(source, label, expectedActivations = 1) {
  mustContain(source, `REVIEWED_PNPM_SELECTOR: '${PACKAGE_MANAGER}'`, label)
  for (const forbidden of ['pnpm/action-setup@', 'cache: pnpm', 'cache-dependency-path']) {
    mustNotContain(source, forbidden, label)
  }
  for (const needle of [
    'name: Activate integrity-verified pnpm',
    'corepack_root="$RUNNER_TEMP/acgs-corepack"',
    'install -d -m 0700 "$corepack_root/home" "$corepack_root/bin"',
    'export COREPACK_HOME="$corepack_root/home"',
    'corepack enable --install-directory "$corepack_root/bin"',
    'test "$(corepack pnpm --version)" = \'9.15.4\'',
    'test "$(pnpm --version)" = \'9.15.4\'',
    'test "$(command -v pnpm)" = "$corepack_root/bin/pnpm"',
    'printf \'COREPACK_HOME=%s\\n\' "$COREPACK_HOME" >> "$GITHUB_ENV"',
    'printf \'%s\\n\' "$corepack_root/bin" >> "$GITHUB_PATH"',
  ]) {
    check(
      occurrenceCount(source, needle) >= expectedActivations,
      `${label} must include ${expectedActivations} isolated Corepack activation(s) with ${JSON.stringify(needle)}.`,
    )
  }
}

function assertVerificationBoundary(source, label, readinessCommand = 'pnpm test:all') {
  mustContain(source, 'pull_request:', label)
  mustContain(source, 'permissions:\n  contents: read', label)
  mustContain(source, `node-version: '${NODE_VERSION}'`, label)
  mustContain(source, ACTIONS.checkout, label)
  mustContain(source, ACTIONS.node, label)
  mustContain(source, 'pnpm install --frozen-lockfile --ignore-workspace', label)
  mustContain(source, readinessCommand, label)
  for (const forbidden of [
    '\n  push:',
    'id-token: write',
    'pages: write',
    'deployments: write',
    '${{ secrets.',
    'environment: production',
    'gcloud run services replace',
    'wrangler-action@',
    'actions/deploy-pages@',
  ]) {
    mustNotContain(source, forbidden, label)
  }
  assertImmutableActionPins(source, label)
}

function assertPushOnlyBoundary(source, label) {
  mustContain(source, '\n  push:', label)
  mustContain(source, 'permissions: {}', label)
  mustNotContain(source, 'pull_request:', label)
  assertImmutableActionPins(source, label)
}

function jobBlock(source, jobName) {
  const escaped = jobName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return source.match(new RegExp(`(?:^|\\n)  ${escaped}:\\n[\\s\\S]*?(?=\\n  [A-Za-z0-9_-]+:\\n|$)`))?.[0] ?? ''
}

function assertCommitAuthorization(source, label, variable, environment, downstreamJobs) {
  const authorization = jobBlock(source, 'authorize')
  check(authorization.length > 0, `${label} must define an authorize job.`)
  for (const needle of [
    'needs:',
    'permissions: {}',
    `environment: ${environment}`,
    `APPROVED_SHA: \${{ vars.${variable} }}`,
    'CANDIDATE_SHA: ${{ github.sha }}',
    '^[0-9a-f]{40}$',
    '"$APPROVED_SHA" == "$CANDIDATE_SHA"',
    "approved=true",
    "approved=false",
  ]) {
    mustContain(authorization, needle, `${label} authorize job`)
  }
  for (const forbidden of ['uses:', '${{ secrets.', 'id-token: write', 'pages: write', 'deployments: write']) {
    mustNotContain(authorization, forbidden, `${label} authorize job`)
  }
  for (const downstreamJob of downstreamJobs) {
    const downstream = jobBlock(source, downstreamJob)
    check(downstream.length > 0, `${label} must define ${downstreamJob}.`)
    mustContain(downstream, 'authorize', `${label} ${downstreamJob} job dependencies`)
    mustContain(
      downstream,
      "needs.authorize.outputs.approved == 'true'",
      `${label} ${downstreamJob} authorization gate`,
    )
  }
}

const packageJson = JSON.parse(read('package.json'))
const rootPackageJson = JSON.parse(readRepo('package.json'))
const paths = Object.freeze({
  marketing: '.github/workflows/marketing.yml',
  marketingDeploy: '.github/workflows/marketing-cloudflare.yml',
  console: '.github/workflows/console.yml',
  consoleDeploy: '.github/workflows/console-deploy.yml',
  storybook: '.github/workflows/storybook.yml',
  storybookDeploy: '.github/workflows/storybook-deploy.yml',
})
for (const path of Object.values(paths)) {
  check(existsSync(resolve(repoRoot, path)), `${path} must exist.`)
}

const marketing = readRepo(paths.marketing)
const marketingDeploy = readRepo(paths.marketingDeploy)
const consoleWorkflow = readRepo(paths.console)
const consoleDeploy = readRepo(paths.consoleDeploy)
const storybook = readRepo(paths.storybook)
const storybookDeploy = readRepo(paths.storybookDeploy)
const wranglerConfig = read('infra/cloudflare/workers/wrangler.toml')
const lockfile = read('pnpm-lock.yaml')
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')

check(packageJson.packageManager === PACKAGE_MANAGER, 'acgi-ai packageManager selector must remain integrity-qualified and exact.')
check(rootPackageJson.packageManager === PACKAGE_MANAGER, 'root packageManager selector must match the acgi-ai integrity-qualified selector.')
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

for (const [label, source, readinessCommand] of [
  [paths.console, consoleWorkflow, 'pnpm test:all'],
  [paths.marketing, marketing, 'pnpm test:all'],
  [paths.storybook, storybook, 'pnpm test:storybook-publication'],
]) {
  assertVerificationBoundary(source, label, readinessCommand)
}
assertCorepackIntegritySetup(consoleWorkflow, paths.console, 2)
assertCorepackIntegritySetup(marketing, paths.marketing, 1)
assertCorepackIntegritySetup(storybook, paths.storybook, 1)
for (const [label, source] of [
  [paths.consoleDeploy, consoleDeploy],
  [paths.marketingDeploy, marketingDeploy],
  [paths.storybookDeploy, storybookDeploy],
]) {
  assertPushOnlyBoundary(source, label)
  mustContain(source, `node-version: '${NODE_VERSION}'`, label)
}
assertCorepackIntegritySetup(consoleDeploy, paths.consoleDeploy, 1)
assertCorepackIntegritySetup(marketingDeploy, paths.marketingDeploy, 2)
assertCorepackIntegritySetup(storybookDeploy, paths.storybookDeploy, 1)
assertCommitAuthorization(
  consoleDeploy,
  paths.consoleDeploy,
  'CONSOLE_PRODUCTION_APPROVED_SHA',
  'production',
  ['publish', 'deploy'],
)
assertCommitAuthorization(
  marketingDeploy,
  paths.marketingDeploy,
  'MARKETING_PRODUCTION_APPROVED_SHA',
  'production',
  ['deploy'],
)
assertCommitAuthorization(
  storybookDeploy,
  paths.storybookDeploy,
  'STORYBOOK_PRODUCTION_APPROVED_SHA',
  'github-pages',
  ['deploy-pages'],
)

// PR verification must remain physically separated from every credentialed deploy.
for (const forbidden of [ACTIONS.gcpAuth, 'GCP_WORKLOAD_IDENTITY_PROVIDER', 'CONSOLE_AUTH_UPSTREAM']) {
  mustNotContain(consoleWorkflow, forbidden, paths.console)
}
for (const forbidden of ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', ACTIONS.wrangler]) {
  mustNotContain(marketing, forbidden, paths.marketing)
}
for (const forbidden of [ACTIONS.pagesUpload, ACTIONS.pagesDeploy, 'pages: write', 'id-token: write']) {
  mustNotContain(storybook, forbidden, paths.storybook)
}

// Console deploy uses short-lived WIF only in production jobs, with no static key path.
for (const needle of [
  'name: console-deploy',
  'needs: verify',
  'contents: read',
  'id-token: write',
  'environment: production',
  ACTIONS.gcpAuth,
  ACTIONS.gcloud,
  ACTIONS.upload,
  ACTIONS.download,
  'GCP_WORKLOAD_IDENTITY_PROVIDER',
  'GCP_SERVICE_ACCOUNT',
  'CONSOLE_AUTH_UPSTREAM',
  'CONSOLE_BUS_UPSTREAM',
  'node scripts/render-cloudrun-service.mjs',
  'gcloud run services replace',
  'scripts/postdeploy-verify.sh',
]) {
  mustContain(consoleDeploy, needle, paths.consoleDeploy)
}
for (const forbidden of ['GCP_SA_KEY', 'GOOGLE_APPLICATION_CREDENTIALS', 'credentials_json']) {
  mustNotContain(consoleDeploy, forbidden, paths.consoleDeploy)
}

// The live marketing origin is the reviewed Worker and four explicit routes, not shadow Pages.
for (const needle of [
  'name: marketing-cloudflare',
  'needs: verify',
  'deployments: write',
  'environment: production',
  'Require Cloudflare production credentials',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_ACCOUNT_ID',
  '::error::Cloudflare Workers deploy blocked',
  'exit 1',
  ACTIONS.wrangler,
  'pnpm install --frozen-lockfile --ignore-workspace',
  "test \"$(node -p 'process.versions.node')\" = '24.18.0'",
  'node_modules/wrangler/package.json',
  "= '4.110.0'",
  'packageManager: pnpm',
  "wranglerVersion: '4.110.0'",
  "if: steps.cf_auth.outputs.available == 'true'",
  'command: deploy --config infra/cloudflare/workers/wrangler.toml',
]) {
  mustContain(marketingDeploy, needle, paths.marketingDeploy)
}
for (const forbidden of ['::warning::', 'available=false', 'pages deploy']) {
  mustNotContain(marketingDeploy, forbidden, paths.marketingDeploy)
}
const routeLines = wranglerConfig.match(/\{ pattern = "[^"]+", zone_name = "acgs\.ai" \}/g) ?? []
check(routeLines.length === 4, 'Workers configuration must contain exactly four acgs.ai routes.')
check(
  lockfile.includes('wrangler@4.110.0:'),
  'pnpm-lock.yaml must resolve the deployment Wrangler CLI to 4.110.0.',
)
for (const route of ['acgs.ai/*', 'www.acgs.ai/*', 'console.acgs.ai/*', 'api.acgs.ai/telegram/*']) {
  mustContain(wranglerConfig, `{ pattern = "${route}", zone_name = "acgs.ai" }`, 'Workers configuration')
}

// Storybook publication remains a public, read-only gallery with no console authority or secrets.
for (const needle of [
  'name: buyer-evidence-storybook-deploy',
  'contents: read',
  'pages: write',
  'id-token: write',
  'environment:',
  'name: github-pages',
  'url: https://storybook.acgs.ai',
  ACTIONS.pagesUpload,
  ACTIONS.pagesDeploy,
]) {
  mustContain(storybookDeploy, needle, paths.storybookDeploy)
}
for (const forbidden of ['${{ secrets.', 'environment: production', 'GCP_', 'CLOUDFLARE_', 'CONSOLE_']) {
  mustNotContain(storybookDeploy, forbidden, paths.storybookDeploy)
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
