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

const packetPath = 'production-authority.example.json'
const checkerPath = 'scripts/check-production-authority-packet.mjs'

check(existsSync(resolve(root, packetPath)), `${packetPath} must exist.`)
check(existsSync(resolve(root, checkerPath)), `${checkerPath} must exist.`)

const packetText = read(packetPath)
const packet = JSON.parse(packetText)
const packageJson = JSON.parse(read('package.json'))
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const releaseEvidenceTests = readRepo('tests/test_release_evidence_bundle.py')
const readinessTests = readRepo('tests/test_platform_readiness_report.py')

check(packet.schemaVersion === 1, 'production authority packet schemaVersion must be 1.')
check(packet.artifactKind === 'production-authority-packet', 'artifactKind must be production-authority-packet.')
check(packet.status === 'pending-external-authority', 'status must remain pending-external-authority in the example packet.')

for (const needle of [
  'not production deployment proof',
  'not deploy approval',
  'not DNS proof',
  'not legal signoff',
  'not hosted Storybook proof',
  'pending-external',
]) {
  mustContain(packet.claimBoundary ?? '', needle, 'production authority packet claimBoundary')
  mustContain(packetText, needle, packetPath)
}

const approvalIds = new Set((packet.requiredApprovals ?? []).map((approval) => approval.id))
for (const id of [
  'deploy-owner-approval',
  'dns-owner-approval',
  'auth-owner-approval',
  'claims-owner-approval',
]) {
  check(approvalIds.has(id), `requiredApprovals must include ${id}.`)
  mustContain(packetText, `pending-external:${id}`, packetPath)
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
]) {
  check(packet.requiredGitHubSecrets?.includes(secret), `requiredGitHubSecrets must include ${secret}.`)
  mustContain(packetText, secret, packetPath)
}

const variables = packet.requiredGitHubVariables ?? []
check(
  variables.some((variable) => variable.name === 'STORYBOOK_PAGES_ENABLED' && variable.expectedValue === 'true'),
  'requiredGitHubVariables must include STORYBOOK_PAGES_ENABLED=true.',
)

const dnsHosts = new Set((packet.dnsAuthority ?? []).map((entry) => entry.host))
for (const host of ['acgs.ai', 'console.acgs.ai', 'storybook.acgs.ai']) {
  check(dnsHosts.has(host), `dnsAuthority must include ${host}.`)
}

for (const value of Object.values(packet.productionRunRefs ?? {})) {
  check(
    typeof value === 'string' && value.startsWith('pending-external:'),
    'productionRunRefs values must stay pending-external in the example packet.',
  )
}

mustContain(packet.operatorAssertion ?? '', 'Do not deploy', 'operatorAssertion')
mustContain(packet.operatorAssertion ?? '', 'production evidence manifest validates', 'operatorAssertion')

check(
  packageJson.scripts?.['test:production-authority-packet'] ===
    'node scripts/check-production-authority-packet.mjs',
  'package.json must expose test:production-authority-packet.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-authority-packet'),
  'package.json test:all must include production authority packet verification.',
)
check(
  packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-launch-handoff') <
    packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-authority-packet'),
  'test:all must check the launch handoff before the authority packet.',
)
check(
  packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-authority-packet') <
    packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-evidence-template'),
  'test:all must check the authority packet before the production evidence template.',
)

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['release evidence tests', releaseEvidenceTests],
  ['platform readiness tests', readinessTests],
]) {
  mustContain(source, 'production-authority.example.json', label)
  mustContain(source, 'test:production-authority-packet', label)
  mustContain(source, 'pending-external:deploy-owner-approval', label)
  mustContain(source, 'not production deployment proof', label)
}

if (failures.length > 0) {
  console.error('Production authority packet check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production authority packet check passed.')
