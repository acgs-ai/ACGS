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

function pathFilterCount(workflow, path) {
  return (workflow.match(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? [])
    .length
}

const templatePath = 'hosted-storybook-proof.example.json'
const checkerPath = 'scripts/check-hosted-storybook-proof-template.mjs'
check(existsSync(resolve(root, templatePath)), `${templatePath} must exist.`)
check(existsSync(resolve(root, checkerPath)), `${checkerPath} must exist.`)

const templateText = read(templatePath)
const template = JSON.parse(templateText)
const checker = read(checkerPath)
const packageJson = JSON.parse(read('package.json'))
const storybookWorkflow = readRepo('.github/workflows/storybook.yml')
const consoleWorkflow = readRepo('.github/workflows/console.yml')
const deploy = read('DEPLOY.md')
const launch = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const securityCheck = read('scripts/check-security-invariants.mjs')
const hostedHandoffCheck = read('scripts/check-hosted-storybook-handoff.mjs')
const productionEvidenceTemplateCheck = read('scripts/check-production-evidence-template.mjs')
const productionLiveVerifierCheck = read('scripts/check-production-live-verifier.mjs')

check(template.schemaVersion === 1, 'hosted Storybook proof template schemaVersion must be 1.')
check(
  template.artifactKind === 'hosted-storybook-proof-template',
  'hosted Storybook proof template artifactKind must match.',
)
check(template.status === 'template-only', 'hosted Storybook proof template must stay template-only.')

for (const needle of [
  'not hosted Storybook proof',
  'not official Storybook runtime proof',
  'not production deployment proof',
  'not legal signoff',
  'not SOC2 proof',
  'not WCAG conformance proof',
  'not pentest completion',
  'pending-external',
]) {
  mustContain(template.claimBoundary ?? '', needle, `${templatePath} claimBoundary`)
  mustContain(templateText, needle, templatePath)
}

check(template.target?.url === 'https://storybook.acgs.ai', 'target.url must be storybook.acgs.ai.')
check(
  template.target?.manifestUrl === 'https://storybook.acgs.ai/manifest.json',
  'target.manifestUrl must be the hosted manifest.',
)
check(
  template.target?.expectedPublishTarget === 'https://storybook.acgs.ai',
  'target.expectedPublishTarget must match Storybook host.',
)
for (const storyId of [
  'receipt-proof-journey',
  'bus-owned-proof-source',
  'claim-safe-trust-surface',
  'deploy-readiness-boundary',
]) {
  check(
    template.target?.requiredStoryIds?.includes(storyId) &&
      template.manifestEvidence?.storyIds?.includes(storyId),
    `template must require story id ${storyId}.`,
  )
}
check(
  template.target?.manifestClaimBoundaryMustInclude === 'not production deployment proof',
  'target must require the hosted manifest claim boundary.',
)

check(template.workflow?.name === 'buyer-evidence-storybook', 'workflow.name must match.')
check(template.workflow?.file === '.github/workflows/storybook.yml', 'workflow.file must match.')
check(template.workflow?.artifactName === 'buyer-evidence-storybook', 'workflow artifact must match.')
check(
  template.workflow?.requiredRepoVariable === 'STORYBOOK_PAGES_ENABLED=true',
  'workflow must require STORYBOOK_PAGES_ENABLED=true.',
)
for (const key of ['runUrl', 'pagesDeployUrl', 'buildOutputRef']) {
  check(
    String(template.workflow?.[key] ?? '').startsWith('REPLACE_WITH_'),
    `workflow.${key} must stay an operator-supplied placeholder.`,
  )
}

check(template.dns?.host === 'storybook.acgs.ai', 'dns.host must match.')
check(template.dns?.recordType === 'CNAME', 'dns.recordType must be CNAME.')
for (const key of ['configuredBy', 'evidenceRef']) {
  check(
    String(template.dns?.[key] ?? '').startsWith('REPLACE_WITH_'),
    `dns.${key} must stay an operator-supplied placeholder.`,
  )
}

check(
  template.liveVerification?.command === 'pnpm -F acgi-ai run verify:production-live -- --json',
  'liveVerification.command must capture verify:production-live.',
)
check(
  template.liveVerification?.outputRef ===
    'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH',
  'liveVerification.outputRef must require saved verifier JSON evidence.',
)
check(
  template.liveVerification?.status === 'REPLACE_WITH_PASS_FROM_VERIFY_PRODUCTION_LIVE',
  'liveVerification.status must require pass status from verifier.',
)
for (const checkId of ['storybook-dns-live', 'storybook-https-live', 'storybook-manifest-live']) {
  check(
    template.liveVerification?.requiredPassingCheckIds?.includes(checkId),
    `liveVerification must require passing ${checkId}.`,
  )
}
for (const blockerId of [
  'live-storybook-dns',
  'live-storybook-https',
  'live-storybook-manifest',
]) {
  check(
    template.liveVerification?.requiredAbsentBlockerIds?.includes(blockerId),
    `liveVerification must require absent blocker ${blockerId}.`,
  )
}

check(
  template.manifestEvidence?.artifactKind === 'local-buyer-evidence-gallery',
  'manifestEvidence.artifactKind must match buyer evidence manifest.',
)
check(
  template.manifestEvidence?.publishTarget === 'https://storybook.acgs.ai',
  'manifestEvidence.publishTarget must match hosted target.',
)
for (const key of ['manifestJsonRef', 'claimBoundaryRef']) {
  check(
    String(template.manifestEvidence?.[key] ?? '').startsWith('REPLACE_WITH_'),
    `manifestEvidence.${key} must stay an operator-supplied placeholder.`,
  )
}

check(
  template.validation?.localTemplateCheckCommand ===
    'pnpm -F acgi-ai run test:hosted-storybook-proof-template',
  'validation.localTemplateCheckCommand must capture the local proof-template test.',
)
for (const needle of [
  'build:hosted-storybook-handoff',
  'test:hosted-storybook-handoff',
  'hosted-storybook-handoff.json',
  '--require-live-clear',
  'validate:production-evidence',
  '--require-pass',
]) {
  mustContain(JSON.stringify(template.validation ?? {}), needle, 'validation commands')
}
check(
  template.copyIntoProductionEvidence?.hostedStorybook?.status === 'verified',
  'copyIntoProductionEvidence.hostedStorybook.status must be verified for completed proof.',
)
check(
  template.copyIntoProductionEvidence?.remainingBlockerToRemove ===
    'hosted-storybook-buyer-evidence',
  'copyIntoProductionEvidence must name the blocker to remove after proof.',
)
check(
  (template.remainingExternalUntilReplaced ?? []).includes('pending-external:storybook-pages-proof'),
  'remainingExternalUntilReplaced must include Storybook Pages proof placeholder.',
)

check(
  packageJson.scripts?.['test:hosted-storybook-proof-template'] ===
    'node scripts/check-hosted-storybook-proof-template.mjs',
  'package.json must expose test:hosted-storybook-proof-template.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-proof-template'),
  'package.json test:all must include hosted Storybook proof template verification.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:hosted-storybook-handoff'),
  'package.json test:all must not run input-dependent hosted Storybook handoff builder.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run verify:production-live'),
  'package.json test:all must not run live production network checks.',
)

for (const workflow of [storybookWorkflow, consoleWorkflow]) {
  check(
    pathFilterCount(workflow, 'acgi-ai/hosted-storybook-proof.example.json') >= 2,
    'workflow path filters must include hosted-storybook-proof.example.json for pull_request and push.',
  )
}
check(
  pathFilterCount(storybookWorkflow, 'acgi-ai/scripts/check-hosted-storybook-proof-template.mjs') >=
    2,
  'storybook workflow path filters must include check-hosted-storybook-proof-template.mjs.',
)

for (const needle of [
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'hosted-storybook-proof-template',
  'storybook-manifest-live',
  'pending-external:storybook-pages-proof',
  'build:hosted-storybook-handoff',
  'verify:production-live',
  'not hosted Storybook proof',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', launch],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['security invariants checker', securityCheck],
    ['hosted Storybook handoff checker', hostedHandoffCheck],
    ['production evidence template checker', productionEvidenceTemplateCheck],
    ['production live verifier checker', productionLiveVerifierCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of [
  'Hosted Storybook proof template check',
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'REPLACE_WITH_STORYBOOK_WORKFLOW_RUN_URL',
  'requiredAbsentBlockerIds',
  'remainingBlockerToRemove',
]) {
  mustContain(checker, needle, checkerPath)
}

if (failures.length > 0) {
  console.error('Hosted Storybook proof template check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Hosted Storybook proof template check passed.')
