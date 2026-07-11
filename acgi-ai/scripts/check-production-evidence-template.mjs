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
  return (workflow.match(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? []).length
}

const packageJson = JSON.parse(read('package.json'))
const templatePath = 'production-evidence.example.json'
const templateText = read(templatePath)
const template = JSON.parse(templateText)
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const securityCheck = read('scripts/check-security-invariants.mjs')
const productionLiveVerifierCheck = read('scripts/check-production-live-verifier.mjs')
const productionBlockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const productionEvidenceValidatorCheck = read('scripts/check-production-evidence-validator.mjs')
const hostedStorybookProofTemplate = read('hosted-storybook-proof.example.json')
const hostedStorybookProofTemplateCheck = read('scripts/check-hosted-storybook-proof-template.mjs')
const consoleWorkflow = readRepo('.github/workflows/console.yml')
const consoleDeployWorkflow = readRepo('.github/workflows/console-deploy.yml')

check(existsSync(resolve(root, templatePath)), `${templatePath} must exist.`)
check(template.schemaVersion === 1, `${templatePath} schemaVersion must be 1.`)
check(
  template.artifactKind === 'production-evidence-template',
  `${templatePath} artifactKind must identify the template.`,
)
check(template.status === 'template-only', `${templatePath} must remain explicitly template-only.`)

for (const needle of [
  'not live production proof',
  'do not claim legal',
  'SOC2',
  'WCAG conformance',
  'pentest completion',
  'regulatory compliance',
  'hosted Storybook proof',
]) {
  mustContain(template.claimBoundary, needle, `${templatePath} claimBoundary`)
}

check(
  template.deploy?.marketingUrl === 'https://acgs.ai',
  `${templatePath} must name the marketing origin.`,
)
check(
  template.deploy?.consoleUrl === 'https://console.acgs.ai',
  `${templatePath} must name the console origin.`,
)
check(
  template.deploy?.cloudRunRevisionUrl === 'REPLACE_WITH_CLOUD_RUN_REVISION_URL',
  `${templatePath} must keep Cloud Run revision URL as an operator-supplied placeholder.`,
)
check(
  template.deploy?.cloudflareUrl === 'REPLACE_WITH_CLOUDFLARE_DEPLOYMENT_URL',
  `${templatePath} must keep Cloudflare URL as an operator-supplied placeholder.`,
)
for (const key of ['marketing', 'console', 'storybook']) {
  check(
    template.deploy?.githubActionsRunUrls?.[key]?.startsWith('REPLACE_WITH_'),
    `${templatePath} must keep ${key} GitHub Actions run URL as a placeholder.`,
  )
}

check(
  template.verification?.expectedBuildId === 'REPLACE_WITH_EXPECTED_BUILD_ID_OR_COMMIT_SHA',
  `${templatePath} must require the deployed build id or commit SHA.`,
)
check(
  template.verification?.healthz?.url === 'https://console.acgs.ai/healthz' &&
    template.verification.healthz.served_hash === 'REPLACE_WITH_HEALTHZ_SERVED_HASH' &&
    template.verification.healthz.build_id === 'REPLACE_WITH_HEALTHZ_BUILD_ID',
  `${templatePath} must capture live /healthz served_hash and build_id placeholders.`,
)
check(
  template.verification?.postdeployCommand ===
    'pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai',
  `${templatePath} must capture the live postdeploy verification command.`,
)
check(
  template.verification?.postdeployOutputRef === 'REPLACE_WITH_POSTDEPLOY_OUTPUT_ARTIFACT_OR_HASH',
  `${templatePath} must require a postdeploy output artifact or hash.`,
)
check(
  template.verification?.productionLiveCommand ===
    'pnpm -F acgi-ai run verify:production-live -- --json',
  `${templatePath} must capture the live production verifier command.`,
)
check(
  template.verification?.productionLiveOutputRef ===
    'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH',
  `${templatePath} must require a live production verifier JSON artifact or hash.`,
)
check(
  template.verification?.productionLiveStatus ===
    'REPLACE_WITH_PASS_OR_FAIL_FROM_VERIFY_PRODUCTION_LIVE',
  `${templatePath} must require the pass/fail status from verify:production-live.`,
)
check(
  Array.isArray(template.verification?.productionLiveBlockers) &&
    template.verification.productionLiveBlockers.includes(
      'REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY',
    ),
  `${templatePath} must capture blocker ids from verify:production-live.`,
)
check(
  template.verification?.productionEvidenceValidationCommand ===
    'pnpm -F acgi-ai run validate:production-evidence -- --manifest REPLACE_WITH_COMPLETED_PRODUCTION_EVIDENCE_JSON --live-output REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON',
  `${templatePath} must capture the production evidence validator command.`,
)
check(
  template.verification?.productionEvidenceValidationOutputRef ===
    'REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH',
  `${templatePath} must require a production evidence validator output artifact or hash.`,
)

check(
  template.hostedStorybook?.url === 'https://storybook.acgs.ai',
  `${templatePath} must name the Storybook target.`,
)
check(
  template.hostedStorybook?.manifestUrl === 'https://storybook.acgs.ai/manifest.json',
  `${templatePath} must name the hosted Storybook manifest target.`,
)
check(
  template.hostedStorybook?.status === 'pending',
  `${templatePath} must keep hosted Storybook pending.`,
)
check(
  template.hostedStorybook?.claimBoundary?.includes('does not prove hosted Storybook'),
  `${templatePath} must preserve the hosted Storybook claim boundary.`,
)

for (const key of ['legalClaimMatrix', 'pentest', 'wcagManual', 'browserScreenshots']) {
  check(
    template.assurance?.[key]?.status === 'pending-external' &&
      template.assurance[key].proofRef?.startsWith('REPLACE_WITH_'),
    `${templatePath} assurance.${key} must remain pending-external with an operator proof placeholder.`,
  )
}
check(
  template.assurance?.legalClaimMatrix?.reviewer === 'REPLACE_WITH_LEGAL_OR_CLAIM_REVIEWER' &&
    template.assurance.legalClaimMatrix.reviewedAt ===
      'REPLACE_WITH_LEGAL_REVIEW_ISO8601_TIMESTAMP' &&
    template.assurance.legalClaimMatrix.claimMatrixRef ===
      'REPLACE_WITH_LEGAL_REVIEWED_CLAIM_MATRIX_ARTIFACT_OR_HASH',
  `${templatePath} assurance.legalClaimMatrix must require reviewer, reviewedAt, and claimMatrixRef placeholders.`,
)
check(
  template.assurance?.pentest?.vendor === 'REPLACE_WITH_THIRD_PARTY_PENTEST_VENDOR' &&
    template.assurance.pentest.completedAt ===
      'REPLACE_WITH_PENTEST_COMPLETION_ISO8601_TIMESTAMP' &&
    template.assurance.pentest.reportRef ===
      'REPLACE_WITH_THIRD_PARTY_PENTEST_REPORT_ARTIFACT_OR_HASH' &&
    template.assurance.pentest.criticalFindingsOpen ===
      'REPLACE_WITH_ZERO_OPEN_CRITICAL_FINDINGS_COUNT',
  `${templatePath} assurance.pentest must require vendor, completedAt, reportRef, and zero-open-critical placeholders.`,
)
check(
  template.assurance?.wcagManual?.reviewer === 'REPLACE_WITH_ACCESSIBILITY_REVIEWER' &&
    template.assurance.wcagManual.reviewedAt ===
      'REPLACE_WITH_MANUAL_WCAG_REVIEW_ISO8601_TIMESTAMP' &&
    template.assurance.wcagManual.reportRef ===
      'REPLACE_WITH_MANUAL_SCREEN_READER_AND_WCAG_REPORT_ARTIFACT_OR_HASH' &&
    template.assurance.wcagManual.assistiveTech?.includes('REPLACE_WITH_NVDA_EVIDENCE') &&
    template.assurance.wcagManual.assistiveTech?.includes('REPLACE_WITH_VOICEOVER_EVIDENCE'),
  `${templatePath} assurance.wcagManual must require reviewer, reviewedAt, reportRef, NVDA, and VoiceOver placeholders.`,
)
check(
  template.assurance?.browserScreenshots?.capturedAt ===
    'REPLACE_WITH_BROWSER_SCREENSHOT_CAPTURE_ISO8601_TIMESTAMP' &&
    template.assurance.browserScreenshots.bundleRef ===
      'REPLACE_WITH_BROWSER_SCREENSHOT_OR_VISUAL_DIFF_BUNDLE_ARTIFACT_OR_HASH',
  `${templatePath} assurance.browserScreenshots must require capturedAt and bundleRef placeholders.`,
)

for (const [key, expected] of [
  ['releaseEvidenceManifest', 'dist-release-evidence/manifest.json'],
  ['platformReadinessJson', 'dist-release-evidence/platform-readiness.json'],
  ['buyerEvidenceGallery', 'buyer-evidence-gallery'],
  ['consoleDist', 'console-dist'],
  ['postdeployOutput', 'REPLACE_WITH_POSTDEPLOY_OUTPUT_ARTIFACT_OR_HASH'],
  ['verifyProductionLiveOutput', 'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH'],
  [
    'validatedProductionEvidence',
    'REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH',
  ],
]) {
  check(
    template.artifacts?.[key] === expected,
    `${templatePath} artifacts.${key} must equal ${expected}.`,
  )
}

for (const blocker of [
  'production-deployment',
  'frontend-production-auth',
  'legal-review-of-claim-matrix',
  'third-party-penetration-test',
  'full-wcag-manual-screen-reader-evidence',
  'hosted-storybook-buyer-evidence',
]) {
  check(
    template.remainingBlockers?.includes(blocker),
    `${templatePath} must keep ${blocker} in remainingBlockers.`,
  )
}

check(
  packageJson.scripts?.['test:production-evidence-template'] ===
    'node scripts/check-production-evidence-template.mjs',
  'package.json must expose test:production-evidence-template.',
)
check(
  packageJson.scripts?.['verify:production-live'] === 'node scripts/verify-production-live.mjs',
  'package.json must expose verify:production-live.',
)
check(
  packageJson.scripts?.['test:production-live-verifier'] ===
    'node scripts/check-production-live-verifier.mjs',
  'package.json must expose test:production-live-verifier.',
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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-template'),
  'package.json test:all must include production evidence template verification.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-live-verifier'),
  'package.json test:all must include production live verifier wiring verification.',
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
  !packageJson.scripts?.['test:all']?.includes('pnpm run verify:production-live'),
  'package.json test:all must not run live production network verification.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-blocker-report'),
  'package.json test:all must not run input-dependent production blocker report building.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run validate:production-evidence'),
  'package.json test:all must not run operator-specific production evidence validation.',
)

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['security invariants checker', securityCheck],
  ['production live verifier checker', productionLiveVerifierCheck],
  ['production blocker report checker', productionBlockerReportCheck],
  ['production evidence validator checker', productionEvidenceValidatorCheck],
]) {
  mustContain(source, 'production-evidence.example.json', label)
  mustContain(source, 'test:production-evidence-template', label)
  mustContain(source, 'verify:production-live', label)
  mustContain(source, 'test:production-live-verifier', label)
  mustContain(source, 'build:production-blocker-report', label)
  mustContain(source, 'test:production-blocker-report', label)
  mustContain(source, 'production-blocker-report', label)
  mustContain(source, 'copyIntoProductionEvidence', label)
  mustContain(source, 'validate:production-evidence', label)
  mustContain(source, 'test:production-evidence-validator', label)
  mustContain(source, 'productionLiveBlockers', label)
  mustContain(source, 'productionEvidenceValidationCommand', label)
  mustContain(source, 'productionEvidenceValidationOutputRef', label)
  mustContain(source, 'validatedProductionEvidence', label)
  mustContain(source, 'not live production proof', label)
  mustContain(source, 'pending-external', label)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['production live verifier checker', productionLiveVerifierCheck],
  ['production blocker report checker', productionBlockerReportCheck],
  ['production evidence validator checker', productionEvidenceValidatorCheck],
  ['hosted Storybook proof template', hostedStorybookProofTemplate],
  ['hosted Storybook proof template checker', hostedStorybookProofTemplateCheck],
]) {
  mustContain(source, 'storybook-manifest-live', label)
}

for (const needle of [
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'build:hosted-storybook-handoff',
  'pending-external:storybook-pages-proof',
  'copyIntoProductionEvidence.hostedStorybook',
  'not hosted Storybook proof',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['hosted Storybook proof template', hostedStorybookProofTemplate],
    ['hosted Storybook proof template checker', hostedStorybookProofTemplateCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const [label, workflow] of [
  ['console.yml', consoleWorkflow],
  ['console-deploy.yml', consoleDeployWorkflow],
]) {
  check(
    pathFilterCount(workflow, 'acgi-ai/production-evidence.example.json') >= 1,
    `${label} path filters must include acgi-ai/production-evidence.example.json.`,
  )
  check(
    pathFilterCount(workflow, 'acgi-ai/hosted-storybook-proof.example.json') >= 1,
    `${label} path filters must include acgi-ai/hosted-storybook-proof.example.json.`,
  )
}

if (failures.length > 0) {
  console.error('Production evidence template check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production evidence template check passed.')
