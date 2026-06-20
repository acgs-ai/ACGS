import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
// Cross-contract anchors: test:production-blocker-report, productionEvidenceValidationOutputRef.
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

function writeJson(path, payload) {
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`)
}

function runBuilder(args) {
  return spawnSync(process.execPath, ['scripts/build-production-evidence-draft.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
}

function runValidator(args) {
  return spawnSync(process.execPath, ['scripts/validate-production-evidence.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
}

function makeLiveOutput() {
  const blockers = [
    {
      blockerId: 'live-console-dns',
      checkId: 'console-dns-live',
      status: 'fail',
      area: 'Console DNS',
      requiredAction: 'Create or repair console.acgs.ai DNS.',
      error: 'getaddrinfo ENOTFOUND console.acgs.ai',
      evidence: { hostname: 'console.acgs.ai' },
    },
    {
      blockerId: 'live-storybook-manifest',
      checkId: 'storybook-manifest-live',
      status: 'fail',
      area: 'Hosted Storybook buyer-evidence manifest',
      requiredAction: 'Publish the claim-safe buyer-evidence manifest.',
      error: 'fetch failed',
      evidence: { url: 'https://storybook.acgs.ai/manifest.json' },
    },
  ]
  return {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    generatedAt: '2026-05-25T00:00:00.000Z',
    status: 'fail',
    claimBoundary:
      'Live verifier output is production evidence only when every required live check passes; failures remain blockers and are not live production proof.',
    targets: {
      marketingUrl: 'https://acgs.ai',
      consoleUrl: 'https://console.acgs.ai',
      storybookUrl: 'https://storybook.acgs.ai',
      expectedServedHash: '608508a9bd224290',
      expectedBuildId: null,
      allowStorybookPending: false,
    },
    blockedUntil: 'Resolve every listed blocker and rerun verify:production-live.',
    blockers,
    checks: [
      { id: 'marketing-dns-live', status: 'pass', evidence: { hostname: 'acgs.ai' } },
      { id: 'console-dns-live', status: 'fail', evidence: { hostname: 'console.acgs.ai' } },
      {
        id: 'console-healthz-live',
        status: 'fail',
        error: 'fetch failed',
        evidence: { url: 'https://console.acgs.ai/healthz' },
      },
      {
        id: 'storybook-manifest-live',
        status: 'fail',
        error: 'fetch failed',
        evidence: { url: 'https://storybook.acgs.ai/manifest.json' },
      },
    ],
  }
}

function makeBlockerReport() {
  return {
    schemaVersion: 1,
    artifactKind: 'production-blocker-report',
    generatedAt: '2026-05-25T00:01:00.000Z',
    status: 'blocked',
    claimBoundary: 'Production blocker report is not live production proof.',
    command:
      'pnpm -F acgi-ai run build:production-blocker-report -- --live-output <verify-production-live.json> --out <production-blocker-report.json>',
    liveOutputPath: 'live.json',
    productionLiveStatus: 'fail',
    productionLiveBlockers: ['live-console-dns', 'live-storybook-manifest'],
    blockedUntil: 'Resolve every listed blocker and rerun verify:production-live.',
    failedCheckIds: ['console-dns-live', 'storybook-manifest-live'],
    blockers: makeLiveOutput().blockers,
    copyIntoProductionEvidence: {
      verification: {
        productionLiveStatus: 'fail',
        productionLiveBlockers: ['live-console-dns', 'live-storybook-manifest'],
        productionEvidenceValidationCommand:
          'pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>',
      },
      artifacts: {
        verifyProductionLiveOutput: '<verify-production-live.json artifact or hash>',
        validatedProductionEvidence: '<validate-production-evidence JSON artifact or hash>',
      },
    },
  }
}

function makeCutoverPlan() {
  return {
    schemaVersion: 1,
    artifactKind: 'production-cutover-plan',
    generatedAt: '2026-05-25T00:02:00.000Z',
    status: 'blocked',
    claimBoundary: 'Production cutover plan is not live production proof.',
    command:
      'pnpm -F acgi-ai run build:production-cutover-plan -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --out <production-cutover-plan.json>',
    inputs: { productionLiveStatus: 'fail', blockerReportStatus: 'blocked' },
    requiredGitHubSecrets: ['CLOUDFLARE_API_TOKEN', 'GCP_PROJECT_ID'],
    requiredGitHubVariables: ['STORYBOOK_PAGES_ENABLED=true'],
    dnsCutover: { records: [] },
    operatorSequence: [],
    productionLiveBlockers: ['live-console-dns', 'live-storybook-manifest'],
    failedCheckIds: ['console-dns-live', 'storybook-manifest-live'],
    blockers: makeLiveOutput().blockers,
    blockedUntil: 'Resolve every listed productionLiveBlocker.',
    copyIntoProductionEvidence: {
      verification: {
        productionLiveStatus: 'fail',
        productionLiveBlockers: ['live-console-dns', 'live-storybook-manifest'],
        productionEvidenceValidationCommand:
          'pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>',
      },
      artifacts: {
        verifyProductionLiveOutput: '<verify-production-live.json artifact or hash>',
        productionBlockerReport: '<production-blocker-report.json artifact or hash>',
        productionCutoverPlan: '<production-cutover-plan.json artifact or hash>',
        validatedProductionEvidence: '<validate-production-evidence JSON artifact or hash>',
      },
    },
  }
}

const builderPath = 'scripts/build-production-evidence-draft.mjs'
const checkerPath = 'scripts/check-production-evidence-draft.mjs'
const packageJson = JSON.parse(read('package.json'))
const builder = read(builderPath)
const checker = read(checkerPath)
const validator = read('scripts/validate-production-evidence.mjs')
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const evidenceValidatorCheck = read('scripts/check-production-evidence-validator.mjs')
const blockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const cutoverPlanCheck = read('scripts/check-production-cutover-plan.mjs')
const launchHandoffCheck = read('scripts/check-production-launch-handoff.mjs')

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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-draft'),
  'package.json test:all must include the local production evidence draft check.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-evidence-draft'),
  'package.json test:all must not run input-dependent production evidence draft building.',
)

for (const needle of [
  'production-evidence-draft',
  'deployment-blocked',
  'pending-external',
  'validate:production-evidence',
  'build:production-blocker-report',
  'build:production-cutover-plan',
  'productionLiveBlockers',
  'productionEvidenceValidationCommand',
  'productionBlockerReport',
  'productionCutoverPlan',
  'claimMatrixRef',
  'criticalFindingsOpen',
  'assistiveTech',
  'not live production proof',
  'does not deploy',
]) {
  mustContain(builder, needle, builderPath)
  mustContain(checker, needle, checkerPath)
}

for (const needle of [
  'build:production-evidence-draft',
  'test:production-evidence-draft',
  'production-evidence.deployment-blocked.json',
  'production-evidence-draft',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production evidence validator checker', evidenceValidatorCheck],
    ['production blocker report checker', blockerReportCheck],
    ['production cutover plan checker', cutoverPlanCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of ['isBlockedPendingExternalRef', 'deployment-blocked', 'pending-external']) {
  mustContain(validator, needle, 'validate-production-evidence.mjs')
}

const help = runBuilder(['--help'])
check(help.status === 0, 'build-production-evidence-draft --help must exit zero.')
for (const needle of ['--live-output', '--blocker-report', '--cutover-plan', '--out']) {
  mustContain(help.stdout, needle, 'build-production-evidence-draft --help')
}

const tempDir = mkdtempSync(join(tmpdir(), 'production-evidence-draft-'))
try {
  const livePath = join(tempDir, 'live.json')
  const blockerReportPath = join(tempDir, 'blocker-report.json')
  const cutoverPlanPath = join(tempDir, 'cutover-plan.json')
  const draftPath = join(tempDir, 'production-evidence.deployment-blocked.json')
  writeJson(livePath, makeLiveOutput())
  writeJson(blockerReportPath, makeBlockerReport())
  writeJson(cutoverPlanPath, makeCutoverPlan())

  const buildResult = runBuilder([
    '--live-output',
    livePath,
    '--blocker-report',
    blockerReportPath,
    '--cutover-plan',
    cutoverPlanPath,
    '--out',
    draftPath,
    '--json',
  ])
  check(
    buildResult.status === 0,
    `valid failing live artifacts must build a deployment-blocked draft: ${buildResult.stderr || buildResult.stdout}`,
  )
  const draft = JSON.parse(readFileSync(draftPath, 'utf8'))
  check(draft.artifactKind === 'production-evidence', 'draft artifactKind must be production-evidence.')
  check(draft.status === 'deployment-blocked', 'draft status must be deployment-blocked.')
  check(
    draft.deploy.cloudRunRevisionUrl === 'pending-external:cloud-run-revision-url',
    'draft must preserve missing Cloud Run revision as a pending-external ref.',
  )
  check(
    draft.verification.productionLiveStatus === 'fail' &&
      draft.verification.productionLiveBlockers.includes('live-console-dns') &&
      draft.verification.productionLiveBlockers.includes('live-storybook-manifest'),
    'draft must copy productionLiveStatus and every productionLiveBlocker.',
  )
  check(
    draft.artifacts.productionBlockerReport.endsWith('blocker-report.json') &&
      draft.artifacts.productionCutoverPlan.endsWith('cutover-plan.json'),
    'draft must reference blocker-report and cutover-plan source artifacts.',
  )
  check(
    draft.assurance.legalClaimMatrix.claimMatrixRef ===
      'pending-external:legal-reviewed-claim-matrix' &&
      draft.assurance.pentest.criticalFindingsOpen ===
        'pending-external:zero-open-critical-findings-count' &&
      draft.assurance.wcagManual.assistiveTech.includes('pending-external:nvda-evidence') &&
      draft.assurance.browserScreenshots.bundleRef ===
        'pending-external:browser-screenshot-or-visual-diff-bundle',
    'draft must preserve pending external assurance detail refs for completed-proof replacement.',
  )

  const validationResult = runValidator([
    '--manifest',
    draftPath,
    '--live-output',
    livePath,
    '--json',
  ])
  check(
    validationResult.status === 0,
    `generated deployment-blocked draft must pass validate:production-evidence: ${validationResult.stderr || validationResult.stdout}`,
  )
  const validation = JSON.parse(validationResult.stdout)
  check(
    validation.artifactKind === 'production-evidence-validation' && validation.status === 'pass',
    'generated draft must emit a passing production-evidence-validation artifact.',
  )
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Production evidence draft check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production evidence draft check passed.')
