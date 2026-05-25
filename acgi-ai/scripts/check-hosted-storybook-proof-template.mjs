import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
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

function writeJson(path, payload) {
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`)
}

function runValidator(args) {
  return spawnSync(process.execPath, ['scripts/validate-hosted-storybook-proof.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
}

function makeCompletedProof() {
  return {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-proof',
    status: 'verified',
    sourceTemplate: 'acgi-ai/hosted-storybook-proof.example.json',
    claimBoundary:
      'Completed hosted Storybook buyer-evidence proof; not production deployment proof, not legal signoff, not SOC2 proof, not WCAG conformance proof, not pentest completion, and not regulatory compliance proof.',
    target: {
      url: 'https://storybook.acgs.ai',
      manifestUrl: 'https://storybook.acgs.ai/manifest.json',
      expectedPublishTarget: 'https://storybook.acgs.ai',
      requiredStoryIds: [
        'receipt-proof-journey',
        'bus-owned-proof-source',
        'claim-safe-trust-surface',
        'visual-governance-workbench',
        'launch-proof-ladder',
        'deploy-readiness-boundary',
      ],
      manifestClaimBoundaryMustInclude: 'not production deployment proof',
    },
    workflow: {
      name: 'buyer-evidence-storybook',
      file: '.github/workflows/storybook.yml',
      artifactName: 'buyer-evidence-storybook',
      requiredRepoVariable: 'STORYBOOK_PAGES_ENABLED=true',
      runUrl: 'https://github.com/acgs/acgi-ai/actions/runs/1003',
      pagesDeployUrl: 'https://github.com/acgs/acgi-ai/actions/deployments/1003',
      buildOutputRef: 'sha256:buyer-evidence-storybook',
    },
    dns: {
      host: 'storybook.acgs.ai',
      recordType: 'CNAME',
      configuredBy: 'dns-owner-change-123',
      evidenceRef: 'sha256:storybook-dns-provider-record',
    },
    liveVerification: {
      command: 'pnpm -F acgi-ai run verify:production-live -- --json',
      outputRef: 'sha256:verify-production-live-pass',
      status: 'pass',
      requiredPassingCheckIds: [
        'storybook-dns-live',
        'storybook-https-live',
        'storybook-manifest-live',
      ],
      requiredAbsentBlockerIds: [
        'live-storybook-dns',
        'live-storybook-https',
        'live-storybook-manifest',
      ],
    },
    manifestEvidence: {
      artifactKind: 'local-buyer-evidence-gallery',
      publishTarget: 'https://storybook.acgs.ai',
      manifestJsonRef: 'sha256:hosted-storybook-manifest-json',
      storyIds: [
        'receipt-proof-journey',
        'bus-owned-proof-source',
        'claim-safe-trust-surface',
        'visual-governance-workbench',
        'launch-proof-ladder',
        'deploy-readiness-boundary',
      ],
      claimBoundaryRef: 'sha256:hosted-storybook-manifest-claim-boundary',
    },
    browserEvidence: {
      status: 'pass',
      targetUrl: 'https://storybook.acgs.ai',
      storyIds: [
        'receipt-proof-journey',
        'bus-owned-proof-source',
        'claim-safe-trust-surface',
        'visual-governance-workbench',
        'launch-proof-ladder',
        'deploy-readiness-boundary',
      ],
      viewportSet: [360, 768, 834, 1024, 1440],
      screenshotRefs: {
        'receipt-proof-journey': 'sha256:receipt-proof-journey-screenshot',
        'bus-owned-proof-source': 'sha256:bus-owned-proof-source-screenshot',
        'claim-safe-trust-surface': 'sha256:claim-safe-trust-surface-screenshot',
        'visual-governance-workbench': 'sha256:visual-governance-workbench-screenshot',
        'launch-proof-ladder': 'sha256:launch-proof-ladder-screenshot',
        'deploy-readiness-boundary': 'sha256:deploy-readiness-boundary-screenshot',
      },
      automatedA11yReportRefs: {
        'receipt-proof-journey': 'sha256:receipt-proof-journey-automated-a11y',
        'bus-owned-proof-source': 'sha256:bus-owned-proof-source-automated-a11y',
        'claim-safe-trust-surface': 'sha256:claim-safe-trust-surface-automated-a11y',
        'visual-governance-workbench': 'sha256:visual-governance-workbench-automated-a11y',
        'launch-proof-ladder': 'sha256:launch-proof-ladder-automated-a11y',
        'deploy-readiness-boundary': 'sha256:deploy-readiness-boundary-automated-a11y',
      },
      visualDiffRefs: {
        'receipt-proof-journey': 'sha256:receipt-proof-journey-visual-diff',
        'bus-owned-proof-source': 'sha256:bus-owned-proof-source-visual-diff',
        'claim-safe-trust-surface': 'sha256:claim-safe-trust-surface-visual-diff',
        'visual-governance-workbench': 'sha256:visual-governance-workbench-visual-diff',
        'launch-proof-ladder': 'sha256:launch-proof-ladder-visual-diff',
        'deploy-readiness-boundary': 'sha256:deploy-readiness-boundary-visual-diff',
      },
      claimBoundary:
        'Hosted browser QA evidence is rendering, automated accessibility, and visual-diff proof only; not production deployment proof, not WCAG conformance proof, not manual screen-reader evidence, not legal signoff, not SOC2 proof, and not pentest completion.',
    },
    validation: {
      localTemplateCheckCommand: 'pnpm -F acgi-ai run test:hosted-storybook-proof-template',
      completedProofValidationCommand:
        'pnpm -F acgi-ai run validate:hosted-storybook-proof -- --proof <hosted-storybook-proof.json> --live-output <verify-production-live.json> --out ../dist-release-evidence/hosted-storybook-proof-validation.json --require-pass',
      completedProofValidationOutputRef: 'sha256:hosted-storybook-proof-validation',
      productionEvidenceValidationCommand:
        'pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json> --require-pass',
    },
    copyIntoProductionEvidence: {
      productionEvidencePointer: 'copyIntoProductionEvidence.hostedStorybook',
      hostedStorybook: {
        url: 'https://storybook.acgs.ai',
        manifestUrl: 'https://storybook.acgs.ai/manifest.json',
        status: 'verified',
        proofRef: 'sha256:storybook-pages-run-and-passing-live-verifier',
        claimBoundary:
          'verified only by attached Storybook Pages deploy evidence, DNS evidence, hosted manifest evidence, and passing verify:production-live JSON.',
      },
      remainingBlockerToRemove: 'hosted-storybook-buyer-evidence',
    },
  }
}

function makeLiveOutput(status = 'pass') {
  const pass = status === 'pass'
  return {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    generatedAt: '2026-05-25T00:00:00.000Z',
    status,
    claimBoundary:
      'Live verifier output is production evidence only when every required live check passes against the deployed origins; failures or pending Storybook checks remain deployment blockers and are not live production proof.',
    targets: {
      marketingUrl: 'https://acgs.ai',
      consoleUrl: 'https://console.acgs.ai',
      storybookUrl: 'https://storybook.acgs.ai',
      expectedServedHash: '608508a9bd224290',
      expectedBuildId: 'commit-abc123',
      allowStorybookPending: false,
    },
    blockedUntil: pass ? null : 'Resolve every listed blocker and rerun verify:production-live.',
    blockers: pass
      ? []
      : [
          {
            blockerId: 'live-storybook-manifest',
            checkId: 'storybook-manifest-live',
            status: 'fail',
          },
        ],
    checks: [
      { id: 'storybook-dns-live', status: pass ? 'pass' : 'fail' },
      { id: 'storybook-https-live', status: pass ? 'pass' : 'fail' },
      {
        id: 'storybook-manifest-live',
        status: pass ? 'pass' : 'fail',
        evidence: pass
          ? {
              url: 'https://storybook.acgs.ai/manifest.json',
              artifactKind: 'local-buyer-evidence-gallery',
              publishTarget: 'https://storybook.acgs.ai',
              storyIds: [
                'receipt-proof-journey',
                'bus-owned-proof-source',
                'claim-safe-trust-surface',
                'visual-governance-workbench',
                'launch-proof-ladder',
                'deploy-readiness-boundary',
              ],
              claimBoundaryPreserved: true,
            }
          : { url: 'https://storybook.acgs.ai/manifest.json' },
      },
    ],
  }
}

const templatePath = 'hosted-storybook-proof.example.json'
const checkerPath = 'scripts/check-hosted-storybook-proof-template.mjs'
const validatorPath = 'scripts/validate-hosted-storybook-proof.mjs'
check(existsSync(resolve(root, templatePath)), `${templatePath} must exist.`)
check(existsSync(resolve(root, checkerPath)), `${checkerPath} must exist.`)
check(existsSync(resolve(root, validatorPath)), `${validatorPath} must exist.`)

const templateText = read(templatePath)
const template = JSON.parse(templateText)
const checker = read(checkerPath)
const validator = read(validatorPath)
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
  'visual-governance-workbench',
  'launch-proof-ladder',
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
  template.browserEvidence?.status === 'REPLACE_WITH_PASS_FROM_HOSTED_BROWSER_QA',
  'browserEvidence.status must require hosted browser QA pass evidence.',
)
check(
  template.browserEvidence?.targetUrl === 'https://storybook.acgs.ai',
  'browserEvidence.targetUrl must match hosted Storybook.',
)
check(
  JSON.stringify(template.browserEvidence?.viewportSet) === JSON.stringify([360, 768, 834, 1024, 1440]),
  'browserEvidence.viewportSet must match the visual baseline viewport set.',
)
for (const storyId of [
  'receipt-proof-journey',
  'bus-owned-proof-source',
  'claim-safe-trust-surface',
  'visual-governance-workbench',
  'launch-proof-ladder',
  'deploy-readiness-boundary',
]) {
  check(
    template.browserEvidence?.storyIds?.includes(storyId),
    `browserEvidence.storyIds must include ${storyId}.`,
  )
  for (const key of ['screenshotRefs', 'automatedA11yReportRefs', 'visualDiffRefs']) {
    check(
      String(template.browserEvidence?.[key]?.[storyId] ?? '').startsWith('REPLACE_WITH_'),
      `browserEvidence.${key}.${storyId} must stay an operator-supplied placeholder.`,
    )
  }
}
for (const needle of [
  'not production deployment proof',
  'not WCAG conformance proof',
  'not manual screen-reader evidence',
  'not legal signoff',
  'not SOC2 proof',
  'not pentest completion',
]) {
  mustContain(template.browserEvidence?.claimBoundary ?? '', needle, 'browserEvidence.claimBoundary')
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
  'validate:hosted-storybook-proof',
  'hosted-storybook-proof',
  'validate:production-evidence',
  '--require-pass',
]) {
  mustContain(JSON.stringify(template.validation ?? {}), needle, 'validation commands')
}
check(
  template.validation?.completedProofValidationCommand?.includes(
    'validate:hosted-storybook-proof',
  ) && template.validation?.completedProofValidationCommand?.includes('--require-pass'),
  'validation.completedProofValidationCommand must capture the completed proof validator.',
)
check(
  template.validation?.completedArtifactKind === 'hosted-storybook-proof',
  'validation.completedArtifactKind must document the completed proof artifact kind.',
)
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
  packageJson.scripts?.['validate:hosted-storybook-proof'] ===
    'node scripts/validate-hosted-storybook-proof.mjs',
  'package.json must expose validate:hosted-storybook-proof.',
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

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', launch],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['security invariants checker', securityCheck],
  ['hosted Storybook handoff checker', hostedHandoffCheck],
]) {
  mustContain(source, 'validate:hosted-storybook-proof', label)
}

for (const needle of [
  'Hosted Storybook proof template check',
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'validate-hosted-storybook-proof',
  'REPLACE_WITH_STORYBOOK_WORKFLOW_RUN_URL',
  'requiredAbsentBlockerIds',
  'browserEvidence',
  'automatedA11yReportRefs',
  'visualDiffRefs',
  'remainingBlockerToRemove',
]) {
  mustContain(checker, needle, checkerPath)
}

for (const needle of [
  'Hosted Storybook proof validation',
  'hosted-storybook-proof-validation',
  'hosted-storybook-proof',
  '--proof',
  '--live-output',
  '--require-pass',
  'storybook-manifest-live',
  'live-storybook-manifest',
  'browserEvidence',
  'automatedA11yReportRefs',
  'visualDiffRefs',
  'not WCAG conformance proof',
  'copyIntoProductionEvidence.hostedStorybook',
  'not production deployment proof',
]) {
  mustContain(validator, needle, validatorPath)
}

const help = runValidator(['--help'])
check(help.status === 0, 'validate-hosted-storybook-proof --help must exit zero.')
for (const needle of ['--proof', '--live-output', '--require-pass', 'does not deploy']) {
  mustContain(help.stdout, needle, 'validate-hosted-storybook-proof --help')
}

const tempDir = mkdtempSync(join(tmpdir(), 'hosted-storybook-proof-'))
try {
  const proofPath = join(tempDir, 'hosted-storybook-proof.json')
  const livePath = join(tempDir, 'production-live.json')
  const failingLivePath = join(tempDir, 'production-live-fail.json')
  const templateAsProofPath = join(tempDir, 'template-as-proof.json')
  const missingBrowserEvidencePath = join(tempDir, 'missing-browser-evidence.json')
  writeJson(proofPath, makeCompletedProof())
  writeJson(livePath, makeLiveOutput('pass'))
  writeJson(failingLivePath, makeLiveOutput('fail'))
  writeJson(templateAsProofPath, template)
  const missingBrowserEvidence = makeCompletedProof()
  delete missingBrowserEvidence.browserEvidence.visualDiffRefs['claim-safe-trust-surface']
  writeJson(missingBrowserEvidencePath, missingBrowserEvidence)

  const passing = runValidator([
    '--proof',
    proofPath,
    '--live-output',
    livePath,
    '--require-pass',
    '--json',
  ])
  check(passing.status === 0, `completed hosted proof fixture must pass: ${passing.stderr}`)
  const passingPayload = JSON.parse(passing.stdout)
  check(
    passingPayload.artifactKind === 'hosted-storybook-proof-validation',
    'validator output artifact kind must match.',
  )
  check(passingPayload.status === 'pass', 'validator must pass the completed proof fixture.')

  const failingLive = runValidator([
    '--proof',
    proofPath,
    '--live-output',
    failingLivePath,
    '--require-pass',
    '--json',
  ])
  check(failingLive.status !== 0, 'validator must reject failing Storybook live output.')
  const failingLivePayload = JSON.parse(failingLive.stdout)
  check(
    failingLivePayload.checks.some((entry) => entry.id === 'live-output-status'),
    'validator failure must include live-output-status check.',
  )

  const templateResult = runValidator([
    '--proof',
    templateAsProofPath,
    '--live-output',
    livePath,
    '--require-pass',
    '--json',
  ])
  check(templateResult.status !== 0, 'validator must reject the template-only proof file.')
  const templatePayload = JSON.parse(templateResult.stdout)
  check(
    templatePayload.checks.some((entry) => entry.id === 'artifact-kind'),
    'template-only rejection must include artifact-kind check.',
  )

  const missingBrowserResult = runValidator([
    '--proof',
    missingBrowserEvidencePath,
    '--live-output',
    livePath,
    '--require-pass',
    '--json',
  ])
  check(
    missingBrowserResult.status !== 0,
    'validator must reject completed proof missing hosted browser QA refs.',
  )
  const missingBrowserPayload = JSON.parse(missingBrowserResult.stdout)
  check(
    missingBrowserPayload.checks.some((entry) => entry.id === 'browser-evidence-visualDiffRefs'),
    'missing browser QA rejection must include browser-evidence-visualDiffRefs check.',
  )
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Hosted Storybook proof template check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Hosted Storybook proof template check passed.')
