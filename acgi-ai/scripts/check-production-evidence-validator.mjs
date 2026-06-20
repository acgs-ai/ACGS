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

function runValidator(args) {
  return spawnSync(process.execPath, ['scripts/validate-production-evidence.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
}

function writeJson(path, payload) {
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`)
}

function makeLiveOutput(status) {
  const pass = status === 'pass'
  const blockers = pass
    ? []
    : [
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
          blockerId: 'live-storybook-dns',
          checkId: 'storybook-dns-live',
          status: 'fail',
          area: 'Hosted Storybook DNS',
          requiredAction: 'Create or repair storybook.acgs.ai DNS.',
          error: 'getaddrinfo ENOTFOUND storybook.acgs.ai',
          evidence: { hostname: 'storybook.acgs.ai' },
        },
        {
          blockerId: 'live-storybook-manifest',
          checkId: 'storybook-manifest-live',
          status: 'fail',
          area: 'Hosted Storybook buyer-evidence manifest',
          requiredAction: 'Publish the claim-safe buyer-evidence manifest.',
          error: 'Invalid JSON from https://storybook.acgs.ai/manifest.json',
          evidence: { url: 'https://storybook.acgs.ai/manifest.json' },
        },
      ]
  return {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    generatedAt: '2026-05-25T00:00:00.000Z',
    status,
    claimBoundary:
      'Live verifier output is production evidence only when every required live check passes; failures remain blockers and are not live production proof.',
    targets: {
      marketingUrl: 'https://acgs.ai',
      consoleUrl: 'https://console.acgs.ai',
      storybookUrl: 'https://storybook.acgs.ai',
      expectedServedHash: '608508a9bd224290',
      expectedBuildId: 'commit-abc123',
      allowStorybookPending: false,
    },
    blockedUntil: pass
      ? null
      : 'Resolve every listed blocker and rerun verify:production-live until all checks pass.',
    blockers,
    checks: [
      { id: 'marketing-dns-live', status: 'pass', evidence: { hostname: 'acgs.ai' } },
      {
        id: 'console-dns-live',
        status: pass ? 'pass' : 'fail',
        evidence: { hostname: 'console.acgs.ai' },
      },
      {
        id: 'storybook-dns-live',
        status: pass ? 'pass' : 'fail',
        evidence: { hostname: 'storybook.acgs.ai' },
      },
      {
        id: 'marketing-https-live',
        status: 'pass',
        evidence: { url: 'https://acgs.ai', status: 200 },
      },
      {
        id: 'console-healthz-live',
        status: pass ? 'pass' : 'fail',
        evidence: {
          url: 'https://console.acgs.ai/healthz',
          status: pass ? 200 : 503,
          ok: pass,
          served_hash: '608508a9bd224290',
          build_id: 'commit-abc123',
          expectedServedHash: '608508a9bd224290',
          expectedBuildId: 'commit-abc123',
        },
      },
      { id: 'console-security-headers-live', status: pass ? 'pass' : 'fail', evidence: {} },
      { id: 'storybook-https-live', status: pass ? 'pass' : 'fail', evidence: {} },
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
                'operator-decision-rail',
                'guided-review-path',
                'launch-proof-ladder',
                'deploy-readiness-boundary',
              ],
            }
          : { url: 'https://storybook.acgs.ai/manifest.json' },
      },
    ],
  }
}

function makeManifest({ status, productionLiveStatus }) {
  const blocked = status === 'deployment-blocked'
  return {
    schemaVersion: 1,
    artifactKind: 'production-evidence',
    status,
    claimBoundary:
      'Completed production deployment evidence; not legal signoff, not SOC2 attestation, not WCAG conformance proof, not pentest completion, and not regulatory compliance proof.',
    deploy: {
      marketingUrl: 'https://acgs.ai',
      consoleUrl: 'https://console.acgs.ai',
      cloudRunRevisionUrl: 'https://console-acgs-ai-abc123-uc.a.run.app',
      cloudflareUrl: 'https://acgs-marketing-abc123.pages.dev',
      githubActionsRunUrls: {
        marketing: 'https://github.com/acgs/acgi-ai/actions/runs/1001',
        console: 'https://github.com/acgs/acgi-ai/actions/runs/1002',
        storybook: 'https://github.com/acgs/acgi-ai/actions/runs/1003',
      },
    },
    verification: {
      expectedBuildId: 'commit-abc123',
      healthz: {
        url: 'https://console.acgs.ai/healthz',
        served_hash: '608508a9bd224290',
        build_id: 'commit-abc123',
      },
      postdeployCommand: 'pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai',
      postdeployOutputRef: 'sha256:postdeploy-output',
      liveCheckedAt: '2026-05-25T00:00:00.000Z',
      productionLiveCommand: 'pnpm -F acgi-ai run verify:production-live -- --json',
      productionLiveOutputRef: 'sha256:production-live-output',
      productionLiveStatus,
      productionLiveBlockers: blocked
        ? ['live-console-dns', 'live-storybook-dns', 'live-storybook-manifest']
        : [],
      productionEvidenceValidationCommand:
        'pnpm -F acgi-ai run validate:production-evidence -- --manifest production-evidence.json --live-output production-live.json',
      productionEvidenceValidationOutputRef: 'sha256:production-evidence-validation',
    },
    hostedStorybook: {
      url: 'https://storybook.acgs.ai',
      manifestUrl: 'https://storybook.acgs.ai/manifest.json',
      status: blocked ? 'pending' : 'verified',
      proofRef: blocked ? 'pending-external:storybook-pages-proof' : 'sha256:storybook-proof',
      claimBoundary: blocked
        ? 'pending means this file does not prove hosted Storybook buyer evidence.'
        : 'verified only by attached live Storybook proof.',
    },
    assurance: {
      legalClaimMatrix: blocked
        ? { status: 'pending-external', proofRef: 'pending-external:legal-review' }
        : {
            status: 'verified',
            proofRef: 'sha256:legal-claim-matrix-review',
            reviewer: 'claim-legal-owner',
            reviewedAt: '2026-05-25T00:00:00.000Z',
            claimMatrixRef: 'sha256:claim-matrix',
          },
      pentest: blocked
        ? { status: 'pending-external', proofRef: 'pending-external:pentest' }
        : {
            status: 'verified',
            proofRef: 'sha256:pentest-report',
            vendor: 'regulated-ai-pentest-vendor',
            completedAt: '2026-05-25T00:00:00.000Z',
            reportRef: 'sha256:pentest-report',
            criticalFindingsOpen: 0,
          },
      wcagManual: blocked
        ? { status: 'pending-external', proofRef: 'pending-external:wcag-manual' }
        : {
            status: 'verified',
            proofRef: 'sha256:manual-wcag-report',
            reviewer: 'accessibility-owner',
            reviewedAt: '2026-05-25T00:00:00.000Z',
            reportRef: 'sha256:manual-wcag-report',
            assistiveTech: ['NVDA', 'VoiceOver'],
          },
      browserScreenshots: {
        status: blocked ? 'pending-external' : 'verified',
        proofRef: blocked ? 'pending-external:browser-screenshots' : 'sha256:browser-screenshots',
        ...(blocked
          ? {}
          : {
              capturedAt: '2026-05-25T00:00:00.000Z',
              bundleRef: 'sha256:browser-screenshot-bundle',
            }),
      },
    },
    artifacts: {
      releaseEvidenceManifest: 'dist-release-evidence/manifest.json',
      platformReadinessJson: 'dist-release-evidence/platform-readiness.json',
      buyerEvidenceGallery: 'buyer-evidence-gallery',
      consoleDist: 'console-dist',
      postdeployOutput: 'sha256:postdeploy-output',
      verifyProductionLiveOutput: 'sha256:production-live-output',
      validatedProductionEvidence: 'sha256:production-evidence-validation',
    },
    remainingBlockers: blocked
      ? [
          'production-deployment',
          'frontend-production-auth',
          'legal-review-of-claim-matrix',
          'third-party-penetration-test',
          'full-wcag-manual-screen-reader-evidence',
          'hosted-storybook-buyer-evidence',
        ]
      : [],
  }
}

const validatorPath = 'scripts/validate-production-evidence.mjs'
const packageJson = JSON.parse(read('package.json'))
const validator = read(validatorPath)
const template = read('production-evidence.example.json')
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const templateCheck = read('scripts/check-production-evidence-template.mjs')
const liveVerifierCheck = read('scripts/check-production-live-verifier.mjs')
const blockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const evidenceDraftCheck = read('scripts/check-production-evidence-draft.mjs')
const launchHandoffCheck = read('scripts/check-production-launch-handoff.mjs')

check(
  packageJson.scripts?.['validate:production-evidence'] ===
    'node scripts/validate-production-evidence.mjs',
  'package.json must expose validate:production-evidence.',
)
check(
  packageJson.scripts?.['test:production-evidence-template'] ===
    'node scripts/check-production-evidence-template.mjs',
  'package.json must expose test:production-evidence-template.',
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
  packageJson.scripts?.['test:production-evidence-validator'] ===
    'node scripts/check-production-evidence-validator.mjs',
  'package.json must expose test:production-evidence-validator.',
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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-blocker-report'),
  'package.json test:all must include the local production blocker report check.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-validator'),
  'package.json test:all must include the local production evidence validator check.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-draft'),
  'package.json test:all must include the local production evidence draft check.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-blocker-report'),
  'package.json test:all must not run input-dependent production blocker report building.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-evidence-draft'),
  'package.json test:all must not run input-dependent production evidence draft building.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run validate:production-evidence'),
  'package.json test:all must not run operator-specific production evidence validation.',
)

for (const needle of [
  'production-evidence-validation',
  '--manifest',
  '--live-output',
  '--out',
  '--require-pass',
  'production-evidence',
  'deployment-blocked',
  'live-verified',
  'hosted-storybook-manifest-url',
  'live-verified-requires-storybook-manifest',
  'storybook-manifest-live',
  'https://storybook.acgs.ai/manifest.json',
  'productionLiveStatus',
  'productionLiveBlockers',
  'live-output-blockers-field',
  'deployment-blocked-live-blockers-match',
  'validatedProductionEvidence',
  'pending-external',
  'isBlockedPendingExternalRef',
  'require-pass-assurance-legalClaimMatrix-verified',
  'criticalFindingsOpen',
  'assistiveTech',
  'not legal signoff',
  'not SOC2 proof',
  'not WCAG conformance evidence',
  'not pentest completion',
  'not regulatory compliance proof',
]) {
  mustContain(validator, needle, validatorPath)
}

for (const needle of [
  'validate:production-evidence',
  'productionEvidenceValidationCommand',
  'productionEvidenceValidationOutputRef',
  'validatedProductionEvidence',
]) {
  for (const [label, source] of [
    ['production-evidence.example.json', template],
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production evidence template checker', templateCheck],
    ['production live verifier checker', liveVerifierCheck],
    ['production blocker report checker', blockerReportCheck],
    ['production evidence draft checker', evidenceDraftCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of [
  'build:production-blocker-report',
  'test:production-blocker-report',
  'production-blocker-report',
  'copyIntoProductionEvidence',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production evidence template checker', templateCheck],
    ['production live verifier checker', liveVerifierCheck],
    ['production blocker report checker', blockerReportCheck],
    ['production evidence draft checker', evidenceDraftCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of ['test:production-evidence-validator']) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production evidence template checker', templateCheck],
    ['production live verifier checker', liveVerifierCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of ['test:production-evidence-draft']) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of [
  'build:production-evidence-draft',
  'test:production-evidence-draft',
  'production-evidence-draft',
  'production-evidence.deployment-blocked.json',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production evidence draft checker', evidenceDraftCheck],
    ['production launch handoff checker', launchHandoffCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

const help = runValidator(['--help'])
check(help.status === 0, 'validate-production-evidence --help must exit zero.')
check(help.stdout.includes('--manifest'), '--help must document --manifest.')
check(help.stdout.includes('--live-output'), '--help must document --live-output.')
check(help.stdout.includes('--out'), '--help must document --out.')
check(help.stdout.includes('--require-pass'), '--help must document --require-pass.')

const tempDir = mkdtempSync(join(tmpdir(), 'production-evidence-validator-'))
try {
  const passManifest = join(tempDir, 'pass-manifest.json')
  const passLive = join(tempDir, 'pass-live.json')
  const blockedManifest = join(tempDir, 'blocked-manifest.json')
  const blockedLive = join(tempDir, 'blocked-live.json')
  const blockedLiveWithoutBlockers = join(tempDir, 'blocked-live-without-blockers.json')
  const blockedPendingExternalManifest = join(tempDir, 'blocked-pending-external-manifest.json')
  const blockedMismatchManifest = join(tempDir, 'blocked-mismatch-manifest.json')
  const pendingAssuranceManifest = join(tempDir, 'pending-assurance-manifest.json')
  const failLive = join(tempDir, 'fail-live.json')
  const validationOut = join(tempDir, 'production-evidence-validation.json')

  writeJson(passManifest, makeManifest({ status: 'live-verified', productionLiveStatus: 'pass' }))
  writeJson(passLive, makeLiveOutput('pass'))
  writeJson(
    blockedManifest,
    makeManifest({ status: 'deployment-blocked', productionLiveStatus: 'fail' }),
  )
  writeJson(blockedLive, makeLiveOutput('fail'))
  writeJson(blockedLiveWithoutBlockers, { ...makeLiveOutput('fail'), blockers: [] })
  writeJson(blockedPendingExternalManifest, {
    ...makeManifest({ status: 'deployment-blocked', productionLiveStatus: 'fail' }),
    deploy: {
      ...makeManifest({ status: 'deployment-blocked', productionLiveStatus: 'fail' }).deploy,
      cloudRunRevisionUrl: 'pending-external:cloud-run-revision-url',
      cloudflareUrl: 'pending-external:cloudflare-deployment-url',
      githubActionsRunUrls: {
        marketing: 'pending-external:marketing-workflow-run-url',
        console: 'pending-external:console-workflow-run-url',
        storybook: 'pending-external:storybook-workflow-run-url',
      },
    },
  })
  writeJson(blockedMismatchManifest, {
    ...makeManifest({ status: 'deployment-blocked', productionLiveStatus: 'fail' }),
    verification: {
      ...makeManifest({ status: 'deployment-blocked', productionLiveStatus: 'fail' })
        .verification,
      productionLiveBlockers: ['live-console-dns'],
    },
  })
  writeJson(pendingAssuranceManifest, {
    ...makeManifest({ status: 'live-verified', productionLiveStatus: 'pass' }),
    assurance: {
      ...makeManifest({ status: 'live-verified', productionLiveStatus: 'pass' }).assurance,
      legalClaimMatrix: { status: 'pending-external', proofRef: 'pending-external:legal-review' },
    },
    remainingBlockers: ['legal-review-of-claim-matrix'],
  })
  writeJson(failLive, makeLiveOutput('fail'))

  const passResult = runValidator(['--manifest', passManifest, '--live-output', passLive, '--json'])
  check(
    passResult.status === 0,
    `valid live-verified manifest must pass: ${passResult.stderr || passResult.stdout}`,
  )
  const passPayload = JSON.parse(passResult.stdout)
  check(
    passPayload.artifactKind === 'production-evidence-validation' && passPayload.status === 'pass',
    'valid live-verified manifest must emit a passing production-evidence-validation artifact.',
  )

  const blockedResult = runValidator([
    '--manifest',
    blockedManifest,
    '--live-output',
    blockedLive,
    '--json',
  ])
  check(
    blockedResult.status === 0,
    `deployment-blocked manifest with failing live output must pass validation: ${blockedResult.stderr || blockedResult.stdout}`,
  )

  const savedBlockedResult = runValidator([
    '--manifest',
    blockedManifest,
    '--live-output',
    blockedLive,
    '--out',
    validationOut,
    '--json',
  ])
  check(
    savedBlockedResult.status === 0,
    `validator --out must save a passing deployment-blocked validation artifact: ${savedBlockedResult.stderr || savedBlockedResult.stdout}`,
  )
  check(existsSync(validationOut), 'validate-production-evidence --out must write JSON.')
  if (existsSync(validationOut)) {
    const savedPayload = JSON.parse(readFileSync(validationOut, 'utf8'))
    const printedPayload = JSON.parse(savedBlockedResult.stdout)
    check(
      savedPayload.artifactKind === 'production-evidence-validation' &&
        savedPayload.status === 'pass',
      'validator --out artifact must be a passing production-evidence-validation payload.',
    )
    check(
      printedPayload.generatedAt === savedPayload.generatedAt &&
        savedPayload.liveOutputPath === blockedLive,
      'validator --json stdout and --out artifact must describe the same validation run.',
    )
  }

  const missingBlockersResult = runValidator([
    '--manifest',
    blockedManifest,
    '--live-output',
    blockedLiveWithoutBlockers,
    '--json',
  ])
  check(
    missingBlockersResult.status !== 0,
    'deployment-blocked live output without blockers must fail validation.',
  )

  const mismatchedBlockersResult = runValidator([
    '--manifest',
    blockedMismatchManifest,
    '--live-output',
    blockedLive,
    '--json',
  ])
  check(
    mismatchedBlockersResult.status !== 0,
    'deployment-blocked manifest missing a live blocker id must fail validation.',
  )

  const templateResult = runValidator(['--manifest', 'production-evidence.example.json', '--json'])
  check(
    templateResult.status !== 0,
    'template with REPLACE_WITH_ placeholders must fail validation.',
  )

  const requirePassResult = runValidator([
    '--manifest',
    passManifest,
    '--live-output',
    failLive,
    '--require-pass',
    '--json',
  ])
  check(
    requirePassResult.status !== 0,
    'live-verified manifest with failing live output must fail --require-pass validation.',
  )

  const pendingAssuranceResult = runValidator([
    '--manifest',
    pendingAssuranceManifest,
    '--live-output',
    passLive,
    '--require-pass',
    '--json',
  ])
  check(
    pendingAssuranceResult.status !== 0,
    'live-verified --require-pass manifest with pending external assurance must fail validation.',
  )
  if (pendingAssuranceResult.stdout.trim()) {
    const pendingAssurancePayload = JSON.parse(pendingAssuranceResult.stdout)
    check(
      pendingAssurancePayload.checks?.some(
        (entry) =>
          entry.id === 'require-pass-assurance-legalClaimMatrix-verified' &&
          entry.status === 'fail',
      ),
      'pending external legal claim matrix assurance must fail require-pass-assurance-legalClaimMatrix-verified.',
    )
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Production evidence validator check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production evidence validator check passed.')
