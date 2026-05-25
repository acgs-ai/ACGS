import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

function writeJson(path, payload) {
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`)
}

function runBuilder(args) {
  return spawnSync(process.execPath, ['scripts/build-production-blocker-report.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
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
          requiredAction: 'Create or repair the console.acgs.ai DNS record.',
          error: 'getaddrinfo ENOTFOUND console.acgs.ai',
          evidence: { hostname: 'console.acgs.ai' },
        },
        {
          blockerId: 'live-storybook-dns',
          checkId: 'storybook-dns-live',
          status: 'fail',
          area: 'Hosted Storybook DNS',
          requiredAction: 'Create or repair the storybook.acgs.ai DNS record.',
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
        evidence: { url: 'https://console.acgs.ai/healthz', status: pass ? 200 : 503 },
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
              storyIds: ['receipt-proof-journey', 'deploy-readiness-boundary'],
            }
          : { url: 'https://storybook.acgs.ai/manifest.json' },
      },
    ],
  }
}

const packageJson = JSON.parse(read('package.json'))
const builderPath = 'scripts/build-production-blocker-report.mjs'
const checkerPath = 'scripts/check-production-blocker-report.mjs'
const builder = read(builderPath)
const checker = read(checkerPath)
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const productionEvidenceTemplateCheck = read('scripts/check-production-evidence-template.mjs')
const productionLiveVerifierCheck = read('scripts/check-production-live-verifier.mjs')
const productionEvidenceValidatorCheck = read('scripts/check-production-evidence-validator.mjs')
const productionLaunchHandoffCheck = read('scripts/check-production-launch-handoff.mjs')
const productionCutoverPlanCheck = read('scripts/check-production-cutover-plan.mjs')

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
  'package.json test:all must include the local production blocker report check.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-blocker-report'),
  'package.json test:all must not run the input-dependent production blocker report builder.',
)

for (const needle of [
  'production-blocker-report',
  '--live-output',
  '--out',
  '--require-clear',
  'copyIntoProductionEvidence',
  'productionLiveBlockers',
  'productionLiveStatus',
  'not live production proof',
  'does not deploy',
  'fetch live origins',
]) {
  mustContain(builder, needle, builderPath)
  mustContain(checker, needle, checkerPath)
}

for (const needle of [
  'production-evidence.example.json',
  'test:production-evidence-template',
  'test:production-live-verifier',
  'validate:production-evidence',
  'test:production-evidence-validator',
  'productionEvidenceValidationCommand',
  'productionEvidenceValidationOutputRef',
  'validatedProductionEvidence',
  'build:production-cutover-plan',
  'test:production-cutover-plan',
  'production-cutover-plan',
  'build:production-evidence-draft',
  'test:production-evidence-draft',
  'production-evidence-draft',
  'production-evidence.deployment-blocked.json',
  'pending-external',
]) {
  mustContain(checker, needle, checkerPath)
}

const help = runBuilder(['--help'])
check(help.status === 0, 'build-production-blocker-report --help must exit zero.')
check(help.stdout.includes('--live-output'), '--help must document --live-output.')
check(help.stdout.includes('--require-clear'), '--help must document --require-clear.')
check(
  help.stdout.includes('does not deploy') && help.stdout.includes('live production proof'),
  '--help must preserve the claim boundary.',
)

const tempDir = mkdtempSync(join(tmpdir(), 'production-blocker-report-'))
try {
  const failLive = join(tempDir, 'fail-live.json')
  const passLive = join(tempDir, 'pass-live.json')
  const reportPath = join(tempDir, 'production-blocker-report.json')
  writeJson(failLive, makeLiveOutput('fail'))
  writeJson(passLive, makeLiveOutput('pass'))

  const blockedResult = runBuilder(['--live-output', failLive, '--out', reportPath])
  check(
    blockedResult.status === 0,
    `blocked live output must still produce a report: ${blockedResult.stderr || blockedResult.stdout}`,
  )
  const blockedReport = JSON.parse(readFileSync(reportPath, 'utf8'))
  check(
    blockedReport.artifactKind === 'production-blocker-report' &&
      blockedReport.status === 'blocked',
    'failing live output must emit a blocked production-blocker-report artifact.',
  )
  check(
    blockedReport.productionLiveStatus === 'fail' &&
      blockedReport.productionLiveBlockers.includes('live-console-dns') &&
      blockedReport.productionLiveBlockers.includes('live-storybook-dns') &&
      blockedReport.productionLiveBlockers.includes('live-storybook-manifest'),
    'blocked report must expose productionLiveStatus and productionLiveBlockers from live output.',
  )
  check(
    blockedReport.copyIntoProductionEvidence?.verification?.productionLiveStatus === 'fail' &&
      blockedReport.copyIntoProductionEvidence.verification.productionLiveBlockers.includes(
        'live-console-dns',
      ),
    'blocked report must provide copyIntoProductionEvidence.verification payload.',
  )
  check(
    blockedReport.claimBoundary.includes('not live production proof') &&
      blockedReport.claimBoundary.includes('does not deploy'),
    'blocked report claimBoundary must stay conservative.',
  )

  const requireClearResult = runBuilder(['--live-output', failLive, '--require-clear', '--json'])
  check(requireClearResult.status !== 0, '--require-clear must fail while blockers remain.')

  const clearResult = runBuilder(['--live-output', passLive, '--require-clear', '--json'])
  check(
    clearResult.status === 0,
    `passing live output must satisfy --require-clear: ${clearResult.stderr || clearResult.stdout}`,
  )
  const clearReport = JSON.parse(clearResult.stdout)
  check(
    clearReport.status === 'clear' && clearReport.productionLiveBlockers.length === 0,
    'passing live output must emit a clear report with no productionLiveBlockers.',
  )
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['security invariants checker', securityCheck],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['production evidence template checker', productionEvidenceTemplateCheck],
  ['production live verifier checker', productionLiveVerifierCheck],
  ['production evidence validator checker', productionEvidenceValidatorCheck],
  ['production launch handoff checker', productionLaunchHandoffCheck],
  ['production cutover plan checker', productionCutoverPlanCheck],
]) {
  mustContain(source, 'build:production-blocker-report', label)
  mustContain(source, 'test:production-blocker-report', label)
  mustContain(source, 'production-blocker-report', label)
  mustContain(source, 'copyIntoProductionEvidence', label)
  mustContain(source, 'not live production proof', label)
}

if (failures.length > 0) {
  console.error('Production blocker report check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production blocker report check passed.')
