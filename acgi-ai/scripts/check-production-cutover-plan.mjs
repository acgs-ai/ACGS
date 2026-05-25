import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { dirname } from 'node:path'
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
  try {
    const stdout = execFileSync(
      process.execPath,
      ['scripts/build-production-cutover-plan.mjs', ...args],
      {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    )
    return { status: 0, stdout, stderr: '' }
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout?.toString() ?? '',
      stderr: error.stderr?.toString() ?? error.message,
    }
  }
}

const packageJson = JSON.parse(read('package.json'))
const builderPath = 'scripts/build-production-cutover-plan.mjs'
const checkerPath = 'scripts/check-production-cutover-plan.mjs'
const builder = read(builderPath)
const checker = read(checkerPath)
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const productionBlockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const productionLaunchHandoffCheck = read('scripts/check-production-launch-handoff.mjs')

// Cross-contract anchors for the upstream blocker report handoff:
// build:production-blocker-report, test:production-blocker-report.

check(
  packageJson.scripts?.['build:production-cutover-plan'] ===
    'node scripts/build-production-cutover-plan.mjs',
  'package.json must expose build:production-cutover-plan.',
)
check(
  packageJson.scripts?.['test:production-cutover-plan'] ===
    'node scripts/check-production-cutover-plan.mjs',
  'package.json must expose test:production-cutover-plan.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-cutover-plan'),
  'package.json test:all must include the local production cutover plan check.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-cutover-plan'),
  'package.json test:all must not run input-dependent production cutover plan building.',
)

for (const needle of [
  'production-cutover-plan',
  '--live-output',
  '--blocker-report',
  '--require-clear',
  'console.acgs.ai',
  'storybook.acgs.ai',
  'STORYBOOK_PAGES_ENABLED=true',
  'productionLiveBlockers',
  'liveCheckSummary',
  'cutoverDelta',
  'safeToClaimProduction',
  'copyIntoProductionEvidence',
  'not live production proof',
  'does not deploy',
  'mutate DNS',
  'validate:production-evidence',
  'build:production-evidence-draft',
  'test:production-evidence-draft',
  'production-evidence-draft',
  'production-evidence.deployment-blocked.json',
]) {
  mustContain(builder, needle, builderPath)
  mustContain(checker, needle, checkerPath)
}

const help = runBuilder(['--help'])
check(help.status === 0, 'build-production-cutover-plan --help must exit zero.')
check(help.stdout.includes('--live-output'), '--help must document --live-output.')
check(help.stdout.includes('--blocker-report'), '--help must document --blocker-report.')
check(
  help.stdout.includes('does not deploy') && help.stdout.includes('live production proof'),
  '--help must preserve the claim boundary.',
)

const tempDir = mkdtempSync(join(tmpdir(), 'production-cutover-plan-'))
try {
  const livePath = join(tempDir, 'live.json')
  const blockerPath = join(tempDir, 'blockers.json')
  const planPath = join(tempDir, 'plan.json')
  writeJson(livePath, {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    status: 'fail',
    blockedUntil:
      'Resolve every listed blocker and rerun verify:production-live until all checks pass.',
    blockers: [
      { blockerId: 'live-console-dns', checkId: 'console-dns-live', error: 'ENOTFOUND' },
      { blockerId: 'live-storybook-manifest', checkId: 'storybook-manifest-live' },
    ],
    checks: [
      { id: 'marketing-dns-live', status: 'pass' },
      { id: 'marketing-https-live', status: 'pass' },
      { id: 'console-dns-live', status: 'fail' },
      { id: 'storybook-manifest-live', status: 'fail' },
    ],
  })
  writeJson(blockerPath, {
    schemaVersion: 1,
    artifactKind: 'production-blocker-report',
    status: 'blocked',
    productionLiveStatus: 'fail',
    productionLiveBlockers: ['live-console-dns', 'live-storybook-manifest'],
    failedCheckIds: ['console-dns-live', 'storybook-manifest-live'],
    blockedUntil:
      'Resolve every listed blocker and rerun verify:production-live until all checks pass.',
    blockers: [
      {
        blockerId: 'live-console-dns',
        checkId: 'console-dns-live',
        area: 'Console DNS',
        requiredAction: 'Create or repair the console.acgs.ai DNS record.',
      },
    ],
  })

  const result = runBuilder([
    '--live-output',
    livePath,
    '--blocker-report',
    blockerPath,
    '--out',
    planPath,
  ])
  check(result.status === 0, `blocked cutover inputs must still produce a plan: ${result.stderr}`)
  const plan = JSON.parse(readFileSync(planPath, 'utf8'))
  check(
    plan.artifactKind === 'production-cutover-plan',
    'builder must emit production-cutover-plan.',
  )
  check(plan.status === 'blocked', 'blocked live inputs must produce a blocked cutover plan.')
  check(
    plan.productionLiveBlockers.includes('live-console-dns') &&
      plan.productionLiveBlockers.includes('live-storybook-manifest'),
    'cutover plan must carry productionLiveBlockers.',
  )
  check(
    plan.liveCheckSummary?.counts?.pass === 2 &&
      plan.liveCheckSummary?.counts?.fail === 2 &&
      plan.liveCheckSummary?.passedCheckIds?.includes('marketing-dns-live') &&
      plan.liveCheckSummary?.failedCheckIds?.includes('storybook-manifest-live'),
    'cutover plan must summarize saved live check pass/fail state.',
  )
  check(
    plan.liveCheckSummary?.checks?.some(
      (check) =>
        check.id === 'console-dns-live' &&
        check.lane === 'console' &&
        check.operatorAction.includes('console.acgs.ai DNS'),
    ),
    'liveCheckSummary must attach operator action guidance to failed checks.',
  )
  check(
    plan.cutoverDelta?.state === 'blocked-live-cutover' &&
      plan.cutoverDelta?.safeToClaimProduction === false &&
      plan.cutoverDelta?.evidenceValidation?.state === 'waiting-for-live-checks',
    'cutoverDelta must preserve blocked state and evidence-validation guidance.',
  )
  check(
    plan.cutoverDelta?.lanes?.some(
      (lane) => lane.lane === 'marketing' && lane.state === 'already-live',
    ) &&
      plan.cutoverDelta?.lanes?.some(
        (lane) =>
          lane.lane === 'console' &&
          lane.state === 'dns-or-service-blocked' &&
          lane.blockerIds.includes('live-console-dns'),
      ) &&
      plan.cutoverDelta?.lanes?.some(
        (lane) =>
          lane.lane === 'storybook' &&
          lane.state === 'dns-or-pages-blocked' &&
          lane.blockerIds.includes('live-storybook-manifest'),
      ),
    'cutoverDelta must separate marketing, console, and Storybook lane state.',
  )
  check(
    plan.requiredGitHubSecrets.includes('CONSOLE_AUTH_UPSTREAM') &&
      plan.requiredGitHubVariables.includes('STORYBOOK_PAGES_ENABLED=true'),
    'cutover plan must list required GitHub production secrets and variables.',
  )
  check(
    plan.dnsCutover.records.some((record) => record.host === 'console.acgs.ai') &&
      plan.dnsCutover.records.some((record) => record.host === 'storybook.acgs.ai'),
    'cutover plan must list console and Storybook DNS records.',
  )
  check(
    plan.copyIntoProductionEvidence?.artifacts?.productionCutoverPlan ===
      '<production-cutover-plan.json artifact or hash>' &&
      plan.copyIntoProductionEvidence?.artifacts?.productionCutoverDelta ===
        '<production-cutover-plan.cutoverDelta JSON pointer or hash>',
    'cutover plan must provide copyIntoProductionEvidence artifact and cutoverDelta slots.',
  )
  check(
    plan.claimBoundary.includes('not live production proof') &&
      plan.claimBoundary.includes('does not deploy'),
    'cutover plan claimBoundary must stay conservative.',
  )

  const requireClear = runBuilder(['--live-output', livePath, '--require-clear', '--json'])
  check(requireClear.status !== 0, '--require-clear must fail while blockers remain.')
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['production blocker report checker', productionBlockerReportCheck],
  ['production launch handoff checker', productionLaunchHandoffCheck],
]) {
  mustContain(source, 'build:production-cutover-plan', label)
  mustContain(source, 'test:production-cutover-plan', label)
  mustContain(source, 'production-cutover-plan', label)
  mustContain(source, 'build:production-evidence-draft', label)
  mustContain(source, 'test:production-evidence-draft', label)
  mustContain(source, 'production-evidence-draft', label)
  mustContain(source, 'not live production proof', label)
}

if (failures.length > 0) {
  console.error('Production cutover plan check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production cutover plan check passed.')
