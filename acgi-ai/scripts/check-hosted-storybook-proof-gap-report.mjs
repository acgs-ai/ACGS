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
  return spawnSync(
    process.execPath,
    ['scripts/build-hosted-storybook-proof-gap-report.mjs', ...args],
    {
      cwd: root,
      encoding: 'utf8',
    },
  )
}

const packageJson = JSON.parse(read('package.json'))
const builderPath = 'scripts/build-hosted-storybook-proof-gap-report.mjs'
const checkerPath = 'scripts/check-hosted-storybook-proof-gap-report.mjs'
const builder = read(builderPath)
const checker = read(checkerPath)
const proofTemplate = read('hosted-storybook-proof.example.json')
const productionLaunch = read('PRODUCTION-LAUNCH.md')
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const blockerWrapper = readRepo('scripts/build_production_blocker_evidence.py')
const preflight = readRepo('scripts/production_launch_preflight.py')
const workbenchContent = read('src/routes/workbench-content.ts')

check(
  packageJson.scripts?.['build:hosted-storybook-proof-gap-report'] ===
    'node scripts/build-hosted-storybook-proof-gap-report.mjs',
  'package.json must expose build:hosted-storybook-proof-gap-report.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-proof-gap-report'] ===
    'node scripts/check-hosted-storybook-proof-gap-report.mjs',
  'package.json must expose test:hosted-storybook-proof-gap-report.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-proof-gap-report'),
  'package.json test:all must include hosted Storybook proof gap report verification.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:hosted-storybook-proof-gap-report'),
  'package.json test:all must not run input-dependent hosted Storybook proof gap report building.',
)

for (const needle of [
  'hosted-storybook-proof-gap-report',
  '--proof-template',
  '--live-output',
  '--handoff',
  'storybook-live-verifier-pass',
  'hosted-browser-evidence',
  'production-evidence-copy-field',
  'copyIntoProductionEvidence.hostedStorybook',
  'live-storybook-dns',
  'storybook-manifest-live',
  'not live production proof',
  'does not deploy',
]) {
  mustContain(builder, needle, builderPath)
  mustContain(checker, needle, checkerPath)
}

for (const [needle, sources] of [
  [
    'hosted-storybook-proof-gap-report.json',
    [
      ['PRODUCTION-LAUNCH.md', productionLaunch],
      ['DEPLOY.md', deploy],
      ['integration readiness map', readiness],
      ['platform readiness report', platformReadiness],
      ['release evidence builder', releaseEvidence],
      ['production blocker wrapper', blockerWrapper],
      ['workbench content', workbenchContent],
    ],
  ],
  [
    'build:hosted-storybook-proof-gap-report',
    [
      ['PRODUCTION-LAUNCH.md', productionLaunch],
      ['DEPLOY.md', deploy],
      ['integration readiness map', readiness],
      ['platform readiness report', platformReadiness],
      ['release evidence builder', releaseEvidence],
      ['production blocker wrapper', blockerWrapper],
      ['workbench content', workbenchContent],
    ],
  ],
  [
    'test:hosted-storybook-proof-gap-report',
    [
      ['PRODUCTION-LAUNCH.md', productionLaunch],
      ['DEPLOY.md', deploy],
      ['integration readiness map', readiness],
      ['platform readiness report', platformReadiness],
      ['release evidence builder', releaseEvidence],
    ],
  ],
  [
    'Build proof gap report',
    [
      ['PRODUCTION-LAUNCH.md', productionLaunch],
      ['DEPLOY.md', deploy],
      ['integration readiness map', readiness],
      ['platform readiness report', platformReadiness],
      ['release evidence builder', releaseEvidence],
      ['workbench content', workbenchContent],
    ],
  ],
  [
    'hostedStorybookProofGapReport',
    [
      ['release evidence builder', releaseEvidence],
      ['production launch preflight', preflight],
    ],
  ],
]) {
  for (const [label, source] of sources) mustContain(source, needle, label)
}

for (const needle of [
  'pending-external:storybook-pages-proof',
  'visualDiffRefs',
  'automatedA11yReportRefs',
]) {
  mustContain(proofTemplate, needle, 'hosted-storybook-proof.example.json')
}

const tmp = mkdtempSync(join(tmpdir(), 'hosted-storybook-gap-'))
try {
  const proofPath = join(tmp, 'hosted-storybook-proof.example.json')
  const livePath = join(tmp, 'production-live-verification.json')
  const handoffPath = join(tmp, 'hosted-storybook-handoff.json')
  const outPath = join(tmp, 'hosted-storybook-proof-gap-report.json')
  writeFileSync(proofPath, proofTemplate)
  writeJson(livePath, {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    status: 'fail',
    targets: { storybookUrl: 'https://storybook.acgs.ai' },
    blockers: [
      { blockerId: 'live-storybook-dns', checkId: 'storybook-dns-live', status: 'fail' },
      { blockerId: 'live-storybook-manifest', checkId: 'storybook-manifest-live', status: 'fail' },
    ],
    checks: [
      { id: 'storybook-dns-live', status: 'fail' },
      { id: 'storybook-https-live', status: 'fail' },
      { id: 'storybook-manifest-live', status: 'fail' },
    ],
  })
  writeJson(handoffPath, {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-handoff',
    status: 'blocked',
  })
  const result = runBuilder([
    '--proof-template',
    proofPath,
    '--live-output',
    livePath,
    '--handoff',
    handoffPath,
    '--out',
    outPath,
    '--json',
  ])
  check(result.status === 0, `builder should exit 0 for a blocked gap report: ${result.stderr}`)
  const report = JSON.parse(readFileSync(outPath, 'utf8'))
  check(
    report.artifactKind === 'hosted-storybook-proof-gap-report',
    'gap report artifactKind must match.',
  )
  check(
    report.status === 'blocked',
    'template plus failing live output must produce blocked status.',
  )
  check(
    report.summary.openGapIds.includes('storybook-live-verifier-pass'),
    'live verifier gap must stay open.',
  )
  check(
    report.summary.openGapIds.includes('hosted-browser-evidence'),
    'hosted browser evidence gap must stay open.',
  )
  check(
    report.summary.openGapIds.includes('no-template-or-pending-refs'),
    'pending refs gap must stay open.',
  )
  check(
    report.gaps.some((gap) => gap.id === 'production-evidence-copy-field'),
    'gap report must include production-evidence copy field guidance.',
  )
  check(
    report.claimBoundary.includes('not live production proof') &&
      report.claimBoundary.includes('does not deploy'),
    'gap report must preserve claim boundary.',
  )
} finally {
  rmSync(tmp, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Hosted Storybook proof gap report check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Hosted Storybook proof gap report check passed.')
