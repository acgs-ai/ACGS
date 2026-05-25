import { execFileSync, spawnSync } from 'node:child_process'
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
  return spawnSync(process.execPath, ['scripts/build-hosted-storybook-handoff.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
  })
}

function makeLiveOutput(status = 'fail') {
  const pass = status === 'pass'
  const blockers = pass
    ? []
    : [
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
          error: 'fetch failed',
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
    blockedUntil: pass ? null : 'Resolve every listed blocker and rerun verify:production-live.',
    blockers,
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
            }
          : { url: 'https://storybook.acgs.ai/manifest.json' },
      },
    ],
  }
}

const packageJson = JSON.parse(read('package.json'))
const builderPath = 'scripts/build-hosted-storybook-handoff.mjs'
const checkerPath = 'scripts/check-hosted-storybook-handoff.mjs'
const builder = read(builderPath)
const checker = read(checkerPath)
const buildBuyerEvidence = read('scripts/build-buyer-evidence.mjs')
const storybookCheck = read('scripts/check-storybook-publication.mjs')
const productionLiveVerifierCheck = read('scripts/check-production-live-verifier.mjs')
const hostedStorybookProofTemplate = read('hosted-storybook-proof.example.json')
const hostedStorybookProofTemplateCheck = read('scripts/check-hosted-storybook-proof-template.mjs')
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const workflow = readRepo('.github/workflows/storybook.yml')

check(
  packageJson.scripts?.['build:hosted-storybook-handoff'] ===
    'node scripts/build-hosted-storybook-handoff.mjs',
  'package.json must expose build:hosted-storybook-handoff.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-handoff'] ===
    'node scripts/check-hosted-storybook-handoff.mjs',
  'package.json must expose test:hosted-storybook-handoff.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-handoff'),
  'package.json test:all must include hosted Storybook handoff verification.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:hosted-storybook-handoff'),
  'package.json test:all must not run input-dependent hosted Storybook handoff building.',
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

for (const needle of [
  'hosted-storybook-handoff',
  '--buyer-evidence-manifest',
  '--live-output',
  '--require-live-clear',
  'storybook.acgs.ai',
  'https://storybook.acgs.ai/manifest.json',
  'STORYBOOK_PAGES_ENABLED=true',
  'buyer-evidence-storybook',
  'storybook-manifest-live',
  'pending-external:storybook-pages-proof',
  'copyIntoProductionEvidence',
  'not live production proof',
  'does not deploy',
]) {
  mustContain(builder, needle, builderPath)
  mustContain(checker, needle, checkerPath)
}

for (const needle of ['ACGI_EVIDENCE_CNAME', 'publishTarget', 'storybook.acgs.ai']) {
  mustContain(buildBuyerEvidence, needle, 'scripts/build-buyer-evidence.mjs')
}
for (const needle of [
  'actions/upload-pages-artifact@v3',
  'actions/deploy-pages@v4',
  "vars.STORYBOOK_PAGES_ENABLED == 'true'",
]) {
  mustContain(workflow, needle, '.github/workflows/storybook.yml')
}

for (const needle of [
  'build:hosted-storybook-handoff',
  'test:hosted-storybook-handoff',
  'hosted-storybook-handoff',
  'hosted-storybook-handoff.json',
]) {
  for (const [label, source] of [
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['storybook publication checker', storybookCheck],
    ['production live verifier checker', productionLiveVerifierCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

for (const needle of [
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'validate:hosted-storybook-proof',
  'hosted-storybook-proof-template',
  'storybook-manifest-live',
  'pending-external:storybook-pages-proof',
  'copyIntoProductionEvidence.hostedStorybook',
  'not hosted Storybook proof',
]) {
  for (const [label, source] of [
    ['hosted-storybook-proof.example.json', hostedStorybookProofTemplate],
    ['hosted proof template checker', hostedStorybookProofTemplateCheck],
    ['DEPLOY.md', deploy],
    ['PRODUCTION-LAUNCH.md', handoff],
    ['integration readiness map', readiness],
    ['platform readiness report', platformReadiness],
    ['release evidence builder', releaseEvidence],
    ['security invariants checker', securityCheck],
    ['CI readiness gate checker', ciReadinessGateCheck],
    ['production live verifier checker', productionLiveVerifierCheck],
  ]) {
    mustContain(source, needle, label)
  }
}

const help = runBuilder(['--help'])
check(help.status === 0, 'build-hosted-storybook-handoff --help must exit zero.')
for (const needle of ['--buyer-evidence-manifest', '--live-output', '--require-live-clear']) {
  mustContain(help.stdout, needle, 'build-hosted-storybook-handoff --help')
}

const tempDir = mkdtempSync(join(tmpdir(), 'hosted-storybook-handoff-'))
try {
  const publicationDir = join(tempDir, 'publication')
  const livePath = join(tempDir, 'live.json')
  const passLivePath = join(tempDir, 'pass-live.json')
  const handoffPath = join(tempDir, 'hosted-storybook-handoff.json')
  execFileSync(process.execPath, ['scripts/build-buyer-evidence.mjs'], {
    cwd: root,
    env: {
      ...process.env,
      ACGI_EVIDENCE_OUT_DIR: publicationDir,
      ACGI_EVIDENCE_CNAME: 'storybook.acgs.ai',
    },
  })
  writeJson(livePath, makeLiveOutput('fail'))
  writeJson(passLivePath, makeLiveOutput('pass'))

  const result = runBuilder([
    '--buyer-evidence-manifest',
    join(publicationDir, 'manifest.json'),
    '--live-output',
    livePath,
    '--out',
    handoffPath,
    '--json',
  ])
  check(
    result.status === 0,
    `blocked hosted Storybook inputs must still produce a handoff: ${result.stderr || result.stdout}`,
  )
  const payload = JSON.parse(readFileSync(handoffPath, 'utf8'))
  check(payload.artifactKind === 'hosted-storybook-handoff', 'handoff artifact kind must match.')
  check(payload.status === 'blocked', 'failing Storybook live output must produce blocked status.')
  check(payload.localPublication.publishTargetReady === true, 'publication manifest must target Storybook.')
  check(
    payload.localPublication.storyIds.includes('receipt-proof-journey') &&
      payload.localPublication.storyIds.includes('visual-governance-workbench') &&
      payload.localPublication.storyIds.includes('operator-decision-rail') &&
      payload.localPublication.storyIds.includes('launch-proof-ladder') &&
      payload.localPublication.storyIds.includes('deploy-readiness-boundary'),
    'handoff must include expected buyer-evidence story ids.',
  )
  check(
    payload.liveVerification.storybookBlockers.some(
      (blocker) => blocker.blockerId === 'live-storybook-dns',
    ) &&
      payload.liveVerification.storybookBlockers.some(
        (blocker) => blocker.blockerId === 'live-storybook-manifest',
      ),
    'handoff must carry hosted Storybook live blockers.',
  )
  check(
    payload.copyIntoProductionEvidence.hostedStorybook.status === 'pending' &&
      payload.copyIntoProductionEvidence.remainingBlocker === 'hosted-storybook-buyer-evidence',
    'blocked handoff must preserve hosted-storybook-buyer-evidence blocker.',
  )
  check(
    payload.claimBoundary.includes('not live production proof') &&
      payload.claimBoundary.includes('does not deploy'),
    'handoff claim boundary must stay conservative.',
  )

  const requireClearResult = runBuilder([
    '--buyer-evidence-manifest',
    join(publicationDir, 'manifest.json'),
    '--live-output',
    livePath,
    '--out',
    join(tempDir, 'require-clear-handoff.json'),
    '--require-live-clear',
    '--json',
  ])
  check(requireClearResult.status !== 0, '--require-live-clear must fail with blockers.')

  const passResult = runBuilder([
    '--buyer-evidence-manifest',
    join(publicationDir, 'manifest.json'),
    '--live-output',
    passLivePath,
    '--out',
    join(tempDir, 'pass-handoff.json'),
    '--require-live-clear',
    '--json',
  ])
  check(
    passResult.status === 0,
    `passing Storybook live output must satisfy --require-live-clear: ${passResult.stderr}`,
  )
  const passPayload = JSON.parse(passResult.stdout)
  check(
    passPayload.status === 'live-verifier-clear' &&
      passPayload.copyIntoProductionEvidence.hostedStorybook.status === 'verified',
    'passing Storybook live output must produce verified hostedStorybook copy fields.',
  )
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Hosted Storybook handoff check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Hosted Storybook handoff check passed.')
