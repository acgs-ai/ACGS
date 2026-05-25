import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
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

const packageJson = JSON.parse(read('package.json'))
const verifierPath = 'scripts/verify-production-live.mjs'
const checkerPath = 'scripts/check-production-live-verifier.mjs'
const verifier = read(verifierPath)
const checker = read(checkerPath)
const productionEvidence = JSON.parse(read('production-evidence.example.json'))
const productionEvidenceText = read('production-evidence.example.json')
const deploy = read('DEPLOY.md')
const handoff = read('PRODUCTION-LAUNCH.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const productionEvidenceTemplateCheck = read('scripts/check-production-evidence-template.mjs')
const productionBlockerReportCheck = read('scripts/check-production-blocker-report.mjs')
const productionEvidenceValidatorCheck = read('scripts/check-production-evidence-validator.mjs')
const productionLaunchHandoffCheck = read('scripts/check-production-launch-handoff.mjs')
const hostedStorybookHandoffCheck = read('scripts/check-hosted-storybook-handoff.mjs')
const hostedStorybookProofTemplate = read('hosted-storybook-proof.example.json')
const hostedStorybookProofTemplateCheck = read('scripts/check-hosted-storybook-proof-template.mjs')

check(existsSync(resolve(root, verifierPath)), `${verifierPath} must exist.`)
check(existsSync(resolve(root, checkerPath)), `${checkerPath} must exist.`)
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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-live-verifier'),
  'package.json test:all must include production live verifier local wiring.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-blocker-report'),
  'package.json test:all must include production blocker report local wiring.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:production-evidence-validator'),
  'package.json test:all must include production evidence validator local wiring.',
)
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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-handoff'),
  'package.json test:all must include hosted Storybook handoff local wiring.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-proof-template'),
  'package.json test:all must include hosted Storybook proof template local wiring.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run verify:production-live'),
  'package.json test:all must not run the live network verifier.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:production-blocker-report'),
  'package.json test:all must not run the input-dependent production blocker report builder.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:hosted-storybook-handoff'),
  'package.json test:all must not run the input-dependent hosted Storybook handoff builder.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run validate:production-evidence'),
  'package.json test:all must not run operator-specific production evidence validation.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run validate:hosted-storybook-proof'),
  'package.json test:all must not run operator-specific hosted Storybook proof validation.',
)
check(
  packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-evidence-template') <
    packageJson.scripts?.['test:all']?.indexOf('pnpm run test:production-live-verifier'),
  'package.json test:all must run production evidence template before the local live-verifier wiring check.',
)

for (const needle of [
  'lookup',
  'fetch',
  'https://acgs.ai',
  'https://console.acgs.ai',
  'https://storybook.acgs.ai',
  '/healthz',
  '/manifest.json',
  'EXPECTED_SERVED_HASH',
  'EXPECTED_BUILD_ID',
  '608508a9bd224290',
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'X-Frame-Options',
  'Referrer-Policy',
  'claimBoundary',
  'production-live-verification',
  'blockedUntil',
  'blockers',
  'live-console-dns',
  'live-storybook-dns',
  'live-storybook-manifest',
  'storybook-manifest-live',
  'local-buyer-evidence-gallery',
  'receipt-proof-journey',
  'bus-owned-proof-source',
  'claim-safe-trust-surface',
  'visual-governance-workbench',
  'launch-proof-ladder',
  'deploy-readiness-boundary',
  '--json',
  '--out',
  '--timeout-ms',
  '--allow-storybook-pending',
]) {
  mustContain(verifier, needle, verifierPath)
}

const help = spawnSync(process.execPath, [verifierPath, '--help'], {
  cwd: root,
  encoding: 'utf8',
})
check(help.status === 0, 'verify-production-live --help must exit zero.')
check(help.stdout.includes('--json'), 'verify-production-live --help must document --json.')
check(help.stdout.includes('--out'), 'verify-production-live --help must document --out.')
check(
  help.stdout.includes('not part of pnpm test:all'),
  'verify-production-live --help must state the live network command is not part of test:all.',
)

const tempDir = mkdtempSync(join(tmpdir(), 'production-live-verifier-'))
try {
  const outPath = join(tempDir, 'verify-production-live.json')
  const savedOutput = spawnSync(
    process.execPath,
    [
      verifierPath,
      '--json',
      '--out',
      outPath,
      '--timeout-ms',
      '50',
      '--marketing-url',
      'https://127.0.0.1',
      '--console-url',
      'https://127.0.0.1',
      '--storybook-url',
      'https://127.0.0.1',
    ],
    {
      cwd: root,
      encoding: 'utf8',
    },
  )
  check(savedOutput.status !== 0, 'loopback live verifier run should fail but still save JSON.')
  check(existsSync(outPath), 'verify-production-live --out must write a JSON artifact on fail.')
  if (existsSync(outPath)) {
    const saved = JSON.parse(readFileSync(outPath, 'utf8'))
    const printed = JSON.parse(savedOutput.stdout)
    check(
      saved.artifactKind === 'production-live-verification' && saved.status === 'fail',
      '--out artifact must be a failing production-live-verification payload for blocked runs.',
    )
    check(
      printed.generatedAt === saved.generatedAt &&
        Array.isArray(saved.blockers) &&
        saved.blockers.length > 0,
      '--json stdout and --out artifact must describe the same blocked live verifier run.',
    )
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

check(
  productionEvidence.verification?.productionLiveCommand ===
    'pnpm -F acgi-ai run verify:production-live -- --json',
  'production-evidence.example.json must name the live verifier command.',
)
check(
  productionEvidence.verification?.productionLiveOutputRef ===
    'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH',
  'production-evidence.example.json must require a production live verifier output artifact or hash.',
)
check(
  productionEvidence.artifacts?.verifyProductionLiveOutput ===
    'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH',
  'production-evidence.example.json must expose the production live verifier artifact slot.',
)
check(
  productionEvidence.verification?.productionLiveStatus ===
    'REPLACE_WITH_PASS_OR_FAIL_FROM_VERIFY_PRODUCTION_LIVE',
  'production-evidence.example.json must capture productionLiveStatus from the live verifier.',
)
check(
  Array.isArray(productionEvidence.verification?.productionLiveBlockers) &&
    productionEvidence.verification.productionLiveBlockers.includes(
      'REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY',
    ),
  'production-evidence.example.json must capture productionLiveBlockers from the live verifier.',
)
check(
  productionEvidence.verification?.productionEvidenceValidationCommand?.includes(
    'validate:production-evidence',
  ),
  'production-evidence.example.json must name the production evidence validator command.',
)
check(
  productionEvidence.verification?.productionEvidenceValidationOutputRef ===
    'REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH',
  'production-evidence.example.json must require validator output evidence.',
)
check(
  productionEvidence.artifacts?.validatedProductionEvidence ===
    'REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH',
  'production-evidence.example.json must expose the validated production evidence artifact slot.',
)
check(
  productionEvidence.hostedStorybook?.manifestUrl === 'https://storybook.acgs.ai/manifest.json',
  'production-evidence.example.json must expose the hosted Storybook manifest URL.',
)

for (const needle of [
  'verify:production-live',
  'validate:production-evidence',
  'productionLiveStatus',
  'productionLiveBlockers',
  'REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH',
  'REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY',
  'REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH',
  'not live production proof',
  'pending-external',
]) {
  mustContain(productionEvidenceText, needle, 'production-evidence.example.json')
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['production evidence template checker', productionEvidenceTemplateCheck],
  ['production blocker report checker', productionBlockerReportCheck],
  ['production evidence validator checker', productionEvidenceValidatorCheck],
  ['production launch handoff checker', productionLaunchHandoffCheck],
  ['security invariants checker', securityCheck],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['production live verifier checker', checker],
]) {
  mustContain(source, 'verify:production-live', label)
  mustContain(source, 'test:production-live-verifier', label)
  mustContain(source, 'build:production-blocker-report', label)
  mustContain(source, 'test:production-blocker-report', label)
  mustContain(source, 'production-blocker-report', label)
  mustContain(source, 'copyIntoProductionEvidence', label)
  mustContain(source, 'validate:production-evidence', label)
  mustContain(source, 'test:production-evidence-validator', label)
  mustContain(source, 'not live production proof', label)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['hosted Storybook handoff checker', hostedStorybookHandoffCheck],
  ['hosted Storybook proof template', hostedStorybookProofTemplate],
  ['hosted Storybook proof template checker', hostedStorybookProofTemplateCheck],
  ['security invariants checker', securityCheck],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['production live verifier checker', checker],
]) {
  mustContain(source, 'build:hosted-storybook-handoff', label)
  mustContain(source, 'test:hosted-storybook-handoff', label)
  mustContain(source, 'hosted-storybook-handoff', label)
  mustContain(source, 'hosted-storybook-handoff.json', label)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['platform readiness report', platformReadiness],
  ['release evidence builder', releaseEvidence],
  ['hosted Storybook handoff checker', hostedStorybookHandoffCheck],
  ['hosted Storybook proof template', hostedStorybookProofTemplate],
  ['hosted Storybook proof template checker', hostedStorybookProofTemplateCheck],
  ['security invariants checker', securityCheck],
  ['CI readiness gate checker', ciReadinessGateCheck],
  ['production live verifier checker', checker],
]) {
  mustContain(source, 'hosted-storybook-proof.example.json', label)
  mustContain(source, 'test:hosted-storybook-proof-template', label)
  mustContain(source, 'validate:hosted-storybook-proof', label)
  mustContain(source, 'storybook-manifest-live', label)
  mustContain(source, 'pending-external:storybook-pages-proof', label)
  mustContain(source, 'copyIntoProductionEvidence.hostedStorybook', label)
  mustContain(source, 'not hosted Storybook proof', label)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['integration readiness map', readiness],
  ['release evidence builder', releaseEvidence],
]) {
  mustContain(source, 'console.acgs.ai', label)
  mustContain(source, 'storybook.acgs.ai', label)
  mustContain(source, 'pending-external', label)
}

for (const [label, source] of [
  ['DEPLOY.md', deploy],
  ['PRODUCTION-LAUNCH.md', handoff],
  ['production live verifier checker', checker],
]) {
  mustContain(
    source,
    '--out ../dist-release-evidence/production-live-verification.json',
    label,
  )
}
mustContain(releaseEvidence, 'savedOutputCommand', 'release evidence builder')
mustContain(releaseEvidence, '--out', 'release evidence builder')
mustContain(
  releaseEvidence,
  '../dist-release-evidence/production-live-verification.json',
  'release evidence builder',
)

if (failures.length > 0) {
  console.error('Production live verifier check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Production live verifier check passed.')
