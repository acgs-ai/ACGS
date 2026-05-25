import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
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

const packageJson = JSON.parse(read('package.json'))
const buildScript = read('scripts/build-buyer-evidence.mjs')
const workflow = readRepo('.github/workflows/storybook.yml')
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')
const hostedStorybookHandoffBuilder = read('scripts/build-hosted-storybook-handoff.mjs')
const hostedStorybookHandoffCheck = read('scripts/check-hosted-storybook-handoff.mjs')

check(
  packageJson.scripts?.['storybook:build'] === 'pnpm run evidence:build',
  'package.json must keep storybook:build as the current buyer-evidence build entry point.',
)
check(
  packageJson.scripts?.['test:storybook-publication'] ===
    'node scripts/check-storybook-publication.mjs',
  'package.json must expose test:storybook-publication.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:storybook-publication'),
  'package.json test:all must include storybook publication verification.',
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
  packageJson.scripts?.['test:all']?.includes('pnpm run test:hosted-storybook-handoff'),
  'package.json test:all must include hosted Storybook handoff verification.',
)
check(
  !packageJson.scripts?.['test:all']?.includes('pnpm run build:hosted-storybook-handoff'),
  'package.json test:all must not run the input-dependent hosted Storybook handoff builder.',
)

for (const needle of [
  'ACGI_EVIDENCE_CNAME',
  'CNAME',
  '.nojekyll',
  'github-pages-custom-domain',
  'hostedProofRequirements',
  'publishTarget',
  'storybook.acgs.ai',
]) {
  mustContain(buildScript, needle, 'scripts/build-buyer-evidence.mjs')
}

for (const needle of [
  'name: buyer-evidence-storybook',
  'branches: [master]',
  "node-version: '24'",
  'pnpm install --frozen-lockfile --ignore-workspace',
  'pnpm test:storybook-publication',
  'ACGI_EVIDENCE_CNAME: storybook.acgs.ai',
  'pnpm storybook:build',
  'buyer-evidence-storybook',
  'actions/upload-pages-artifact@v3',
  "vars.STORYBOOK_PAGES_ENABLED == 'true'",
  'actions/deploy-pages@v4',
  'url: https://storybook.acgs.ai',
]) {
  mustContain(workflow, needle, '.github/workflows/storybook.yml')
}

for (const source of [deploy, readiness, platformReadiness, releaseEvidence]) {
  mustContain(source, 'test:storybook-publication', 'storybook publication evidence')
  mustContain(source, 'storybook.acgs.ai', 'storybook publication evidence')
  mustContain(source, 'build:hosted-storybook-handoff', 'hosted Storybook handoff evidence')
  mustContain(source, 'test:hosted-storybook-handoff', 'hosted Storybook handoff evidence')
  mustContain(source, 'hosted-storybook-handoff', 'hosted Storybook handoff evidence')
  mustContain(source, 'hosted-storybook-handoff.json', 'hosted Storybook handoff evidence')
}

for (const source of [hostedStorybookHandoffBuilder, hostedStorybookHandoffCheck]) {
  mustContain(source, 'storybook.acgs.ai', 'hosted Storybook handoff contract')
  mustContain(source, 'storybook-manifest-live', 'hosted Storybook handoff contract')
  mustContain(source, 'pending-external:storybook-pages-proof', 'hosted Storybook handoff contract')
  mustContain(source, 'copyIntoProductionEvidence', 'hosted Storybook handoff contract')
  mustContain(source, 'not live production proof', 'hosted Storybook handoff contract')
}

const outRelative = `.storybook-publication-check-${process.pid}`
const outDir = resolve(root, outRelative)
try {
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(outDir, { recursive: true })
  execFileSync('node', ['scripts/build-buyer-evidence.mjs'], {
    cwd: root,
    env: {
      ...process.env,
      ACGI_EVIDENCE_OUT_DIR: outRelative,
      ACGI_EVIDENCE_CNAME: 'storybook.acgs.ai',
    },
    stdio: 'pipe',
  })

  const cnamePath = resolve(outDir, 'CNAME')
  const nojekyllPath = resolve(outDir, '.nojekyll')
  const manifestPath = resolve(outDir, 'manifest.json')
  check(existsSync(cnamePath), 'published buyer evidence artifact must include a CNAME file.')
  check(existsSync(nojekyllPath), 'published buyer evidence artifact must include .nojekyll.')
  if (existsSync(cnamePath)) {
    check(
      readFileSync(cnamePath, 'utf8').trim() === 'storybook.acgs.ai',
      'CNAME must target storybook.acgs.ai.',
    )
  }
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    check(
      manifest.publishTarget === 'https://storybook.acgs.ai',
      'manifest publishTarget must identify the hosted buyer-evidence target.',
    )
    check(
      manifest.publication?.mode === 'github-pages-custom-domain',
      'manifest publication mode must identify GitHub Pages custom-domain publishing.',
    )
    check(
      manifest.publication?.customDomain === 'storybook.acgs.ai',
      'manifest publication customDomain must match storybook.acgs.ai.',
    )
    check(
      manifest.publication?.requiredFiles?.includes('CNAME') &&
        manifest.publication?.requiredFiles?.includes('.nojekyll'),
      'manifest publication requiredFiles must include CNAME and .nojekyll.',
    )
    check(
      JSON.stringify(manifest.publication?.hostedProofRequirements ?? []).includes(
        'storybook-manifest-live',
      ),
      'manifest publication must list the Storybook live manifest proof requirement.',
    )
    check(
      manifest.claimBoundary.includes('not production deployment proof'),
      'manifest must preserve the production-proof boundary even for hosted publication.',
    )
  }
} catch (error) {
  failures.push(`could not build Storybook publication artifact: ${error.message}`)
} finally {
  rmSync(outDir, { force: true, recursive: true })
}

if (failures.length > 0) {
  console.error('Storybook publication contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Storybook publication contract check passed.')
