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
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const gettingStarted = read('GETTING_STARTED.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const rootReadme = readRepo('README.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')

check(
  packageJson.scripts?.['evidence:build'] === 'node scripts/build-buyer-evidence.mjs',
  'package.json must expose evidence:build.',
)
check(
  packageJson.scripts?.['storybook:build'] === 'pnpm run evidence:build',
  'package.json must expose storybook:build as a dependency-free local evidence alias.',
)
check(
  packageJson.scripts?.['test:buyer-evidence'] === 'node scripts/check-buyer-evidence-artifact.mjs',
  'package.json must expose test:buyer-evidence.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:buyer-evidence'),
  'package.json test:all must include test:buyer-evidence.',
)

for (const needle of [
  'local-buyer-evidence-gallery',
  'Receipt proof journey',
  'Bus-owned proof source',
  'Claim-safe trust surface',
  'Deploy readiness boundary',
  'not hosted Storybook',
  'not production deployment proof',
]) {
  mustContain(buildScript, needle, 'scripts/build-buyer-evidence.mjs')
}

for (const [label, source] of [
  ['ARCHITECTURE.md', architecture],
  ['DEPLOY.md', deploy],
  ['GETTING_STARTED.md', gettingStarted],
  ['README.md', rootReadme],
  ['docs/integration-readiness-task-map.md', readiness],
]) {
  mustContain(source, 'evidence:build', label)
  mustContain(source, 'test:buyer-evidence', label)
  mustContain(source, 'local buyer-evidence', label)
}

mustContain(
  platformReadiness,
  'buyer-evidence-gallery-local',
  'scripts/platform_readiness_report.py',
)
mustContain(
  platformReadiness,
  'hosted-storybook-buyer-evidence',
  'scripts/platform_readiness_report.py',
)

const outRelative = `.buyer-evidence-check-${process.pid}`
const outDir = resolve(root, outRelative)
try {
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(outDir, { recursive: true })
  execFileSync('node', ['scripts/build-buyer-evidence.mjs'], {
    cwd: root,
    env: { ...process.env, ACGI_EVIDENCE_OUT_DIR: outRelative },
    stdio: 'pipe',
  })

  const htmlPath = resolve(outDir, 'index.html')
  const manifestPath = resolve(outDir, 'manifest.json')
  check(existsSync(htmlPath), 'evidence build must write index.html.')
  check(existsSync(manifestPath), 'evidence build must write manifest.json.')

  if (existsSync(htmlPath)) {
    const html = readFileSync(htmlPath, 'utf8')
    for (const needle of [
      'ACGS buyer evidence gallery',
      'Receipt proof journey',
      'signed evidence packet',
      'not the hosted',
      'not live Cloud Run/Vercel proof',
    ]) {
      mustContain(html, needle, 'generated index.html')
    }
    check(
      !/production[- ]ready|SOC 2 certified|WCAG 2\.2 AA conformant|compliance certification/i.test(
        html,
      ),
      'generated index.html must not contain unsupported production/compliance claims.',
    )
  }

  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    check(
      manifest.artifactKind === 'local-buyer-evidence-gallery',
      'manifest must identify the local buyer evidence gallery artifact kind.',
    )
    check(
      manifest.claimBoundary.includes('not production deployment proof'),
      'manifest must preserve the production-proof boundary.',
    )
    check(
      Array.isArray(manifest.stories) && manifest.stories.length >= 4,
      'manifest must include at least four buyer-evidence stories.',
    )
  }
} catch (error) {
  failures.push(`could not build buyer evidence gallery: ${error.message}`)
} finally {
  rmSync(outDir, { force: true, recursive: true })
}

if (failures.length > 0) {
  console.error('Buyer evidence artifact check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Buyer evidence artifact check passed.')
