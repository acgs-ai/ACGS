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
  'Visual governance workbench',
  'Operator decision rail',
  'Launch proof ladder',
  'Deploy readiness boundary',
  'operator-decision-rail',
  'Pick the case',
  'Inspect the path',
  'Decide and export',
  'Operator quick start',
  'Guided review path',
  'Start here',
  'Hold release',
  'Export proof',
  'Choose the case',
  'Follow the path',
  'Check the hold',
  'Export bounded proof',
  'Local readiness',
  'Live verifier',
  'Assurance packet',
  'Current saved cutover lanes',
  'Release blocker queue',
  'owner, proof artifact, and unblock command',
  'production-deployment',
  'frontend-production-auth',
  'Framework integration rail',
  'Agent framework starter kits',
  'OpenAI Responses',
  'LangChain',
  'MCP / Claude / Codex hooks',
  'uv run --package gove-zone gove-zone gate',
  'uv run --package gove-zone gove-zone eval',
  'Live verifier blocker map',
  'live-console-dns',
  'Production command rail',
  'make production-blocker-evidence',
  'Hosted Storybook runway',
  'Build local gallery',
  'Build proof gap report',
  'hosted-storybook-proof-gap-report.json',
  'STORYBOOK_PAGES_ENABLED=true',
  'copyIntoProductionEvidence.hostedStorybook',
  'Assurance proof intake',
  'production-authority.example.json',
  'verify:production-live',
  '.nojekyll',
  'hostedProofRequirements',
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
  const nojekyllPath = resolve(outDir, '.nojekyll')
  check(existsSync(htmlPath), 'evidence build must write index.html.')
  check(existsSync(manifestPath), 'evidence build must write manifest.json.')
  check(existsSync(nojekyllPath), 'evidence build must write .nojekyll for Pages readiness.')

  if (existsSync(htmlPath)) {
    const html = readFileSync(htmlPath, 'utf8')
    for (const needle of [
      'ACGS buyer evidence gallery',
      'Receipt proof journey',
      'Visual governance workbench',
      'Operator decision rail',
      'Launch proof ladder',
      'next safe action',
      'Pick the case',
      'Inspect the path',
      'Decide and export',
      'Operator quick start',
      'Guided review path',
      'Start here',
      'Hold release',
      'Export proof',
      'Choose the case',
      'Follow the path',
      'Check the hold',
      'Export bounded proof',
      'Local readiness',
      'Live verifier',
      'Assurance packet',
      'Current saved cutover lanes',
      'Release blocker queue',
      'owner, proof artifact, and unblock command',
      'production-deployment',
      'frontend-production-auth',
      'Framework integration rail',
      'Agent framework starter kits',
      'OpenAI Responses',
      'LangChain',
      'MCP / Claude / Codex hooks',
      'uv run --package gove-zone gove-zone gate',
      'uv run --package gove-zone gove-zone eval',
      'Live verifier blocker map',
      'live-console-dns',
      'Production command rail',
      'make production-blocker-evidence',
      'Hosted Storybook runway',
      'Build local gallery',
      'Build proof gap report',
      'hosted-storybook-proof-gap-report.json',
      'Build proof gap report',
      'hosted-storybook-proof-gap-report.json',
      'STORYBOOK_PAGES_ENABLED=true',
      'copyIntoProductionEvidence.hostedStorybook',
      'Assurance proof intake',
      'production-authority.example.json',
      'verify:production-live',
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
      Array.isArray(manifest.stories) && manifest.stories.length >= 8,
      'manifest must include at least eight buyer-evidence stories.',
    )
    check(
      JSON.stringify(manifest.stories).includes('operator-decision-rail'),
      'manifest must include the operator decision rail story.',
    )
    check(
      JSON.stringify(manifest.stories).includes('guided-review-path'),
      'manifest must include the guided review path story.',
    )
    check(
      JSON.stringify(manifest.stories).includes('visual-governance-workbench'),
      'manifest must include the visual governance workbench story.',
    )
    check(
      JSON.stringify(manifest.stories).includes('launch-proof-ladder'),
      'manifest must include the launch proof ladder story.',
    )
    check(
      manifest.publication?.requiredFiles?.includes('.nojekyll'),
      'manifest publication requiredFiles must include .nojekyll.',
    )
    check(
      JSON.stringify(manifest.publication?.hostedProofRequirements ?? []).includes(
        'storybook-manifest-live',
      ),
      'manifest must preserve hosted proof requirements for Storybook manifest verification.',
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
