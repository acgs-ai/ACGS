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
const capture = read('scripts/capture-workbench-browser-evidence.mjs')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const gettingStarted = read('GETTING_STARTED.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const readinessReport = readRepo('scripts/platform_readiness_report.py')

check(
  packageJson.scripts?.['evidence:browser-workbench'] ===
    'node scripts/capture-workbench-browser-evidence.mjs',
  'package.json must expose evidence:browser-workbench.',
)
check(
  packageJson.scripts?.['test:browser-evidence'] ===
    'node scripts/check-browser-evidence-foundation.mjs',
  'package.json must expose test:browser-evidence.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:browser-evidence'),
  'package.json test:all must include test:browser-evidence.',
)

for (const needle of [
  'local-browser-workbench-evidence',
  'WORKBENCH_BROWSER_TARGETS',
  'BROWSER_EVIDENCE_VIEWPORTS',
  '/#workbench',
  '/console/workbench',
  '/console/workbench#operator-decision-rail',
  '/console/workbench#guided-review-path',
  '/console/workbench#framework-integration-rail',
  '/console/workbench#launch-proof-ladder',
  '/console/workbench#live-verifier-blocker-map',
  '/console/workbench#production-command-rail',
  '/console/workbench#assurance-proof-intake',
  '--headless=new',
  '--dump-dom',
  'Page.captureScreenshot',
  'scrollIntoView',
  'targetVisibleHash',
  'VITE_BYPASS_SESSION',
  'VITE_USE_MOCKS',
  'VITE_ACGI_SURFACE',
  'expectedText',
  'assertRenderedDom',
  'assertScreenshotContent',
  'sameViewportHashDiversity',
  'not production deployment proof',
  'not WCAG conformance proof',
]) {
  mustContain(capture, needle, 'scripts/capture-workbench-browser-evidence.mjs')
}

for (const [label, source] of [
  ['ARCHITECTURE.md', architecture],
  ['DEPLOY.md', deploy],
  ['GETTING_STARTED.md', gettingStarted],
  ['docs/integration-readiness-task-map.md', readiness],
]) {
  mustContain(source, 'evidence:browser-workbench', label)
  mustContain(source, 'test:browser-evidence', label)
  mustContain(source, 'local browser evidence', label)
  mustContain(source, 'not production deployment proof', label)
}

mustContain(
  readinessReport,
  'browser-workbench-evidence-local',
  'scripts/platform_readiness_report.py',
)
mustContain(readinessReport, 'evidence:browser-workbench', 'scripts/platform_readiness_report.py')
mustContain(
  readinessReport,
  '/console/workbench#operator-decision-rail',
  'scripts/platform_readiness_report.py',
)
mustContain(
  readinessReport,
  '/console/workbench#framework-integration-rail',
  'scripts/platform_readiness_report.py',
)
mustContain(
  readinessReport,
  '/console/workbench#live-verifier-blocker-map',
  'scripts/platform_readiness_report.py',
)
mustContain(
  readinessReport,
  '/console/workbench#production-command-rail',
  'scripts/platform_readiness_report.py',
)
mustContain(
  readinessReport,
  '/console/workbench#assurance-proof-intake',
  'scripts/platform_readiness_report.py',
)

const outRelative = `.browser-evidence-check-${process.pid}`
const outDir = resolve(root, outRelative)
try {
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(outDir, { recursive: true })
  execFileSync('node', ['scripts/capture-workbench-browser-evidence.mjs', '--dry-run'], {
    cwd: root,
    env: { ...process.env, ACGI_BROWSER_EVIDENCE_OUT_DIR: outRelative },
    stdio: 'pipe',
  })

  const manifestPath = resolve(outDir, 'manifest.json')
  check(existsSync(manifestPath), 'dry-run must write manifest.json.')
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    check(
      manifest.artifactKind === 'local-browser-workbench-evidence',
      'manifest must identify the browser workbench evidence artifact kind.',
    )
    check(manifest.status === 'dry-run-plan', 'dry-run manifest status must be dry-run-plan.')
    check(manifest.targets?.length === 9, 'manifest must include nine browser targets.')
    check(
      manifest.targets?.some((target) => target.surface === 'marketing') === true &&
        manifest.targets?.some((target) => target.surface === 'console') === true,
      'manifest targets must cover both marketing and console surfaces.',
    )
    check(manifest.viewports?.length === 5, 'manifest must include five visual viewports.')
    check(
      manifest.screenshotGuard?.minimumBytes >= 12000,
      'manifest must record a minimum screenshot byte guard.',
    )
    check(
      manifest.screenshots?.length === 45,
      'manifest must plan one screenshot per target/viewport.',
    )
    mustContain(JSON.stringify(manifest.targets), 'console-decision-rail', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'console-framework-integration-rail', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'runtime.malformed_batch', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'Pick the case', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'console-guided-review-path', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'Export bounded proof', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'console-launch-proof-ladder', 'dry-run manifest')
    mustContain(JSON.stringify(manifest.targets), 'Current saved cutover state', 'dry-run manifest')
    mustContain(
      JSON.stringify(manifest.targets),
      'console-live-verifier-blocker-map',
      'dry-run manifest',
    )
    mustContain(JSON.stringify(manifest.targets), 'live-console-dns', 'dry-run manifest')
    mustContain(
      JSON.stringify(manifest.targets),
      'console-production-command-rail',
      'dry-run manifest',
    )
    mustContain(
      JSON.stringify(manifest.targets),
      'make production-blocker-evidence',
      'dry-run manifest',
    )
    mustContain(
      JSON.stringify(manifest.targets),
      'console-assurance-proof-intake',
      'dry-run manifest',
    )
    mustContain(JSON.stringify(manifest.targets), 'Legal claim review', 'dry-run manifest')
    mustContain(manifest.claimBoundary ?? '', 'not production deployment proof', 'dry-run manifest')
    mustContain(manifest.claimBoundary ?? '', 'not WCAG conformance proof', 'dry-run manifest')
  }
} catch (error) {
  failures.push(`could not dry-run browser workbench evidence capture: ${error.message}`)
} finally {
  rmSync(outDir, { force: true, recursive: true })
}

if (failures.length > 0) {
  console.error('Browser evidence foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Browser evidence foundation check passed.')
