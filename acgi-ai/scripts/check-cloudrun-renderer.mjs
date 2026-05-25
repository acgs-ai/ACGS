import { execFileSync, spawnSync } from 'node:child_process'
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
  check(source.includes(needle), `${label} must include ${needle}.`)
}

const packageJson = JSON.parse(read('package.json'))
const renderScript = read('scripts/render-cloudrun-service.mjs')
const cloudrunCheck = read('scripts/check-cloudrun-templates.mjs')
const authCheck = read('scripts/check-auth-boundary.mjs')
const busCheck = read('scripts/check-bus-proxy-contract.mjs')
const consoleWorkflow = readRepo('.github/workflows/console.yml')
const deployDoc = read('DEPLOY.md')
const readinessMap = readRepo('docs/integration-readiness-task-map.md')
const platformReadiness = readRepo('scripts/platform_readiness_report.py')
const releaseEvidence = readRepo('scripts/build_release_evidence.py')

check(
  existsSync(resolve(root, 'scripts/render-cloudrun-service.mjs')),
  'render-cloudrun-service.mjs must exist.',
)
for (const needle of [
  'REPLACE_AT_DEPLOY_TIME',
  'REPLACE_BUILD_ID_AT_DEPLOY_TIME',
  'REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME',
  'REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME',
  'replaceExactlyOnce',
  'rendered service.yaml still contains REPLACE_* placeholders',
  'must start with http:// or https://',
]) {
  mustContain(renderScript, needle, 'scripts/render-cloudrun-service.mjs')
}

check(
  packageJson.scripts?.['render:cloudrun'] === 'node scripts/render-cloudrun-service.mjs',
  'package.json must expose render:cloudrun.',
)
check(
  packageJson.scripts?.['test:cloudrun-renderer'] === 'node scripts/check-cloudrun-renderer.mjs',
  'package.json must expose test:cloudrun-renderer.',
)
check(
  packageJson.scripts?.['test:contract']?.includes('pnpm run test:cloudrun-renderer'),
  'package.json test:contract must include cloudrun renderer verification.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:cloudrun-renderer'),
  'package.json test:all must include cloudrun renderer verification.',
)

for (const source of [cloudrunCheck, authCheck, busCheck]) {
  mustContain(source, 'render-cloudrun-service.mjs', 'Cloud Run/auth/bus contract checks')
}

check(
  /node scripts\/render-cloudrun-service\.mjs[\s\S]*--env "\$\{DEPLOY_ENV\}"[\s\S]*--image "\$\{IMAGE_URI\}"[\s\S]*--build-id "\$\{BUILD_ID\}"[\s\S]*--auth-upstream "\$\{AUTH_UPSTREAM\}"[\s\S]*--bus-upstream "\$\{BUS_UPSTREAM\}"[\s\S]*--out infra\/cloudrun\/service\.yaml/.test(
    consoleWorkflow,
  ),
  'console.yml must render service.yaml through the shared fail-closed renderer.',
)
check(
  !/sed -i "s\|REPLACE_/.test(consoleWorkflow) && !/cp "\$SERVICE_TEMPLATE"/.test(consoleWorkflow),
  'console.yml must not duplicate renderer substitutions with cp/sed.',
)

for (const source of [deployDoc, readinessMap, platformReadiness, releaseEvidence]) {
  mustContain(source, 'test:cloudrun-renderer', 'deployment docs/readiness evidence')
  mustContain(source, 'render-cloudrun-service.mjs', 'deployment docs/readiness evidence')
}

const checkDir = resolve(root, `.cloudrun-render-check-${process.pid}`)
const renderedPath = resolve(checkDir, 'service.yaml')
try {
  mkdirSync(checkDir, { recursive: true })
  execFileSync(
    process.execPath,
    [
      'scripts/render-cloudrun-service.mjs',
      '--env',
      'production',
      '--image',
      'us-central1-docker.pkg.dev/acgs/acgi/acgi-console:test123',
      '--build-id',
      'test123',
      '--auth-upstream',
      'https://auth.internal.example/authorize',
      '--bus-upstream',
      'https://bus.internal.example',
      '--out',
      renderedPath,
    ],
    { cwd: root, stdio: 'pipe' },
  )
  const rendered = readFileSync(renderedPath, 'utf8')
  check(
    rendered.includes('us-central1-docker.pkg.dev/acgs/acgi/acgi-console:test123'),
    'rendered service must include the image URI.',
  )
  check(rendered.includes('value: "test123"'), 'rendered service must include the build ID.')
  check(
    rendered.includes('https://auth.internal.example/authorize'),
    'rendered service must include AUTH_UPSTREAM.',
  )
  check(
    rendered.includes('https://bus.internal.example'),
    'rendered service must include BUS_UPSTREAM.',
  )
  check(
    rendered.includes('autoscaling.knative.dev/minScale: "2"'),
    'production render must use the production template.',
  )
  check(!/REPLACE_[A-Z_]+/.test(rendered), 'rendered service must not contain placeholders.')

  const missingAuth = spawnSync(
    process.execPath,
    [
      'scripts/render-cloudrun-service.mjs',
      '--env',
      'production',
      '--image',
      'image:test',
      '--build-id',
      'test123',
      '--bus-upstream',
      'https://bus.internal.example',
      '--out',
      resolve(checkDir, 'missing-auth.yaml'),
    ],
    { cwd: root, encoding: 'utf8' },
  )
  check(missingAuth.status !== 0, 'renderer must fail closed when AUTH_UPSTREAM is missing.')
  check(
    /AUTH_UPSTREAM is required/.test(`${missingAuth.stderr}\n${missingAuth.stdout}`),
    'missing AUTH_UPSTREAM failure must name the missing deploy secret.',
  )
} finally {
  rmSync(checkDir, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Cloud Run renderer contract check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Cloud Run renderer contract check passed.')
