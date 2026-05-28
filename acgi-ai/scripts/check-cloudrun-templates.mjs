import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readIfExists(relativePath) {
  const path = resolve(root, relativePath)
  return existsSync(path) ? readFileSync(path, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function scalarRegex(key, value) {
  return new RegExp(`${escapeRegExp(key)}:\\s+"?${escapeRegExp(value)}"?`)
}

const environments = {
  preview: {
    minScale: '0',
    concurrency: '80',
    memory: '256Mi',
  },
  staging: {
    minScale: '1',
    concurrency: '80',
    memory: '512Mi',
  },
  production: {
    minScale: '2',
    concurrency: '60',
    memory: '1Gi',
  },
}

for (const [environment, contract] of Object.entries(environments)) {
  const relativePath = `infra/cloudrun/service.${environment}.yaml`
  const path = resolve(root, relativePath)
  check(existsSync(path), `${relativePath} must exist.`)
  const manifest = existsSync(path) ? readFileSync(path, 'utf8') : ''

  check(
    scalarRegex('autoscaling.knative.dev/minScale', contract.minScale).test(manifest),
    `${relativePath} must set minScale=${contract.minScale}.`,
  )
  check(
    scalarRegex('containerConcurrency', contract.concurrency).test(manifest),
    `${relativePath} must set containerConcurrency=${contract.concurrency}.`,
  )
  check(
    scalarRegex('memory', contract.memory).test(manifest),
    `${relativePath} must set memory=${contract.memory}.`,
  )
  check(
    /image:\s+REPLACE_AT_DEPLOY_TIME/.test(manifest) &&
      /name:\s+ACGI_BUILD_ID[\s\S]*value:\s+"REPLACE_BUILD_ID_AT_DEPLOY_TIME"/.test(manifest) &&
      /name:\s+AUTH_UPSTREAM[\s\S]*value:\s+"REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME"/.test(
        manifest,
      ) &&
      /name:\s+BUS_UPSTREAM[\s\S]*value:\s+"REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME"/.test(manifest) &&
      /name:\s+ACGS_SCHEMA_VERSION[\s\S]*value:\s+"v1"/.test(manifest),
    `${relativePath} must keep image/build/auth/bus/schema placeholders for render-time substitution.`,
  )
  check(
    /startupProbe:[\s\S]*path:\s+\/healthz/.test(manifest) &&
      /livenessProbe:[\s\S]*path:\s+\/healthz/.test(manifest),
    `${relativePath} must keep startup and liveness probes pointed at /healthz.`,
  )
}

const packageJson = JSON.parse(read('package.json'))
check(
  packageJson.scripts?.['test:cloudrun-templates'] === 'node scripts/check-cloudrun-templates.mjs',
  'package.json must expose test:cloudrun-templates.',
)
check(
  packageJson.scripts?.['test:cloudrun-renderer'] === 'node scripts/check-cloudrun-renderer.mjs',
  'package.json must expose test:cloudrun-renderer.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:cloudrun-templates') &&
    packageJson.scripts['test:all'].includes('pnpm run test:cloudrun-renderer'),
  'package.json test:all must include Cloud Run template and renderer verification.',
)

const consoleWorkflow = read('../.github/workflows/console.yml')
const renderScript = read('scripts/render-cloudrun-service.mjs')
check(
  /DEPLOY_ENV:\s+production/.test(consoleWorkflow) &&
    /CONSOLE_AUTH_UPSTREAM/.test(consoleWorkflow) &&
    /node scripts\/render-cloudrun-service\.mjs/.test(consoleWorkflow) &&
    /--env "\$\{DEPLOY_ENV\}"/.test(consoleWorkflow) &&
    /--auth-upstream "\$\{AUTH_UPSTREAM\}"/.test(consoleWorkflow) &&
    /--bus-upstream "\$\{BUS_UPSTREAM\}"/.test(consoleWorkflow) &&
    /--out infra\/cloudrun\/service\.yaml/.test(consoleWorkflow),
  'console.yml must render infra/cloudrun/service.yaml through the shared renderer.',
)
check(
  /unsupported DEPLOY_ENV/.test(renderScript) &&
    /service\.\$\{environment\}\.yaml/.test(renderScript),
  'render-cloudrun-service.mjs must fail closed when the requested Cloud Run service template is unsupported.',
)
check(
  /requireUpstream\(\s*'AUTH_UPSTREAM'/.test(renderScript) && /is required/.test(renderScript),
  'render-cloudrun-service.mjs must fail closed when the console auth upstream secret is missing.',
)
check(
  !/sed -i ['"]s\|autoscaling\.knative\.dev\/minScale/.test(consoleWorkflow) &&
    !/cp "\$SERVICE_TEMPLATE" infra\/cloudrun\/service\.yaml/.test(consoleWorkflow),
  'console.yml must not patch Cloud Run fields with cp/sed; use the shared renderer and per-environment templates instead.',
)

const deployDocs = read('DEPLOY.md')
check(
  /service\.preview\.yaml/.test(deployDocs) &&
    /service\.staging\.yaml/.test(deployDocs) &&
    /service\.production\.yaml/.test(deployDocs) &&
    /AUTH_UPSTREAM/.test(deployDocs),
  'DEPLOY.md must document the per-environment Cloud Run templates and AUTH_UPSTREAM gate.',
)
check(
  /preview[\s\S]*minScale[\s\S]*0[\s\S]*80[\s\S]*256Mi/.test(deployDocs) &&
    /staging[\s\S]*minScale[\s\S]*1[\s\S]*80[\s\S]*512Mi/.test(deployDocs) &&
    /production[\s\S]*minScale[\s\S]*2[\s\S]*60[\s\S]*1Gi/.test(deployDocs),
  'DEPLOY.md must document preview/staging/production minScale, concurrency, and memory.',
)
check(
  /\$15-25\/mo per always-on instance/.test(deployDocs) &&
    /external pinger every 30s/.test(deployDocs) &&
    /800ms/.test(deployDocs),
  'DEPLOY.md must carry the A14 cost estimate and cold-start SLO test shape.',
)

const readinessMap = readIfExists('../docs/integration-readiness-task-map.md')
check(
  /Cloud Run service templates/.test(readinessMap) && /test:cloudrun-templates/.test(readinessMap),
  'docs/integration-readiness-task-map.md must map Cloud Run template readiness to its gate.',
)

const cloudrunAgentGuide = read('infra/cloudrun/AGENTS.md')
check(
  /service\.preview\.yaml/.test(cloudrunAgentGuide) &&
    /service\.staging\.yaml/.test(cloudrunAgentGuide) &&
    /service\.production\.yaml/.test(cloudrunAgentGuide),
  'infra/cloudrun/AGENTS.md must list the per-environment service templates.',
)

if (failures.length > 0) {
  console.error('Cloud Run template contract check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Cloud Run template contract check passed.')
