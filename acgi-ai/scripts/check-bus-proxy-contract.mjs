import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

const caddyfile = read('infra/Caddyfile')
const serviceYaml = read('infra/cloudrun/service.yaml')
const consoleWorkflow = read('../.github/workflows/console.yml')
const renderScript = read('scripts/render-cloudrun-service.mjs')
const deployDoc = read('DEPLOY.md')
const plan = read('PLAN.md')

check(
  /handle \/api\/\* \{[\s\S]*reverse_proxy\s+\{\$BUS_UPSTREAM:[^}]+\}/.test(caddyfile),
  'Caddyfile must route /api/* through reverse_proxy {$BUS_UPSTREAM:...}.',
)
check(
  /route\s+\{[\s\S]*handle \/healthz[\s\S]*handle \/api\/\*[\s\S]*handle \{[\s\S]*try_files \{path\} \/index\.html[\s\S]*file_server[\s\S]*\}/.test(
    caddyfile,
  ),
  'Caddyfile must keep health/api handlers ahead of the SPA fallback in a route block.',
)
check(
  /header_up\s+X-ACGS-Schema-Version\s+"\{\$ACGS_SCHEMA_VERSION:v1\}"/.test(caddyfile),
  'Caddyfile must send X-ACGS-Schema-Version upstream.',
)
check(
  /header_down\s+X-ACGS-Schema-Version\s+"\{\$ACGS_SCHEMA_VERSION:v1\}"/.test(caddyfile),
  'Caddyfile must expose X-ACGS-Schema-Version downstream for handshake evidence.',
)
check(
  !/API not yet wired/.test(caddyfile),
  'Caddyfile must not retain the old "API not yet wired" static 503 path.',
)
check(
  /name:\s+BUS_UPSTREAM[\s\S]*value:\s+"REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME"/.test(serviceYaml),
  'Cloud Run service must template BUS_UPSTREAM.',
)
check(
  /name:\s+ACGS_SCHEMA_VERSION[\s\S]*value:\s+"v1"/.test(serviceYaml),
  'Cloud Run service must define ACGS_SCHEMA_VERSION.',
)
check(
  /CONSOLE_BUS_UPSTREAM/.test(consoleWorkflow) &&
    /BUS_UPSTREAM/.test(consoleWorkflow) &&
    /node scripts\/render-cloudrun-service\.mjs/.test(consoleWorkflow),
  'console.yml must read CONSOLE_BUS_UPSTREAM into BUS_UPSTREAM and call the shared renderer.',
)
check(
  /REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME/.test(renderScript) &&
    /--bus-upstream/.test(consoleWorkflow),
  'console.yml must render BUS_UPSTREAM into service.yaml through render-cloudrun-service.mjs.',
)
check(
  /requireUpstream\(\s*'BUS_UPSTREAM'/.test(renderScript) && /is required/.test(renderScript),
  'render-cloudrun-service.mjs must fail clearly when CONSOLE_BUS_UPSTREAM-derived BUS_UPSTREAM is absent.',
)
check(
  /BUS_UPSTREAM/.test(deployDoc) &&
    /X-ACGS-Schema-Version/.test(deployDoc) &&
    /render-cloudrun-service\.mjs/.test(deployDoc),
  'DEPLOY.md must document the BUS_UPSTREAM/schema-version proxy contract and shared renderer.',
)
check(
  /`?\/api\/\*`? reverse-proxy \+ bus contract/.test(plan) && /BUS_UPSTREAM/.test(plan),
  'PLAN.md must remain the source reference for bus-proxy readiness.',
)
check(
  existsSync(resolve(root, 'scripts/smoke-bus-proxy-contract.mjs')),
  'Docker-backed smoke script must exist for runtime proxy verification.',
)
const smokeScript = read('scripts/smoke-bus-proxy-contract.mjs')
check(
  /:ro,z`/.test(smokeScript) && /server\.listen\(0, '0\.0\.0\.0'/.test(smokeScript),
  'Docker-backed smoke must support SELinux bind mounts and a container-reachable stub bus.',
)

if (failures.length > 0) {
  console.error('Bus proxy contract check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Bus proxy contract check passed.')
