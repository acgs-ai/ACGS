import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []
const nodeImage = 'node:24-alpine'
const caddyImage = 'caddy:2.10.2-alpine'

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

const packageJson = JSON.parse(read('package.json'))
const dockerfile = read('infra/Dockerfile.console')
const smokeBusProxy = read('scripts/smoke-bus-proxy-contract.mjs')
const securityInvariants = read('scripts/check-security-invariants.mjs')
const deployDocs = read('DEPLOY.md')
const contributorGuide = read('CLAUDE.md')
const readinessMap = readIfExists('../docs/integration-readiness-task-map.md')
const nodeVersion = readIfExists('.node-version').trim()

check(nodeVersion === '24', 'acgi-ai/.node-version must pin Node 24 for local deploy parity.')
check(
  packageJson.engines?.node === '>=24 <25',
  'package.json engines.node must require the Node 24 major used by CI and console image builds.',
)
check(
  packageJson.packageManager === 'pnpm@9.15.4',
  'package.json must pin pnpm through packageManager for Corepack and CI parity.',
)
check(
  new RegExp(`FROM\\s+${nodeImage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+AS\\s+build`).test(
    dockerfile,
  ),
  `infra/Dockerfile.console must build with ${nodeImage}.`,
)
check(
  new RegExp(`FROM\\s+${caddyImage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+AS\\s+runtime`).test(
    dockerfile,
  ),
  `infra/Dockerfile.console must pin the runtime image to ${caddyImage}, not a floating major tag.`,
)
check(
  !/FROM\s+caddy:2-alpine\s+AS\s+runtime/.test(dockerfile),
  'infra/Dockerfile.console must not use floating caddy:2-alpine.',
)
check(
  smokeBusProxy.includes(`'${caddyImage}'`) || smokeBusProxy.includes(`"${caddyImage}"`),
  `smoke:bus-proxy must run the same pinned ${caddyImage} image as production.`,
)
check(
  !smokeBusProxy.includes("'caddy:2-alpine'") && !smokeBusProxy.includes('"caddy:2-alpine"'),
  'smoke:bus-proxy must not keep testing against floating caddy:2-alpine.',
)
check(
  packageJson.scripts?.['test:container-pins'] === 'node scripts/check-container-pins.mjs',
  'package.json must expose test:container-pins for deploy image/toolchain pin verification.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:container-pins'),
  'package.json test:all must include container image/toolchain pin verification.',
)
check(
  securityInvariants.includes('check-container-pins.mjs') &&
    securityInvariants.includes('test:container-pins') &&
    securityInvariants.includes(caddyImage),
  'security invariant check must guard the container pin verifier and pinned Caddy image.',
)
check(
  deployDocs.includes(nodeImage) && deployDocs.includes(caddyImage),
  `DEPLOY.md must document the pinned ${nodeImage} and ${caddyImage} images.`,
)
check(
  !/Docker base images are `node:20-alpine`/.test(contributorGuide) &&
    !/`caddy:2-alpine` \(floating\)/.test(contributorGuide) &&
    contributorGuide.includes(caddyImage),
  'CLAUDE.md must not list Node/Caddy image pinning as an unresolved gap after it is enforced.',
)
check(
  /Container image and toolchain pins/.test(readinessMap) &&
    /test:container-pins/.test(readinessMap),
  'docs/integration-readiness-task-map.md must map container image/toolchain pinning to its gate.',
)

if (failures.length > 0) {
  console.error('Container pin contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Container pin contract check passed.')
