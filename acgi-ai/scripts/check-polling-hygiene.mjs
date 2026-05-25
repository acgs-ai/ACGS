import { existsSync, readFileSync } from 'node:fs'
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

const packageJson = JSON.parse(read('package.json'))
const hooks = read('src/api/hooks.ts')
const main = read('src/main.tsx')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')

check(
  /export const POLL_WINDOWS\s*=\s*\{/.test(hooks),
  'src/api/hooks.ts must declare POLL_WINDOWS.',
)
check(
  /live:\s*\{[\s\S]*minInterval:\s*5_000[\s\S]*maxInterval:\s*10_000/.test(hooks),
  'LIVE polling must jitter within 5-10s.',
)
check(
  /slow:\s*\{[\s\S]*minInterval:\s*30_000[\s\S]*maxInterval:\s*60_000/.test(hooks),
  'SLOW polling must jitter within 30-60s.',
)
check(
  /jitteredRefetchInterval/.test(hooks),
  'src/api/hooks.ts must compute jittered refetch intervals.',
)
check(
  /getBusHealthBackoffMultiplier/.test(hooks),
  'src/api/hooks.ts must compute bus-health adaptive backoff.',
)
check(
  /fetchFailureCount/.test(hooks),
  'bus-health backoff must consider TanStack Query fetchFailureCount.',
)
check(
  /document\.visibilityState/.test(hooks),
  'src/api/hooks.ts must gate polling with the Visibility API.',
)
check(/visibilitychange/.test(hooks), 'src/api/hooks.ts must subscribe to visibilitychange.')
check(
  /export function useBusHealth\b/.test(hooks),
  'src/api/hooks.ts must export the single useBusHealth hook.',
)
check(
  /refetchIntervalInBackground:\s*false/.test(hooks),
  'query polling options must set refetchIntervalInBackground false.',
)
check(
  /enabled:\s*visible/.test(hooks),
  'query polling options must stop polling when the document is hidden.',
)
check(
  !/const LIVE\s*=\s*\{\s*staleTime:\s*5_000,\s*refetchInterval:\s*10_000\s*\}/.test(hooks),
  'LIVE must not be a fixed 10s refetchInterval object.',
)
check(
  !/const SLOW\s*=\s*\{\s*staleTime:\s*30_000,\s*refetchInterval:\s*60_000\s*\}/.test(hooks),
  'SLOW must not be a fixed 60s refetchInterval object.',
)
check(
  (hooks.match(/useBusHealth\('live'\)/g) ?? []).length >= 8,
  "live query consumers must depend on useBusHealth('live').",
)
check(
  (hooks.match(/useBusHealth\('slow'\)/g) ?? []).length >= 4,
  "slow query consumers must depend on useBusHealth('slow').",
)
check(
  /refetchIntervalInBackground:\s*false/.test(main),
  'QueryClient defaults in src/main.tsx must disable background interval refetching.',
)
check(
  packageJson.scripts?.['test:polling-hygiene'] === 'node scripts/check-polling-hygiene.mjs',
  'package.json must expose test:polling-hygiene.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:polling-hygiene'),
  'package.json test:all must include test:polling-hygiene.',
)
check(
  /check-polling-hygiene\.mjs/.test(security) && /test:polling-hygiene/.test(security),
  'security invariant check must guard polling hygiene wiring.',
)
check(/test:polling-hygiene/.test(ciGates), 'CI readiness gate must include polling hygiene.')
check(
  /Polling hygiene/.test(architecture) && /test:polling-hygiene/.test(architecture),
  'ARCHITECTURE.md must document the polling hygiene gate.',
)
check(
  /Polling hygiene gate/.test(deploy) && /test:polling-hygiene/.test(deploy),
  'DEPLOY.md must document the polling hygiene gate.',
)
check(
  /Polling hygiene foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:polling-hygiene/.test(readiness),
  'integration readiness map must record polling hygiene foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Polling hygiene check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Polling hygiene check passed.')
console.log('- LIVE jitter window: 5-10s')
console.log('- SLOW jitter window: 30-60s')
console.log('- background interval refetch: disabled')
