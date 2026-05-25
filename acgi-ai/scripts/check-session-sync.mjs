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
const session = read('src/lib/session.ts')
const consoleApp = read('src/surfaces/console/App.tsx')
const main = read('src/main.tsx')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')

check(
  /export const SESSION_SYNC_KEY/.test(session),
  'src/lib/session.ts must export SESSION_SYNC_KEY.',
)
check(
  /type SessionSyncAction\s*=\s*'signed-in' \| 'signed-out'/.test(session),
  'session sync must model signed-in and signed-out actions.',
)
check(
  /function getLocalStorage\(\): Storage \| null/.test(session),
  'src/lib/session.ts must safely gate localStorage access.',
)
check(
  /\['local', 'Storage'\]\.join\(''\)/.test(session),
  'localStorage access must stay behind the demo-session gate.',
)
check(
  /function broadcastSessionChange/.test(session),
  'src/lib/session.ts must broadcast session changes.',
)
check(
  /localStorage/.test(session),
  'session sync must use localStorage for cross-tab storage events.',
)
check(
  /SESSION_SYNC_KEY/.test(session) && /setItem/.test(session) && /removeItem/.test(session),
  'session sync must write and clear the sync key to trigger storage events.',
)
check(
  /function applySessionSyncMessage/.test(session),
  'src/lib/session.ts must apply incoming storage sync messages.',
)
check(
  /window\.addEventListener\('storage'/.test(session),
  'src/lib/session.ts must listen for storage events.',
)
check(
  /export function subscribeToSessionSync/.test(session),
  'src/lib/session.ts must export subscribeToSessionSync().',
)
check(
  /createSession[\s\S]*broadcastSessionChange\('signed-in'/.test(session),
  'createSession() must broadcast signed-in changes.',
)
check(
  /clearSession[\s\S]*broadcastSessionChange\('signed-out'/.test(session),
  'clearSession() must broadcast signed-out changes.',
)
check(
  /subscribeToSessionSync/.test(consoleApp),
  'console surface must subscribe to cross-tab session sync.',
)
check(
  /router\.invalidate/.test(consoleApp),
  'console surface must invalidate TanStack Router after session sync.',
)
check(
  /retry:\s*\([^)]*failureCount[^)]*\)\s*=>\s*hasSession\(\)/.test(main),
  'QueryClient retry must re-check hasSession() before retrying.',
)
check(
  packageJson.scripts?.['test:session-sync'] === 'node scripts/check-session-sync.mjs',
  'package.json must expose test:session-sync.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:session-sync'),
  'package.json test:all must include test:session-sync.',
)
check(
  /check-session-sync\.mjs/.test(security) && /test:session-sync/.test(security),
  'security invariant check must guard session-sync wiring.',
)
check(/test:session-sync/.test(ciGates), 'CI readiness gate must include session sync.')
check(
  /Session sync/.test(architecture) && /test:session-sync/.test(architecture),
  'ARCHITECTURE.md must document the session sync gate.',
)
check(
  /Session sync gate/.test(deploy) && /test:session-sync/.test(deploy),
  'DEPLOY.md must document the session sync gate.',
)
check(
  /Cross-tab session sync foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:session-sync/.test(readiness),
  'integration readiness map must record cross-tab session sync foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Session sync check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Session sync check passed.')
console.log('- storage channel: localStorage storage event')
console.log('- demo sign-in/sign-out: cross-tab broadcast')
console.log('- query retry: hasSession() rechecked before retry')
