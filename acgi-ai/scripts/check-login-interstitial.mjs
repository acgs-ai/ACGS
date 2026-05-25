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

const login = read('src/routes/Login.tsx')
const shared = read('src/routes/console/shared.tsx')
const appCss = read('src/App.css')
const packageJson = JSON.parse(read('package.json'))
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''

const minDelayMatch = login.match(/LOGIN_INTERSTITIAL_MIN_MS\s*=\s*(\d+)/)
const minDelay = minDelayMatch ? Number(minDelayMatch[1]) : 0

check(
  minDelay >= 800,
  'Login.tsx must define LOGIN_INTERSTITIAL_MIN_MS with a minimum 800ms parchment handoff.',
)
check(
  /LOGIN_OPERATOR\s*=\s*['"]custodian-01['"]/.test(login),
  'Login.tsx must name the operator custodian-01 during the handoff.',
)
check(
  /function describeConsoleMatter\(/.test(login) && /nextConsolePath\(nextPath\)/.test(login),
  'Login.tsx must derive and render the entered matter from the validated /login?next= console path.',
)
check(
  /type LoginInterstitial/.test(login) && /loginInterstitial/.test(login),
  'Login.tsx must model the parchment interstitial state explicitly.',
)
check(
  /setLoginInterstitial/.test(login) &&
    /window\.setTimeout\([\s\S]*LOGIN_INTERSTITIAL_MIN_MS/.test(login),
  'Login.tsx must hold the interstitial for LOGIN_INTERSTITIAL_MIN_MS before handoff completion.',
)
check(
  /function completeInterstitial\(/.test(login) && /queuedDismiss/.test(login),
  'Login.tsx must let Enter or click request dismissal while still preserving the minimum dwell time.',
)
check(
  /window\.addEventListener\('keydown'/.test(login) && /event\.key === ['"]Enter['"]/.test(login),
  'Login.tsx must make the interstitial dismissible via the Enter key.',
)
check(
  /className="login-interstitial"/.test(login) && /role="status"/.test(login),
  'Login.tsx must render a visible login-interstitial status region.',
)
check(
  /aria-live="polite"/.test(login),
  'Login.tsx interstitial must be announced through a polite live region.',
)
check(
  /CONSTITUTION_HASH/.test(login) && /608508a9bd224290/.test(shared),
  'Login.tsx must surface the constitutional hash 608508a9bd224290 in the handoff.',
)
check(
  /Matter/.test(login) && /Operator/.test(login),
  'Login.tsx interstitial copy must label Operator and Matter fields.',
)
check(
  !/import\s+\{[^}]*createSession[^}]*\}\s+from\s+['"][^'"]*session['"]/.test(login) &&
    !/\bcreateSession\(/.test(login),
  'Login.tsx must not fake-grant console access through createSession; production auth remains external.',
)
check(
  /\.login-interstitial\b/.test(appCss) && /\.login-interstitial-grid\b/.test(appCss),
  'App.css must style the parchment login interstitial without inline styles.',
)
check(
  packageJson.scripts?.['test:login-interstitial'] === 'node scripts/check-login-interstitial.mjs',
  'package.json must expose test:login-interstitial.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:login-interstitial'),
  'package.json test:all must include test:login-interstitial.',
)
check(
  /check-login-interstitial\.mjs/.test(security) && /test:login-interstitial/.test(security),
  'security invariant check must guard login interstitial wiring.',
)
check(/test:login-interstitial/.test(ciGates), 'CI readiness gate must include login interstitial.')
check(
  /Login interstitial/.test(architecture) && /test:login-interstitial/.test(architecture),
  'ARCHITECTURE.md must document the login interstitial gate.',
)
check(
  /Login interstitial gate/.test(deploy) && /test:login-interstitial/.test(deploy),
  'DEPLOY.md must document the login interstitial gate.',
)
check(
  /Login interstitial foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:login-interstitial/.test(readiness),
  'integration readiness map must record the login interstitial foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Login interstitial check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Login interstitial check passed.')
console.log(`- dwell: ${minDelay}ms minimum`)
console.log('- handoff: operator, matter, constitutional hash')
console.log('- auth boundary: no client-side createSession grant')
