import { existsSync, readdirSync, readFileSync } from 'node:fs'
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

const sessionSource = read('src/lib/session.ts')
const consoleAppSource = read('src/surfaces/console/App.tsx')
const packageJson = JSON.parse(read('package.json'))
const plan = read('PLAN.md')
const caddyfile = read('infra/Caddyfile')
const consoleWorkflow = read('../.github/workflows/console.yml')
const renderScript = read('scripts/render-cloudrun-service.mjs')
const deployDoc = read('DEPLOY.md')
const readinessMap = read('../docs/integration-readiness-task-map.md')

check(
  /function isDemoSessionEnabled\(\): boolean \{[\s\S]*return !import\.meta\.env\.PROD/.test(
    sessionSource,
  ),
  'src/lib/session.ts must centralize the non-production-only demo-session gate.',
)
check(
  /function getSessionStorage\(\): Storage \| null \{[\s\S]*if \(!isDemoSessionEnabled\(\)\) return null/.test(
    sessionSource,
  ),
  'getSessionStorage() must refuse sessionStorage in production before touching window.sessionStorage.',
)
check(
  /export function hasSession\(\): boolean \{[\s\S]*if \(!isDemoSessionEnabled\(\)\) return false/.test(
    sessionSource,
  ),
  'hasSession() must always return false for demo sessionStorage in production.',
)
check(
  /PRODUCTION_SESSION_STATUS_PATH\s*=\s*['"]\/auth\/status['"]/.test(sessionSource) &&
    /export async function hasProductionSession\(\): Promise<boolean> \{[\s\S]*fetch\(PRODUCTION_SESSION_STATUS_PATH/.test(
      sessionSource,
    ) &&
    /credentials:\s*['"]same-origin['"]/.test(sessionSource) &&
    /cache:\s*['"]no-store['"]/.test(sessionSource) &&
    /forward-auth-status-bridge/.test(sessionSource) &&
    /client demo storage is not accepted/.test(sessionSource),
  'src/lib/session.ts must use the same-origin /auth/status production session bridge without demo sessionStorage.',
)
check(
  /async function requireConsoleSession\([^)]*\): Promise<void> \{[\s\S]*hasSession\(\)[\s\S]*await hasProductionSession\(\)[\s\S]*throw redirect/.test(
    consoleAppSource,
  ),
  '/console route guard must await the production /auth/status bridge before redirecting to login.',
)
check(
  /export function createSession\(\): void \{[\s\S]*if \(!isDemoSessionEnabled\(\)\) \{[\s\S]*throw new Error/.test(
    sessionSource,
  ),
  'createSession() must throw when the demo-session gate is disabled.',
)
check(
  /sessionStorage path remains as a non-production demo-tenant escape hatch/.test(plan) &&
    /NOT sessionStorage/.test(plan),
  'PLAN.md must preserve the UC2 rule that sessionStorage is never the production auth path.',
)
check(
  /@console_routes path \/console \/console\/\*/.test(caddyfile),
  'Caddyfile must define an exact/deep /console matcher for the privileged route auth gate.',
)
check(
  /handle \/auth\/status \{[\s\S]*forward_auth\s+\{\$AUTH_UPSTREAM:127\.0\.0\.1:65535\}[\s\S]*uri \/authorize[\s\S]*copy_headers[\s\S]*X-ACGS-Operator[\s\S]*header Cache-Control "no-store"[\s\S]*forward-auth-status-bridge[\s\S]*client demo storage is not accepted[\s\S]*\}/.test(
    caddyfile,
  ),
  'Caddyfile must expose /auth/status only after the AUTH_UPSTREAM forward-auth status bridge accepts the request.',
)
check(
  /handle @console_routes \{[\s\S]*forward_auth\s+\{\$AUTH_UPSTREAM:127\.0\.0\.1:65535\}[\s\S]*uri \/authorize[\s\S]*copy_headers[\s\S]*try_files \{path\} \/index\.html[\s\S]*file_server[\s\S]*\}/.test(
    caddyfile,
  ),
  'Caddyfile must forward-auth /console* through AUTH_UPSTREAM before serving the SPA fallback.',
)
check(
  /route\s+\{[\s\S]*handle \/healthz[\s\S]*handle \/auth\/status[\s\S]*handle \/api\/\*[\s\S]*handle @internal_docs[\s\S]*handle @console_routes[\s\S]*handle \{/.test(
    caddyfile,
  ),
  'Caddyfile route order must keep health/auth-status/api/internal-doc handlers before console routes and the public SPA fallback last.',
)
for (const environment of ['preview', 'staging', 'production']) {
  const manifest = read(`infra/cloudrun/service.${environment}.yaml`)
  check(
    /name:\s+AUTH_UPSTREAM[\s\S]*value:\s+"REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME"/.test(manifest),
    `infra/cloudrun/service.${environment}.yaml must template AUTH_UPSTREAM for the Caddy forward-auth gate.`,
  )
}
check(
  /CONSOLE_AUTH_UPSTREAM/.test(consoleWorkflow) &&
    /AUTH_UPSTREAM/.test(consoleWorkflow) &&
    /node scripts\/render-cloudrun-service\.mjs/.test(consoleWorkflow) &&
    /--auth-upstream "\$\{AUTH_UPSTREAM\}"/.test(consoleWorkflow),
  'console.yml must read CONSOLE_AUTH_UPSTREAM and render AUTH_UPSTREAM through the shared service renderer.',
)
check(
  /REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME/.test(renderScript) &&
    /requireUpstream\(\s*'AUTH_UPSTREAM'/.test(renderScript) &&
    /is required/.test(renderScript),
  'render-cloudrun-service.mjs must fail clearly when CONSOLE_AUTH_UPSTREAM-derived AUTH_UPSTREAM is absent.',
)
check(
  /AUTH_UPSTREAM/.test(deployDoc) &&
    /forward_auth/.test(deployDoc) &&
    /\/auth\/status/.test(deployDoc) &&
    /test:auth-boundary/.test(deployDoc) &&
    /render-cloudrun-service\.mjs/.test(deployDoc),
  'DEPLOY.md must document the AUTH_UPSTREAM forward-auth gate, /auth/status bridge, shared renderer, and local auth-boundary check.',
)
check(
  /Console auth forward gate/.test(readinessMap) &&
    /\/auth\/status/.test(readinessMap) &&
    /test:auth-boundary/.test(readinessMap),
  'docs/integration-readiness-task-map.md must map the console auth forward gate and /auth/status bridge to test:auth-boundary.',
)
check(
  packageJson.scripts?.['test:auth-boundary'] === 'node scripts/check-auth-boundary.mjs',
  'package.json must expose test:auth-boundary.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:auth-boundary'),
  'package.json test:all must include auth-boundary verification.',
)

const distAssets = resolve(root, 'dist/assets')
if (existsSync(distAssets)) {
  const bundleText = readdirSync(distAssets)
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFileSync(resolve(distAssets, name), 'utf8'))
    .join('\n')

  for (const forbidden of ['acgs.console.session', 'createSession is development-only']) {
    check(
      !bundleText.includes(forbidden),
      `production console bundle must not contain demo auth sentinel: ${forbidden}`,
    )
  }

  const unexpectedSessionStorage = []
  let offset = bundleText.indexOf('sessionStorage')
  while (offset !== -1) {
    const context = bundleText.slice(Math.max(0, offset - 320), offset + 320)
    if (
      !context.includes('tsr-scroll-restoration') &&
      !context.includes('[ts-router] Could not persist scroll restoration state')
    ) {
      unexpectedSessionStorage.push(context)
    }
    offset = bundleText.indexOf('sessionStorage', offset + 'sessionStorage'.length)
  }
  check(
    unexpectedSessionStorage.length === 0,
    'production console bundle sessionStorage use must be limited to TanStack Router scroll restoration, never demo auth.',
  )
}

if (failures.length > 0) {
  console.error('Auth boundary contract check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Auth boundary contract check passed.')
