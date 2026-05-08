import { existsSync, readFileSync, readdirSync } from 'node:fs'
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

function withoutLineComments(source) {
  return source
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
}

const workspace = read('pnpm-workspace.yaml')
const hooks = read('src/api/hooks.ts')
const session = read('src/lib/session.ts')
const login = read('src/routes/Login.tsx')
const loginCode = withoutLineComments(login)
const packageJson = JSON.parse(read('package.json'))

check(
  /^packages:\s*$/m.test(workspace) && /^\s*-\s+['"]?\.[ '"]*$/m.test(workspace),
  'pnpm-workspace.yaml must define packages for this app.',
)

check(
  /import\.meta\.env\.PROD/.test(hooks) && /return false/.test(hooks),
  'src/api/hooks.ts must explicitly block fixture fallback in production.',
)
check(
  !/import\s+\{[^}]+\}\s+from\s+['"]\.\.\/mocks\/data\//.test(hooks),
  'src/api/hooks.ts must not statically import fixture data into the production graph.',
)
check(
  /import[^;]*\bApiError\b[^;]*from\s+['"]\.\/client['"]/.test(hooks) &&
    /import[^;]*\bapi\b[^;]*from\s+['"]\.\/client['"]/.test(hooks) &&
    /error\s+instanceof\s+ApiError/.test(hooks) &&
    /throw error/.test(hooks),
  'src/api/hooks.ts must import/check ApiError and rethrow API failures.',
)

check(
  /export function createSession\(\): void/.test(session) &&
    /import\.meta\.env\.PROD/.test(session) &&
    /throw new Error/.test(session) &&
    /IdP callback/.test(session),
  'src/lib/session.ts must prevent production createSession usage.',
)

check(
  !/import\s+\{[^}]*createSession[^}]*\}\s+from\s+['"][^'"]*session['"]/.test(loginCode) &&
    !/\bcreateSession\(/.test(loginCode),
  'src/routes/Login.tsx must not import or call createSession.',
)

check(
  packageJson.scripts?.['test:security'] === 'node scripts/check-security-invariants.mjs',
  'package.json must expose test:security.',
)
check(
  packageJson.scripts?.['test:all'] ===
    'pnpm run lint && pnpm run build && pnpm run test:security',
  'package.json test:all must run lint, build, and test:security.',
)

const distAssets = resolve(root, 'dist/assets')
if (existsSync(distAssets)) {
  const bundleText = readdirSync(distAssets)
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFileSync(resolve(distAssets, name), 'utf8'))
    .join('\n')
  const fixtureSentinels = [
    'Hofstra & Lorenz',
    'Northway Mutual',
    'Praesidium Trust',
    'vendor.api.attestation',
    'deprecated.tool.scope',
    'public-counsel role',
  ]
  check(
    fixtureSentinels.every((sentinel) => !bundleText.includes(sentinel)),
    'production dist bundle must not contain console fixture data sentinels.',
  )
}

if (failures.length > 0) {
  console.error('Security invariant check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Security invariant check passed.')
