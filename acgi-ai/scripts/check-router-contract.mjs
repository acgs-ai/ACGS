import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function maybeRead(relativePath) {
  const absolute = resolve(root, relativePath)
  return existsSync(absolute) ? readFileSync(absolute, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function mustContain(source, needle, label) {
  check(source.includes(needle), `${label} must include ${JSON.stringify(needle)}.`)
}

const packageJson = JSON.parse(read('package.json'))
const marketingApp = read('src/surfaces/marketing/App.tsx')
const consoleApp = read('src/surfaces/console/App.tsx')
const navigate = read('src/lib/navigate.ts')
const architecture = read('ARCHITECTURE.md')
const dxScaffoldCheck = read('scripts/check-dx-scaffold.mjs')
const securityCheck = read('scripts/check-security-invariants.mjs')
const readiness = read('../docs/integration-readiness-task-map.md')

for (const [label, source] of [
  ['src/surfaces/marketing/App.tsx', marketingApp],
  ['src/surfaces/console/App.tsx', consoleApp],
]) {
  mustContain(source, '@tanstack/react-router', label)
  mustContain(source, 'createRootRoute', label)
  mustContain(source, 'createRoute', label)
  mustContain(source, 'createRouter', label)
  mustContain(source, 'RouterProvider', label)
  check(!/useState/.test(source), `${label} must not keep a useState pathname router.`)
  check(
    !/addEventListener\(['"]popstate['"]/.test(source),
    `${label} must not own popstate routing.`,
  )
  check(
    !/switch\s*\(path\)|if \(path ===/.test(source),
    `${label} must not route via path switch/if chains.`,
  )
}

mustContain(marketingApp, "path: '/products/$slug'", 'marketing router')
mustContain(marketingApp, 'ProductSurface path={`/products/${slug}`}', 'marketing router')
mustContain(marketingApp, "path: '/console/$'", 'marketing router')
mustContain(marketingApp, 'PrivilegedRedirect', 'marketing router')

mustContain(consoleApp, "path: '/login'", 'console router')
mustContain(consoleApp, 'validateSearch', 'console router')
mustContain(consoleApp, "path: '/console'", 'console router')
mustContain(consoleApp, "path: '/console/$section'", 'console router')
mustContain(consoleApp, "path: '/console/audit/$receiptId'", 'console router')
mustContain(consoleApp, 'ConsoleAuditReceiptRoute', 'console router')
mustContain(consoleApp, 'beforeLoad', 'console router')
mustContain(consoleApp, "redirect({ to: '/login'", 'console router')
mustContain(consoleApp, "redirect({ to: '/console'", 'console router')
mustContain(consoleApp, 'SESSION_CHANGE_EVENT', 'console router')
mustContain(consoleApp, 'router.invalidate()', 'console router')

check(
  /window\.history\.pushState\(\{\}, '', to\)/.test(navigate) &&
    /dispatchEvent\(new PopStateEvent\('popstate'\)\)/.test(navigate),
  'navigate.ts must remain a small history+popstate bridge for existing route buttons.',
)

check(
  packageJson.scripts?.['test:router'] === 'node scripts/check-router-contract.mjs',
  'package.json must expose test:router.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:router'),
  'package.json test:all must include test:router.',
)

mustContain(architecture, 'TanStack Router route trees', 'ARCHITECTURE.md')
check(
  !architecture.includes('custom pathname router pending TanStack Router'),
  'ARCHITECTURE.md must not describe TanStack Router as pending after migration.',
)
check(
  !dxScaffoldCheck.includes('custom pathname router pending TanStack Router'),
  'DX scaffold check must not require stale custom-router wording.',
)
check(
  securityCheck.includes('check-router-contract.mjs') && securityCheck.includes('test:router'),
  'security invariant check must cover router contract wiring.',
)
check(
  readiness.includes('TanStack Router migration') &&
    readiness.includes('pnpm -F acgi-ai run test:router'),
  'integration readiness map must record the router migration gate.',
)

if (failures.length) {
  console.error('Router contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Router contract check passed.')
