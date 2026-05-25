import { readdirSync, readFileSync, statSync } from 'node:fs'
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

function walkFiles(dir, predicate) {
  const entries = readdirSync(dir)
  const files = []
  for (const entry of entries) {
    const absolute = resolve(dir, entry)
    const stat = statSync(absolute)
    if (stat.isDirectory()) files.push(...walkFiles(absolute, predicate))
    if (stat.isFile() && predicate(absolute)) files.push(absolute)
  }
  return files
}

const packageJson = JSON.parse(read('package.json'))
const errors = read('src/lib/errors.ts')
const main = read('src/main.tsx')
const consoleShell = read('src/routes/Console.tsx')
const shared = read('src/routes/console/shared.tsx')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

const expectedKinds = [
  'Auth',
  'Network',
  'Parse',
  'RetryExhausted',
  'CSP',
  'Permission',
  'RateLimit',
]

for (const kind of expectedKinds) {
  check(
    new RegExp(`\\| '${kind}'`).test(errors),
    `src/lib/errors.ts must include AppErrorKind ${kind}.`,
  )
  check(
    new RegExp(
      `${kind}:\\s*{[\\s\\S]*?title:\\s*['"][^'"]+['"][\\s\\S]*?cause:\\s*['"][^'"]+['"][\\s\\S]*?fix:\\s*['"][^'"]+['"]`,
    ).test(errors),
    `APP_ERROR_DETAILS.${kind} must include non-empty title, cause, and fix.`,
  )
}

check(/export class AppError extends Error/.test(errors), 'src/lib/errors.ts must export AppError.')
check(
  /export function toAppError\(error: unknown/.test(errors),
  'src/lib/errors.ts must export toAppError(error).',
)

check(
  /ErrorBoundary/.test(consoleShell) && /react-error-boundary/.test(consoleShell),
  'Console shell must import/use react-error-boundary.',
)
check(
  /toAppError/.test(consoleShell) && /ConsolePageErrorFallback/.test(consoleShell),
  'Console shell must normalize page faults through toAppError in a console fallback.',
)
check(
  /<ErrorBoundary[\s\S]*FallbackComponent=\{ConsolePageErrorFallback\}[\s\S]*resetKeys=\{\[path\]\}[\s\S]*<PageBody path=\{path\} \/>[\s\S]*<\/ErrorBoundary>/.test(
    consoleShell,
  ),
  'Console shell must wrap PageBody with a path-resetting ErrorBoundary.',
)
check(
  /ConsoleError[\s\S]*appError=\{appError\}/.test(consoleShell),
  'Console error boundary must pass normalized AppError details to ConsoleError.',
)

check(
  /import\s+type\s+\{[^}]*\bAppError\b[^}]*\}\s+from\s+['"]\.\.\/\.\.\/lib\/errors['"]/.test(
    shared,
  ) || /import[^;]*\bAppError\b[^;]*from\s+['"][^'"]*lib\/errors['"]/.test(shared),
  'Console shared states must import AppError for typed error rendering.',
)
check(/appError\?: AppError/.test(shared), 'ConsoleError must accept an optional appError prop.')
check(
  (/data-app-error-kind=\{appError\?\.kind/.test(shared) ||
    (/data-app-error-kind=\{appErrorKind\}/.test(shared) &&
      /appErrorKind=\{appError\?\.kind\}/.test(shared))) &&
    /Trace ID/.test(shared) &&
    /appError\.cause/.test(shared) &&
    /appError\.fix/.test(shared),
  'ConsoleError must render AppError kind, cause, fix, and trace ID.',
)

check(
  /function AppErrorFallback\(\{\s*error,\s*resetErrorBoundary\s*\}: FallbackProps\)/.test(main) &&
    /toAppError\(error,\s*['"]CSP['"]\)/.test(main),
  'Root AppErrorFallback must normalize unexpected root faults through toAppError.',
)
check(
  /appError\.traceId/.test(main) && /appError\.cause/.test(main) && /appError\.fix/.test(main),
  'Root error fallback must render AppError cause, fix, and trace ID.',
)

const routeFiles = walkFiles(resolve(root, 'src/routes'), (file) => /\.(tsx?|jsx?)$/.test(file))
for (const file of routeFiles) {
  const source = readFileSync(file, 'utf8')
  const relative = file.slice(root.length + 1)
  check(!/throw\s+new\s+Error\s*\(/.test(source), `${relative} must not throw new Error(...).`)
  check(!/throw\s+['"`]/.test(source), `${relative} must not throw bare string errors.`)
}

check(
  packageJson.scripts?.['test:app-errors'] === 'node scripts/check-app-error-contract.mjs',
  'package.json must expose test:app-errors.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:app-errors'),
  'package.json test:all must include test:app-errors.',
)
check(
  /check-app-error-contract\.mjs/.test(securityCheck) && /test:app-errors/.test(securityCheck),
  'security invariant check must guard AppError contract wiring.',
)
check(
  /test:app-errors/.test(ciGateCheck),
  'CI readiness gate must include AppError contract verification.',
)
check(
  /AppError boundary/.test(architecture) && /test:app-errors/.test(architecture),
  'ARCHITECTURE.md must document the AppError boundary gate.',
)
check(
  /AppError boundary foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:app-errors/.test(readiness),
  'integration readiness map must record the AppError boundary foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('AppError contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('AppError contract check passed.')
console.log(`- taxonomy cases: ${expectedKinds.join(', ')}`)
console.log('- console shell: path-resetting ErrorBoundary')
console.log('- route throws: no bare Error/string throws under src/routes')
