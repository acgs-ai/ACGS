import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
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

function walkFiles(dir, extensions) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walkFiles(path, extensions))
    if (entry.isFile() && extensions.has(extname(entry.name))) out.push(path)
  }
  return out
}

const packageJson = JSON.parse(read('package.json'))
const viteEnv = read('src/vite-env.d.ts')
const flags = maybeRead('src/lib/flags.ts')
const errors = maybeRead('src/lib/errors.ts')
const securityCheck = read('scripts/check-security-invariants.mjs')
const readiness = read('../docs/integration-readiness-task-map.md')

check(existsSync(resolve(root, 'src/lib/flags.ts')), 'src/lib/flags.ts must exist.')
check(existsSync(resolve(root, 'src/lib/errors.ts')), 'src/lib/errors.ts must exist.')

const flagNames = [
  'VITE_USE_MOCKS',
  'VITE_API_PROXY_TARGET',
  'VITE_EVAL_MODE',
  'VITE_LOG_LEVEL',
  'VITE_DISABLE_REFRESH_INTERVAL',
  'VITE_FIXTURE_FALLBACK_VISIBLE',
  'VITE_PRIVILEGE_BANNER_AUDIT',
]
for (const flag of flagNames) {
  mustContain(flags, flag, 'src/lib/flags.ts')
  mustContain(viteEnv, flag, 'src/vite-env.d.ts')
}
for (const exportName of [
  'RuntimeFlags',
  'runtimeFlags',
  'getRuntimeFlags',
  'isEvalMode',
  'isRefreshDisabled',
  'makeDeterministicId',
]) {
  mustContain(flags, exportName, 'src/lib/flags.ts')
}
check(
  /logLevel:\s*'debug' \| 'info' \| 'warn' \| 'error'/.test(flags),
  'src/lib/flags.ts must expose the supported VITE_LOG_LEVEL union.',
)
check(
  /import\.meta\.env\.PROD/.test(flags),
  'src/lib/flags.ts must carry the production flag from import.meta.env.PROD.',
)
check(
  /import\.meta\.env\.DEV/.test(flags),
  'src/lib/flags.ts must carry the development flag from import.meta.env.DEV.',
)

const appErrorKinds = [
  'Auth',
  'Network',
  'Parse',
  'RetryExhausted',
  'CSP',
  'Permission',
  'RateLimit',
]
for (const kind of appErrorKinds) {
  mustContain(errors, kind, 'src/lib/errors.ts')
}
for (const exportName of [
  'AppErrorKind',
  'AppErrorDetails',
  'APP_ERROR_DETAILS',
  'AppError',
  'toAppError',
]) {
  mustContain(errors, exportName, 'src/lib/errors.ts')
}
for (const field of ['title', 'cause', 'fix', 'traceId']) {
  mustContain(errors, field, 'src/lib/errors.ts')
}
check(
  /Record<AppErrorKind,\s*AppErrorDetails>/.test(errors),
  'src/lib/errors.ts must make the taxonomy exhaustive with Record<AppErrorKind, AppErrorDetails>.',
)
check(
  /makeDeterministicId\('app-error'\)/.test(errors),
  'src/lib/errors.ts must use deterministic trace IDs through flags.ts for audit runs.',
)

const routeFiles = walkFiles(resolve(root, 'src/routes'), new Set(['.ts', '.tsx']))
for (const file of routeFiles) {
  const text = readFileSync(file, 'utf8')
  check(
    !/throw\s+new\s+Error\s*\(/.test(text),
    `${relative(root, file)} must throw AppError, not new Error(string).`,
  )
}

check(
  packageJson.scripts?.['test:runtime-primitives'] === 'node scripts/check-runtime-primitives.mjs',
  'package.json must expose test:runtime-primitives.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:runtime-primitives'),
  'package.json test:all must include test:runtime-primitives.',
)
check(
  securityCheck.includes('check-runtime-primitives.mjs') &&
    securityCheck.includes('test:runtime-primitives'),
  'security invariant check must cover runtime primitives wiring.',
)
check(
  readiness.includes('Runtime flags and AppError primitives') &&
    readiness.includes('pnpm -F acgi-ai run test:runtime-primitives'),
  'integration readiness map must record the runtime primitives gate.',
)

if (failures.length) {
  console.error('Runtime primitives check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Runtime primitives check passed.')
