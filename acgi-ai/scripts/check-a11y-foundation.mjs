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

function occurrenceCount(source, needle) {
  return source.split(needle).length - 1
}

const packageJson = JSON.parse(read('package.json'))
const appCss = read('src/App.css')
const indexCss = read('src/index.css')
const marketing = read('src/routes/Marketing.tsx')
const privacy = read('src/routes/Privacy.tsx')
const trust = read('src/routes/Trust.tsx')
const security = read('src/routes/Security.tsx')
const notFound = read('src/routes/NotFound.tsx')
const login = read('src/routes/Login.tsx')
const productSurfaces = read('src/routes/ProductSurfaces.tsx')
const consoleShell = read('src/routes/Console.tsx')
const deploy = read('DEPLOY.md')
const architecture = read('ARCHITECTURE.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const a11y = maybeRead('A11Y.md')

check(existsSync(resolve(root, 'A11Y.md')), 'A11Y.md must exist.')
check(
  packageJson.scripts?.['test:a11y'] === 'node scripts/check-a11y-foundation.mjs',
  'package.json must expose test:a11y.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:a11y'),
  'package.json test:all must include test:a11y.',
)

mustContain(indexCss, ':focus-visible', 'src/index.css')
mustContain(indexCss, '@media (prefers-reduced-motion: reduce)', 'src/index.css')
mustContain(appCss, '.skip-link', 'src/App.css')
mustContain(appCss, '.skip-link:focus', 'src/App.css')
check(
  !/\.skip-link[^{]*{[^}]*display\s*:\s*none/i.test(appCss),
  'skip link must not be display:none.',
)

for (const [label, source] of [
  ['Marketing.tsx', marketing],
  ['Privacy.tsx', privacy],
  ['Trust.tsx', trust],
  ['Security.tsx', security],
  ['NotFound.tsx', notFound],
  ['Login.tsx', login],
  ['ProductSurfaces.tsx', productSurfaces],
]) {
  mustContain(source, 'className="skip-link"', label)
  mustContain(source, 'Skip to', label)
  mustContain(source, 'id="main-content"', label)
  mustContain(source, 'tabIndex={-1}', label)
}

check(
  occurrenceCount(productSurfaces, 'id="main-content"') >= 2,
  'ProductSurfaces.tsx must give both product index and product detail routes a main-content target.',
)

mustContain(consoleShell, 'className="skip-link"', 'Console.tsx')
mustContain(consoleShell, 'href="#console-main-content"', 'Console.tsx')
mustContain(consoleShell, 'id="console-main-content"', 'Console.tsx')
mustContain(consoleShell, 'tabIndex={-1}', 'Console.tsx')
mustContain(consoleShell, 'aria-label="Console navigation"', 'Console.tsx')
mustContain(consoleShell, 'aria-label="Status"', 'Console.tsx')

const publicSources = [marketing, privacy, trust, security, notFound, login, productSurfaces, a11y]
check(
  publicSources.every((source) => !/WCAG 2\.2 AA conformant/i.test(source)),
  'public accessibility copy must not claim WCAG 2.2 AA conformance without manual evidence.',
)

for (const needle of [
  'static accessibility foundation',
  'manual NVDA',
  'VoiceOver',
  'not a WCAG conformance statement',
  'pnpm run test:a11y',
  'skip links',
]) {
  mustContain(a11y, needle, 'A11Y.md')
}

// B16: A11Y.md must honestly document the executed axe smoke and the
// intentionally scoped-out color-contrast (--muted) debt — keep this in lockstep
// with tests/e2e/a11y-smoke.spec.ts and the browser-checks CI job.
for (const needle of [
  'Executed axe smoke',
  '@axe-core/playwright',
  'browser-checks',
  'color-contrast',
  '#6c7382',
  'design review',
]) {
  mustContain(a11y, needle, 'A11Y.md')
}

check(
  /Accessibility foundation gate/.test(readiness) &&
    /pnpm -F acgi-ai run test:a11y/.test(readiness),
  'integration readiness map must record the accessibility foundation gate and verification command.',
)
check(
  /Accessibility foundation gate/.test(deploy) && /test:a11y/.test(deploy),
  'DEPLOY.md must document the accessibility foundation gate.',
)
check(
  /Accessibility foundation/.test(architecture) &&
    /manual WCAG evidence remains external/.test(architecture),
  'ARCHITECTURE.md must document the bounded accessibility foundation and external manual evidence gap.',
)

if (failures.length > 0) {
  console.error('Accessibility foundation check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Accessibility foundation check passed.')
