import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, extname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function cssBundleText() {
  const assets = resolve(root, 'dist', 'assets')
  if (!existsSync(assets)) return ''
  return readdirSync(assets)
    .filter((entry) => extname(entry) === '.css')
    .map((entry) => readFileSync(resolve(assets, entry), 'utf8'))
    .join('\n')
}

const indexCss = read('src/index.css')
const packageJson = JSON.parse(read('package.json'))
const securityCheck = read('scripts/check-security-invariants.mjs')
const css = cssBundleText()

check(
  /@import\s+["']\.\/App\.css["'];/.test(indexCss),
  'src/index.css must import ./App.css so route styles ship in every surface bundle.',
)
check(
  packageJson.scripts?.['test:style-bundle'] ===
    'pnpm run build:console && node scripts/check-style-bundle.mjs',
  'package.json must expose test:style-bundle as a production console build plus CSS selector scan.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:style-bundle'),
  'package.json test:all must include test:style-bundle.',
)
check(
  securityCheck.includes('check-style-bundle.mjs') && securityCheck.includes('test:style-bundle'),
  'security invariant check must cover style-bundle gate wiring.',
)

const requiredSelectors = [
  '.marketing',
  '.m-hero',
  '.console',
  '.c-main',
  '.c-banner',
  '.c-rail',
  '.btn-primary',
]

check(css.length > 0, 'dist/assets/*.css must exist before style-bundle scan.')
for (const selector of requiredSelectors) {
  check(css.includes(selector), `production CSS bundle must include selector ${selector}.`)
}

if (failures.length) {
  console.error('Style bundle check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Style bundle check passed.')
