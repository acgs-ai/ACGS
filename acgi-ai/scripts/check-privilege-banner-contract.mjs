import { existsSync, readdirSync, readFileSync } from 'node:fs'
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function cssBlock(source, selector) {
  const match = source.match(new RegExp(`${escapeRegExp(selector)}\\s*{([\\s\\S]*?)\\n}`, 'm'))
  return match?.[1] ?? ''
}

function cssVarNumber(source, name) {
  const match = source.match(new RegExp(`${escapeRegExp(name)}\\s*:\\s*(\\d+)\\s*;`))
  return match ? Number(match[1]) : Number.NaN
}

function routeFiles(relativeDir) {
  const absolute = resolve(root, relativeDir)
  return readdirSync(absolute)
    .filter((name) => name.endsWith('.tsx'))
    .map((name) => [name, read(`${relativeDir}/${name}`)])
}

const consoleShell = read('src/routes/Console.tsx')
const shared = read('src/routes/console/shared.tsx')
const appCss = read('src/App.css')
const indexCss = read('src/index.css')
const packageJson = JSON.parse(read('package.json'))
const security = read('scripts/check-security-invariants.mjs')
const ciGates = read('scripts/check-ci-readiness-gates.mjs')
const architecture = existsSync(resolve(root, 'ARCHITECTURE.md')) ? read('ARCHITECTURE.md') : ''
const deploy = read('DEPLOY.md')
const readiness = existsSync(resolve(repoRoot, 'docs/integration-readiness-task-map.md'))
  ? readRepo('docs/integration-readiness-task-map.md')
  : ''

const bannerBlock = cssBlock(appCss, '.c-banner')
const backdropBlock = cssBlock(appCss, '.c-nav-backdrop')
const sideBlock = cssBlock(appCss, '.c-side')
const navToggleBlock = cssBlock(appCss, '.c-nav-toggle')
const allCss = `${indexCss}\n${appCss}`
const bannerZ = cssVarNumber(allCss, '--z-privilege-banner')
const navZ = cssVarNumber(allCss, '--z-console-nav')
const navToggleZ = cssVarNumber(allCss, '--z-console-nav-toggle')
const backdropZ = cssVarNumber(allCss, '--z-console-backdrop')

check(
  /<section\s+className="c-banner"[\s\S]*?aria-label="Privilege boundary"[\s\S]*?data-privilege-banner/.test(
    consoleShell,
  ),
  'Console.tsx must render c-banner as a semantic privilege-boundary region with aria-label and data-privilege-banner.',
)
check(
  !/className="c-banner"[\s\S]*?aria-hidden/.test(consoleShell),
  'Privilege banner must never be aria-hidden.',
)
check(
  /<aside\s+className="c-rail"[\s\S]*?aria-label="Status"[\s\S]*?aria-live="polite"[\s\S]*?data-receipt-region/.test(
    consoleShell,
  ),
  'Console.tsx right rail must be a polite live status/receipt region.',
)
check(
  /className="c-receipt"[\s\S]*?role="status"[\s\S]*?aria-live="polite"/.test(shared),
  'Receipt component must remain an inline polite status region.',
)
check(
  Number.isFinite(bannerZ) &&
    Number.isFinite(navZ) &&
    Number.isFinite(navToggleZ) &&
    Number.isFinite(backdropZ) &&
    bannerZ > navToggleZ &&
    navToggleZ >= navZ &&
    navZ > backdropZ,
  'CSS z-index tokens must order privilege banner above nav toggle, nav drawer, and backdrop.',
)
check(
  /position:\s*relative/.test(bannerBlock) &&
    /z-index:\s*var\(--z-privilege-banner\)/.test(bannerBlock),
  '.c-banner must establish the protected z-index layer.',
)
check(
  /z-index:\s*var\(--z-console-backdrop\)/.test(backdropBlock),
  '.c-nav-backdrop must use --z-console-backdrop rather than a raw z-index.',
)
check(
  /z-index:\s*var\(--z-console-nav\)/.test(sideBlock),
  '.c-side mobile drawer must use --z-console-nav so it stays below the banner.',
)
check(
  /z-index:\s*var\(--z-console-nav-toggle\)/.test(navToggleBlock),
  '.c-nav-toggle must use --z-console-nav-toggle so it stays below the banner.',
)
check(
  !/z-index:\s*(99|100|101)\s*;/.test(appCss),
  'Console overlay z-index values must use semantic CSS tokens, not raw 99/100/101 values.',
)

for (const [name, source] of routeFiles('src/routes/console')) {
  check(
    !/\bposition\s*:\s*['"`]?(fixed|sticky)\b/i.test(source) &&
      !/\b(fixed|sticky)\b[\s\S]{0,16}\bposition\b/i.test(source),
    `${name} must not introduce fixed or sticky route-local receipt overlays.`,
  )
  check(
    !/\b(sonner|toast|modal|fab)\b/i.test(source),
    `${name} must not introduce route-local toast/modal/FAB affordances outside the shell contract.`,
  )
}

check(
  packageJson.scripts?.['test:privilege-banner'] ===
    'node scripts/check-privilege-banner-contract.mjs',
  'package.json must expose test:privilege-banner.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:privilege-banner'),
  'package.json test:all must include test:privilege-banner.',
)
check(
  /check-privilege-banner-contract\.mjs/.test(security) && /test:privilege-banner/.test(security),
  'security invariant check must guard privilege banner wiring.',
)
check(/test:privilege-banner/.test(ciGates), 'CI readiness gate must include privilege banner.')
check(
  /Privilege banner contract/.test(architecture) && /test:privilege-banner/.test(architecture),
  'ARCHITECTURE.md must document the privilege banner contract gate.',
)
check(
  /Privilege banner gate/.test(deploy) && /test:privilege-banner/.test(deploy),
  'DEPLOY.md must document the privilege banner gate.',
)
check(
  /Privilege banner foundation/.test(readiness) &&
    /pnpm -F acgi-ai run test:privilege-banner/.test(readiness),
  'integration readiness map must record the privilege banner foundation and verified gate.',
)

if (failures.length > 0) {
  console.error('Privilege banner contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Privilege banner contract check passed.')
console.log(
  `- z-index: banner ${bannerZ} > nav-toggle ${navToggleZ} >= nav ${navZ} > backdrop ${backdropZ}`,
)
console.log('- right rail: polite live receipt region')
console.log('- overlays: route-local fixed/sticky receipts and toast/modal/FAB affordances absent')
