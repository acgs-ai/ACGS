import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { dirname, extname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const verifyRoot = resolve(root, '.performance-check')
const failures = []

const budgets = {
  marketing: 200 * 1024,
  console: 350 * 1024,
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readRepo(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), 'utf8')
}

function run(label, args, env = {}) {
  console.log(`\n> ${label}: pnpm ${args.join(' ')}`)
  const result = spawnSync('pnpm', args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  })
  check(result.status === 0, `${label} failed with exit status ${result.status ?? 'unknown'}.`)
}

function collectBundleBytes(outDir) {
  const assetsDir = resolve(outDir, 'assets')
  check(existsSync(resolve(outDir, 'index.html')), `${outDir} must contain index.html.`)
  check(
    existsSync(assetsDir) && statSync(assetsDir).isDirectory(),
    `${outDir} must contain assets/.`,
  )
  if (!existsSync(assetsDir)) return { files: [], gzipBytes: 0, rawBytes: 0 }

  const files = []
  for (const entry of readdirSync(assetsDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue
    if (!['.js', '.css'].includes(extname(entry.name))) continue
    const path = resolve(assetsDir, entry.name)
    const contents = readFileSync(path)
    files.push({
      name: entry.name,
      rawBytes: contents.byteLength,
      gzipBytes: gzipSync(contents).byteLength,
    })
  }
  check(files.length > 0, `${outDir} must contain JS/CSS bundle assets.`)
  return {
    files,
    gzipBytes: files.reduce((sum, file) => sum + file.gzipBytes, 0),
    rawBytes: files.reduce((sum, file) => sum + file.rawBytes, 0),
  }
}

function formatBytes(bytes) {
  return `${(bytes / 1024).toFixed(1)} KiB`
}

rmSync(verifyRoot, { recursive: true, force: true })

run('build:marketing', ['run', 'build:marketing'], {
  ACGI_OUT_DIR: '.performance-check/marketing',
})
run('build:console', ['run', 'build:console'], {
  ACGI_OUT_DIR: '.performance-check/console',
})

const marketing = collectBundleBytes(resolve(verifyRoot, 'marketing'))
const consoleBundle = collectBundleBytes(resolve(verifyRoot, 'console'))

check(
  marketing.gzipBytes <= budgets.marketing,
  `marketing gzipped JS+CSS budget exceeded: ${formatBytes(marketing.gzipBytes)} > ${formatBytes(budgets.marketing)}.`,
)
check(
  consoleBundle.gzipBytes <= budgets.console,
  `console gzipped JS+CSS budget exceeded: ${formatBytes(consoleBundle.gzipBytes)} > ${formatBytes(budgets.console)}.`,
)

const packageJson = JSON.parse(read('package.json'))
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(
  packageJson.scripts?.['test:performance'] === 'node scripts/check-performance-budget.mjs',
  'package.json must expose test:performance.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:performance'),
  'package.json test:all must include test:performance.',
)
check(
  /check-performance-budget\.mjs/.test(securityCheck) && /test:performance/.test(securityCheck),
  'security invariant check must guard performance budget package wiring.',
)
check(
  /test:performance/.test(ciReadinessGateCheck),
  'CI readiness gate check must guard test:performance wiring.',
)
for (const [label, source] of [
  ['ARCHITECTURE.md', architecture],
  ['DEPLOY.md', deploy],
  ['docs/integration-readiness-task-map.md', readiness],
]) {
  check(
    /test:performance/.test(source) &&
      /marketing.*200\s*KB/i.test(source) &&
      /console.*350\s*KB/i.test(source),
    `${label} must document the local performance budget gate and exact budgets.`,
  )
}

rmSync(verifyRoot, { recursive: true, force: true })

if (failures.length > 0) {
  console.error('\nPerformance budget check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  console.error(`\nMeasured marketing gzip: ${formatBytes(marketing.gzipBytes)}`)
  console.error(`Measured console gzip: ${formatBytes(consoleBundle.gzipBytes)}`)
  process.exit(1)
}

console.log('\nPerformance budget check passed.')
console.log(
  `- marketing JS+CSS gzip: ${formatBytes(marketing.gzipBytes)} / ${formatBytes(budgets.marketing)}`,
)
console.log(
  `- console JS+CSS gzip: ${formatBytes(consoleBundle.gzipBytes)} / ${formatBytes(budgets.console)}`,
)
