import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const verifyRoot = resolve(root, '.surface-check')
const failures = []

function fail(message) {
  failures.push(message)
}

function run(label, args, env = {}) {
  console.log(`\n> ${label}: pnpm ${args.join(' ')}`)
  const result = spawnSync('pnpm', args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  })
  if (result.status !== 0) {
    fail(`${label} failed with exit status ${result.status ?? 'unknown'}`)
  }
}

function collectText(dir) {
  if (!existsSync(dir)) {
    fail(`missing artifact directory: ${dir}`)
    return ''
  }

  let text = ''
  const visit = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const filePath = resolve(current, entry.name)
      if (entry.isDirectory()) {
        visit(filePath)
        continue
      }
      if (!entry.isFile()) continue
      if (!/\.(html|js|css|json|txt)$/.test(entry.name)) continue
      text += `\n/* ${filePath} */\n${readFileSync(filePath, 'utf8')}`
    }
  }
  visit(dir)
  return text
}

rmSync(verifyRoot, { recursive: true, force: true })

run('build:marketing', ['run', 'build:marketing'], {
  ACGI_OUT_DIR: '.surface-check/marketing',
})
run('build:console', ['run', 'build:console'], {
  ACGI_OUT_DIR: '.surface-check/console',
})

const marketingDir = resolve(verifyRoot, 'marketing')
const consoleDir = resolve(verifyRoot, 'console')
const marketingText = collectText(marketingDir)
const consoleText = collectText(consoleDir)

const consoleOnlySentinels = [
  ['Action control', 'console navigation label'],
  ['What did the agent try to do?', 'governed action route body'],
  ['Test before execution', 'governed action dry-run control'],
  ['governed-actions', 'React Query key for console actions'],
  ['/api/v1/actions', 'privileged API client endpoint'],
  ['ACGS API unavailable', 'fixture-fallback warning'],
]

for (const [sentinel, reason] of consoleOnlySentinels) {
  if (marketingText.includes(sentinel)) {
    fail(`marketing artifact contains console-only sentinel (${reason}): ${sentinel}`)
  }
}

const marketingSentinels = ['Constitutions that compile', 'Schedule a review', 'acgs']
if (!marketingSentinels.some((sentinel) => marketingText.includes(sentinel))) {
  fail('marketing artifact is missing expected public marketing copy')
}

const consolePresenceSentinels = [
  'What did the agent try to do?',
  'Test before execution',
  'governed-actions',
]
if (!consolePresenceSentinels.some((sentinel) => consoleText.includes(sentinel))) {
  fail('console artifact is missing expected privileged console code sentinels')
}

for (const [dir, label] of [
  [marketingDir, 'marketing artifact'],
  [consoleDir, 'console artifact'],
]) {
  const indexPath = resolve(dir, 'index.html')
  const assetsPath = resolve(dir, 'assets')
  if (!existsSync(indexPath) || !statSync(indexPath).isFile()) {
    fail(`${label} is missing index.html`)
  }
  if (!existsSync(assetsPath) || !statSync(assetsPath).isDirectory()) {
    fail(`${label} is missing Vite assets directory`)
  }
}

rmSync(verifyRoot, { recursive: true, force: true })

if (failures.length > 0) {
  console.error('\nSurface bundle check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('\nSurface bundle check passed: marketing artifact excludes console-only sentinels.')
