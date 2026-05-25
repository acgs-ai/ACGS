import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = resolve(root, process.env.ACGI_BROWSER_EVIDENCE_OUT_DIR ?? 'dist-browser-evidence')
const port = Number.parseInt(process.env.ACGI_BROWSER_EVIDENCE_PORT ?? '5193', 10)
const timeoutMs = Number.parseInt(process.env.ACGI_BROWSER_EVIDENCE_TIMEOUT_MS ?? '30000', 10)
const baseUrl = `http://127.0.0.1:${port}`
const dryRun = process.argv.includes('--dry-run')

export const BROWSER_EVIDENCE_VIEWPORTS = [
  { label: 'mobile', width: 360, height: 900 },
  { label: 'tablet', width: 768, height: 1024 },
  { label: 'tablet-wide', width: 834, height: 1112 },
  { label: 'desktop', width: 1024, height: 900 },
  { label: 'wide', width: 1440, height: 1100 },
]

export const WORKBENCH_BROWSER_TARGETS = [
  {
    id: 'marketing-workbench',
    route: '/#workbench',
    title: 'Marketing visual workbench',
    expectation: 'Buyer can see the same work queue → trace → evaluation → release → evidence path.',
  },
  {
    id: 'console-workbench',
    route: '/console/workbench',
    title: 'Console visual workbench',
    expectation: 'Operator can inspect the visual map, quick start, and evidence panel in one screen.',
  },
  {
    id: 'console-launch-proof-ladder',
    route: '/console/workbench#launch-proof-ladder',
    title: 'Console launch proof ladder',
    expectation: 'Operator can separate Local readiness, Live verifier, and Assurance packet proof.',
  },
]

const claimBoundary =
  'Local browser evidence only; not production deployment proof, not hosted Storybook proof, not WCAG conformance proof, not manual screen-reader evidence, not legal signoff, not SOC2 proof, and not pentest completion.'

function which(binary) {
  const result = spawnSync('which', [binary], { encoding: 'utf8' })
  return result.status === 0 ? result.stdout.trim() : null
}

function chromeBinary() {
  const candidates = [
    process.env.ACGI_CHROME_BINARY,
    which('google-chrome'),
    which('chromium'),
    which('chromium-browser'),
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
  ].filter(Boolean)
  const found = candidates.find((candidate) => existsSync(candidate))
  if (!found) {
    throw new Error(
      'No Chrome/Chromium binary found. Set ACGI_CHROME_BINARY or install google-chrome/chromium.',
    )
  }
  return found
}

function hashFile(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function screenshotPath(target, viewport) {
  return resolve(outDir, 'screenshots', `${target.id}-${viewport.width}x${viewport.height}.png`)
}

function screenshotRecord(target, viewport, status) {
  const path = screenshotPath(target, viewport)
  return {
    targetId: target.id,
    route: target.route,
    viewport: `${viewport.width}x${viewport.height}`,
    artifact: `screenshots/${target.id}-${viewport.width}x${viewport.height}.png`,
    status,
    sha256: existsSync(path) ? hashFile(path) : null,
  }
}

function manifest(status, screenshots = []) {
  return {
    schemaVersion: 1,
    artifactKind: 'local-browser-workbench-evidence',
    status,
    generatedAt: new Date().toISOString(),
    baseUrl,
    claimBoundary,
    captureCommand: 'pnpm run evidence:browser-workbench',
    dryRunCommand: 'pnpm run evidence:browser-workbench -- --dry-run',
    serverEnv: {
      VITE_BYPASS_SESSION: 'true',
      VITE_USE_MOCKS: 'true',
    },
    browser: {
      binary: dryRun ? 'dry-run' : chromeBinary(),
      mode: 'google-chrome --headless=new --screenshot',
    },
    targets: WORKBENCH_BROWSER_TARGETS,
    viewports: BROWSER_EVIDENCE_VIEWPORTS,
    screenshots,
  }
}

function writeManifest(status, screenshots = []) {
  mkdirSync(outDir, { recursive: true })
  writeFileSync(
    resolve(outDir, 'manifest.json'),
    `${JSON.stringify(manifest(status, screenshots), null, 2)}\n`,
  )
}

if (dryRun) {
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(resolve(outDir, 'screenshots'), { recursive: true })
  writeManifest(
    'dry-run-plan',
    WORKBENCH_BROWSER_TARGETS.flatMap((target) =>
      BROWSER_EVIDENCE_VIEWPORTS.map((viewport) => screenshotRecord(target, viewport, 'planned')),
    ),
  )
  console.log(`Browser workbench evidence dry-run manifest written to ${outDir}`)
  process.exit(0)
}

const serverLog = []
function appendLog(chunk) {
  serverLog.push(chunk.toString())
  if (serverLog.join('').length > 20_000) serverLog.shift()
}

const server = spawn(
  'pnpm',
  ['run', 'dev:mock', '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
  {
    cwd: root,
    env: {
      ...process.env,
      VITE_BYPASS_SESSION: 'true',
      VITE_USE_MOCKS: 'true',
      CHOKIDAR_USEPOLLING: process.env.CHOKIDAR_USEPOLLING ?? '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  },
)
server.stdout.on('data', appendLog)
server.stderr.on('data', appendLog)

let exited = false
let exitCode = null
server.on('exit', (code) => {
  exited = true
  exitCode = code
})

async function shutdown() {
  if (!exited) {
    server.kill('SIGTERM')
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
  }
}

async function waitForServer() {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (exited) throw new Error(`dev server exited early with code ${exitCode}`)
    try {
      const response = await fetch(baseUrl)
      if (response.ok) return
    } catch {
      // Retry until timeout.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
  }
  throw new Error(`dev server did not become ready within ${timeoutMs}ms`)
}

function captureScreenshot(chrome, target, viewport) {
  const outputPath = screenshotPath(target, viewport)
  const url = new URL(target.route, baseUrl).toString()
  const result = spawnSync(
    chrome,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--hide-scrollbars',
      '--run-all-compositor-stages-before-draw',
      '--virtual-time-budget=2500',
      `--window-size=${viewport.width},${viewport.height}`,
      `--screenshot=${outputPath}`,
      url,
    ],
    { cwd: root, encoding: 'utf8', timeout: timeoutMs },
  )
  if (result.status !== 0) {
    throw new Error(
      `Chrome screenshot failed for ${target.id} ${viewport.width}x${viewport.height}: ${result.stderr || result.stdout}`,
    )
  }
  if (!existsSync(outputPath)) throw new Error(`Chrome did not create ${outputPath}`)
  console.log(`Browser evidence screenshot ok: ${target.id} ${viewport.width}x${viewport.height}`)
}

try {
  const chrome = chromeBinary()
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(resolve(outDir, 'screenshots'), { recursive: true })
  await waitForServer()

  for (const target of WORKBENCH_BROWSER_TARGETS) {
    for (const viewport of BROWSER_EVIDENCE_VIEWPORTS) {
      captureScreenshot(chrome, target, viewport)
    }
  }

  const screenshots = WORKBENCH_BROWSER_TARGETS.flatMap((target) =>
    BROWSER_EVIDENCE_VIEWPORTS.map((viewport) => screenshotRecord(target, viewport, 'captured')),
  )
  writeManifest('captured', screenshots)
  console.log(`Browser workbench evidence written to ${outDir}`)
} catch (error) {
  console.error('Browser workbench evidence capture failed:')
  console.error(error instanceof Error ? error.message : String(error))
  console.error('--- dev server log ---')
  console.error(serverLog.join('').trim())
  process.exitCode = 1
} finally {
  await shutdown()
}
