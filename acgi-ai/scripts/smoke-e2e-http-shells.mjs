import { spawn } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const port = Number.parseInt(process.env.ACGI_E2E_HTTP_PORT ?? '5191', 10)
const timeoutMs = Number.parseInt(process.env.ACGI_E2E_HTTP_TIMEOUT_MS ?? '30000', 10)
const baseUrl = `http://127.0.0.1:${port}`

export const E2E_HTTP_SHELL_ROUTES = [
  '/',
  '/products/legalguard',
  '/products/governance-eval',
  '/login?next=%2Fconsole%2Fagents',
]

export const CONSOLE_SIDEBAR_ROUTES = [
  '/console',
  '/console/workbench',
  '/console/agents',
  '/console/actions',
  '/console/maci',
  '/console/deliberations',
  '/console/incidents',
  '/console/policies',
  '/console/compile',
  '/console/audit',
  '/console/audit/rcpt-608508a9-8b38',
  '/console/bus',
  '/console/settings',
  '/console/tenants',
  '/console/account',
]

const ENV_CONTRACT = [
  'VITE_BYPASS_SESSION=true',
  'VITE_USE_MOCKS=true',
  'pnpm run dev:mock',
  'test:e2e-http',
  '<div id="root">',
  'browser Playwright execution remains Phase 2 work',
]
void ENV_CONTRACT

const routes = [...E2E_HTTP_SHELL_ROUTES, ...CONSOLE_SIDEBAR_ROUTES]
const serverLog = []

function appendLog(chunk) {
  const text = chunk.toString()
  serverLog.push(text)
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

process.on('SIGINT', async () => {
  await shutdown()
  process.exit(130)
})
process.on('SIGTERM', async () => {
  await shutdown()
  process.exit(143)
})

async function fetchText(path) {
  const response = await fetch(new URL(path, baseUrl), { redirect: 'manual' })
  const body = await response.text()
  if (!response.ok && response.status < 300) {
    throw new Error(`${path} returned HTTP ${response.status}`)
  }
  if (response.status >= 400) {
    throw new Error(`${path} returned HTTP ${response.status}`)
  }
  return body
}

async function waitForServer() {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (exited) throw new Error(`dev server exited early with code ${exitCode}`)
    try {
      await fetchText('/')
      return
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
    }
  }
  throw new Error(`dev server did not become ready within ${timeoutMs}ms`)
}

function assertShell(path, body) {
  if (!body.includes('<div id="root">')) {
    throw new Error(`${path} did not return the Vite root shell`)
  }
  for (const forbidden of ['Internal server error', 'Cannot GET', 'Not Found']) {
    if (body.includes(forbidden)) throw new Error(`${path} returned ${forbidden}`)
  }
}

try {
  await waitForServer()
  for (const route of routes) {
    const body = await fetchText(route)
    assertShell(route, body)
    console.log(`E2E HTTP shell route ok: ${route}`)
  }
  console.log(`E2E HTTP shell smoke passed for ${routes.length} routes.`)
  console.log('browser Playwright execution remains Phase 2 work')
} catch (error) {
  console.error('E2E HTTP shell smoke failed:')
  console.error(error instanceof Error ? error.message : String(error))
  console.error('--- dev server log ---')
  console.error(serverLog.join('').trim())
  process.exitCode = 1
} finally {
  await shutdown()
}
