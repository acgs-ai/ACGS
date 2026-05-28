import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import http from 'node:http'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const name = `acgi-bus-proxy-smoke-${process.pid}`
const schemaVersion = 'v1'
const failures = []
let caddyPort = 0
let stubPort = 0
let stubServer

function fail(message) {
  failures.push(message)
}

function run(args, options = {}) {
  return spawnSync(args[0], args.slice(1), {
    encoding: 'utf8',
    ...options,
  })
}

function requireDocker() {
  const result = run(['docker', 'version', '--format', '{{.Server.Version}}'])
  if (result.status !== 0) {
    fail(`docker is required for bus proxy smoke: ${result.stderr || result.stdout}`.trim())
    return false
  }
  return true
}

function getFreePort() {
  return new Promise((resolvePort, reject) => {
    const server = http.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address ? address.port : 0
      server.close(() => resolvePort(port))
    })
  })
}

function startStubBus() {
  return new Promise((resolveServer, reject) => {
    const server = http.createServer((req, res) => {
      if (!req.url?.startsWith('/api/')) {
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'unexpected path', path: req.url }))
        return
      }
      const receivedSchema = req.headers['x-acgs-schema-version']
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-ACGS-Schema-Version': schemaVersion,
      })
      res.end(
        JSON.stringify({
          ok: true,
          path: req.url,
          received_schema_version: receivedSchema,
          source: 'stub-bus',
        }),
      )
    })
    server.once('error', reject)
    // Docker reaches the host through host.docker.internal, which maps to the
    // bridge gateway rather than host loopback on Linux. Bind the stub to all
    // host interfaces so the container can reach this throwaway random port.
    server.listen(0, '0.0.0.0', () => {
      const address = server.address()
      stubPort = typeof address === 'object' && address ? address.port : 0
      resolveServer(server)
    })
  })
}

async function waitFor(url, attempts = 40) {
  let lastError
  for (let i = 0; i < attempts; i += 1) {
    try {
      const response = await fetch(url)
      if (response.ok) return response
      lastError = new Error(`HTTP ${response.status}`)
    } catch (error) {
      lastError = error
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250))
  }
  throw lastError || new Error(`timed out waiting for ${url}`)
}

async function main() {
  if (!existsSync(resolve(root, 'dist/index.html'))) {
    fail('dist/index.html is missing; run pnpm run build:console before smoke:bus-proxy.')
  }
  if (!requireDocker()) return
  if (failures.length > 0) return

  caddyPort = await getFreePort()
  stubServer = await startStubBus()

  const runResult = run([
    'docker',
    'run',
    '--rm',
    '--detach',
    '--name',
    name,
    '--add-host=host.docker.internal:host-gateway',
    '-e',
    'PORT=8080',
    '-e',
    'ACGI_BUILD_ID=smoke-build',
    '-e',
    `BUS_UPSTREAM=http://host.docker.internal:${stubPort}`,
    '-e',
    `ACGS_SCHEMA_VERSION=${schemaVersion}`,
    '-v',
    `${resolve(root, 'infra/Caddyfile')}:/etc/caddy/Caddyfile:ro,z`,
    '-v',
    `${resolve(root, 'dist')}:/srv/dist:ro,z`,
    '-p',
    `127.0.0.1:${caddyPort}:8080`,
    'caddy:2.10.2-alpine',
  ])
  if (runResult.status !== 0) {
    fail(`docker run failed: ${runResult.stderr || runResult.stdout}`.trim())
    return
  }

  const base = `http://127.0.0.1:${caddyPort}`
  const health = await waitFor(`${base}/healthz`)
  const healthPayload = await health.json()
  if (healthPayload.build_id !== 'smoke-build') {
    fail(`healthz build_id mismatch: ${JSON.stringify(healthPayload)}`)
  }

  const apiResponse = await waitFor(`${base}/api/v1/console-summary`)
  const schema = apiResponse.headers.get('x-acgs-schema-version')
  const payload = await apiResponse.json()
  if (schema !== schemaVersion) {
    fail(`schema response header mismatch: expected ${schemaVersion}, got ${schema}`)
  }
  if (payload.path !== '/api/v1/console-summary') {
    fail(`proxy path mismatch: ${JSON.stringify(payload)}`)
  }
  if (payload.received_schema_version !== schemaVersion) {
    fail(`upstream did not receive schema header: ${JSON.stringify(payload)}`)
  }
}

try {
  await main()
} catch (error) {
  fail(error instanceof Error ? error.message : String(error))
} finally {
  run(['docker', 'rm', '-f', name])
  if (stubServer) {
    await new Promise((resolveClose) => stubServer.close(resolveClose))
  }
}

if (failures.length > 0) {
  console.error('Bus proxy smoke failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log(
  `Bus proxy smoke passed: /api/* proxied to stub bus with X-ACGS-Schema-Version ${schemaVersion}.`,
)
