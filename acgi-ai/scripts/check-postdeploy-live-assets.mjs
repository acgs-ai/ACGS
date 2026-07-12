import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const tmpRoot = mkdtempSync(join(tmpdir(), 'acgi-postdeploy-live-assets-'))
const distDir = join(tmpRoot, 'dist')
const assetsDir = join(distDir, 'assets')
mkdirSync(assetsDir, { recursive: true })
writeFileSync(join(distDir, 'index.html'), '<!doctype html><div id="root"></div>\n')
writeFileSync(join(assetsDir, 'local.js'), "console.log('local console bundle')\n")
writeFileSync(join(assetsDir, 'local.css'), 'body{color:#111}\n')

const requiredHeaders = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
}

function html() {
  return `<!doctype html>
<html>
  <head>
    <script type="module" crossorigin src="/assets/index.js"></script>
    <link rel="stylesheet" href="/assets/index.css">
  </head>
  <body><div id="root"></div></body>
</html>`
}

function startServer({ deployedJs }) {
  const server = createServer((request, response) => {
    const url = request.url ?? '/'
    if (url === '/console' || url.startsWith('/console/')) {
      // Model the production forward_auth wall (DEPLOY.md section 7 / Caddyfile
      // @console_routes): a correct deployment fails /console* closed with a
      // non-2xx status, never a 200 SPA shell served by the try_files fallback.
      // This is what the postdeploy /console fail-closed probe asserts, so the
      // "clean deployed assets" fixture must model the wall rather than leak the
      // SPA page (which would itself be the breach the probe is meant to catch).
      response.writeHead(401, { ...requiredHeaders, 'Content-Type': 'text/plain; charset=utf-8' })
      response.end('unauthorized')
      return
    }
    if (url === '/') {
      response.writeHead(200, { ...requiredHeaders, 'Content-Type': 'text/html; charset=utf-8' })
      response.end(html())
      return
    }
    if (url === '/healthz') {
      response.writeHead(200, { 'Content-Type': 'application/json' })
      response.end(
        JSON.stringify({ ok: true, served_hash: '608508a9bd224290', build_id: 'test-build' }),
      )
      return
    }
    if (url === '/assets/index.js') {
      response.writeHead(200, { 'Content-Type': 'application/javascript' })
      response.end(deployedJs)
      return
    }
    if (url === '/assets/index.css') {
      response.writeHead(200, { 'Content-Type': 'text/css' })
      response.end('body{background:#fff}\n')
      return
    }
    response.writeHead(404)
    response.end('not found')
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server))
  })
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

function verify(baseUrl) {
  return new Promise((resolve) => {
    const child = spawn('bash', ['scripts/postdeploy-verify.sh', baseUrl], {
      cwd: root,
      env: {
        ...process.env,
        DIST_DIR: distDir,
        EXPECTED_BUILD_ID: 'test-build',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      stderr += String(error)
    })
    child.on('close', (status) => {
      resolve({ status, stdout, stderr })
    })
  })
}

const failures = []

try {
  const goodServer = await startServer({
    deployedJs: "console.log('production bundle keeps the auth wall fail closed')\n",
  })
  try {
    const address = goodServer.address()
    const result = await verify(`http://${address.address}:${address.port}`)
    if (result.status !== 0) {
      failures.push(
        `expected clean deployed assets to pass, got ${result.status}: ${result.stderr || result.stdout}`,
      )
    }
  } finally {
    await closeServer(goodServer)
  }

  const badServer = await startServer({
    deployedJs:
      "window.sessionStorage.setItem('acgs.console.session', JSON.stringify({createdAt:'now',nonce:'bad'}))\n",
  })
  try {
    const address = badServer.address()
    const result = await verify(`http://${address.address}:${address.port}`)
    const combined = `${result.stdout}\n${result.stderr}`
    if (result.status === 0) {
      failures.push(
        'postdeploy verifier accepted a live deployed asset containing demo auth sentinels.',
      )
    } else if (!/demo auth sentinel|sessionStorage|acgs\.console\.session/i.test(combined)) {
      failures.push(`expected demo-auth sentinel failure, got: ${combined}`)
    }
  } finally {
    await closeServer(badServer)
  }
} finally {
  rmSync(tmpRoot, { recursive: true, force: true })
}

if (failures.length > 0) {
  console.error('Postdeploy live asset check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Postdeploy live asset check passed.')
