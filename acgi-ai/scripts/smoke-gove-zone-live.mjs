import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(appRoot, '..')
const apiPort = 18080
const webPort = 15173
const apiBase = `http://127.0.0.1:${apiPort}`
const webBase = `http://127.0.0.1:${webPort}`
const children = []

function spawnChild(command, args, options) {
  const child = spawn(command, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  })
  children.push(child)
  child.stdout.on('data', (chunk) => process.stdout.write(chunk))
  child.stderr.on('data', (chunk) => process.stderr.write(chunk))
  return child
}

async function waitFor(url, label) {
  const deadline = Date.now() + 15_000
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.ok) return
    } catch {
      // keep polling
    }
    await new Promise((resolvePoll) => setTimeout(resolvePoll, 250))
  }
  throw new Error(`Timed out waiting for ${label}: ${url}`)
}

function check(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

async function main() {
  spawnChild('python', ['-m', 'gove_zone.api'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      GOVE_ZONE_API_PORT: String(apiPort),
      PYTHONPATH: resolve(repoRoot, 'packages/gove-zone/src'),
    },
  })

  spawnChild(resolve(appRoot, 'node_modules/.bin/vite'), ['--host', '127.0.0.1', '--port', String(webPort)], {
    cwd: appRoot,
    env: {
      ...process.env,
      VITE_USE_MOCKS: 'false',
      VITE_API_PROXY_TARGET: apiBase,
    },
  })

  await waitFor(`${apiBase}/api/v1/actions`, 'gove-zone API')
  await waitFor(`${webBase}/`, 'Vite dev server')

  const actionsRes = await fetch(`${webBase}/api/v1/actions`)
  check(actionsRes.ok, `proxied actions endpoint returned ${actionsRes.status}`)
  const actions = await actionsRes.json()
  const outcomes = new Set(actions.map((action) => action.outcome))
  for (const outcome of ['denied', 'transformed', 'escalated']) {
    check(outcomes.has(outcome), `missing governed outcome ${outcome}`)
  }
  for (const action of actions) {
    check(action.agent, 'action is missing agent')
    check(action.action, 'action is missing tool/action')
    check(action.plainReason, 'action is missing plain reason')
    check(action.receiptHash, 'action is missing receipt hash')
    check(action.traceId, 'action is missing trace id')
    check(action.replayCommand?.startsWith('gove-zone replay'), 'action is missing replay command')
    check(action.auditEventId, 'action is missing audit event id')
  }

  const dryRunRes = await fetch(`${webBase}/api/v1/actions/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      actionId: 'matter.fetch',
      payload: '{"matter_id":"Matter-9821"}',
    }),
  })
  check(dryRunRes.ok, `proxied action dry-run returned ${dryRunRes.status}`)
  const dryRun = await dryRunRes.json()
  check(dryRun.outcome === 'denied', 'dry-run should deny matter_id payload')
  check(
    dryRun.body.includes('No production tool was executed'),
    'dry-run must state that no production tool was executed',
  )

  const routeRes = await fetch(`${webBase}/console/actions`)
  check(routeRes.ok, `/console/actions returned ${routeRes.status}`)
  const routeHtml = await routeRes.text()
  check(routeHtml.includes('<div id="root"></div>'), 'console route did not serve app shell')

  const actionsSource = readFileSync(resolve(appRoot, 'src/routes/console/Actions.tsx'), 'utf8')
  for (const phrase of [
    'What did the agent try to do?',
    'Why did governance decide that?',
    'Can it be verified?',
    'Test before execution',
    'Run policy test',
  ]) {
    check(actionsSource.includes(phrase), `action UI missing phrase: ${phrase}`)
  }

  console.log('Gove Zone live smoke passed.')
}

try {
  await main()
} finally {
  for (const child of children.reverse()) {
    if (!child.killed) child.kill('SIGTERM')
  }
}
