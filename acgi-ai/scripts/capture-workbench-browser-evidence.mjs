import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = resolve(root, process.env.ACGI_BROWSER_EVIDENCE_OUT_DIR ?? 'dist-browser-evidence')
const port = Number.parseInt(process.env.ACGI_BROWSER_EVIDENCE_PORT ?? '5193', 10)
const timeoutMs = Number.parseInt(process.env.ACGI_BROWSER_EVIDENCE_TIMEOUT_MS ?? '30000', 10)
const minScreenshotBytes = Number.parseInt(
  process.env.ACGI_BROWSER_EVIDENCE_MIN_BYTES ?? '12000',
  10,
)
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
    surface: 'marketing',
    route: '/#workbench',
    title: 'Marketing visual workbench',
    expectation:
      'Buyer can see the same work queue → trace → evaluation → release → evidence path.',
    expectedText: 'What a leading agent-governance platform should make easy.',
  },
  {
    id: 'console-workbench',
    surface: 'console',
    route: '/console/workbench',
    title: 'Console visual workbench',
    expectation:
      'Operator can inspect the visual map, quick start, and evidence panel in one screen.',
    expectedText: 'One screen for the next safe action',
  },
  {
    id: 'console-decision-rail',
    surface: 'console',
    route: '/console/workbench#operator-decision-rail',
    title: 'Console operator decision rail',
    expectation:
      'Operator can pick the case, inspect the path, and choose the bounded next action.',
    expectedText: 'Pick the case',
  },
  {
    id: 'console-launch-proof-ladder',
    surface: 'console',
    route: '/console/workbench#launch-proof-ladder',
    title: 'Console launch proof ladder',
    expectation:
      'Operator can separate Local readiness, Live verifier, and Assurance packet proof.',
    expectedText: '35/36 local pass',
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
    surface: target.surface,
    route: target.route,
    viewport: `${viewport.width}x${viewport.height}`,
    artifact: `screenshots/${target.id}-${viewport.width}x${viewport.height}.png`,
    status,
    sha256: existsSync(path) ? hashFile(path) : null,
    bytes: existsSync(path) ? statSync(path).size : null,
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
      VITE_USE_MOCKS: 'false',
      VITE_ACGI_SURFACE: 'per-target surface',
    },
    browser: {
      binary: dryRun ? 'dry-run' : chromeBinary(),
      mode: 'google-chrome --headless=new --dump-dom + Chrome DevTools Protocol Page.captureScreenshot',
    },
    screenshotGuard: {
      minimumBytes: minScreenshotBytes,
      expectedText: 'checked by target before screenshot capture',
      targetVisibleHash: 'hash targets are scrolled into view and verified before capture',
      sameViewportHashDiversity: 'at least two distinct target hashes per viewport',
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

function appendLog(serverLog, chunk) {
  serverLog.push(chunk.toString())
  if (serverLog.join('').length > 20_000) serverLog.shift()
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms))
}

async function freePort() {
  return await new Promise((resolvePromise, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('could not allocate a Chrome DevTools port')))
        return
      }
      const allocatedPort = address.port
      server.close(() => resolvePromise(allocatedPort))
    })
  })
}

function startServer(surface) {
  const serverLog = []
  const server = spawn(
    'pnpm',
    ['run', 'dev', '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
    {
      cwd: root,
      env: {
        ...process.env,
        VITE_ACGI_SURFACE: surface,
        VITE_BYPASS_SESSION: 'true',
        VITE_USE_MOCKS: 'false',
        CHOKIDAR_USEPOLLING: process.env.CHOKIDAR_USEPOLLING ?? '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  server.stdout.on('data', (chunk) => appendLog(serverLog, chunk))
  server.stderr.on('data', (chunk) => appendLog(serverLog, chunk))

  let exited = false
  let exitCode = null
  server.on('exit', (code) => {
    exited = true
    exitCode = code
  })

  return { server, serverLog, isExited: () => exited, exitCode: () => exitCode }
}

async function shutdown(serverState) {
  if (!serverState.isExited()) {
    serverState.server.kill('SIGTERM')
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
  }
}

async function waitForServer(serverState, surface) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (serverState.isExited()) {
      throw new Error(`dev server for ${surface} exited early with code ${serverState.exitCode()}`)
    }
    try {
      const response = await fetch(baseUrl)
      if (response.ok) return
    } catch {
      // Retry until timeout.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
  }
  throw new Error(`dev server for ${surface} did not become ready within ${timeoutMs}ms`)
}

function targetUrl(target) {
  return new URL(target.route, baseUrl).toString()
}

function targetHashId(target) {
  const hash = new URL(targetUrl(target)).hash
  return hash ? decodeURIComponent(hash.slice(1)) : null
}

function assertRenderedDom(chrome, target) {
  const result = spawnSync(
    chrome,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--dump-dom',
      '--virtual-time-budget=5000',
      targetUrl(target),
    ],
    { cwd: root, encoding: 'utf8', timeout: timeoutMs },
  )
  if (result.status !== 0) {
    throw new Error(
      `Chrome DOM check failed for ${target.id}: ${result.stderr || result.stdout.slice(0, 2000)}`,
    )
  }
  if (!result.stdout.includes(target.expectedText)) {
    throw new Error(
      `Chrome DOM check for ${target.id} did not include expected text ${JSON.stringify(
        target.expectedText,
      )}.`,
    )
  }
}

function assertScreenshotContent(path, target, viewport) {
  const size = statSync(path).size
  if (size < minScreenshotBytes) {
    throw new Error(
      `Screenshot for ${target.id} ${viewport.width}x${viewport.height} is too small (${size} bytes < ${minScreenshotBytes}); likely blank or not rendered.`,
    )
  }
}

function messageToString(data) {
  if (typeof data === 'string') return data
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString('utf8')
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('utf8')
  }
  return String(data)
}

class CdpSession {
  constructor(ws) {
    this.ws = ws
    this.nextId = 1
    this.pending = new Map()
    this.waiters = new Map()

    this.ws.addEventListener('message', (event) => {
      const message = JSON.parse(messageToString(event.data))
      if (message.id) {
        const pending = this.pending.get(message.id)
        if (!pending) return
        this.pending.delete(message.id)
        if (message.error) {
          pending.reject(
            new Error(
              `${pending.method} failed: ${message.error.message ?? JSON.stringify(message.error)}`,
            ),
          )
          return
        }
        pending.resolve(message.result ?? {})
        return
      }

      if (message.method) {
        const waiters = this.waiters.get(message.method) ?? []
        const waiter = waiters.shift()
        if (waiter) {
          clearTimeout(waiter.timer)
          waiter.resolve(message.params ?? {})
        }
        if (waiters.length === 0) this.waiters.delete(message.method)
      }
    })

    this.ws.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        pending.reject(new Error('Chrome DevTools socket closed before command completed'))
      }
      this.pending.clear()
      for (const waiters of this.waiters.values()) {
        for (const waiter of waiters) {
          clearTimeout(waiter.timer)
          waiter.reject(new Error('Chrome DevTools socket closed before event fired'))
        }
      }
      this.waiters.clear()
    })
  }

  send(method, params = {}) {
    const id = this.nextId
    this.nextId += 1
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, { method, resolve: resolvePromise, reject })
      this.ws.send(JSON.stringify({ id, method, params }))
    })
  }

  waitForEvent(method, ms = timeoutMs) {
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        const waiters = this.waiters.get(method) ?? []
        this.waiters.set(
          method,
          waiters.filter((waiter) => waiter.timer !== timer),
        )
        reject(new Error(`timed out waiting for ${method}`))
      }, ms)
      const waiters = this.waiters.get(method) ?? []
      waiters.push({ timer, resolve: resolvePromise, reject })
      this.waiters.set(method, waiters)
    })
  }

  close() {
    this.ws.close()
  }
}

async function connectCdp(webSocketDebuggerUrl) {
  const ws = new WebSocket(webSocketDebuggerUrl)
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out opening Chrome DevTools socket')), 5000)
    ws.addEventListener(
      'open',
      () => {
        clearTimeout(timer)
        resolvePromise()
      },
      { once: true },
    )
    ws.addEventListener(
      'error',
      () => {
        clearTimeout(timer)
        reject(new Error('could not open Chrome DevTools socket'))
      },
      { once: true },
    )
  })
  return new CdpSession(ws)
}

function startChrome(chrome, debuggingPort, userDataDir) {
  const chromeLog = []
  const browser = spawn(
    chrome,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--hide-scrollbars',
      '--run-all-compositor-stages-before-draw',
      '--remote-debugging-address=127.0.0.1',
      `--remote-debugging-port=${debuggingPort}`,
      `--user-data-dir=${userDataDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank',
    ],
    { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  browser.stdout.on('data', (chunk) => appendLog(chromeLog, chunk))
  browser.stderr.on('data', (chunk) => appendLog(chromeLog, chunk))

  let exited = false
  let exitCode = null
  browser.on('exit', (code) => {
    exited = true
    exitCode = code
  })

  return { browser, chromeLog, isExited: () => exited, exitCode: () => exitCode }
}

async function waitForDebuggingPage(debuggingPort, chromeState) {
  const started = Date.now()
  const endpoint = `http://127.0.0.1:${debuggingPort}/json/list`
  while (Date.now() - started < timeoutMs) {
    if (chromeState.isExited()) {
      throw new Error(
        `Chrome exited early with code ${chromeState.exitCode()}: ${chromeState.chromeLog.join('')}`,
      )
    }
    try {
      const response = await fetch(endpoint)
      if (response.ok) {
        const pages = await response.json()
        const page = pages.find((entry) => entry.type === 'page' && entry.webSocketDebuggerUrl)
        if (page) return page
      }
    } catch {
      // Retry until timeout.
    }
    await sleep(100)
  }
  throw new Error(`Chrome DevTools endpoint did not become ready: ${chromeState.chromeLog.join('')}`)
}

async function shutdownChrome(chromeState, userDataDir) {
  if (!chromeState.isExited()) {
    chromeState.browser.kill('SIGTERM')
    await sleep(250)
  }
  rmSync(userDataDir, { force: true, recursive: true })
}

async function withCdpPage(chrome, target, viewport, callback) {
  const debuggingPort = await freePort()
  const userDataDir = mkdtempSync(resolve(tmpdir(), 'acgi-browser-evidence-'))
  const chromeState = startChrome(chrome, debuggingPort, userDataDir)
  let cdp = null
  try {
    const page = await waitForDebuggingPage(debuggingPort, chromeState)
    cdp = await connectCdp(page.webSocketDebuggerUrl)
    return await callback(cdp)
  } catch (error) {
    const chromeTail = chromeState.chromeLog.join('').slice(-2000)
    const context = chromeTail ? `\nChrome log tail:\n${chromeTail}` : ''
    throw new Error(
      `Chrome CDP capture failed for ${target.id} ${viewport.width}x${viewport.height}: ${
        error instanceof Error ? error.message : String(error)
      }${context}`,
    )
  } finally {
    if (cdp) cdp.close()
    await shutdownChrome(chromeState, userDataDir)
  }
}

async function waitForRenderedTarget(cdp, target, viewport) {
  await cdp.send('Page.enable')
  await cdp.send('Runtime.enable')
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: viewport.width,
    height: viewport.height,
    deviceScaleFactor: 1,
    mobile: false,
  })

  const loadEvent = cdp.waitForEvent('Page.loadEventFired')
  await cdp.send('Page.navigate', { url: targetUrl(target) })
  await loadEvent

  const hashId = targetHashId(target)
  const expression = `
    (async () => {
      const expectedText = ${JSON.stringify(target.expectedText)};
      const hashId = ${JSON.stringify(hashId)};
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      let text = '';
      for (let attempt = 0; attempt < 50; attempt += 1) {
        text = document.body?.innerText ?? '';
        if (text.includes(expectedText)) break;
        await sleep(100);
      }
      const targetEl = hashId ? document.getElementById(hashId) : null;
      if (targetEl) {
        document.documentElement.style.scrollBehavior = 'auto';
        document.body.style.scrollBehavior = 'auto';
        const targetTop = targetEl.getBoundingClientRect().top + window.scrollY;
        window.scrollTo({ top: Math.max(0, targetTop - 16), behavior: 'instant' });
        if (document.scrollingElement) {
          document.scrollingElement.scrollTop = Math.max(0, targetTop - 16);
        }
        targetEl.scrollIntoView({ block: 'start', inline: 'nearest', behavior: 'instant' });
        await new Promise((resolve) => requestAnimationFrame(resolve));
        await sleep(250);
      }
      text = document.body?.innerText ?? '';
      const rect = targetEl ? targetEl.getBoundingClientRect() : null;
      const targetVisible =
        !hashId ||
        Boolean(
          rect &&
            rect.bottom > 0 &&
            rect.right > 0 &&
            rect.top < window.innerHeight &&
            rect.left < window.innerWidth,
        );
      return {
        expectedFound: text.includes(expectedText),
        expectedText,
        hashId,
        hashFound: !hashId || Boolean(targetEl),
        targetVisible,
        rect: rect
          ? {
              top: rect.top,
              right: rect.right,
              bottom: rect.bottom,
              left: rect.left,
              width: rect.width,
              height: rect.height,
            }
          : null,
        scrollY: window.scrollY,
        viewport: { width: window.innerWidth, height: window.innerHeight },
        textSample: text.slice(0, 1000),
      };
    })()
  `
  const result = await cdp.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  })
  if (result.exceptionDetails) {
    throw new Error(`target visibility evaluation failed: ${JSON.stringify(result.exceptionDetails)}`)
  }
  const value = result.result?.value
  if (!value?.expectedFound) {
    throw new Error(
      `expected text ${JSON.stringify(target.expectedText)} was not rendered for ${target.id}; text sample=${JSON.stringify(
        value?.textSample ?? '',
      )}`,
    )
  }
  if (!value.hashFound) {
    throw new Error(`hash target ${JSON.stringify(value.hashId)} was not found for ${target.id}`)
  }
  if (!value.targetVisible) {
    throw new Error(
      `hash target ${JSON.stringify(value.hashId)} was not visible before screenshot for ${
        target.id
      }; rect=${JSON.stringify(value.rect)}, viewport=${JSON.stringify(value.viewport)}`,
    )
  }
  return value
}

async function captureScreenshot(chrome, target, viewport) {
  const outputPath = screenshotPath(target, viewport)
  await withCdpPage(chrome, target, viewport, async (cdp) => {
    const visibility = await waitForRenderedTarget(cdp, target, viewport)
    const screenshot = await cdp.send('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: false,
    })
    if (!screenshot.data) {
      throw new Error(`Chrome did not return screenshot data for ${target.id}`)
    }
    writeFileSync(outputPath, Buffer.from(screenshot.data, 'base64'))
    return visibility
  })
  if (!existsSync(outputPath)) throw new Error(`Chrome did not create ${outputPath}`)
  assertScreenshotContent(outputPath, target, viewport)
  console.log(
    `Browser evidence screenshot ok: ${target.id} ${viewport.width}x${viewport.height} target-visible`,
  )
}

function assertViewportDiversity(screenshots) {
  for (const viewport of BROWSER_EVIDENCE_VIEWPORTS) {
    const key = `${viewport.width}x${viewport.height}`
    const hashes = screenshots
      .filter((screenshot) => screenshot.viewport === key)
      .map((screenshot) => screenshot.sha256)
      .filter(Boolean)
    if (new Set(hashes).size < 2) {
      throw new Error(
        `Screenshots for viewport ${key} are identical across targets; likely captured a blank or wrong page.`,
      )
    }
  }
}

try {
  const chrome = chromeBinary()
  rmSync(outDir, { force: true, recursive: true })
  mkdirSync(resolve(outDir, 'screenshots'), { recursive: true })

  for (const surface of ['marketing', 'console']) {
    const targets = WORKBENCH_BROWSER_TARGETS.filter((target) => target.surface === surface)
    if (targets.length === 0) continue
    const serverState = startServer(surface)
    try {
      await waitForServer(serverState, surface)
      for (const target of targets) {
        assertRenderedDom(chrome, target)
        for (const viewport of BROWSER_EVIDENCE_VIEWPORTS) {
          await captureScreenshot(chrome, target, viewport)
        }
      }
    } finally {
      await shutdown(serverState)
    }
  }

  const screenshots = WORKBENCH_BROWSER_TARGETS.flatMap((target) =>
    BROWSER_EVIDENCE_VIEWPORTS.map((viewport) => screenshotRecord(target, viewport, 'captured')),
  )
  assertViewportDiversity(screenshots)
  writeManifest('captured', screenshots)
  console.log(`Browser workbench evidence written to ${outDir}`)
} catch (error) {
  console.error('Browser workbench evidence capture failed:')
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
}
