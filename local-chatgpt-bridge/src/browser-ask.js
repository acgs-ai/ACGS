import { chromium } from 'playwright-core'
import { acquireBrowser, releaseBrowser } from './kernel.js'

// Always start a temporary chat so reused pool browsers don't accumulate conversation history.
const CHATGPT_URL = 'https://chatgpt.com/?temporary-chat=true'
const INPUT_SEL = '#prompt-textarea'
const SEND_SEL = '[data-testid="send-button"]'
const STOP_SEL = '[data-testid="stop-button"]'
const REPLY_SEL = '[data-message-author-role="assistant"]'

function authError() {
  return new Error(
    'ChatGPT requires authentication — the pool browser is not logged in, ' +
    'or a sign-up gate appeared mid-session. Log in to ChatGPT in the ' +
    'pool browser and try again.'
  )
}

/**
 * Connect to an already-acquired kernel.sh browser by CDP URL and ask ChatGPT.
 *
 * @param {string} cdpWsUrl   - WebSocket CDP endpoint from kernel.sh acquire response.
 * @param {string} prompt     - Text to submit to ChatGPT.
 * @param {object} [opts]
 * @param {boolean} [opts.closeBrowser=true] - Pass false when the browser belongs to a pool
 *   so the process is not killed before kernel.sh release() is called.
 */
export async function browserAskCdp(cdpWsUrl, prompt, opts = {}) {
  const navTimeoutMs = opts.navTimeoutMs ?? 30_000
  const responseTimeoutMs = opts.responseTimeoutMs ?? 120_000
  const closeBrowser = opts.closeBrowser ?? true

  const browser = await chromium.connectOverCDP(cdpWsUrl)
  let page = null
  try {
    const context = browser.contexts()[0] ?? await browser.newContext()
    page = await context.newPage()

    await page.goto(CHATGPT_URL, { waitUntil: 'domcontentloaded', timeout: navTimeoutMs })

    const loginLink = await page.$('[data-testid="login-button"], a[href*="/auth/login"]')
    if (loginLink) throw authError()

    await page.waitForSelector(INPUT_SEL, { timeout: 15_000 })

    // fill() fires the full React synthetic event chain on contenteditable.
    await page.locator(INPUT_SEL).fill(prompt)

    // Confirm the text actually landed before clicking send.
    const inputText = await page.locator(INPUT_SEL).textContent()
    if (!inputText?.trim()) {
      throw new Error('Prompt was not entered into the ChatGPT input — fill() returned empty content.')
    }

    await page.locator(`${SEND_SEL}:not([disabled])`).waitFor({ state: 'visible', timeout: 5_000 })
    await page.locator(SEND_SEL).click()

    // Wait for generation to START: stop button becomes visible.
    await page.locator(STOP_SEL).waitFor({ state: 'visible', timeout: 15_000 })

    // Wait for generation to FINISH: stop button disappears. Also detect mid-session auth gates.
    const gate = await page.waitForFunction(
      ({ stopSel, authSel }) => {
        if (document.querySelector(authSel)) return 'auth'
        if (!document.querySelector(stopSel)) return 'done'
        return null
      },
      {
        stopSel: STOP_SEL,
        authSel: '[data-testid="login-button"], a[href*="/auth/login"]',
      },
      { timeout: responseTimeoutMs, polling: 1000 }
    )
    if (await gate.jsonValue() === 'auth') throw authError()

    const messages = await page.$$(REPLY_SEL)
    const last = messages[messages.length - 1]
    return last ? (await last.textContent())?.trim() ?? '' : ''
  } finally {
    // Always close the page we created to avoid accumulating open tabs in pool browsers.
    await page?.close().catch(() => {})
    // Only close the browser for one-shot sessions. Pool callers pass closeBrowser=false
    // so the Chrome process stays alive for kernel.sh to recycle.
    if (closeBrowser) {
      await browser.close().catch(() => {})
    }
  }
}

/**
 * Acquire a browser from a kernel.sh pool, ask ChatGPT, release the browser.
 */
export async function browserAsk(poolName, prompt, opts = {}) {
  const acquireTimeoutSeconds = opts.acquireTimeoutSeconds ?? 30
  const reuse = opts.reuse ?? true

  const kernelBrowser = await acquireBrowser(poolName, acquireTimeoutSeconds)
  const { session_id: sessionId, cdp_ws_url: cdpWsUrl } = kernelBrowser

  try {
    // closeBrowser=false: leave the Chrome process running so kernel.sh can recycle it.
    return await browserAskCdp(cdpWsUrl, prompt, { ...opts, closeBrowser: false })
  } finally {
    await releaseBrowser(poolName, sessionId, reuse).catch((err) => {
      process.stderr.write(`Warning: could not release browser ${sessionId}: ${err.message}\n`)
    })
  }
}
