// T063 — Console /console/bus end-to-end smoke.
//
// The console surface is auth-gated by `hasSession()` in src/App.tsx, which
// reads `acgs.console.session` from sessionStorage. We seed that key before
// navigating to /console/bus so the route guard admits us without a real
// IdP roundtrip. Note: `createSession()` itself throws in PROD, so we set
// the storage directly via Playwright rather than calling the helper.

import { expect, test } from '@playwright/test'

const SESSION_KEY = 'acgs.console.session'
const SESSION_VALUE = JSON.stringify({
  createdAt: '2026-05-14T13:51:09.000Z',
  nonce: 'e2e-bus-analysis-smoke',
})

test.describe('Bus Analysis console route', () => {
  test.beforeEach(async ({ page }) => {
    // sessionStorage is per-origin; we need to be on the origin before we
    // can set it. Land on the marketing root first, seed the session, then
    // navigate to the privileged route.
    await page.goto('/')
    await page.evaluate(
      ([key, value]) => {
        window.sessionStorage.setItem(key, value)
      },
      [SESSION_KEY, SESSION_VALUE],
    )
  })

  test('renders the bus analysis page with 2xx response and a bus heading', async ({ page }) => {
    const response = await page.goto('/console/bus')
    expect(response).not.toBeNull()
    const status = response?.status() ?? 0
    expect(status, `expected 2xx for /console/bus, got ${status}`).toBeGreaterThanOrEqual(200)
    expect(status).toBeLessThan(300)

    await expect(page).toHaveURL(/\/console\/bus/)

    // The console shell exposes the section name; we accept any heading-level
    // element whose accessible name mentions "bus" case-insensitively.
    const busHeading = page.getByRole('heading', { name: /bus/i }).first()
    await expect(busHeading).toBeVisible({ timeout: 30_000 })
  })
})
