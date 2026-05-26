// T063 — Console /console/bus end-to-end smoke.
//
// The console surface is auth-gated by `requireConsoleSession` in
// src/surfaces/console/App.tsx. In dev/preview builds the demo session lives
// at `acgs.console.session` in sessionStorage with shape
// `{ createdAt: string, nonce: string }` (see src/lib/session.ts). We inject
// that key via `addInitScript` before any console route is loaded so the
// route guard accepts the request without a real IdP roundtrip.

import { expect, test } from '@playwright/test'

test.describe('Bus Analysis console route', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      const session = {
        createdAt: new Date().toISOString(),
        nonce: 'e2e-bus-analysis-nonce',
      }
      try {
        window.sessionStorage.setItem('acgs.console.session', JSON.stringify(session))
      } catch {
        // sessionStorage may be unavailable on some surface modes; we still
        // try the navigation so the test fails on the visible symptom.
      }
    })
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
