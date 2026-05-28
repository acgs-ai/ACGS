// T063 — Console /console/bus end-to-end smoke.
//
// The console surface is auth-gated by `requireConsoleSession` in
// src/surfaces/console/App.tsx. In a production build (which `vite preview`
// serves), the demo sessionStorage path is intentionally disabled
// (`isDemoSessionEnabled` returns `!import.meta.env.PROD`), so `hasSession()`
// always returns false. The only remaining gate is `hasProductionSession()`,
// which fetches `/auth/status` and accepts the exact forward-auth-status-bridge
// payload shape pinned in `isProductionSessionStatus` (session.ts).
//
// We mock `/auth/status` with that exact payload so the route guard admits
// the smoke navigation without a real IdP roundtrip.

import { expect, test } from '@playwright/test'

const AUTH_STATUS_PAYLOAD = {
  authenticated: true,
  source: 'forward-auth-status-bridge',
  claimBoundary:
    'production · forward-auth status bridge · client demo storage is not accepted',
}

test.describe('Bus Analysis console route', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/auth/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(AUTH_STATUS_PAYLOAD),
      })
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
