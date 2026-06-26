// Shared helper: admit the console route guard without a real IdP roundtrip.
//
// The console surface is auth-gated by `requireConsoleSession` in
// src/surfaces/console/App.tsx. In a production build (which `vite preview`
// serves) the demo sessionStorage path is disabled, so the only gate is
// `hasProductionSession()`, which fetches `/auth/status` and accepts the exact
// forward-auth-status-bridge payload shape pinned in `isProductionSessionStatus`
// (session.ts). We fulfil `/auth/status` with that payload. Mirrors the inline
// mock in bus-analysis.spec.ts.

import type { Page } from '@playwright/test'

export const AUTH_STATUS_PAYLOAD = {
  authenticated: true,
  source: 'forward-auth-status-bridge',
  claimBoundary:
    'production · forward-auth status bridge · client demo storage is not accepted',
}

export async function mockConsoleSession(page: Page): Promise<void> {
  await page.route('**/auth/status', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(AUTH_STATUS_PAYLOAD),
    })
  })
}
