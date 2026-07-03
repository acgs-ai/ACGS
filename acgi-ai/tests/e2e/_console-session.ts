// Shared helpers for console-surface e2e specs.
//
// 1) mockConsoleSession: admit the console route guard without a real IdP.
//    The console surface is auth-gated by `requireConsoleSession`
//    (src/surfaces/console/App.tsx). In a production build (which `vite preview`
//    serves) the demo sessionStorage path is disabled, so the only gate is
//    `hasProductionSession()`, which fetches `/auth/status` and accepts the exact
//    forward-auth-status-bridge payload shape pinned in `isProductionSessionStatus`
//    (session.ts). We fulfil `/auth/status` with that payload.
//
// 2) mockConsoleData: serve the console's read APIs from the SAME fixtures the
//    dev-mode MSW worker uses (src/mocks/data/*). `vite preview` serves the
//    static bundle with NO MSW worker (worker.start() is dev-only) and proxies
//    `/api/*` to a dead upstream, so without this the data-bearing views render
//    their fail-closed error state. Reusing the canonical fixtures keeps the
//    scanned/screenshotted console POPULATED with zero shape drift.

import type { Page } from '@playwright/test'

import { ACCOUNT_VIEW } from '../../src/mocks/data/account'
import { GOVERNED_ACTIONS } from '../../src/mocks/data/actions'
import { AGENTS } from '../../src/mocks/data/agents'
import { AUDIT_EVENTS } from '../../src/mocks/data/audit'
import { COMPILE_DRAFT } from '../../src/mocks/data/compile'
import { CONSOLE_SUMMARY } from '../../src/mocks/data/console-summary'
import { DELIBERATIONS } from '../../src/mocks/data/deliberations'
import { INCIDENTS } from '../../src/mocks/data/incidents'
import { MACI_LANES } from '../../src/mocks/data/maci'
import { OVERVIEW_SUMMARY } from '../../src/mocks/data/overview'
import { POLICIES } from '../../src/mocks/data/policies'
import { SETTING_SECTIONS } from '../../src/mocks/data/settings'
import { TENANTS } from '../../src/mocks/data/tenants'

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

// Mirror of the GET handlers in src/mocks/handlers.ts (same fixtures).
const CONSOLE_GET_FIXTURES: Record<string, unknown> = {
  '/api/v1/overview': OVERVIEW_SUMMARY,
  '/api/v1/console-summary': CONSOLE_SUMMARY,
  '/api/v1/agents': AGENTS,
  '/api/v1/actions': GOVERNED_ACTIONS,
  '/api/v1/maci': MACI_LANES,
  '/api/v1/deliberations': DELIBERATIONS,
  '/api/v1/incidents': INCIDENTS,
  '/api/v1/policies': POLICIES,
  '/api/v1/compile/draft': COMPILE_DRAFT,
  '/api/v1/audit': AUDIT_EVENTS,
  '/api/v1/settings': SETTING_SECTIONS,
  '/api/v1/tenants': TENANTS,
  '/api/v1/account': ACCOUNT_VIEW,
}

export async function mockConsoleData(page: Page): Promise<void> {
  for (const [path, body] of Object.entries(CONSOLE_GET_FIXTURES)) {
    await page.route(`**${path}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(body),
      })
    })
  }
}
