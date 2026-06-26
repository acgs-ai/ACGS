// B16 — visual-diff baseline (ONE console route, ONE viewport).
//
// Scope (honest): a single pixel baseline of the POPULATED console overview at
// 1440 wide (read APIs served from the same fixtures dev-mode MSW uses, so the
// data-bearing views render rather than their fail-closed error state). The full
// five-viewport matrix and the remaining visual targets enumerated in
// VISUAL_BASELINE_TARGETS remain Phase 3 work (see PLAN.md / check-visual-
// baseline-foundation.mjs). Dynamic regions (live counters, timestamps, data
// tables) are masked so the baseline guards layout chrome, not volatile data.

import { expect, test } from '@playwright/test'

import { mockConsoleData, mockConsoleSession } from './_console-session'

test.use({ viewport: { width: 1440, height: 900 } })

test('console overview matches the 1440 visual baseline', async ({ page }) => {
  await mockConsoleSession(page)
  await mockConsoleData(page)
  await page.goto('/console')
  await expect(page.locator('#console-main-content')).toBeVisible({ timeout: 30_000 })

  await expect(page).toHaveScreenshot('console-overview-1440.png', {
    fullPage: true,
    // Mask volatile regions: live counters / timestamps (.c-meta) and the
    // mock-data tables (.c-table). The baseline guards the console chrome and
    // layout, not the contents of these regions.
    mask: [page.locator('.c-meta'), page.locator('.c-table')],
    // Absorb sub-pixel anti-aliasing noise; the self-hosted CI runner shares
    // this machine's font stack, so drift is small but non-zero.
    maxDiffPixelRatio: 0.001,
  })
})
