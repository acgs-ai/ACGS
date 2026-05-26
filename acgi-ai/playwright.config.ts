import { defineConfig, devices } from '@playwright/test'

// Playwright config for acgi-ai end-to-end smoke tests.
//
// We use `vite preview` (not `vite dev`) because the host system has a tight
// inotify instance limit (1024) and Vite dev's per-file watchers exhaust it
// with ENOSPC. Preview serves the production bundle without watchers.
const PORT = 5174

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 120_000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `bash -c "VITE_USE_MOCKS=true pnpm build:console && pnpm exec vite preview --mode console --port ${PORT} --strictPort"`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
})
