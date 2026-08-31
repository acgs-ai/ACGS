import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:3302",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop-chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-chromium", use: { viewport: { width: 390, height: 844 } } },
  ],
  webServer: {
    command: "exec ../service/.venv/bin/python tests/e2e/real-persistence-harness.py",
    gracefulShutdown: { signal: "SIGTERM", timeout: 15_000 },
    url: "http://127.0.0.1:3302/today",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
