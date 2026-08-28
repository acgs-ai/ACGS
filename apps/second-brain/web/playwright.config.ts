import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testIgnore: "**/e2e/**",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:3301",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop-chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile-chromium", use: { viewport: { width: 390, height: 844 } } },
  ],
  webServer: [
    {
      command: "node tests/upstream-harness.mjs",
      url: "http://127.0.0.1:3310/ready",
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command:
        "SECOND_BRAIN_API_URL=http://127.0.0.1:3310 SECOND_BRAIN_PUBLIC_ORIGIN=http://127.0.0.1:3301 SECOND_BRAIN_WEB_APP_ENV=test SECOND_BRAIN_WEB_AUTH_MODE=session SECOND_BRAIN_WEB_BIND_HOST=127.0.0.1 SECOND_BRAIN_WEB_PORT=3301 pnpm start",
      url: "http://127.0.0.1:3301/today",
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
