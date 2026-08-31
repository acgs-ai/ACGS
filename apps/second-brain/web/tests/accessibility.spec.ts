import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const routes = [
  "/today",
  "/inbox",
  "/library",
  "/library/11111111-1111-4111-8111-111111111111",
  "/search",
  "/ask",
  "/memories",
  "/memories/review",
  "/settings",
] as const;

for (const route of routes) {
  test(`${route} has no automated full-page accessibility violations`, async ({ page }) => {
    await page.goto(route);
    await expect(page.locator("main")).toBeVisible();

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  });
}

test("the shell exposes a predictable keyboard focus order", async ({ page }) => {
  await page.goto("/today");

  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Today", exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Inbox", exact: true })).toBeFocused();
});
