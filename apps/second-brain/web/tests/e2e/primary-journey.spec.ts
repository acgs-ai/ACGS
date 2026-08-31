import { createHmac } from "node:crypto";

import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";

const ORIGIN = "http://127.0.0.1:3302";
const RECOVERY_STATUS_URL = "http://127.0.0.1:3321/status";
const OWNER = "11111111-1111-4111-8111-111111111111";
const WORKSPACE = "22222222-2222-4222-8222-222222222222";
const SECRET = "e2e-proxy-secret-material-at-least-32-bytes";
const SEEDED_PRIVATE_TEXT = "PRIVATE_E2E_SOURCE_STRING_DO_NOT_LOG";

async function activateByKeyboard(page: Page, target: Locator) {
  await target.focus();
  await page.keyboard.press("Enter");
}

async function assertPopulatedPageQuality(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
  expect((await new AxeBuilder({ page }).include("main").analyze()).violations).toEqual([]);
}

async function assertRecoveryProof(page: Page) {
  const deadline = Date.now() + 35_000;
  while (Date.now() < deadline) {
    const response = await page.request.get(RECOVERY_STATUS_URL);
    const payload = (await response.json()) as { state?: unknown; code?: unknown };
    if (response.status() === 503 || payload.state === "error") {
      throw new Error(`worker recovery proof failed: ${String(payload.code)}`);
    }
    if (response.status() === 200 && payload.state === "success") {
      return;
    }
    expect(response.status()).toBe(202);
    expect(payload).toEqual({ state: "pending" });
    await page.waitForTimeout(100);
  }
  throw new Error("worker recovery proof did not complete before its deadline");
}

async function authenticate(page: Page): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const assertion = {
    issuer: "e2e-issuer",
    audience: "e2e-audience",
    issued_at: now,
    expires_at: now + 120,
    nonce: crypto.randomUUID(),
    owner_id: OWNER,
    workspace_id: WORKSPACE,
  };
  const material = [
    assertion.issuer,
    assertion.audience,
    assertion.issued_at,
    assertion.expires_at,
    assertion.nonce,
    assertion.owner_id,
    assertion.workspace_id,
  ].join("\n");
  const response = await page.request.post("/api/backend/auth/exchange", {
    data: { ...assertion, signature: createHmac("sha256", SECRET).update(material).digest("hex") },
    headers: { origin: ORIGIN },
  });
  expect(response.status()).toBe(200);
  expect(response.headers()["set-cookie"]).toContain("HttpOnly");
  const csrf = (await response.json()).csrf_token as string;
  await page.goto("/today");
  await page.evaluate((token) => sessionStorage.setItem("second-brain.csrf", token), csrf);
  return csrf;
}

async function capture(
  page: Page,
  title: string,
  content: string,
  mode: "note" | "upload",
  project: string,
  tag: string,
) {
  await page.goto("/inbox");
  if (mode === "upload") {
    await page.getByLabel("Document").focus();
    await page.keyboard.press("Space");
    await page.getByLabel("Supported document").setInputFiles({
      name: `${title}.txt`,
      mimeType: "text/plain",
      buffer: Buffer.from(content),
    });
  } else {
    await page.getByLabel("Source content").fill(content);
  }
  await page.getByLabel("Display title").fill(title);
  await page.getByLabel("Project").selectOption({ label: project });
  await page.getByLabel("Tags").selectOption({ label: tag });
  await activateByKeyboard(page, page.getByRole("button", { name: "Capture source" }));
  await expect(
    page.getByRole("heading", { name: /Source (queued|processing|ready)/ }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Source ready" })).toBeVisible({
    timeout: 20_000,
  });
  const href = await page.getByRole("link", { name: "Open source" }).getAttribute("href");
  expect(href).toMatch(/^\/library\/[0-9a-f-]+$/);
  return href?.split("/").at(-1) as string;
}

async function captureFailedPdf(page: Page, title: string, project: string, tag: string) {
  await page.goto("/inbox");
  await page.getByLabel("Document").focus();
  await page.keyboard.press("Space");
  await page.getByLabel("Supported document").setInputFiles({
    name: `${title}.pdf`,
    mimeType: "application/pdf",
    buffer: Buffer.from(["%PDF-1.4", "startxref", "0", "%%EOF"].join("\n")),
  });
  await page.getByLabel("Display title").fill(title);
  await page.getByLabel("Project").selectOption({ label: project });
  await page.getByLabel("Tags").selectOption({ label: tag });
  await activateByKeyboard(page, page.getByRole("button", { name: "Capture source" }));
  await expect(page.getByRole("heading", { name: "Source failed" })).toBeVisible({
    timeout: 20_000,
  });
  const href = await page.getByRole("link", { name: "Open source" }).getAttribute("href");
  expect(href).toMatch(/^\/library\/[0-9a-f-]+$/);
  return href?.split("/").at(-1) as string;
}

test("real persistence supports the primary evidence and memory journey", async ({
  page,
}, testInfo) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on(
    "console",
    (message) => message.type() === "error" && errors.push(`console:${message.text()}`),
  );
  page.on(
    "response",
    (response) =>
      response.status() >= 500 && errors.push(`http:${response.status()} ${response.url()}`),
  );
  const csrf = await authenticate(page);
  const suffix = `${testInfo.project.name}-${Date.now()}`;
  const project = `Project ${suffix}`,
    emptyProject = `Empty project ${suffix}`,
    tag = `Tag ${suffix}`;
  const noteTitle = `Research note ${suffix}`,
    fileTitle = `Purge file ${suffix}`,
    failedTitle = `Failed parser ${suffix}`;
  const marker = `evidence-${suffix}`,
    purgeMarker = `purge-${suffix}`;

  await page.goto("/settings");
  await page.getByLabel("New project name").fill(project);
  await activateByKeyboard(page, page.getByRole("button", { name: "Create project" }));
  await expect(page.getByRole("status").filter({ hasText: "Project created." })).toBeVisible();
  await page.getByLabel("New project name").fill(emptyProject);
  await activateByKeyboard(page, page.getByRole("button", { name: "Create project" }));
  await expect
    .poll(() =>
      page
        .getByRole("textbox", { name: "Project name", exact: true })
        .evaluateAll((inputs) => inputs.map((input) => (input as HTMLInputElement).value)),
    )
    .toContain(emptyProject);
  await page.getByLabel("New tag name").fill(tag);
  await activateByKeyboard(page, page.getByRole("button", { name: "Create tag" }));
  await expect(page.getByRole("status").filter({ hasText: "Tag created." })).toBeVisible();

  const sourceId = await capture(
    page,
    noteTitle,
    `${SEEDED_PRIVATE_TEXT}. Context before. ${marker}: Rowan keeps release evidence in this source. Context after.`,
    "note",
    project,
    tag,
  );
  const purgeSourceId = await capture(
    page,
    fileTitle,
    `${purgeMarker}: temporary TXT evidence.`,
    "upload",
    project,
    tag,
  );
  await assertPopulatedPageQuality(page);
  const failedSourceId = await captureFailedPdf(page, failedTitle, project, tag);
  await assertPopulatedPageQuality(page);
  await page.goto(`/library/${failedSourceId}`);
  await expect(page.getByRole("heading", { name: "Source processing details" })).toBeVisible();
  await expect(page.getByText("Processing failed", { exact: true })).toBeVisible();
  await expect(page.getByText("Error code:")).toBeVisible();
  await assertPopulatedPageQuality(page);

  await page.goto("/library");
  await page.getByLabel("Search library").fill(marker);
  await page.getByLabel("Project").selectOption({ label: project });
  await page.getByLabel("Tag").selectOption({ label: tag });
  await page.getByLabel("Source type").selectOption("note");
  await activateByKeyboard(page, page.getByRole("button", { name: "Apply filters" }));
  await expect(page.getByRole("link", { name: noteTitle })).toBeVisible();
  await expect(page.getByRole("link", { name: fileTitle })).toHaveCount(0);
  await assertPopulatedPageQuality(page);

  await page.goto("/search");
  await page.getByLabel("Search evidence").fill(marker);
  await page.getByLabel("Project").selectOption({ label: project });
  await page.getByLabel("Tag").selectOption({ label: tag });
  await page.getByLabel("Source type").selectOption("note");
  await activateByKeyboard(page, page.getByRole("button", { name: "Search sources" }));
  const result = page
    .getByRole("list", { name: "Search results" })
    .getByRole("listitem")
    .filter({ hasText: noteTitle });
  await expect(result).toContainText(marker);
  await expect(result).toContainText("Lexical");
  await expect(result).toContainText("Semantic");
  await assertPopulatedPageQuality(page);
  await activateByKeyboard(page, result.getByRole("link", { name: noteTitle }));
  await expect(page.getByRole("heading", { name: "Selected supporting passage" })).toBeVisible();
  await expect(page.locator("mark")).toContainText(marker);
  await expect(page.locator("mark")).toBeFocused();
  await assertPopulatedPageQuality(page);

  await page.goto("/ask");
  await page.getByLabel("Question").fill(marker);
  await page.getByLabel("Project").selectOption({ label: project });
  await page.getByLabel("Tag").selectOption({ label: tag });
  await page.getByLabel("Source type").selectOption("note");
  await activateByKeyboard(page, page.getByRole("button", { name: "Ask from sources" }));
  await expect(page.getByRole("heading", { name: "Source-supported response" })).toBeVisible();
  await expect(page.getByText("Proposed memory · inactive")).toBeVisible();
  await assertPopulatedPageQuality(page);
  await activateByKeyboard(page, page.getByRole("link", { name: "Inspect evidence" }));
  await expect(page.locator("mark")).toBeFocused();

  await page.goto("/ask");
  await page.getByLabel("Question").fill(`xylophone-nebula-unrelated-${crypto.randomUUID()}`);
  await page.getByLabel("Project").selectOption({ label: project });
  const unrelatedAnswer = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/backend/answers") && response.request().method() === "POST",
  );
  await activateByKeyboard(page, page.getByRole("button", { name: "Ask from sources" }));
  const unrelatedResponse = await unrelatedAnswer;
  expect(unrelatedResponse.status()).toBe(200);
  expect(await unrelatedResponse.json()).toMatchObject({
    status: "insufficient_evidence",
    sufficiency: { sufficient: false, reason_code: "semantic_threshold_unconfigured" },
    provider_status: "not_called",
  });
  await expect(page.getByRole("heading", { name: "No source-supported answer" })).toBeVisible();

  await page.goto("/ask");
  await page.getByLabel("Question").fill(`unsupported-${crypto.randomUUID()}`);
  await page.getByLabel("Project").selectOption({ label: emptyProject });
  await activateByKeyboard(page, page.getByRole("button", { name: "Ask from sources" }));
  await expect(page.getByRole("heading", { name: "No source-supported answer" })).toBeVisible();

  await page.goto("/memories");
  await expect(page.getByText(marker)).toHaveCount(0);
  await page.goto("/memories/review");
  const proposal = page.getByRole("listitem").filter({ hasText: marker });
  await expect(proposal).toContainText("inactive");
  await assertPopulatedPageQuality(page);
  await activateByKeyboard(page, proposal.getByRole("button", { name: "Approve" }));
  await expect(page.getByRole("status").filter({ hasText: "approved" })).toBeVisible();
  await page.goto("/memories");
  const memory = page.getByRole("listitem").filter({ hasText: marker }).first();
  await expect(memory).toContainText("revision 1");
  await memory.locator("summary").filter({ hasText: "Add revision" }).focus();
  await page.keyboard.press("Enter");
  await memory.getByLabel("Statement").fill(`Durable revision ${marker}`);
  await activateByKeyboard(page, memory.getByRole("button", { name: "Add revision" }));
  await expect(page.getByRole("status").filter({ hasText: "revision added" })).toBeVisible();
  await expect(page.getByRole("heading", { name: `Durable revision ${marker}` })).toBeVisible();
  await assertPopulatedPageQuality(page);

  await page.goto(`/library/${purgeSourceId}`);
  const chunkId = (await page.locator("[id^=chunk-]").first().getAttribute("id"))?.slice(
    6,
  ) as string;
  await page.goto("/library");
  const purgeRow = page.getByRole("listitem").filter({ hasText: fileTitle });
  await activateByKeyboard(page, purgeRow.getByRole("button", { name: "Request purge" }));
  const confirmation = purgeRow.getByRole("alertdialog", {
    name: new RegExp(`Confirm purge for.*${fileTitle}`),
  });
  await expect(confirmation).toBeVisible();
  await activateByKeyboard(
    page,
    confirmation.getByRole("button", { name: `Confirm purge ${fileTitle}` }),
  );
  await expect(purgeRow).toContainText(/Purge (queued|processing) · operation [0-9a-f-]+/);
  await expect(purgeRow).toBeVisible();
  await expect(purgeRow).toHaveCount(0, { timeout: 20_000 });
  const sessionCookie = (await page.context().cookies()).find(
    (cookie) => cookie.name === "second_brain_session",
  );
  expect(sessionCookie).toMatchObject({ httpOnly: true, secure: true });
  await expect
    .poll(
      async () =>
        (
          await page.request.get(`/api/backend/sources/${purgeSourceId}/context/${chunkId}`, {
            headers: { cookie: `${sessionCookie?.name}=${sessionCookie?.value}` },
          })
        ).status(),
      { timeout: 20_000 },
    )
    .toBe(404);
  await page.goto("/search");
  await page.getByLabel("Search evidence").fill(purgeMarker);
  await activateByKeyboard(page, page.getByRole("button", { name: "Search sources" }));
  const postPurgeResults = page.getByRole("list", { name: "Search results" });
  await expect(postPurgeResults.getByRole("link", { name: fileTitle })).toHaveCount(0);
  await expect(postPurgeResults).not.toContainText(purgeMarker);

  await page.goto("/today");
  for (const heading of [
    "Sources added lately",
    "Jobs requiring attention",
    "Durable memories",
    "Relevant sources",
    "Review set",
  ]) {
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
  }
  await expect(page.getByRole("link", { name: noteTitle }).first()).toBeVisible();
  await expect(page.getByText(`Durable revision ${marker}`, { exact: true })).toBeVisible();
  await assertPopulatedPageQuality(page);

  const requestHeaders = { cookie: `${sessionCookie?.name}=${sessionCookie?.value}` };
  const memoriesResponse = await page.request.get("/api/backend/memories", {
    headers: requestHeaders,
  });
  expect(memoriesResponse.status()).toBe(200);
  const approvedMemories = (await memoriesResponse.json()) as Array<{
    memory_id: string;
    statement: string;
  }>;
  const approvedMemory = approvedMemories.find(
    (candidate) => candidate.statement === `Durable revision ${marker}`,
  );
  expect(approvedMemory?.memory_id).toMatch(/^[0-9a-f-]+$/);
  await page.goto("/memories");
  const purgeMemoryRow = page
    .getByRole("listitem")
    .filter({ hasText: `Durable revision ${marker}` })
    .first();
  await activateByKeyboard(page, purgeMemoryRow.getByRole("button", { name: "Request purge" }));
  const memoryConfirmation = purgeMemoryRow.getByRole("alertdialog", {
    name: `Confirm purge of memory Durable revision ${marker}`,
  });
  await expect(memoryConfirmation).toBeVisible();
  await activateByKeyboard(
    page,
    memoryConfirmation.getByRole("button", {
      name: `Confirm purge Durable revision ${marker}`,
    }),
  );
  await expect(purgeMemoryRow).toContainText(/Purge (queued|processing) · operation [0-9a-f-]+/);
  await expect(purgeMemoryRow).toHaveCount(0, { timeout: 20_000 });
  await expect
    .poll(
      async () =>
        (
          await page.request.get(`/api/backend/memories/${approvedMemory?.memory_id}`, {
            headers: requestHeaders,
          })
        ).status(),
      { timeout: 20_000 },
    )
    .toBe(404);
  const postPurgeMemories = await page.request.get("/api/backend/memories", {
    headers: requestHeaders,
  });
  expect(postPurgeMemories.status()).toBe(200);
  expect(await postPurgeMemories.json()).not.toContainEqual(
    expect.objectContaining({ memory_id: approvedMemory?.memory_id }),
  );
  await assertRecoveryProof(page);
  expect(errors).toEqual([]);
  expect(sourceId).toMatch(/^[0-9a-f-]+$/);
  expect(csrf.length).toBeGreaterThan(16);
});
