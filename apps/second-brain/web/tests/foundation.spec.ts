import { readdir } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";

import { type APIRequestContext, expect, test } from "@playwright/test";

const MAX_BODY_BYTES = 12_000_000;
const productionCookie =
  "second_brain_session=replaced-session-token; expires=Fri, 28 Aug 2026 19:54:45 GMT; HttpOnly; Max-Age=86400; Path=/; SameSite=lax; Secure";

async function upstreamMutationCount(request: APIRequestContext): Promise<number> {
  const response = await request.get("http://127.0.0.1:3310/test/stats");
  return (await response.json()).mutation_request_count as number;
}

async function proxySpools(): Promise<string[]> {
  return (await readdir("/tmp")).filter((name) => name.startsWith("second-brain-proxy-"));
}

function postWithDeclaredLength(contentLength: number): Promise<{ body: string; status: number }> {
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(
      "http://127.0.0.1:3301/api/backend/session/check",
      {
        method: "POST",
        headers: {
          "content-length": String(contentLength),
          "content-type": "application/octet-stream",
          origin: "http://127.0.0.1:3301",
        },
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
        incoming.on("end", () => {
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            status: incoming.statusCode ?? 0,
          });
        });
      },
    );
    outgoing.on("error", reject);
    outgoing.setTimeout(10_000, () => outgoing.destroy(new Error("request timed out")));
    outgoing.end();
  });
}

function postStalledBody(): Promise<{ raw: string; status: number }> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let settled = false;
    const socket = netConnect(3301, "127.0.0.1", () => {
      socket.write(
        "POST /api/backend/session/check HTTP/1.1\r\n" +
          "Host: 127.0.0.1:3301\r\n" +
          "Origin: http://127.0.0.1:3301\r\n" +
          "Content-Type: application/octet-stream\r\n" +
          "Transfer-Encoding: chunked\r\n" +
          "Connection: close\r\n\r\n" +
          "1\r\nx\r\n",
      );
    });
    const finish = () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString("utf8");
      const status = Number(/^HTTP\/1\.1 (\d{3})/m.exec(raw)?.[1] ?? 0);
      resolve({ raw, status });
    };
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("end", finish);
    socket.on("close", finish);
    socket.on("error", (error) => {
      if (chunks.length > 0) finish();
      else reject(error);
    });
    socket.setTimeout(15_000, () => socket.destroy(new Error("request timed out")));
  });
}

function byteStream(totalBytes: number): ReadableStream<Uint8Array> {
  let emitted = 0;
  return new ReadableStream({
    pull(controller) {
      if (emitted >= totalBytes) {
        controller.close();
        return;
      }
      const size = Math.min(64 * 1024, totalBytes - emitted);
      emitted += size;
      controller.enqueue(new Uint8Array(size));
    },
  });
}

function postStream(totalBytes: number, contentLength?: number): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/octet-stream",
    origin: "http://127.0.0.1:3301",
  };
  if (contentLength !== undefined) headers["content-length"] = String(contentLength);
  return fetch("http://127.0.0.1:3301/api/backend/session/check", {
    method: "POST",
    headers,
    body: byteStream(totalBytes),
    duplex: "half",
  } as RequestInit & { duplex: "half" });
}

const routes = [
  ["/today", "Today"],
  ["/inbox", "Inbox"],
  ["/library", "Library"],
  ["/search", "Search"],
  ["/ask", "Ask"],
  ["/memories", "Approved memories"],
  ["/memories/review", "Memory review"],
] as const;

test("every required product route exposes its implemented surface", async ({ page }) => {
  for (const [path, heading] of routes) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.getByRole("heading", { name: /unavailable/i })).toHaveCount(0);
  }

  await page.goto("/library/not-a-uuid");
  await expect(
    page.getByRole("heading", { level: 2, name: "Invalid source reference" }),
  ).toBeVisible();

  await page.goto("/settings");
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "Service ready" })).toBeVisible();
  await expect(page.getByText("available", { exact: true })).toHaveCount(3);
  await expect(page.getByText("filesystem", { exact: true })).toBeVisible();
  await expect(page.getByText("fake", { exact: true })).toBeVisible();
  await expect(page.getByText("10,000,000 bytes", { exact: true })).toBeVisible();
});

test("the server API boundary rejects unlisted routes and cross-origin mutations", async ({
  request,
}) => {
  const unlisted = await request.delete("/api/backend/sources");
  expect(unlisted.status()).toBe(404);
  expect((await unlisted.json()).code).toBe("route_unavailable");

  const crossOrigin = await request.post("/api/backend/answers", {
    data: { query: "must not reach the service" },
    headers: { origin: "https://hostile.example" },
  });
  expect(crossOrigin.status()).toBe(403);
  expect((await crossOrigin.json()).code).toBe("origin_forbidden");
});

test("the real Next dispatcher strips browser identity and forwards only approved session metadata", async ({
  context,
}) => {
  await context.addCookies([
    {
      name: "other",
      value: "private-cookie-value",
      domain: "127.0.0.1",
      path: "/",
    },
    {
      name: "second_brain_session",
      value: "opaque-session-token-with-entropy",
      domain: "127.0.0.1",
      path: "/",
    },
  ]);
  const requestId = crypto.randomUUID();
  const response = await context.request.post("/api/backend/session/check", {
    data: { check: true },
    headers: {
      authorization: "Bearer browser-controlled",
      "idempotency-key": "capture-attempt-1",
      origin: "http://127.0.0.1:3301",
      "x-csrf-token": "bound-csrf-token",
      "x-request-id": requestId,
      "x-second-brain-owner-id": crypto.randomUUID(),
      "x-second-brain-workspace-id": crypto.randomUUID(),
    },
  });

  expect(response.status()).toBe(200);
  expect(await response.json()).toEqual({
    authorization: null,
    cookie: "second_brain_session=opaque-session-token-with-entropy",
    csrf: "bound-csrf-token",
    host: "127.0.0.1:3301",
    idempotency_key: "capture-attempt-1",
    origin: "http://127.0.0.1:3301",
    owner_id: null,
    received_bytes: 14,
    request_id: requestId,
    workspace_id: null,
  });
  expect(response.headers()["set-cookie"]).toBeUndefined();
  expect(response.headers()["x-request-id"]).toBe(requestId);
});

test("the real auth exchange forwards the backend production session cookie safely", async ({
  request,
}) => {
  const response = await request.post("/api/backend/auth/exchange", {
    data: { assertion: "bounded-test-assertion" },
    headers: { origin: "http://127.0.0.1:3301" },
  });

  expect(response.status()).toBe(200);
  expect(response.headers()["set-cookie"]).toBe(productionCookie);
});

test("the real Next dispatcher does not follow upstream redirects or forward unsafe cookies", async ({
  request,
}) => {
  const redirect = await request.get("/api/backend/health?redirect=1", { maxRedirects: 0 });
  expect(redirect.status()).toBe(302);
  expect(redirect.headers().location).toBeUndefined();
  expect(await redirect.text()).not.toContain("followed");

  const unsafeCookie = await request.post("/api/backend/auth/exchange?unsafe_cookie=1", {
    data: { check: true },
    headers: { origin: "http://127.0.0.1:3301" },
  });
  expect(unsafeCookie.status()).toBe(200);
  expect(unsafeCookie.headers()["set-cookie"]).toBeUndefined();
});

test("the real dispatcher bounds declared and streamed request bodies before forwarding", async ({
  request,
}) => {
  const before = await upstreamMutationCount(request);

  const declared = await postWithDeclaredLength(MAX_BODY_BYTES + 1);
  expect(declared.status).toBe(413);
  expect(declared.body).toBe("");

  const chunked = await postStream(MAX_BODY_BYTES + 1);
  expect(chunked.status).toBe(413);
  expect(await chunked.text()).toBe("");
  expect(await upstreamMutationCount(request)).toBe(before);

  const boundary = await postStream(MAX_BODY_BYTES, MAX_BODY_BYTES);
  expect(boundary.status).toBe(200);
  expect((await boundary.json()).received_bytes).toBe(MAX_BODY_BYTES);
  expect(await upstreamMutationCount(request)).toBe(before + 1);
});

test("the real dispatcher times out a stalled request body without forwarding or leaking a spool", async ({
  request,
}) => {
  const beforeSpools = await proxySpools();
  const beforeMutations = await upstreamMutationCount(request);

  const stalled = await postStalledBody();
  expect(stalled.status).toBe(408);
  expect(stalled.raw).toContain('"code":"request_body_timeout"');
  expect(stalled.raw).toContain('"retryable":true');
  expect(stalled.raw).toContain('"title":"Request timed out"');
  expect(await upstreamMutationCount(request)).toBe(beforeMutations);
  expect(await proxySpools()).toEqual(beforeSpools);
});

test("the real dispatcher rejects an oversized query without leaving a request spool", async ({
  request,
}) => {
  const beforeSpools = await proxySpools();
  const beforeMutations = await upstreamMutationCount(request);

  const response = await request.post(`/api/backend/session/check?${"q".repeat(4097)}`, {
    data: { bounded: true },
    headers: { origin: "http://127.0.0.1:3301" },
  });

  expect(response.status()).toBe(414);
  expect((await response.json()).code).toBe("query_too_large");
  expect(await upstreamMutationCount(request)).toBe(beforeMutations);
  expect(await proxySpools()).toEqual(beforeSpools);
});

test("pages and API success and error responses carry the security policy", async ({
  page,
  request,
}) => {
  const pageResponse = await page.goto("/today");
  expect(pageResponse).not.toBeNull();
  const success = await request.get("/api/backend/status");
  const error = await request.get("/api/backend/not-allowed");

  for (const headers of [pageResponse?.headers() ?? {}, success.headers(), error.headers()]) {
    expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(headers["permissions-policy"]).toContain("camera=()");
    expect(headers["referrer-policy"]).toBe("no-referrer");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["cache-control"]).toContain("private");
    expect(headers["cache-control"]).toContain("no-store");
    expect(headers["x-powered-by"]).toBeUndefined();
    expect(headers["strict-transport-security"]).toBeUndefined();
  }
});

test("keyboard users can skip navigation", async ({ page }) => {
  await page.goto("/today");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("the application shell does not overflow a 390 pixel viewport", async ({ page }) => {
  await page.goto("/today");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
});
