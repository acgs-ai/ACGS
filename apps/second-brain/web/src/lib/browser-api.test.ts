import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  apiRequest,
  exchangeSession,
  formatApiError,
  storeSessionCsrf,
} from "./browser-api";

const queued = (value: unknown) => {
  if (
    typeof value !== "object" ||
    value === null ||
    !("state" in value) ||
    value.state !== "queued"
  ) {
    throw new TypeError("invalid queued response");
  }
  return { state: value.state };
};

describe("browser API boundary", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("uses only same-origin credentials and mutation protection", async () => {
    storeSessionCsrf("csrf-token-with-enough-entropy");
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(
        async () => new Response(JSON.stringify({ state: "queued" }), { status: 202 }),
      );

    await apiRequest("/captures/text", {
      method: "POST",
      body: { title: "Note", content: "Evidence" },
      idempotencyAction: "capture:text:stable",
      parse: queued,
    });
    const first = fetchMock.mock.calls[0];
    expect(first?.[0]).toBe("/api/backend/captures/text");
    expect(first?.[1]).toMatchObject({ credentials: "same-origin", redirect: "manual" });
    const firstHeaders = first?.[1]?.headers as Headers;
    expect(firstHeaders.get("x-csrf-token")).toBe("csrf-token-with-enough-entropy");
    expect(firstHeaders.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("rejects external paths and exposes only bounded safe errors", async () => {
    await expect(apiRequest("https://hostile.example/steal", { parse: queued })).rejects.toThrow(
      "API path is invalid",
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ code: "denied", title: "Denied", detail: "Safe detail" }), {
        status: 403,
      }),
    );
    const rejected = apiRequest("/sources", { parse: queued });
    await expect(rejected).rejects.toBeInstanceOf(ApiError);
    await expect(rejected).rejects.toHaveProperty("status", 403);
    expect(formatApiError(new Error("private stack"))).toBe("The request could not be completed.");
  });

  it("fails closed with an explicit contract error for malformed success payloads", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ state: "surprise" }), { status: 200 }),
    );

    const response = apiRequest("/captures/text", { parse: queued });
    await expect(response).rejects.toMatchObject({
      status: 502,
      problem: {
        code: "response_contract_invalid",
        detail: "The service returned an invalid response.",
      },
    });
  });

  it("rejects malformed CSRF values", () => {
    expect(() => storeSessionCsrf("short")).toThrow("CSRF token is invalid");
  });

  it("retains one fingerprint key across an ambiguous commit, reload, and retry", async () => {
    const seenKeys: string[] = [];
    const fetchMock = vi.spyOn(globalThis, "fetch");
    fetchMock.mockImplementationOnce(async (_input, init) => {
      seenKeys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      throw new TypeError("response lost after commit");
    });

    const request = {
      method: "POST" as const,
      body: { title: "Stable", content: "Committed once" },
      idempotencyAction: "capture:text:Stable",
      parse: queued,
    };
    await expect(apiRequest("/captures/text", request)).rejects.toBeInstanceOf(ApiError);

    vi.resetModules();
    const reloaded = await import("./browser-api");
    fetchMock.mockImplementationOnce(async (_input, init) => {
      seenKeys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      return new Response(JSON.stringify({ state: "queued" }), { status: 202 });
    });
    await reloaded.apiRequest("/captures/text", request);

    fetchMock.mockImplementationOnce(async (_input, init) => {
      seenKeys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      return new Response(JSON.stringify({ state: "queued" }), { status: 202 });
    });
    await reloaded.apiRequest("/captures/text", request);

    expect(seenKeys[0]).toBe(seenKeys[1]);
    expect(seenKeys[2]).not.toBe(seenKeys[1]);
  });

  it("uses streamed file bytes in the durable upload fingerprint", async () => {
    const seenKeys: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      seenKeys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      throw new TypeError("response lost after commit");
    });
    const form = (contents: string) => {
      const body = new FormData();
      const bytes = new TextEncoder().encode(contents);
      const file = new File([bytes], "same.txt", {
        type: "text/plain",
        lastModified: 1_788_000_000_000,
      });
      Object.defineProperty(file, "stream", {
        value: () =>
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(bytes);
              controller.close();
            },
          }),
      });
      body.set("file", file);
      body.set("title", "Same metadata");
      return body;
    };
    const request = (body: FormData) =>
      apiRequest("/captures/upload", {
        method: "POST",
        body,
        idempotencyAction: "capture:upload:Same metadata",
        parse: queued,
      });

    await expect(request(form("alpha"))).rejects.toBeInstanceOf(ApiError);
    await expect(request(form("bravo"))).rejects.toBeInstanceOf(ApiError);
    await expect(request(form("alpha"))).rejects.toBeInstanceOf(ApiError);

    expect(seenKeys[0]).not.toBe(seenKeys[1]);
    expect(seenKeys[0]).toBe(seenKeys[2]);
  });

  it("exchanges a typed trusted assertion and retains only the returned CSRF token", async () => {
    const assertion = {
      issuer: "e2e-issuer",
      audience: "e2e-audience",
      issued_at: 1,
      expires_at: 2,
      nonce: crypto.randomUUID(),
      owner_id: crypto.randomUUID(),
      workspace_id: crypto.randomUUID(),
      signature: "a".repeat(64),
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ csrf_token: "returned-csrf-token-with-entropy" }), {
        status: 200,
      }),
    );

    await exchangeSession(assertion);

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.body).toBe(JSON.stringify(assertion));
    expect(sessionStorage.getItem("second-brain.csrf")).toBe("returned-csrf-token-with-entropy");
  });
});
