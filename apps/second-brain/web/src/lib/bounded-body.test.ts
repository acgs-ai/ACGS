import { readdir } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { MAX_BODY_BYTES, readBoundedRequestBody } from "./bounded-body";

async function bytes(stream: NodeJS.ReadableStream): Promise<number[]> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of stream) chunks.push(new Uint8Array(chunk as Uint8Array));
  return [...Buffer.concat(chunks)];
}

describe("bounded request body reader", () => {
  it("uses the service request-envelope limit", () => {
    expect(MAX_BODY_BYTES).toBe(12_000_000);
  });

  it("rejects an oversized declared length before reading", async () => {
    let pulled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(1));
      },
      pull() {
        pulled = true;
      },
    });
    const request = new Request("https://brain.example.test/upload", {
      method: "POST",
      headers: { "content-length": "9" },
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    await expect(readBoundedRequestBody(request, 8)).resolves.toEqual({ kind: "too_large" });
    expect(pulled).toBe(false);
  });

  it("cancels a streamed body as soon as its cumulative size exceeds the bound", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(8));
        controller.enqueue(new Uint8Array(1));
      },
      cancel() {
        cancelled = true;
      },
    });
    const request = new Request("https://brain.example.test/upload", {
      method: "POST",
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    await expect(readBoundedRequestBody(request, 8)).resolves.toEqual({ kind: "too_large" });
    expect(cancelled).toBe(true);
  });

  it("accepts an exact-boundary stream without changing its bytes", async () => {
    const request = new Request("https://brain.example.test/upload", {
      method: "POST",
      headers: { "content-length": "8" },
      body: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    });

    const result = await readBoundedRequestBody(request, 8);
    expect(result.kind).toBe("ready");
    if (result.kind !== "ready") throw new Error("Expected a bounded body");
    expect(result.body).not.toBeNull();
    if (!result.body) throw new Error("Expected a spooled body");
    expect(await bytes(result.body.openStream())).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    await result.body.cleanup();
    await expect(bytes(result.body.openStream())).rejects.toThrow();
  });

  it("isolates concurrent spools and cleans each exact temporary resource", async () => {
    const create = (value: number) =>
      readBoundedRequestBody(
        new Request("https://brain.example.test/upload", {
          method: "POST",
          body: new Uint8Array([value]),
        }),
        8,
      );
    const [first, second] = await Promise.all([create(1), create(2)]);
    if (first.kind !== "ready" || !first.body || second.kind !== "ready" || !second.body) {
      throw new Error("Expected isolated spools");
    }
    expect(await bytes(first.body.openStream())).toEqual([1]);
    expect(await bytes(second.body.openStream())).toEqual([2]);
    await Promise.all([first.body.cleanup(), second.body.cleanup()]);
    await expect(bytes(first.body.openStream())).rejects.toThrow();
    await expect(bytes(second.body.openStream())).rejects.toThrow();
  });

  it("applies one absolute deadline, cancels a stalled reader, and removes its spool", async () => {
    const before = (await readdir("/tmp")).filter((name) => name.startsWith("second-brain-proxy-"));
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    });
    const request = new Request("https://brain.example.test/upload", {
      method: "POST",
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });

    const result = await readBoundedRequestBody(request, 8, 25);
    expect(result.kind).toBe("timed_out");
    if (result.kind !== "timed_out") throw new Error("Expected a request-body timeout");
    await result.cancel();
    expect(cancelled).toBe(true);
    expect(
      (await readdir("/tmp")).filter((name) => name.startsWith("second-brain-proxy-")),
    ).toEqual(before);
  });
});
