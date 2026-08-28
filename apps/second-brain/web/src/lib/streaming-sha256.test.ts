import { describe, expect, it } from "vitest";

import { sha256Stream } from "./streaming-sha256";

function stream(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

describe("sha256Stream", () => {
  it("hashes the exact bytes independently of stream boundaries", async () => {
    await expect(sha256Stream(stream("a", "b", "c"), 3)).resolves.toBe(
      [
        "ba7816bf",
        "8f01cfea",
        "414140de",
        "5dae2223",
        "b00361a3",
        "96177a9c",
        "b410ff61",
        "f20015ad",
      ].join(""),
    );
  });

  it("rejects before retaining bytes beyond the configured bound", async () => {
    await expect(sha256Stream(stream("abcd"), 3)).rejects.toThrow(
      "Upload exceeds the fingerprint byte limit",
    );
  });
});
