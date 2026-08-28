import { createReadStream } from "node:fs";
import { type FileHandle, mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const MAX_BODY_BYTES = 12_000_000;
export const BODY_READ_DEADLINE_MS = 10_000;

export interface SpooledBody {
  byteLength: number;
  openStream(): NodeJS.ReadableStream;
  cleanup(): Promise<void>;
}

export type BoundedBodyResult =
  | { kind: "ready"; body: SpooledBody | null }
  | { kind: "too_large" }
  | { kind: "timed_out"; cancel(): Promise<void> }
  | { kind: "invalid" };

function declaredLength(headers: Headers): number | null | undefined {
  const value = headers.get("content-length");
  if (value === null) return undefined;
  if (!/^(?:0|[1-9]\d*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

async function removeSpool(directory: string): Promise<void> {
  await rm(directory, { force: true, maxRetries: 2, recursive: true });
}

export async function readBoundedRequestBody(
  request: Request,
  maximumBytes = MAX_BODY_BYTES,
  deadlineMs = BODY_READ_DEADLINE_MS,
): Promise<BoundedBodyResult> {
  const deadlineAt = Date.now() + deadlineMs;
  const declared = declaredLength(request.headers);
  if (declared === null) return { kind: "invalid" };
  if (declared !== undefined && declared > maximumBytes) return { kind: "too_large" };
  if (request.body === null) {
    return declared === undefined || declared === 0
      ? { kind: "ready", body: null }
      : { kind: "invalid" };
  }

  const directory = await mkdtemp(join(tmpdir(), "second-brain-proxy-"));
  const filePath = join(directory, "request-body");
  let file: FileHandle;
  try {
    file = await open(filePath, "wx", 0o600);
  } catch (error) {
    await removeSpool(directory);
    throw error;
  }
  const reader = request.body.getReader();
  let totalBytes = 0;
  let result: "ready" | "too_large" | "timed_out" | "invalid" = "ready";
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    const timedOut = new Promise<"timed_out">((resolve) => {
      deadline = setTimeout(() => resolve("timed_out"), Math.max(0, deadlineAt - Date.now()));
    });
    while (true) {
      const next = reader.read().then((read) => ({ kind: "read" as const, read }));
      const outcome = await Promise.race([next, timedOut.then((kind) => ({ kind }) as const)]);
      if (outcome.kind === "timed_out") {
        result = "timed_out";
        break;
      }
      const { done, value } = outcome.read;
      if (done) break;
      if (value.byteLength > maximumBytes - totalBytes) {
        result = "too_large";
        await reader.cancel("request_too_large");
        break;
      }
      await file.write(value);
      totalBytes += value.byteLength;
    }
  } catch {
    if (result === "ready") result = "invalid";
  } finally {
    if (deadline !== undefined) clearTimeout(deadline);
    if (result !== "timed_out") reader.releaseLock();
    await file.close();
  }

  if (result !== "ready" || (declared !== undefined && declared !== totalBytes)) {
    await removeSpool(directory);
    if (result === "timed_out") {
      let cancelled = false;
      return {
        kind: "timed_out",
        cancel: async () => {
          if (cancelled) return;
          cancelled = true;
          try {
            await reader.cancel("request_body_timeout");
          } catch {
            // The peer may already have disconnected after receiving the 408.
          } finally {
            reader.releaseLock();
          }
        },
      };
    }
    return {
      kind: result === "too_large" ? "too_large" : "invalid",
    };
  }

  let cleaned = false;
  return {
    kind: "ready",
    body: {
      byteLength: totalBytes,
      openStream: () => createReadStream(filePath),
      cleanup: async () => {
        if (cleaned) return;
        cleaned = true;
        await removeSpool(directory);
      },
    },
  };
}
