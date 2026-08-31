import "server-only";

import { parseServiceStatus } from "./resource-parsers";
import { resolveWebRuntimeConfig } from "./runtime-config";

export type ServiceStatus =
  | {
      kind: "available";
      service: string;
      database: string;
      storage: string;
      modelProvider: string;
      embeddingProviderStatus: "available" | "unavailable";
      generationProviderStatus: "available" | "unavailable";
      maxUploadBytes: number;
      maxExtractedChars: number;
      maxChunks: number;
      maxProcessingSeconds: number;
    }
  | { kind: "unavailable"; reason: "configuration_invalid" | "service_unavailable" };

function statusPayload(value: unknown): Extract<ServiceStatus, { kind: "available" }> {
  const record = parseServiceStatus(value);
  return {
    kind: "available",
    service: record.service,
    database: record.database,
    storage: record.storage,
    modelProvider: record.model_provider,
    embeddingProviderStatus: record.embedding_provider_status,
    generationProviderStatus: record.generation_provider_status,
    maxUploadBytes: record.max_upload_bytes,
    maxExtractedChars: record.max_extracted_chars,
    maxChunks: record.max_chunks,
    maxProcessingSeconds: record.max_processing_seconds,
  };
}

export async function getServiceStatus(): Promise<ServiceStatus> {
  const runtime = resolveWebRuntimeConfig(process.env, "probe");
  if (!runtime.ok) return { kind: "unavailable", reason: "configuration_invalid" };

  try {
    const response = await fetch(new URL("/api/v1/status", runtime.value.apiUrl), {
      method: "GET",
      headers: { accept: "application/json" },
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) return { kind: "unavailable", reason: "service_unavailable" };
    return statusPayload(await response.json());
  } catch {
    return { kind: "unavailable", reason: "service_unavailable" };
  }
}
