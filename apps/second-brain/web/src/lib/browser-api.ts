"use client";

import { parseSession } from "./resource-parsers";
import { sha256Stream } from "./streaming-sha256";

const API_PREFIX = "/api/backend";
const CSRF_STORAGE_KEY = "second-brain.csrf";
const IDEMPOTENCY_STORAGE_KEY = "second-brain.idempotency";
const SAFE_TOKEN = /^[A-Za-z0-9_-]{16,512}$/;
const MAX_UPLOAD_FINGERPRINT_BYTES = 25 * 1024 * 1024;

export interface ApiProblem {
  code: string;
  title: string;
  detail: string;
  retryable: boolean;
}

export class ApiError extends Error {
  readonly problem: ApiProblem;
  readonly status: number;

  constructor(status: number, problem: ApiProblem) {
    super(problem.detail);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
}

function storage(): Storage | null {
  try {
    return globalThis.sessionStorage;
  } catch {
    return null;
  }
}

export function storeSessionCsrf(value: string): void {
  if (!SAFE_TOKEN.test(value)) throw new TypeError("CSRF token is invalid");
  storage()?.setItem(CSRF_STORAGE_KEY, value);
}

function csrfToken(): string | null {
  const value = storage()?.getItem(CSRF_STORAGE_KEY) ?? null;
  return value && SAFE_TOKEN.test(value) ? value : null;
}

interface ActiveIdempotencyDescriptor {
  fingerprint: string;
  key: string;
  method: string;
  path: string;
  created_at: number;
}

function idempotencyMap(): Record<string, ActiveIdempotencyDescriptor> {
  try {
    const parsed: unknown = JSON.parse(storage()?.getItem(IDEMPOTENCY_STORAGE_KEY) ?? "{}");
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const retained: Record<string, ActiveIdempotencyDescriptor> = {};
    for (const [fingerprint, value] of Object.entries(parsed)) {
      if (
        !/^[0-9a-f]{64}$/.test(fingerprint) ||
        typeof value !== "object" ||
        value === null ||
        Array.isArray(value)
      ) {
        continue;
      }
      const item = value as Record<string, unknown>;
      if (
        item.fingerprint === fingerprint &&
        typeof item.key === "string" &&
        SAFE_TOKEN.test(item.key) &&
        typeof item.method === "string" &&
        typeof item.path === "string" &&
        typeof item.created_at === "number" &&
        Number.isSafeInteger(item.created_at)
      ) {
        retained[fingerprint] = {
          fingerprint,
          key: item.key,
          method: item.method,
          path: item.path,
          created_at: item.created_at,
        };
      }
    }
    return retained;
  } catch {
    return {};
  }
}

function storeIdempotencyMap(entries: Record<string, ActiveIdempotencyDescriptor>): void {
  storage()?.setItem(IDEMPOTENCY_STORAGE_KEY, JSON.stringify(entries));
}

function canonical(value: unknown, depth = 0): unknown {
  if (depth > 20) throw new TypeError("Request body is too deeply nested");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((item) => canonical(item, depth + 1));
  if (typeof value !== "object") throw new TypeError("Request body cannot be fingerprinted");
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonical(item, depth + 1)]),
  );
}

async function formDescriptor(form: FormData): Promise<unknown[]> {
  const entries: unknown[][] = [];
  for (const [name, value] of form.entries()) {
    entries.push([
      name,
      typeof value === "string"
        ? { kind: "text", value }
        : {
            kind: "file",
            name: value.name,
            size: value.size,
            type: value.type,
            last_modified: "lastModified" in value ? value.lastModified : null,
            sha256: await sha256Stream(value.stream(), MAX_UPLOAD_FINGERPRINT_BYTES),
          },
    ]);
  }
  return entries.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

async function requestFingerprint(
  path: string,
  method: string,
  action: string,
  body: FormData | object | undefined,
): Promise<string> {
  if (!action || action.length > 2000) throw new TypeError("Idempotency action is invalid");
  const material = JSON.stringify({
    action,
    method,
    path,
    body: body instanceof FormData ? await formDescriptor(body) : canonical(body ?? null),
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function retainedIdempotencyKey(
  fingerprint: string,
  method: string,
  path: string,
): ActiveIdempotencyDescriptor {
  const entries = idempotencyMap();
  const existing = entries[fingerprint];
  if (existing) return existing;
  const descriptor = {
    fingerprint,
    key: crypto.randomUUID(),
    method,
    path,
    created_at: Date.now(),
  };
  const allEntries: Array<[string, ActiveIdempotencyDescriptor]> = [
    ...Object.entries(entries),
    [fingerprint, descriptor],
  ];
  const retained = Object.fromEntries(
    allEntries.sort(([, left], [, right]) => left.created_at - right.created_at).slice(-100),
  );
  storeIdempotencyMap(retained);
  return descriptor;
}

function concludeIdempotency(descriptor: ActiveIdempotencyDescriptor | null): void {
  if (!descriptor) return;
  const entries = idempotencyMap();
  if (entries[descriptor.fingerprint]?.key !== descriptor.key) return;
  delete entries[descriptor.fingerprint];
  storeIdempotencyMap(entries);
}

function safeProblem(status: number, value: unknown): ApiProblem {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    if (
      typeof record.code === "string" &&
      typeof record.title === "string" &&
      typeof record.detail === "string"
    ) {
      return {
        code: record.code.slice(0, 100),
        title: record.title.slice(0, 200),
        detail: record.detail.slice(0, 1000),
        retryable: record.retryable === true,
      };
    }
  }
  return {
    code: "request_failed",
    title: "Request failed",
    detail: status >= 500 ? "The service is temporarily unavailable." : "The request was rejected.",
    retryable: status >= 500,
  };
}

export interface ApiRequestOptions<T> {
  body?: FormData | object;
  idempotencyAction?: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  parse: (value: unknown) => T;
}

export interface TrustedAssertion {
  issuer: string;
  audience: string;
  issued_at: number;
  expires_at: number;
  nonce: string;
  owner_id: string;
  workspace_id: string;
  signature: string;
}

export async function apiRequest<T>(path: string, options: ApiRequestOptions<T>): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
    throw new TypeError("API path is invalid");
  }
  const method = options.method ?? "GET";
  const headers = new Headers({ accept: "application/json" });
  const csrf = csrfToken();
  if (method !== "GET" && csrf) headers.set("x-csrf-token", csrf);
  let idempotency: ActiveIdempotencyDescriptor | null = null;
  if (options.idempotencyAction) {
    const fingerprint = await requestFingerprint(
      path,
      method,
      options.idempotencyAction,
      options.body,
    );
    idempotency = retainedIdempotencyKey(fingerprint, method, path);
    headers.set("idempotency-key", idempotency.key);
  }
  let body: BodyInit | undefined;
  if (options.body instanceof FormData) {
    body = options.body;
  } else if (options.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(options.body);
  }
  let response: Response;
  try {
    const requestInit: RequestInit = {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "manual",
    };
    if (body !== undefined) requestInit.body = body;
    response = await fetch(`${API_PREFIX}${path}`, requestInit);
  } catch {
    throw new ApiError(503, {
      code: "service_unavailable",
      title: "Service unavailable",
      detail: "The API service could not be reached.",
      retryable: true,
    });
  }
  if (response.status === 204) {
    try {
      const parsed = options.parse(null);
      concludeIdempotency(idempotency);
      return parsed;
    } catch {
      throw new ApiError(502, {
        code: "response_contract_invalid",
        title: "Invalid service response",
        detail: "The service returned an invalid response.",
        retryable: false,
      });
    }
  }
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    if (response.ok) {
      throw new ApiError(502, safeProblem(502, null));
    }
  }
  if (!response.ok) {
    const problem = safeProblem(response.status, payload);
    if (!problem.retryable) concludeIdempotency(idempotency);
    throw new ApiError(response.status, problem);
  }
  try {
    const parsed = options.parse(payload);
    concludeIdempotency(idempotency);
    return parsed;
  } catch {
    throw new ApiError(502, {
      code: "response_contract_invalid",
      title: "Invalid service response",
      detail: "The service returned an invalid response.",
      retryable: false,
    });
  }
}

export async function exchangeSession(assertion: TrustedAssertion): Promise<void> {
  const response = await apiRequest("/auth/exchange", {
    method: "POST",
    body: assertion,
    parse: parseSession,
  });
  storeSessionCsrf(response.csrf_token);
}

export function formatApiError(error: unknown): string {
  return error instanceof ApiError ? error.problem.detail : "The request could not be completed.";
}
