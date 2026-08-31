import "server-only";

import { after } from "next/server";

import {
  buildUpstreamHeaders,
  resolveUpstreamPath,
  safeSessionSetCookie,
  validateBrowserOrigin,
  withServerPrincipal,
} from "@/lib/api-policy";
import { readBoundedRequestBody } from "@/lib/bounded-body";
import { resolveWebRuntimeConfig } from "@/lib/runtime-config";
import { requestUpstream } from "@/lib/upstream-request";

export const dynamic = "force-dynamic";

const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

function errorResponse(
  status: number,
  code: string,
  title: string,
  detail: string,
  retryable = status >= 500,
): Response {
  return Response.json(
    { code, title, detail, retryable, trace_id: crypto.randomUUID() },
    { status, headers: { "cache-control": "private, no-store, max-age=0" } },
  );
}

function requestTooLargeResponse(): Response {
  return new Response(null, {
    status: 413,
    headers: { "cache-control": "private, no-store, max-age=0" },
  });
}

async function proxyRequest(request: Request, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  const upstreamPath = resolveUpstreamPath(request.method, path);
  if (!upstreamPath) {
    return errorResponse(
      404,
      "route_unavailable",
      "Route unavailable",
      "The API route is not available.",
    );
  }

  const runtime = resolveWebRuntimeConfig(process.env, "probe");
  if (!runtime.ok) {
    return errorResponse(
      503,
      "service_configuration_invalid",
      "Service unavailable",
      "The server API connection is not configured safely.",
    );
  }
  const { apiUrl: serviceUrl, developmentPrincipal: principal, publicOrigin } = runtime.value;
  if (
    MUTATION_METHODS.has(request.method) &&
    !validateBrowserOrigin(request.headers, publicOrigin.origin)
  ) {
    return errorResponse(
      403,
      "origin_forbidden",
      "Origin forbidden",
      "The request origin is not allowed.",
    );
  }

  const incomingUrl = new URL(request.url);
  if (incomingUrl.search.length > 4096) {
    return errorResponse(
      414,
      "query_too_large",
      "Query too large",
      "The query exceeded the allowed size.",
    );
  }

  const body = MUTATION_METHODS.has(request.method)
    ? await readBoundedRequestBody(request)
    : undefined;
  if (body?.kind === "too_large") return requestTooLargeResponse();
  if (body?.kind === "timed_out") {
    after(() => body.cancel());
    return errorResponse(
      408,
      "request_body_timeout",
      "Request timed out",
      "The request body was not received before the deadline.",
      true,
    );
  }
  if (body?.kind === "invalid") {
    return errorResponse(
      400,
      "request_body_invalid",
      "Request invalid",
      "The request body could not be read safely.",
    );
  }

  const target = new URL(upstreamPath, serviceUrl);
  target.search = incomingUrl.search;

  try {
    let upstreamHeaders = buildUpstreamHeaders(request.headers, publicOrigin.origin);
    if (principal) {
      try {
        upstreamHeaders = withServerPrincipal(upstreamHeaders, principal);
      } catch {
        return errorResponse(
          503,
          "identity_configuration_invalid",
          "Service unavailable",
          "The server identity connection is not configured safely.",
        );
      }
    }
    const upstream = await requestUpstream(target, {
      method: request.method,
      headers: upstreamHeaders,
      body: body?.kind === "ready" ? body.body : undefined,
      timeoutMs: 120_000,
    });
    const responseHeaders = new Headers({
      "cache-control": "private, no-store, max-age=0",
      "content-type": upstream.headers.get("content-type") ?? "application/json",
    });
    const sessionCookie = safeSessionSetCookie(upstream.headers.get("set-cookie"));
    if (sessionCookie) responseHeaders.set("set-cookie", sessionCookie);
    const requestId = upstream.headers.get("x-request-id");
    if (requestId) responseHeaders.set("x-request-id", requestId);
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return errorResponse(
      503,
      "service_unavailable",
      "Service unavailable",
      "The API service could not be reached.",
    );
  } finally {
    await body?.body?.cleanup();
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
