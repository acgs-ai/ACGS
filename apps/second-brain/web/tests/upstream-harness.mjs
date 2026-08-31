import { createServer } from "node:http";

const host = "127.0.0.1";
const port = 3310;
const productionCookie =
  "second_brain_session=replaced-session-token; expires=Fri, 28 Aug 2026 19:54:45 GMT; HttpOnly; Max-Age=86400; Path=/; SameSite=lax; Secure";
let mutationRequestCount = 0;

function json(response, status, value, headers = {}) {
  response.writeHead(status, { "content-type": "application/json", ...headers });
  response.end(JSON.stringify(value));
}

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://${host}:${port}`);
  if (url.pathname === "/ready") {
    json(response, 200, { ready: true });
    return;
  }
  if (url.pathname === "/test/stats") {
    json(response, 200, { mutation_request_count: mutationRequestCount });
    return;
  }
  if (url.pathname === "/should-not-follow") {
    json(response, 418, { followed: true });
    return;
  }
  if (url.pathname === "/api/v1/status") {
    json(response, 200, {
      service: "second-brain",
      status: "ready",
      database: "available",
      storage: "filesystem",
      model_provider: "fake",
      embedding_provider_status: "available",
      generation_provider_status: "available",
      provider_status_scope: "local_adapter_state_not_remote_health",
      max_upload_bytes: 10_000_000,
      max_extracted_chars: 2_000_000,
      max_chunks: 5_000,
      max_processing_seconds: 30,
    });
    return;
  }
  if (url.pathname === "/api/v1/health" && url.searchParams.get("redirect") === "1") {
    response.writeHead(302, { location: `http://${host}:${port}/should-not-follow` });
    response.end();
    return;
  }
  if (url.pathname === "/api/v1/session/check" || url.pathname === "/api/v1/auth/exchange") {
    mutationRequestCount += 1;
    let receivedBytes = 0;
    request.on("data", (chunk) => {
      receivedBytes += chunk.length;
    });
    request.on("end", () => {
      const headers = { "x-request-id": request.headers["x-request-id"] ?? "missing" };
      if (url.pathname === "/api/v1/auth/exchange") {
        headers["set-cookie"] =
          url.searchParams.get("unsafe_cookie") === "1"
            ? productionCookie.replace("Max-Age=86400", "Max-Age=604801")
            : productionCookie;
      }
      json(
        response,
        200,
        {
          authorization: request.headers.authorization ?? null,
          cookie: request.headers.cookie ?? null,
          csrf: request.headers["x-csrf-token"] ?? null,
          host: request.headers.host ?? null,
          idempotency_key: request.headers["idempotency-key"] ?? null,
          origin: request.headers.origin ?? null,
          owner_id: request.headers["x-second-brain-owner-id"] ?? null,
          received_bytes: receivedBytes,
          request_id: request.headers["x-request-id"] ?? null,
          workspace_id: request.headers["x-second-brain-workspace-id"] ?? null,
        },
        headers,
      );
    });
    return;
  }

  json(response, 404, { code: "harness_route_missing" });
});

server.listen(port, host);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
