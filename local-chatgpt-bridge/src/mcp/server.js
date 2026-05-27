import { createServer } from "node:http";
import { loadConfig } from "../config.js";
import { createAuditor } from "../audit.js";
import {
  corsHeaders,
  endpointPath,
  handleJsonRpc,
  isAllowedOrigin,
  isAuthorizedPath,
  rpcError,
  validateProtocolHeader,
} from "./protocol.js";

export function createMcpHttpServer(config, auditor) {
  return createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (!isAllowedOrigin(config, origin)) {
      res.writeHead(403).end("Forbidden");
      return;
    }

    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const headers = corsHeaders(config, origin);

    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("local-chatgpt-bridge MCP server");
      return;
    }

    if (!isAuthorizedPath(config, url.pathname)) {
      res.writeHead(404).end("Not Found");
      return;
    }

    if (req.method === "OPTIONS") {
      res.writeHead(204, headers).end();
      return;
    }

    if (req.method === "GET") {
      res.writeHead(405, { ...headers, allow: "POST, OPTIONS" }).end("Method Not Allowed");
      return;
    }

    if (req.method !== "POST") {
      res.writeHead(405, { ...headers, allow: "POST, OPTIONS" }).end("Method Not Allowed");
      return;
    }

    if (!validateProtocolHeader(req.headers)) {
      res.writeHead(400, { ...headers, "content-type": "text/plain; charset=utf-8" });
      res.end("Unsupported MCP-Protocol-Version");
      return;
    }

    let payload;
    try {
      payload = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { ...headers, "content-type": "application/json" });
      res.end(JSON.stringify(rpcError(null, -32700, "Parse error")));
      return;
    }

    const rpc = await handleJsonRpc(config, auditor, payload);
    if (rpc.notification) {
      res.writeHead(202, headers).end();
      return;
    }

    res.writeHead(200, { ...headers, "content-type": "application/json" });
    res.end(JSON.stringify(rpc));
  });
}

export function startServer(configPath) {
  const config = loadConfig(configPath);
  const auditor = createAuditor(config);
  const server = createMcpHttpServer(config, auditor);
  server.listen(config.server.port, config.server.host, () => {
    const tokenNote = config.server.endpointToken ? "/<token>" : "";
    console.log(
      `local-chatgpt-bridge listening on http://${config.server.host}:${config.server.port}${config.server.basePath}${tokenNote}`,
    );
  });
  return server;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        req.destroy();
        reject(new Error("request too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
