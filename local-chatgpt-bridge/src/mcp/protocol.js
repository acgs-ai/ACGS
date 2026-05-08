import { timingSafeEqual } from "node:crypto";
import { toolDefinitions, callTool } from "../tools/index.js";

export const PROTOCOL_VERSION = "2025-06-18";

export function endpointPath(config) {
  const base = config.server.basePath.replace(/\/+$/, "");
  return config.server.endpointToken ? `${base}/${config.server.endpointToken}` : base;
}

export function isAuthorizedPath(config, pathname) {
  const expected = endpointPath(config);
  if (pathname.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(pathname), Buffer.from(expected));
}

export function validateProtocolHeader(headers) {
  const version = headers["mcp-protocol-version"];
  return !version || version === PROTOCOL_VERSION;
}

export async function handleJsonRpc(config, auditor, payload) {
  if (Array.isArray(payload)) {
    return rpcError(null, -32600, "Batch requests are not supported");
  }
  if (!payload || payload.jsonrpc !== "2.0" || typeof payload.method !== "string") {
    return rpcError(payload?.id ?? null, -32600, "Invalid Request");
  }
  if (payload.id === undefined && payload.method.startsWith("notifications/")) {
    return { notification: true };
  }

  switch (payload.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id: payload.id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "local-chatgpt-bridge", version: "0.1.0" },
        },
      };
    case "tools/list":
      return {
        jsonrpc: "2.0",
        id: payload.id,
        result: { tools: toolDefinitions.map((tool) => ({ ...tool })) },
      };
    case "tools/call": {
      const name = payload.params?.name;
      const args = payload.params?.arguments || {};
      if (typeof name !== "string") return rpcError(payload.id, -32602, "Missing tool name");
      const result = await callTool(config, auditor, name, args);
      return { jsonrpc: "2.0", id: payload.id, result };
    }
    default:
      return rpcError(payload.id, -32601, "Method not found");
  }
}

export function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export function corsHeaders(config, origin) {
  if (!origin || !config.server.allowedOrigins.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, mcp-protocol-version",
    "Vary": "Origin",
  };
}

export function isAllowedOrigin(config, origin) {
  return !origin || config.server.allowedOrigins.includes(origin);
}
