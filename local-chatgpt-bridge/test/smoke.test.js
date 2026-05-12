import assert from "node:assert/strict";
import { once } from "node:events";
import { loadConfig } from "../src/config.js";
import { createAuditor } from "../src/audit.js";
import { createMcpHttpServer } from "../src/mcp/server.js";
import { getFreePort, makeTempWorkspace } from "./helpers.js";

const workspace = makeTempWorkspace();
const config = loadConfig(workspace.configPath);
const port = await getFreePort();
config.server.port = port;
const server = createMcpHttpServer(
  config,
  createAuditor({ ...config, audit: { ...config.audit, enabled: false } }),
);

server.listen(port, "127.0.0.1");
await once(server, "listening");

async function rpc(payload) {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  return { response, json: text ? JSON.parse(text) : null };
}

try {
  const init = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(init.response.status, 200);
  assert.equal(init.json.result.serverInfo.name, "local-chatgpt-bridge");

  const listed = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.ok(listed.json.result.tools.some((tool) => tool.name === "read_file"));

  const read = await rpc({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "read_file", arguments: { root: "tmp", path: "README.md" } },
  });
  assert.match(read.json.result.structuredContent.text, /hello bridge/);

  const denied = await rpc({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "read_file", arguments: { root: "tmp", path: ".env" } },
  });
  assert.equal(denied.json.result.isError, true);

  console.log("smoke passed");
} finally {
  server.close();
  await once(server, "close");
}
