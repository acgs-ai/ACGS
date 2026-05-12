import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { once } from "node:events";
import { loadConfig } from "../src/config.js";
import { createAuditor } from "../src/audit.js";
import { createMcpHttpServer } from "../src/mcp/server.js";
import { getFreePort, makeTempWorkspace } from "./helpers.js";

async function start(configPath, patch = {}) {
  const config = loadConfig(configPath);
  const port = await getFreePort();
  config.server.port = port;
  Object.assign(config.server, patch);
  const server = createMcpHttpServer(config, createAuditor({ ...config, audit: { ...config.audit, enabled: false } }));
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return { config, port, server };
}

async function request(port, path, payload, headers = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { response, text, json };
}

test("MCP HTTP contract and tool descriptors", async () => {
  const workspace = makeTempWorkspace();
  const { port, server } = await start(workspace.configPath);
  try {
    const health = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(health.status, 200);

    const getMcp = await fetch(`http://127.0.0.1:${port}/mcp`);
    assert.equal(getMcp.status, 405);

    const invalidVersion = await request(
      port,
      "/mcp",
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { "MCP-Protocol-Version": "1999-01-01" },
    );
    assert.equal(invalidVersion.response.status, 400);

    const batch = await request(port, "/mcp", [{ jsonrpc: "2.0", id: 1, method: "tools/list" }]);
    assert.equal(batch.json.error.code, -32600);

    const initialized = await request(port, "/mcp", {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    });
    assert.equal(initialized.response.status, 200);
    assert.equal(initialized.json.result.protocolVersion, "2025-06-18");
    assert.ok(initialized.json.result.capabilities.tools);

    const notification = await request(port, "/mcp", {
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    });
    assert.equal(notification.response.status, 202);
    assert.equal(notification.text, "");

    const listed = await request(port, "/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list" });
    assert.deepEqual(
      listed.json.result.tools.map((tool) => tool.name).sort(),
      ["get_file_metadata", "git_status", "list_allowed_roots", "list_dir", "read_file", "search_files"],
    );
    for (const tool of listed.json.result.tools) {
      assert.ok(tool.inputSchema);
      assert.ok(tool.outputSchema);
      assert.deepEqual(tool.annotations, {
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
        idempotentHint: true,
      });
    }

    const called = await request(port, "/mcp", {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "read_file", arguments: { root: "tmp", path: "README.md" } },
    });
    assert.match(called.json.result.structuredContent.text, /hello bridge/);
    assert.equal(JSON.parse(called.json.result.content[0].text).path, "README.md");

    const unsupported = await request(port, "/mcp", { jsonrpc: "2.0", id: 4, method: "nope" });
    assert.equal(unsupported.json.error.code, -32601);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("MCP token and origin controls", async () => {
  const workspace = makeTempWorkspace();
  const token = "abcdefghijklmnopqrstuvwxyzABCDEF123456";
  const configData = JSON.parse(fs.readFileSync(workspace.configPath, "utf8"));
  configData.server.tunnelMode = true;
  configData.server.endpointToken = token;
  fs.writeFileSync(workspace.configPath, JSON.stringify(configData), "utf8");
  const { port, server } = await start(workspace.configPath);
  try {
    const missing = await request(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(missing.response.status, 404);

    const wrong = await request(port, "/mcp/wrong", { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(wrong.response.status, 404);

    const badOrigin = await request(
      port,
      `/mcp/${token}`,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { Origin: "https://evil.example" },
    );
    assert.equal(badOrigin.response.status, 403);

    const goodOrigin = await request(
      port,
      `/mcp/${token}`,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { Origin: "https://chatgpt.com" },
    );
    assert.equal(goodOrigin.response.status, 200);
    assert.equal(goodOrigin.response.headers.get("access-control-allow-origin"), "https://chatgpt.com");
  } finally {
    server.close();
    await once(server, "close");
  }
});
