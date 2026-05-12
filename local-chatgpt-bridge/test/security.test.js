import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { createAuditor } from "../src/audit.js";
import { loadConfig, normalizeConfig } from "../src/config.js";
import { callTool } from "../src/tools/index.js";
import { makeTempWorkspace, readAudit } from "./helpers.js";

test("config fails closed when missing or empty", () => {
  assert.throws(() => loadConfig("/does/not/exist.json"), /Config file is required/);
  assert.throws(() => normalizeConfig({ roots: [] }), /At least one allowed root/);
  assert.throws(
    () =>
      normalizeConfig({
        server: { host: "0.0.0.0", endpointToken: "" },
        roots: [{ alias: "x", path: "." }],
      }),
    /Non-loopback binding requires/,
  );
  assert.throws(
    () =>
      normalizeConfig({
        server: { host: "127.0.0.1", tunnelMode: true, endpointToken: "short" },
        roots: [{ alias: "x", path: "." }],
      }),
    /Tunnel mode requires/,
  );
});

test("tools enforce path safety and content-free audit", async () => {
  const workspace = makeTempWorkspace();
  const config = loadConfig(workspace.configPath);
  const auditor = createAuditor(config, workspace.dir);

  const read = await callTool(config, auditor, "read_file", { root: "tmp", path: "README.md" });
  assert.equal(read.isError, undefined);
  assert.match(read.structuredContent.text, /hello bridge/);

  for (const deniedPath of [
    "../outside/outside.txt",
    "%2e%2e/outside/outside.txt",
    path.join(workspace.root, "README.md"),
    ".env",
    "secrets/key.txt",
    "node_modules/ignored.txt",
    "binary.bin",
  ]) {
    const result = await callTool(config, auditor, "read_file", {
      root: "tmp",
      path: deniedPath,
    });
    assert.equal(result.isError, true, `${deniedPath} should be refused`);
  }

  if (fs.existsSync(path.join(workspace.root, "outside-link"))) {
    const symlink = await callTool(config, auditor, "read_file", {
      root: "tmp",
      path: "outside-link",
    });
    assert.equal(symlink.isError, true);
    assert.equal(symlink.structuredContent.error, "symlink_refused");
  }

  const audit = readAudit(workspace.dir);
  assert.match(audit, /read_file/);
  assert.doesNotMatch(audit, /TOKEN=secret/);
  assert.doesNotMatch(audit, /hello bridge/);
});

test("list, search, metadata, and git status stay bounded and read-only", async () => {
  const workspace = makeTempWorkspace();
  const config = loadConfig(workspace.configPath);
  const auditor = createAuditor({ ...config, audit: { ...config.audit, enabled: false } });

  const roots = await callTool(config, auditor, "list_allowed_roots", {});
  assert.equal(roots.structuredContent.roots[0].alias, "tmp");

  const listed = await callTool(config, auditor, "list_dir", { root: "tmp", path: "" });
  assert.ok(listed.structuredContent.entries.some((entry) => entry.name === "README.md"));
  assert.ok(!listed.structuredContent.entries.some((entry) => entry.name === ".env"));

  const searched = await callTool(config, auditor, "search_files", {
    root: "tmp",
    query: "bridge",
    path: "",
  });
  assert.ok(searched.structuredContent.matches.some((match) => match.path === "README.md"));
  assert.ok(!searched.structuredContent.matches.some((match) => match.path.includes("node_modules")));

  const metadata = await callTool(config, auditor, "get_file_metadata", {
    root: "tmp",
    path: "README.md",
  });
  assert.equal(metadata.structuredContent.type, "file");
  assert.equal(metadata.structuredContent.text, undefined);

  const gitStatus = await callTool(config, auditor, "git_status", { root: "tmp" });
  assert.equal(typeof gitStatus.structuredContent.status, "string");
});
