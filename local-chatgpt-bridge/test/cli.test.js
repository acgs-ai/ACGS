import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { createAuditor } from "../src/audit.js";
import { buildContext, parseArgs } from "../src/cli.js";
import { makeTempWorkspace } from "./helpers.js";

test("CLI argument parsing and context fallback", async () => {
  const parsed = parseArgs([
    "context",
    "--config",
    "config.json",
    "--root",
    "tmp",
    "--file",
    "README.md",
    "--search",
    "bridge",
    "--prompt",
    "explain",
  ]);
  assert.equal(parsed.command, "context");
  assert.equal(parsed.options.file, "README.md");

  const workspace = makeTempWorkspace();
  const config = loadConfig(workspace.configPath);
  const auditor = createAuditor({ ...config, audit: { ...config.audit, enabled: false } });
  const context = await buildContext(config, auditor, {
    root: "tmp",
    file: "README.md",
    search: "bridge",
    prompt: "explain",
  });
  assert.match(context, /# Local ChatGPT Context/);
  assert.match(context, /hello bridge/);
  assert.match(context, /## User Prompt/);
});
