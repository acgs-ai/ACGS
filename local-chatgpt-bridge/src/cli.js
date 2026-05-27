import https from "node:https";
import fs from "node:fs";
import { loadConfig } from "./config.js";
import { createAuditor } from "./audit.js";
import { callTool } from "./tools/index.js";
import { listPools } from "./kernel.js";

export async function main(argv) {
  const { command, options } = parseArgs(argv);
  const config = loadConfig(options.config);
  const auditor = createAuditor({ ...config, audit: { ...config.audit, enabled: false } });

  switch (command) {
    case "roots":
      console.log(JSON.stringify((await callTool(config, auditor, "list_allowed_roots", {})).structuredContent, null, 2));
      return;
    case "doctor":
      doctor(config, options.config);
      return;
    case "context":
      console.log(await buildContext(config, auditor, options));
      return;
    case "ask": {
      const prompt = await buildContext(config, auditor, options);
      if (!process.env.OPENAI_API_KEY) {
        console.log(prompt);
        return;
      }
      console.log(await callResponsesApi(prompt, options.model || "gpt-5.5"));
      return;
    }
    case "browser-ask": {
      const { browserAsk, browserAskCdp } = await import("./browser-ask.js");
      const prompt = await buildContext(config, auditor, options);
      const sharedOpts = {
        navTimeoutMs: Number(options["nav-timeout-ms"] || 30_000),
        responseTimeoutMs: Number(options["response-timeout-ms"] || config.kernel?.responseTimeoutMs || 120_000),
      };

      // --cdp-url or KERNEL_CDP_URL skips pool acquisition (useful for testing with a pre-acquired browser).
      const cdpUrl = options["cdp-url"] || process.env.KERNEL_CDP_URL;
      if (cdpUrl) {
        console.log(await browserAskCdp(cdpUrl, prompt, sharedOpts));
        return;
      }

      const poolName = options.pool || config.kernel?.poolName;
      if (!poolName) {
        throw new Error(
          "Pool name is required: pass --pool <name>, set KERNEL_CDP_URL, or set kernel.poolName in config.json"
        );
      }
      const response = await browserAsk(poolName, prompt, {
        ...sharedOpts,
        acquireTimeoutSeconds: Number(options["acquire-timeout"] || config.kernel?.acquireTimeoutSeconds || 30),
        reuse: options.reuse !== "false",
      });
      console.log(response);
      return;
    }
    case "pools": {
      const pools = await listPools();
      console.log(JSON.stringify(pools, null, 2));
      return;
    }
    default:
      usage();
      throw new Error(`Unknown command: ${command}`);
  }
}

export async function buildContext(config, auditor, options) {
  const root = options.root || config.roots[0].alias;
  const sections = [`# Local ChatGPT Context`, "", `Root: ${root}`];

  if (options.file) {
    const result = await callTool(config, auditor, "read_file", {
      root,
      path: options.file,
    });
    sections.push("", `## File: ${options.file}`, result.structuredContent.text || JSON.stringify(result.structuredContent));
  }

  if (options.search) {
    const result = await callTool(config, auditor, "search_files", {
      root,
      query: options.search,
      path: options.path || "",
    });
    sections.push("", `## Search: ${options.search}`, JSON.stringify(result.structuredContent, null, 2));
  }

  if (options.git !== false) {
    const result = await callTool(config, auditor, "git_status", { root });
    sections.push("", "## Git Status", result.structuredContent.status || JSON.stringify(result.structuredContent));
  }

  if (options.prompt) {
    sections.push("", "## User Prompt", options.prompt);
  }

  return sections.join("\n");
}

export function parseArgs(argv) {
  const [command = "help", ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    if (key === "no-git") {
      options.git = false;
      continue;
    }
    options[key] = rest[index + 1];
    index += 1;
  }
  return { command, options };
}

export function doctor(config, configPath) {
  const result = {
    config: configPath || "config.json",
    roots: config.roots.map((root) => ({ alias: root.alias, path: root.realPath })),
    server: {
      host: config.server.host,
      port: config.server.port,
      basePath: config.server.basePath,
      tunnelMode: config.server.tunnelMode,
      tokenConfigured: Boolean(config.server.endpointToken),
      allowedOrigins: config.server.allowedOrigins,
    },
    auditEnabled: config.audit.enabled,
  };
  console.log(JSON.stringify(result, null, 2));
}

export function callResponsesApi(prompt, model) {
  const body = JSON.stringify({
    model,
    input: prompt,
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/responses",
        method: "POST",
        headers: {
          authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`OpenAI API returned ${res.statusCode}: ${data}`));
            return;
          }
          resolve(extractResponseText(data));
        });
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function extractResponseText(raw) {
  const parsed = JSON.parse(raw);
  if (typeof parsed.output_text === "string") return parsed.output_text;
  const text = [];
  for (const item of parsed.output || []) {
    for (const content of item.content || []) {
      if (content.type === "output_text" && content.text) text.push(content.text);
    }
  }
  return text.join("\n") || raw;
}

function usage() {
  const text = fs.readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const start = text.indexOf("## CLI");
  const end = text.indexOf("## ChatGPT Developer Mode");
  if (start >= 0 && end > start) console.error(text.slice(start, end).trim());
}
