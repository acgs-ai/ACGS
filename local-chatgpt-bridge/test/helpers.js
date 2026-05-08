import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";

export async function getFreePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  server.close();
  await once(server, "close");
  return port;
}

export function makeTempWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "local-chatgpt-bridge-"));
  const root = path.join(dir, "root");
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "README.md"), "hello bridge\nsecret should not appear\n", "utf8");
  fs.mkdirSync(path.join(root, "src"));
  fs.writeFileSync(path.join(root, "src", "app.js"), "console.log('bridge');\n", "utf8");
  fs.writeFileSync(path.join(root, ".env"), "TOKEN=secret\n", "utf8");
  fs.writeFileSync(path.join(root, "binary.bin"), Buffer.from([0, 1, 2, 3]));
  fs.mkdirSync(path.join(root, "node_modules"));
  fs.writeFileSync(path.join(root, "node_modules", "ignored.txt"), "ignored bridge\n", "utf8");
  fs.mkdirSync(path.join(root, "secrets"));
  fs.writeFileSync(path.join(root, "secrets", "key.txt"), "secret\n", "utf8");
  try {
    execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
  } catch {
    // git_status tests tolerate environments where git is unavailable.
  }
  fs.mkdirSync(path.join(dir, "outside"));
  fs.writeFileSync(path.join(dir, "outside", "outside.txt"), "outside\n", "utf8");
  try {
    fs.symlinkSync(path.join(dir, "outside", "outside.txt"), path.join(root, "outside-link"));
  } catch {
    // Some platforms disallow symlinks; tests that need it can skip.
  }
  const configPath = path.join(dir, "config.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify(
      {
        server: {
          host: "127.0.0.1",
          port: 0,
          basePath: "/mcp",
          tunnelMode: false,
          endpointToken: "",
          allowedOrigins: ["https://chatgpt.com"],
        },
        roots: [{ alias: "tmp", path: root, permission: "read" }],
        limits: {
          maxReadBytes: 1024,
          maxSearchResults: 5,
          maxDirEntries: 20,
          maxOutputBytes: 2048,
          gitTimeoutMs: 1000,
        },
        audit: { enabled: true, path: path.join(dir, "audit.log") },
      },
      null,
      2,
    ),
  );
  return { dir, root, configPath };
}

export function readAudit(dir) {
  const audit = path.join(dir, "audit.log");
  return fs.existsSync(audit) ? fs.readFileSync(audit, "utf8") : "";
}
