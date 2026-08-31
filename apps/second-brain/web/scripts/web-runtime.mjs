import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { resolveWebRuntimeConfig } from "../src/lib/runtime-config.ts";

const command = process.argv[2];
if (command !== "dev" && command !== "start" && command !== "probe") {
  console.error("web_runtime_error code=command_invalid");
  process.exit(1);
}

const result = resolveWebRuntimeConfig(process.env, command);
if (!result.ok) {
  console.error(`web_runtime_error code=${result.code}`);
  process.exit(1);
}

if (command === "probe") {
  console.log(
    JSON.stringify({
      appEnvironment: result.value.appEnvironment,
      authMode: result.value.authMode,
      bindHost: result.value.bindHost,
      port: result.value.port,
    }),
  );
  process.exit(0);
}

const nextBin = fileURLToPath(new URL("../node_modules/next/dist/bin/next", import.meta.url));
const child = spawn(
  process.execPath,
  [nextBin, command, "--hostname", result.value.bindHost, "--port", String(result.value.port)],
  { env: process.env, stdio: "inherit" },
);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
