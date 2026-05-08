import fs from "node:fs";
import path from "node:path";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

const DEFAULT_LIMITS = {
  maxReadBytes: 64 * 1024,
  maxSearchResults: 50,
  maxDirEntries: 200,
  maxOutputBytes: 64 * 1024,
  gitTimeoutMs: 3000,
};

const DEFAULT_IGNORED_DIRS = [
  ".git",
  "node_modules",
  ".venv",
  "dist",
  "build",
  "target",
  ".omx/logs",
  ".omc/logs",
];

const DEFAULT_DENIED_PATTERNS = [
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "credentials/**",
  "secrets/**",
];

export function defaultConfigPath(cwd = process.cwd()) {
  return process.env.LOCAL_CHATGPT_BRIDGE_CONFIG || path.join(cwd, "config.json");
}

export function loadConfig(configPath = defaultConfigPath()) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file is required: ${configPath}`);
  }

  const raw = fs.readFileSync(configPath, "utf8");
  const parsed = JSON.parse(raw);
  return normalizeConfig(parsed, path.dirname(path.resolve(configPath)));
}

export function normalizeConfig(input, baseDir = process.cwd()) {
  const server = {
    host: input.server?.host || "127.0.0.1",
    port: Number(input.server?.port || process.env.PORT || 8788),
    basePath: input.server?.basePath || "/mcp",
    tunnelMode: Boolean(input.server?.tunnelMode),
    endpointToken: input.server?.endpointToken || "",
    allowedOrigins: Array.isArray(input.server?.allowedOrigins)
      ? input.server.allowedOrigins
      : [],
  };

  if (!server.basePath.startsWith("/")) {
    throw new Error("server.basePath must start with /");
  }

  const limits = { ...DEFAULT_LIMITS, ...(input.limits || {}) };
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(Number(value)) || Number(value) <= 0) {
      throw new Error(`limits.${key} must be a positive integer`);
    }
    limits[key] = Number(value);
  }

  const roots = Array.isArray(input.roots) ? input.roots : [];
  if (roots.length === 0) {
    throw new Error("At least one allowed root is required");
  }

  const normalizedRoots = roots.map((root) => {
    if (!root.alias || !/^[a-zA-Z0-9_.-]+$/.test(root.alias)) {
      throw new Error("Each root requires a simple alias");
    }
    if (root.permission && root.permission !== "read") {
      throw new Error(`Root ${root.alias} must use permission read`);
    }
    const rootPath = path.resolve(baseDir, root.path || ".");
    const realPath = fs.realpathSync(rootPath);
    const stat = fs.statSync(realPath);
    if (!stat.isDirectory()) {
      throw new Error(`Root ${root.alias} is not a directory`);
    }
    return {
      alias: root.alias,
      path: rootPath,
      realPath,
      permission: "read",
    };
  });

  const aliases = new Set();
  for (const root of normalizedRoots) {
    if (aliases.has(root.alias)) throw new Error(`Duplicate root alias: ${root.alias}`);
    aliases.add(root.alias);
  }

  validateServerSafety(server);

  const kernel = input.kernel
    ? {
        poolName: input.kernel.poolName || null,
        acquireTimeoutSeconds: Number(input.kernel.acquireTimeoutSeconds ?? 30),
        responseTimeoutMs: Number(input.kernel.responseTimeoutMs ?? 120_000),
      }
    : null;

  return {
    server,
    roots: normalizedRoots,
    limits,
    ignoredDirs: input.ignoredDirs || DEFAULT_IGNORED_DIRS,
    deniedPatterns: input.deniedPatterns || DEFAULT_DENIED_PATTERNS,
    audit: {
      enabled: input.audit?.enabled !== false,
      path: input.audit?.path || "./audit.log",
    },
    kernel,
  };
}

export function validateServerSafety(server) {
  const localOnly = LOOPBACK_HOSTS.has(server.host);
  if (server.tunnelMode && !isHighEntropyToken(server.endpointToken)) {
    throw new Error("Tunnel mode requires a high-entropy endpoint token");
  }
  if (!localOnly && !isHighEntropyToken(server.endpointToken)) {
    throw new Error("Non-loopback binding requires a high-entropy endpoint token");
  }
  return true;
}

export function isLoopbackHost(host) {
  return LOOPBACK_HOSTS.has(host);
}

export function isHighEntropyToken(token) {
  return typeof token === "string" && token.length >= 32 && /^[A-Za-z0-9_-]+$/.test(token);
}

export function findRoot(config, alias) {
  const root = config.roots.find((candidate) => candidate.alias === alias);
  if (!root) throw new Error(`Unknown root alias: ${alias}`);
  return root;
}
