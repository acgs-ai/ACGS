import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { resolveAllowedPath, isTextFile, RefusalError } from "../security/paths.js";

const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
  idempotentHint: true,
};

const content = (structuredContent) => [
  { type: "text", text: JSON.stringify(structuredContent) },
];

const objectSchema = (properties, required = Object.keys(properties)) => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});

const pathInputSchema = objectSchema({
  root: { type: "string", minLength: 1 },
  path: { type: "string", default: "" },
});

const pathOutput = {
  root: { type: "string" },
  path: { type: "string" },
};

export const toolDefinitions = [
  {
    name: "list_allowed_roots",
    title: "List allowed roots",
    description:
      "Use this when the user wants to see which local workspace roots this read-only bridge can inspect.",
    inputSchema: objectSchema({}, []),
    outputSchema: objectSchema({
      roots: {
        type: "array",
        items: objectSchema({
          alias: { type: "string" },
          path: { type: "string" },
          permission: { type: "string" },
        }),
      },
      limits: { type: "object" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "list_dir",
    title: "List directory",
    description:
      "Use this when the user wants a bounded listing of files under an explicitly allowed local root.",
    inputSchema: pathInputSchema,
    outputSchema: objectSchema({
      ...pathOutput,
      entries: {
        type: "array",
        items: objectSchema({
          name: { type: "string" },
          type: { type: "string" },
          size: { type: "number" },
        }),
      },
      truncated: { type: "boolean" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "read_file",
    title: "Read file",
    description:
      "Use this when the user needs the text contents of an allowed local file. Secret-like, binary, oversized, symlinked, and outside-root paths are refused.",
    inputSchema: pathInputSchema,
    outputSchema: objectSchema({
      ...pathOutput,
      text: { type: "string" },
      bytes: { type: "number" },
      truncated: { type: "boolean" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "search_files",
    title: "Search files",
    description:
      "Use this when the user wants to search allowed local text files without exposing ignored directories or secret-like paths.",
    inputSchema: objectSchema({
      root: { type: "string", minLength: 1 },
      query: { type: "string", minLength: 1 },
      path: { type: "string", default: "" },
    }),
    outputSchema: objectSchema({
      root: { type: "string" },
      query: { type: "string" },
      matches: {
        type: "array",
        items: objectSchema({
          path: { type: "string" },
          line: { type: "number" },
          preview: { type: "string" },
        }),
      },
      truncated: { type: "boolean" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "get_file_metadata",
    title: "Get file metadata",
    description:
      "Use this when the user needs size, timestamps, and type for an allowed local path without reading file content.",
    inputSchema: pathInputSchema,
    outputSchema: objectSchema({
      ...pathOutput,
      type: { type: "string" },
      size: { type: "number" },
      mtimeMs: { type: "number" },
      ctimeMs: { type: "number" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "git_status",
    title: "Git status",
    description:
      "Use this when the user wants read-only git status for an allowed local repository root. This runs only git status --short --branch.",
    inputSchema: objectSchema({
      root: { type: "string", minLength: 1 },
    }),
    outputSchema: objectSchema({
      root: { type: "string" },
      status: { type: "string" },
      truncated: { type: "boolean" },
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  },
];

const handlers = {
  list_allowed_roots({ config }) {
    return {
      roots: config.roots.map((root) => ({
        alias: root.alias,
        path: root.realPath,
        permission: root.permission,
      })),
      limits: config.limits,
    };
  },

  list_dir({ config, args }) {
    const target = resolveAllowedPath(config, args.root, args.path || "");
    const stat = fs.statSync(target.realPath);
    if (!stat.isDirectory()) throw new RefusalError("not_directory");
    const names = fs.readdirSync(target.realPath).sort();
    const entries = [];
    for (const name of names.slice(0, config.limits.maxDirEntries)) {
      const relative = target.relativePath ? path.join(target.relativePath, name) : name;
      try {
        const child = resolveAllowedPath(config, args.root, relative);
        const childStat = fs.statSync(child.realPath);
        entries.push({
          name,
          type: childStat.isDirectory() ? "directory" : "file",
          size: childStat.size,
        });
      } catch {
        // Denied children are intentionally omitted from directory listings.
      }
    }
    return {
      root: target.root.alias,
      path: target.relativePath,
      entries,
      truncated: names.length > config.limits.maxDirEntries,
    };
  },

  read_file({ config, args }) {
    const target = resolveAllowedPath(config, args.root, args.path || "");
    const stat = fs.statSync(target.realPath);
    if (!stat.isFile()) throw new RefusalError("not_file");
    if (stat.size > config.limits.maxReadBytes) throw new RefusalError("file_too_large");
    if (!isTextFile(target.realPath)) throw new RefusalError("binary_file");
    const text = fs.readFileSync(target.realPath, "utf8");
    return {
      root: target.root.alias,
      path: target.relativePath,
      text,
      bytes: Buffer.byteLength(text),
      truncated: false,
    };
  },

  search_files({ config, args }) {
    const start = resolveAllowedPath(config, args.root, args.path || "");
    const stat = fs.statSync(start.realPath);
    if (!stat.isDirectory()) throw new RefusalError("not_directory");
    const query = String(args.query || "").toLowerCase();
    const matches = [];
    walk(config, args.root, start.relativePath, (filePath, relativePath) => {
      if (matches.length >= config.limits.maxSearchResults) return false;
      const fileStat = fs.statSync(filePath);
      if (!fileStat.isFile() || fileStat.size > config.limits.maxReadBytes) return true;
      if (!isTextFile(filePath)) return true;
      const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
      for (let index = 0; index < lines.length; index += 1) {
        if (lines[index].toLowerCase().includes(query)) {
          matches.push({
            path: relativePath,
            line: index + 1,
            preview: lines[index].slice(0, 240),
          });
          if (matches.length >= config.limits.maxSearchResults) return false;
        }
      }
      return true;
    });
    return {
      root: args.root,
      query: args.query,
      matches,
      truncated: matches.length >= config.limits.maxSearchResults,
    };
  },

  get_file_metadata({ config, args }) {
    const target = resolveAllowedPath(config, args.root, args.path || "");
    const stat = fs.statSync(target.realPath);
    return {
      root: target.root.alias,
      path: target.relativePath,
      type: stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other",
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      ctimeMs: stat.ctimeMs,
    };
  },

  async git_status({ config, args }) {
    const target = resolveAllowedPath(config, args.root, "");
    const status = await runGitStatus(target.realPath, config.limits.gitTimeoutMs);
    const truncated = Buffer.byteLength(status) > config.limits.maxOutputBytes;
    return {
      root: target.root.alias,
      status: truncated ? status.slice(0, config.limits.maxOutputBytes) : status,
      truncated,
    };
  },
};

export async function callTool(config, auditor, name, args = {}) {
  const started = Date.now();
  try {
    if (!handlers[name]) throw new RefusalError("unknown_tool");
    const structuredContent = await handlers[name]({ config, args });
    auditor.record({
      tool: name,
      rootAlias: args.root,
      relativePath: args.path,
      query: args.query,
      resultCount: resultCount(structuredContent),
      durationMs: Date.now() - started,
    });
    return { structuredContent, content: content(structuredContent) };
  } catch (error) {
    const reason = error instanceof RefusalError ? error.reason : "tool_error";
    const structuredContent = {
      error: reason,
      message: error instanceof Error ? error.message : String(error),
    };
    auditor.record({
      tool: name,
      rootAlias: args.root,
      relativePath: args.path,
      query: args.query,
      refused: true,
      reason,
      durationMs: Date.now() - started,
    });
    return { structuredContent, content: content(structuredContent), isError: true };
  }
}

function walk(config, rootAlias, relativePath, visit) {
  const target = resolveAllowedPath(config, rootAlias, relativePath || "");
  const stat = fs.statSync(target.realPath);
  if (stat.isFile()) {
    visit(target.realPath, target.relativePath);
    return;
  }
  for (const name of fs.readdirSync(target.realPath).sort()) {
    const nextRelative = target.relativePath ? path.join(target.relativePath, name) : name;
    let child;
    try {
      child = resolveAllowedPath(config, rootAlias, nextRelative);
    } catch {
      continue;
    }
    const childStat = fs.statSync(child.realPath);
    if (childStat.isDirectory()) {
      walk(config, rootAlias, child.relativePath, visit);
    } else if (visit(child.realPath, child.relativePath) === false) {
      return;
    }
  }
}

function runGitStatus(cwd, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      ["status", "--short", "--branch"],
      { cwd, timeout: timeoutMs, shell: false, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          reject(new RefusalError("git_status_failed", stderr || error.message));
          return;
        }
        resolve(stdout);
      },
    );
  });
}

function resultCount(structuredContent) {
  if (Array.isArray(structuredContent.entries)) return structuredContent.entries.length;
  if (Array.isArray(structuredContent.matches)) return structuredContent.matches.length;
  if (Array.isArray(structuredContent.roots)) return structuredContent.roots.length;
  return undefined;
}
