import fs from "node:fs";
import path from "node:path";
import { findRoot } from "../config.js";

const TEXT_BYTES = new Set([9, 10, 13]);

export class RefusalError extends Error {
  constructor(reason, message = reason) {
    super(message);
    this.name = "RefusalError";
    this.reason = reason;
  }
}

export function resolveAllowedPath(config, rootAlias, relativePath = "") {
  const root = findRoot(config, rootAlias);
  const decoded = decodePath(relativePath);
  if (decoded.includes("\0")) throw new RefusalError("nul_byte");
  if (path.isAbsolute(decoded)) throw new RefusalError("absolute_path");

  const normalized = path.normalize(decoded || ".");
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) {
    throw new RefusalError("path_traversal");
  }

  const parts = normalized.split(path.sep).filter(Boolean);
  if (containsIgnoredPath(config, parts)) throw new RefusalError("ignored_path");
  if (matchesDeniedPattern(config.deniedPatterns, parts)) throw new RefusalError("denied_path");

  const candidate = path.join(root.realPath, normalized);
  const lstat = fs.lstatSync(candidate);
  if (lstat.isSymbolicLink()) throw new RefusalError("symlink_refused");

  const realPath = fs.realpathSync(candidate);
  if (!isInside(root.realPath, realPath)) throw new RefusalError("outside_root");

  return { root, realPath, relativePath: normalized === "." ? "" : normalized, lstat };
}

export function isTextFile(filePath, maxSampleBytes = 4096) {
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(maxSampleBytes);
    const bytesRead = fs.readSync(fd, buffer, 0, maxSampleBytes, 0);
    for (let index = 0; index < bytesRead; index += 1) {
      const byte = buffer[index];
      if (byte === 0) return false;
      if (byte < 32 && !TEXT_BYTES.has(byte)) return false;
    }
    return true;
  } finally {
    fs.closeSync(fd);
  }
}

export function isInside(rootRealPath, candidateRealPath) {
  const relative = path.relative(rootRealPath, candidateRealPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export function decodePath(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    throw new RefusalError("invalid_path_encoding");
  }
}

export function containsIgnoredPath(config, parts) {
  const normalizedParts = parts.map((part) => part.toLowerCase());
  return config.ignoredDirs.some((ignored) => {
    const ignoredParts = ignored.split(/[\\/]+/).filter(Boolean).map((part) => part.toLowerCase());
    if (ignoredParts.length === 0 || ignoredParts.length > normalizedParts.length) return false;
    for (let start = 0; start <= normalizedParts.length - ignoredParts.length; start += 1) {
      const window = normalizedParts.slice(start, start + ignoredParts.length);
      if (window.every((part, index) => part === ignoredParts[index])) return true;
    }
    return false;
  });
}

export function matchesDeniedPattern(patterns, parts) {
  const relative = parts.join("/");
  const basename = parts.at(-1) || "";
  if (parts.some((part) => ["credentials", "secrets"].includes(part.toLowerCase()))) {
    return true;
  }
  return patterns.some((pattern) => globMatch(pattern, relative) || globMatch(pattern, basename));
}

function globMatch(pattern, value) {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, ":::DOUBLE_STAR:::")
    .replace(/\*/g, "[^/]*")
    .replace(/:::DOUBLE_STAR:::/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}
