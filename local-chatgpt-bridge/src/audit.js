import fs from "node:fs";
import path from "node:path";

export function createAuditor(config, cwd = process.cwd()) {
  const auditPath = path.resolve(cwd, config.audit.path);
  return {
    path: auditPath,
    record(event) {
      if (!config.audit.enabled) return;
      const entry = {
        at: new Date().toISOString(),
        tool: event.tool,
        rootAlias: event.rootAlias,
        relativePath: event.relativePath,
        query: event.query,
        resultCount: event.resultCount,
        refused: Boolean(event.refused),
        reason: event.reason,
        durationMs: event.durationMs,
      };
      fs.mkdirSync(path.dirname(auditPath), { recursive: true });
      fs.appendFileSync(auditPath, `${JSON.stringify(entry)}\n`, "utf8");
    },
  };
}
