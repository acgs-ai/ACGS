#!/usr/bin/env bash
# source-doc-suggest.sh — advisory PostToolUse hook for Edit|Write|MultiEdit.
# Reads Claude hook JSON from stdin, prints source-driven doc reminders to stderr,
# and always exits 0.

set -uo pipefail

command -v python3 >/dev/null 2>&1 || exit 0

event_json="$(cat)"
file_path="$(printf '%s' "$event_json" | python3 -c '
import json
import os
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)

tool_input = payload.get("tool_input") or {}
path = tool_input.get("file_path") or tool_input.get("path") or ""
project_dir = os.environ.get("CLAUDE_PROJECT_DIR", "")
if path and project_dir:
    try:
        rel = os.path.relpath(path, project_dir)
    except Exception:
        rel = path
    if not rel.startswith("../"):
        path = rel
print(path)
' 2>/dev/null)"

[ -n "$file_path" ] || exit 0

message=""
case "$file_path" in
  acgi-ai/src/*.ts|acgi-ai/src/*.tsx|acgi-ai/src/*/*.ts|acgi-ai/src/*/*.tsx|acgi-ai/src/*/*/*.ts|acgi-ai/src/*/*/*.tsx|acgi-ai/src/*/*/*/*.ts|acgi-ai/src/*/*/*/*.tsx|acgi-ai/src/*/*/*/*/*.ts|acgi-ai/src/*/*/*/*/*.tsx|acgi-ai/vite.config.ts|acgi-ai/package.json)
    message="[source-doc] Check exact versions in acgi-ai/package.json; cite official React/Vite/TanStack/MSW docs for framework-specific patterns."
    ;;
  acgs_governance_eval_mvp/governance/service/*|acgs_governance_eval_mvp/governance/service/*/*|acgs_governance_eval_mvp/governance/service/*/*/*|acgs_governance_eval_mvp/governance/*route*.py|acgs_governance_eval_mvp/governance/*router*.py|acgs_governance_eval_mvp/governance/service/*route*.py|acgs_governance_eval_mvp/governance/service/*router*.py)
    message="[source-doc] Cite FastAPI docs for route, dependency, and response behavior before changing API semantics."
    ;;
  .github/workflows/*)
    message="[source-doc] Cite the official GitHub Actions or action/tool docs for workflow syntax and action-version changes."
    ;;
esac

[ -n "$message" ] && printf '%s\n' "$message" >&2
exit 0
