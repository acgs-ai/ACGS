#!/usr/bin/env bash
# related-gate-suggest.sh — advisory PostToolUse hook for Edit|Write|MultiEdit.
# Reads Claude hook JSON from stdin, prints the nearest authoritative gate to
# stderr, and always exits 0.

set -uo pipefail

[ "${SUPPRESS_RELATED_GATE_SUGGEST:-0}" = "1" ] && exit 0
command -v python3 >/dev/null 2>&1 || exit 0

file_path="$(python3 -c '
import json, os, sys
try:
    payload = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
ti = payload.get("tool_input") or {}
path = ti.get("file_path") or ti.get("path") or ""
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
  acgs_governance_eval_mvp/*)
    message="[related-gate] $file_path -> cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q"
    ;;
  tests/*|scripts/*)
    message="[related-gate] $file_path -> uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q"
    ;;
  acgi-ai/src/*|acgi-ai/package.json)
    message="[related-gate] $file_path -> pnpm -F acgi-ai lint && pnpm -F acgi-ai build"
    ;;
  packages/gove-zone/*)
    message="[related-gate] $file_path -> cd packages/gove-zone && uv run python -m pytest --import-mode=importlib"
    ;;
  .github/workflows/*)
    workflow_name="${file_path##*/}"
    gate=""
    case "$workflow_name" in
      console.yml|marketing.yml)
        gate="pnpm -F acgi-ai lint && pnpm -F acgi-ai build"
        ;;
      python-eval-mvp.yml|eval.yml)
        gate="cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q"
        ;;
      python-gove-zone.yml)
        gate="cd packages/gove-zone && uv run python -m pytest --import-mode=importlib"
        ;;
      constitutional-hash.yml)
        gate="python3 scripts/verify_constitutional_hashes.py"
        ;;
    esac
    if [ -n "$gate" ]; then
      message="[related-gate] inspect $workflow_name; run before PR: $gate"
    else
      message="[related-gate] inspect $workflow_name and run the owning package gate before PR"
    fi
    ;;
esac

[ -n "$message" ] && printf '%s\n' "$message" >&2
exit 0
