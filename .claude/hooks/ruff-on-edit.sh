#!/usr/bin/env bash
# ruff-on-edit.sh — PostToolUse hook for Edit|Write|MultiEdit.
#
# Best-effort `uv run ruff check` on Python files in parent-tracked packages.
# Skips files inside submodules (acgs-lite, Acgs-Swarm, clinicalguard) so the
# parent ruff config does not override each submodule's authoritative gate.
# Always exits 0 — ruff output goes to stderr for the model; never blocks.
#
# Skips when:
#   - uv is not installed
#   - the edited file is outside *.py
#   - the file is inside a registered submodule
#
# Set SUPPRESS_RUFF=1 to silence.

set -uo pipefail

[ "${SUPPRESS_RUFF:-0}" = "1" ] && exit 0
command -v uv >/dev/null 2>&1 || exit 0
command -v python3 >/dev/null 2>&1 || exit 0

event_json="$(cat)"
file_path="$(printf '%s' "$event_json" | python3 -c '
import json, sys
try:
    payload = json.loads(sys.stdin.read())
except Exception:
    print("")
    sys.exit(0)
ti = payload.get("tool_input") or {}
print(ti.get("file_path") or ti.get("path") or "")
' 2>/dev/null)"

[ -z "$file_path" ] && exit 0

# Python files only.
case "$file_path" in
  *.py) ;;
  *) exit 0 ;;
esac

# Skip files inside submodules — they have their own ruff config.
case "$file_path" in
  *packages/acgs-lite/*|*packages/Acgs-Swarm/*|*packages/clinicalguard/*)
    exit 0
    ;;
esac

[ -n "${CLAUDE_PROJECT_DIR:-}" ] || exit 0
[ -f "$CLAUDE_PROJECT_DIR/pyproject.toml" ] || exit 0

(cd "$CLAUDE_PROJECT_DIR" && uv run ruff check "$file_path" >&2 2>&1) || true

exit 0
