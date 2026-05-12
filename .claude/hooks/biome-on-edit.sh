#!/usr/bin/env bash
# biome-on-edit.sh — PostToolUse hook for Edit|Write|MultiEdit.
#
# Best-effort biome check on JS/TS files inside acgi-ai/src/. Surfaces lint
# errors immediately so the agent does not get a CI surprise from console.yml
# or marketing.yml. Always exits 0 — biome output goes to stderr for the
# model to read, but does not block subsequent tool calls.
#
# Skips when:
#   - pnpm is not installed
#   - the edited file is outside acgi-ai/src/
#   - acgi-ai/node_modules/ is missing (pnpm install hasn't run yet)
#
# Set SUPPRESS_BIOME=1 to silence.

set -uo pipefail

[ "${SUPPRESS_BIOME:-0}" = "1" ] && exit 0
command -v pnpm >/dev/null 2>&1 || exit 0
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

# Only run for TS/JS files inside acgi-ai/src/.
case "$file_path" in
  *acgi-ai/src/*.ts|*acgi-ai/src/*.tsx|*acgi-ai/src/*.js|*acgi-ai/src/*.jsx) ;;
  *) exit 0 ;;
esac

# Locate the acgi-ai package root by walking up from the file.
pkg_root=""
candidate="$(dirname "$file_path")"
while [ "$candidate" != "/" ] && [ "$candidate" != "." ]; do
  if [ -d "$candidate/acgi-ai/node_modules" ] && [ -f "$candidate/acgi-ai/package.json" ]; then
    pkg_root="$candidate"
    break
  fi
  candidate="$(dirname "$candidate")"
done

# Couldn't find an installed acgi-ai — skip silently.
[ -z "$pkg_root" ] && exit 0

(
  cd "$pkg_root" || exit 0
  pnpm -F acgi-ai exec biome check --no-errors-on-unmatched "$file_path" >&2 2>&1 || true
)

exit 0
