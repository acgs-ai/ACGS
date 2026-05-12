#!/usr/bin/env bash
# seal-block.sh — PreToolUse hook for Edit|Write|MultiEdit.
#
# Blocks edits to files containing a `# Constitutional Hash:` marker unless
# the caller explicitly sets ALLOW_HASH_EDIT=1. Mirrors the enforcement in
# .github/workflows/constitutional-hash.yml so a sealed-file edit fails at
# the tool layer instead of at CI.
#
# Stdin: Claude Code JSON event:
#   {"tool_name":"Edit","tool_input":{"file_path":"...", ...}, ...}
#
# Exit codes:
#   0  allow
#   2  block (stderr message surfaces to the model)
#
# If ALLOW_HASH_EDIT=1, the hook returns 0 with a stderr note that the
# operator must immediately run `python scripts/verify_constitutional_hashes.py --update`
# and commit the resulting lock change in the same PR.

set -euo pipefail

# Read the event payload from stdin. If python3 is missing or stdin is empty,
# fail closed (exit 2) — refusing to edit is safer than silently allowing.
if ! command -v python3 >/dev/null 2>&1; then
  echo "seal-block: python3 not available — failing closed" >&2
  exit 2
fi

event_json="$(cat)"
file_path="$(printf '%s' "$event_json" | python3 -c '
import json, sys
try:
    payload = json.loads(sys.stdin.read())
except Exception:
    sys.exit(99)
ti = payload.get("tool_input") or {}
print(ti.get("file_path") or ti.get("path") or "")
' 2>/dev/null)" || { echo "seal-block: failed to parse hook payload — failing closed" >&2; exit 2; }

# No file_path on this tool call — nothing to check, allow.
[ -z "$file_path" ] && exit 0

# File doesn't exist yet (new Write) — no marker possible, allow.
[ -f "$file_path" ] || exit 0

# Cheap grep: marker must be exactly `# Constitutional Hash:`.
if grep -q '^# Constitutional Hash:' "$file_path" 2>/dev/null; then
  if [ "${ALLOW_HASH_EDIT:-0}" = "1" ]; then
    echo "seal-block: ALLOW_HASH_EDIT=1 set — proceeding. You MUST run" >&2
    echo "  python scripts/verify_constitutional_hashes.py --update" >&2
    echo "and commit the lock change in the same PR." >&2
    exit 0
  fi
  cat >&2 <<EOF
seal-block: refusing to edit sealed file:
  $file_path

This file carries a '# Constitutional Hash:' marker. Per
ACGS/govern-zone/CLAUDE.md rule #1 and .github/workflows/constitutional-hash.yml,
sealed files must not change without recomputing the hash and updating
docs/constitutional-hashes.lock in the same commit.

To proceed:
  1. Set ALLOW_HASH_EDIT=1 in your shell.
  2. Make the edit.
  3. Run: python scripts/verify_constitutional_hashes.py --update
  4. Commit the source + lock changes together.

Refusing this edit.
EOF
  exit 2
fi

exit 0
