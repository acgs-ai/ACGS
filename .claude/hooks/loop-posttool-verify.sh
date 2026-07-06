#!/usr/bin/env bash
# ACGS Governed Loop v2 — PostToolUse verify. DORMANT unless a loop is active.
# The loop-active marker's first line, if present, is the post-edit verify command.
# PostToolUse cannot deny a call; on failure it surfaces the breakage to the
# Executor as stderr guidance so a regression becomes the immediate priority.
set -uo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
MARKER="$ROOT/evidence/loop-active"
[ -f "$MARKER" ] || exit 0

CMD="$(head -1 "$MARKER" 2>/dev/null || true)"
[ -n "$CMD" ] || exit 0

# Temp output inside the (gitignored) evidence dir so a mid-verify kill can't leak
# into /tmp. Bounded by a timeout so a hung verify cannot stall the session.
OUT="$(mktemp -p "$ROOT/evidence" loop-verify.XXXXXX 2>/dev/null || mktemp)"
if ! ( cd "$ROOT" && timeout 300 bash -c "$CMD" ) >"$OUT" 2>&1; then
  echo "loop-verify: FAIL — post-edit check failed (or timed out); fix before any new work:" >&2
  tail -20 "$OUT" >&2 || true
fi
rm -f "$OUT" 2>/dev/null || true
exit 0
