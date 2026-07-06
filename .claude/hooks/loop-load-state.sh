#!/usr/bin/env bash
# ACGS Governed Loop v2 — SessionStart resume banner. DORMANT unless a loop is
# active; stays silent in ordinary sessions so it adds no startup noise.
set -uo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
MARKER="$ROOT/evidence/loop-active"
[ -f "$MARKER" ] || exit 0

S="$ROOT/evidence/state.json"
if [ -f "$S" ]; then
  P="$(jq -r '.phase // "?"' "$S" 2>/dev/null || echo '?')"
  C="$(jq -r '.cycle // "?"' "$S" 2>/dev/null || echo '?')"
  echo "RESUME (governed-loop-v2): phase=$P cycle=$C. Re-derive status from disk before acting; if any criterion last_run is stale or context was compacted, re-run its verify_cmd."
else
  echo "COLD START (governed-loop-v2): loop-active set but no state.json. Initialize from workload.yaml, phase 1, cycle 0."
fi
exit 0
