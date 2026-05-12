#!/usr/bin/env bash
# submodule-warn.sh — PreToolUse hook for Edit|Write|MultiEdit.
#
# Warns (but does not block) when an edit targets a path inside one of the
# three submodules registered in .gitmodules. Edits to submodule files made
# from the parent repo cause pointer drift and lose authorship in the nested
# repo's history.
#
# Mirrors ACGS/govern-zone/CLAUDE.md rule #2 ("Submodule boundaries are
# real") and MONOREPO.md submodule discipline.
#
# Non-blocking by design: there are legitimate reasons to read/edit submodule
# files (e.g. responding to a Codex pass that already entered the submodule).
# The hook just makes sure the operator sees a reminder before the change
# lands.
#
# Set SUPPRESS_SUBMODULE_WARN=1 to silence (e.g. inside an agent that has
# already entered the submodule).

set -euo pipefail

[ "${SUPPRESS_SUBMODULE_WARN:-0}" = "1" ] && exit 0

if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

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

case "$file_path" in
  packages/acgs-lite/*|*/packages/acgs-lite/*)
    submod="packages/acgs-lite"
    ;;
  packages/Acgs-Swarm/*|*/packages/Acgs-Swarm/*)
    submod="packages/Acgs-Swarm"
    ;;
  packages/clinicalguard/*|*/packages/clinicalguard/*)
    submod="packages/clinicalguard"
    ;;
  *)
    exit 0
    ;;
esac

cat >&2 <<EOF
submodule-warn: editing inside $submod (a registered submodule).

Parent-repo edits to submodule files cause pointer drift. Per
CLAUDE.md rule #2 and MONOREPO.md, commits to this path should be staged
from inside the submodule:

  git -C $submod add <files>
  git -C $submod commit -m "..."
  # then in parent repo: git add $submod  (separate commit, pointer bump)

Proceeding with the edit, but do not 'git add' from the parent unless this
is an intentional pointer bump. Set SUPPRESS_SUBMODULE_WARN=1 to silence.
EOF

exit 0
