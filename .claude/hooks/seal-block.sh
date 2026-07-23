#!/usr/bin/env bash
# seal-block.sh — PreToolUse hook for Edit|Write|MultiEdit.
#
# Blocks edits to genuinely sealed / generated files unless the caller
# explicitly sets ALLOW_HASH_EDIT=1. Mirrors the enforcement in
# .github/workflows/constitutional-hash.yml so a sealed-file edit fails at
# the tool layer instead of at CI.
#
# ---------------------------------------------------------------------------
# Matcher rationale (why anchored marker lines, not a broad substring scan)
# ---------------------------------------------------------------------------
# An earlier substring approach (and the post-edit guard's SEAL_HINTS list)
# matched bare tokens anywhere in a file. That false-positived on files whose
# *prose* merely discusses the discipline — e.g. a rule doc mentioning the
# "constitutional-hash discipline" mid-sentence is documentation, not a
# sealed artifact, yet a substring scan would refuse to edit it. Worse, a
# rules file that lists the marker tokens themselves (as this repo's
# security-sensitive-files.md does) would be permanently uneditable.
#
# This hook therefore triggers ONLY on genuine *marker lines*, never on prose:
#
#   1. A sealed-hash comment line: `^#\s*Constitutional Hash:` — anchored to
#      line start + `#`, requires the capitalized "Constitutional Hash:" label
#      with a colon. Hyphenated lower-case prose ("constitutional-hash")
#      cannot match: no `#` anchor, no colon, wrong case.
#   2. A codegen sentinel or sealed banner at *marker position* — the token
#      sits at line start after at most one comment leader (`#` `//` `*` `;`
#      `--` `<!--`) and whitespace. Prose that names the token mid-sentence
#      (preceded by words, backticks, or a bullet) never reaches that
#      position, so documentation stays editable.
#
# The two banner tokens matched at marker position are the codegen sentinel
# (at symbol + "generated") and the upper-case do-not-edit banner. They are
# spelled out only inside the grep patterns below, deliberately not on any
# comment line here, so this hook never blocks edits to itself.
#
# Anything matching is a true positive → fail closed (exit 2). Everything
# else — including docs that merely *mention* sealing — is allowed through.
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

# Marker scan (see rationale above). Only genuine marker lines match, never
# prose. `marker_line` anchors a token to line start after at most one
# optional comment leader + whitespace, so a mid-sentence mention is ignored.
marker_line='^[[:space:]]*([#;*]|//|--|<!--)?[[:space:]]*'
if grep -Eq \
    -e '^#[[:space:]]*Constitutional Hash:' \
    -e "${marker_line}@generated" \
    -e "${marker_line}DO NOT EDIT" \
    "$file_path" 2>/dev/null; then
  if [ "${ALLOW_HASH_EDIT:-0}" = "1" ]; then
    echo "seal-block: ALLOW_HASH_EDIT=1 set — proceeding. You MUST run" >&2
    echo "  python scripts/verify_constitutional_hashes.py --update" >&2
    echo "and commit the lock change in the same PR." >&2
    exit 0
  fi
  cat >&2 <<'EOF'
seal-block: refusing to edit sealed / generated file:
EOF
  echo "  $file_path" >&2
  cat >&2 <<'EOF'

This file carries a genuine seal/generated marker (a `# Constitutional Hash:`
line, a codegen sentinel, or an upper-case do-not-edit banner). Per
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
