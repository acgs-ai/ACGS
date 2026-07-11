#!/usr/bin/env bash
# ACGS Governed Loop v2 — PreToolUse reference monitor.
# DORMANT unless a loop is active (evidence/loop-active marker present), so this
# hook is fully inert in ordinary sessions in this repo.
# Reads the tool-call JSON on stdin. Exit 2 = deny the tool call, 0 = allow.
#
# Every decision (allow AND deny) is written to a hash-chained ledger under an
# flock, and the hook FAILS CLOSED: if a decision cannot be recorded it cannot be
# proven, so the call is denied. The in-hook denylist is a coarse backstop, not the
# boundary — the real gates are the settings.json deny rules and the gove-zone
# policy below.
set -uo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"   # fails open if unset, but dormant-by-default
MARKER="$ROOT/evidence/loop-active"
[ -f "$MARKER" ] || exit 0

LEDGER="$ROOT/evidence/ledger.jsonl"
INPUT="$(cat)"
TOOL="$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)"
CMD="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)"

# Append one hash-chained decision record. Single writer under flock; the
# read-head/append is serialized so concurrent calls cannot fork the chain.
# Returns non-zero if the record could not be written.
append_record() {  # $1=decision  $2=reason
  local decision="$1" reason="$2" prev rec hash
  exec 9>>"$LEDGER.lock" 2>/dev/null || return 1
  flock 9 2>/dev/null || return 1
  prev="genesis"
  if [ -s "$LEDGER" ]; then
    prev="$(tail -1 "$LEDGER" 2>/dev/null | jq -r '.hash // "genesis"' 2>/dev/null || echo genesis)"
  fi
  rec="$(jq -nc --arg t "$TOOL" --arg c "$CMD" --arg d "$decision" --arg r "$reason" --arg p "$prev" \
    '{ts:(now|todate),tool:$t,cmd:$c,decision:$d,reason:$r,prev:$p}' 2>/dev/null)" || return 1
  hash="$(printf '%s' "$rec" | sha256sum | cut -d' ' -f1)" || return 1
  printf '%s' "$rec" | jq -c --arg h "$hash" '. + {hash:$h}' >> "$LEDGER" || return 1
  return 0
}

deny() {  # $1=reason — record the denial, then fail closed.
  if ! append_record deny "$1"; then
    echo "loop-guard: could not record denial; failing closed" >&2
    exit 2
  fi
  echo "loop-guard DENIED: $1" >&2
  exit 2
}

# --- coarse destructive backstop (flag-order-independent) ---
# rm with BOTH a recursive and a force flag, aimed at a root-ish target.
if printf '%s' "$CMD" | grep -Eqw 'rm' \
   && printf '%s' "$CMD" | grep -Eq -- '(-[[:alnum:]]*r|--recursive)' \
   && printf '%s' "$CMD" | grep -Eq -- '(-[[:alnum:]]*f|--force)' \
   && printf '%s' "$CMD" | grep -Eq -- '[[:space:]](/(etc|usr|bin|var|home|boot|lib|lib64|opt|root|sys|proc)?([[:space:]/]|$)|(~|\$HOME)([[:space:]/]|$)|\.\.?([[:space:]]|$))'; then
  deny "recursive-force rm on a root-ish target"
fi
if printf '%s' "$CMD" | grep -Eq 'git[[:space:]]+push[[:space:]]+(--force([[:space:]]|$)|-f([[:space:]]|$))'; then
  deny "force push"
fi
if printf '%s' "$CMD" | grep -Eq -- '--dangerously-skip-permissions'; then
  deny "permission-skip flag"
fi
if printf '%s' "$CMD" | grep -Eq '(curl|wget)[^|]*\|[[:space:]]*(ba)?sh([[:space:]]|$)'; then
  deny "pipe-to-shell"
fi

# --- optional gove-zone policy routing (only if CLI and policy both exist) ---
POLICY="$ROOT/.claude/policy/build.yaml"
if command -v gove-zone >/dev/null 2>&1 && [ -f "$POLICY" ]; then
  printf '%s' "$INPUT" | gove-zone validate --policy "$POLICY" --stdin >/dev/null 2>&1 \
    || deny "gove-zone policy"
fi

# Allowed — record it (fail closed if the decision cannot be proven).
if ! append_record allow ""; then
  echo "loop-guard: could not record allow decision; failing closed" >&2
  exit 2
fi
exit 0
