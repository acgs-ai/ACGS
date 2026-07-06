#!/usr/bin/env bash
# ACGS Governed Loop v2 — Stop gate. DORMANT unless a loop is active.
# When dormant it approves (never blocks an ordinary session's turn-end).
# When active it blocks turn-end until the current phase evidence validates,
# but distinguishes "keep going" from "escalate" on stall/budget exhaustion.
set -uo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
MARKER="$ROOT/evidence/loop-active"
[ -f "$MARKER" ] || { echo '{"decision":"approve"}'; exit 0; }

S="$ROOT/evidence/state.json"
# jq numeric reads with defaults; `// 0` also coerces non-numeric/null.
num() { jq -r "$1" "$S" 2>/dev/null | grep -Eo '^-?[0-9]+' | head -1; }
PHASE="$(jq -r '.phase // 1' "$S" 2>/dev/null || echo 1)"
STALL="$(num '.stall_count // 0')";        STALL="${STALL:-0}"
LIMIT="$(num '.budget.stall_limit // 6')";  LIMIT="${LIMIT:-6}"
REMAINING="$(num '.budget.remaining // 1')"; REMAINING="${REMAINING:-1}"
TOKENS="$(num '.budget.tokens // 1')";       TOKENS="${TOKENS:-1}"
CALLS="$(num '.budget.tool_calls // 1')";    CALLS="${CALLS:-1}"

# Escalation beats continuation: a stalled or broke loop must stop, not spin.
# Budget is exhausted when the running countdown OR either hard resource hits zero.
if [ "$STALL" -ge "$LIMIT" ] || [ "$REMAINING" -le 0 ] || [ "$TOKENS" -le 0 ] || [ "$CALLS" -le 0 ]; then
  # Escalation must leave a human-facing artifact; if none exists, keep blocking.
  if [ -f "$ROOT/evidence/escalation.md" ] || [ -f "$ROOT/evidence/blocks.md" ]; then
    echo '{"decision":"approve","reason":"Stall/budget limit reached and escalation.md/blocks.md is on disk; ending is correct."}'
    exit 0
  fi
  echo '{"decision":"block","reason":"Stall/budget limit reached but no evidence/escalation.md (or blocks.md) written. Write the decision-shaped escalation first, then end."}'
  exit 0
fi

# Otherwise: block turn-end until this phase's evidence validates.
PJSON="$ROOT/evidence/phase-${PHASE}.json"
if [ ! -f "$PJSON" ] || \
   ! jq -e '.exit_criteria_met==true and .validator_signoff==true and (.test_results.failed==0)' \
     "$PJSON" >/dev/null 2>&1; then
  printf '{"decision":"block","reason":"Phase %s evidence missing/unsigned or a test is failing. Continue the loop: remediate, re-run verify commands, regenerate phase-%s.json."}\n' "$PHASE" "$PHASE"
  exit 0
fi

echo '{"decision":"approve"}'
exit 0
