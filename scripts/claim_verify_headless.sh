#!/usr/bin/env bash
# claim_verify_headless.sh: headless claim-verification proof pack.
#
# Runs the govern-zone proof commands named in AGENTS.md and emits ONE JSON
# object to stdout:
#
#   {"claims":[{"name":"...","command":"...","exit_code":0,"passed":true}],
#    "all_passed":true,"timestamp":"...Z"}
#
# Proof-command output (stdout + stderr) goes to stderr; consumers parse stdout.
# Exit 0 whenever valid JSON was emitted, even if some claims failed.
# Exit 1 only on an internal error (could not run / could not emit JSON).
#
# Pure bash + python3: no LLM, no network. Consumed by /claim-verify
# (.claude/commands/claim-verify.md).
set -u

# Run from the repo root regardless of the caller's cwd.
cd "$(dirname "$0")/.." || exit 1

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

NAMES=(
  "root-docs-smoke"
  "gove-zone-smoke"
  "receipt-demo"
  "tamper-demo"
)
COMMANDS=(
  "uv run python -m pytest tests/docs --import-mode=importlib -q"
  "uv run --package gove-zone gove-zone smoke --audit $TMP/audit.jsonl"
  "uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py"
  "uv run --package gove-zone python examples/tamper_demo/demo.py"
)

# One record per claim: name \x1f exit_code \x1f command (the unit separator
# never appears in the names/commands above).
RECORDS=()
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  cmd="${COMMANDS[$i]}"
  printf '==> %s: %s\n' "$name" "$cmd" >&2
  bash -c "$cmd" 1>&2 2>&2
  code=$?
  printf '<== %s exit %d\n' "$name" "$code" >&2
  RECORDS+=("${name}"$'\x1f'"${code}"$'\x1f'"${cmd}")
done

python3 - "${RECORDS[@]}" <<'PY'
import json
import sys
from datetime import datetime, timezone

claims = []
for spec in sys.argv[1:]:
    name, code, cmd = spec.split("\x1f", 2)
    claims.append({
        "name": name,
        "command": cmd,
        "exit_code": int(code),
        "passed": int(code) == 0,
    })
print(json.dumps({
    "claims": claims,
    "all_passed": all(c["passed"] for c in claims),
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}))
PY
exit $?
