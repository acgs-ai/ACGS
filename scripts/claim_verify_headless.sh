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

# Preflight the proof runner. A missing uv is an INTERNAL error (exit 1, no
# JSON), not claim evidence: otherwise every claim would report passed:false
# and /claim-verify would propose wording downgrades for a local setup gap.
if ! command -v uv >/dev/null 2>&1; then
  echo "internal error: 'uv' not found on PATH; cannot run the proof commands" >&2
  exit 1
fi

# Preflight the uv workspace. uv validates the ROOT workspace before running
# any command, so a workspace member whose pyproject.toml is absent (typically
# an uninitialized git submodule such as packages/acgs-lite or an unavailable
# private one such as packages/clinicalguard) makes EVERY proof command fail
# with a setup error before its proof runs. That is a supported checkout
# state and a local setup gap, never claim evidence: report it as an INTERNAL
# error (exit 1, no JSON) instead of letting /claim-verify read the failures
# as claim downgrades. --no-project is not an alternative here because the
# proofs themselves need workspace discovery (uv run --package gove-zone).
MISSING="$(python3 - <<'PY'
import glob
import os
import sys
import tomllib

with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
members = data.get("tool", {}).get("uv", {}).get("workspace", {}).get("members", [])
for pattern in members:
    for path in sorted(glob.glob(pattern)) or [pattern]:
        if not os.path.isfile(os.path.join(path, "pyproject.toml")):
            print(path)
PY
)" || {
  echo "internal error: could not enumerate uv workspace members from pyproject.toml (needs python3 >= 3.11 for tomllib); cannot preflight the workspace" >&2
  exit 1
}
if [ -n "$MISSING" ]; then
  {
    echo "internal error: uv workspace members are missing their pyproject.toml:"
    printf '%s\n' "$MISSING" | sed 's/^/  /'
    echo "This is a checkout setup gap (usually uninitialized git submodules), not claim evidence."
    echo "Initialize them (git submodule update --init <path>) or run from a fully initialized checkout, then re-run."
  } >&2
  exit 1
fi

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

NAMES=(
  "root-docs-smoke"
  "gove-zone-smoke"
  "receipt-demo"
  "tamper-demo"
)
# Display strings for the JSON report only. Execution happens in run_claim
# below as literal argument arrays, never via `bash -c` re-parsing, so a
# TMPDIR containing whitespace or shell metacharacters cannot change the
# audit argument or inject commands into the verification process. The
# gove-zone-smoke entry shows the $TMP placeholder unexpanded on purpose.
COMMANDS=(
  'uv run --offline python -m pytest tests/docs --import-mode=importlib -q'
  'uv run --offline --package gove-zone gove-zone smoke --audit $TMP/audit.jsonl'
  'uv run --offline --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py'
  'uv run --offline --package gove-zone python examples/tamper_demo/demo.py'
)

# Run one claim by name. --offline enforces the documented no-network
# contract: an incomplete uv environment or dependency cache fails the claim
# loudly instead of silently resolving from package indexes. The receipt demo
# needs --extra crypto (per AGENTS.md) because Ed25519Signer requires the
# optional cryptography dependency.
run_claim() {
  case "$1" in
    root-docs-smoke) uv run --offline python -m pytest tests/docs --import-mode=importlib -q ;;
    gove-zone-smoke) uv run --offline --package gove-zone gove-zone smoke --audit "$TMP/audit.jsonl" ;;
    receipt-demo) uv run --offline --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py ;;
    tamper-demo) uv run --offline --package gove-zone python examples/tamper_demo/demo.py ;;
    *) return 127 ;;
  esac
}

# One record per claim: name \x1f exit_code \x1f command (the unit separator
# never appears in the names/commands above).
RECORDS=()
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  cmd="${COMMANDS[$i]}"
  printf '==> %s: %s\n' "$name" "$cmd" >&2
  run_claim "$name" >&2
  code=$?
  printf '<== %s exit %d\n' "$name" "$code" >&2
  # 126/127 mean the command itself could not be executed (not found / not
  # runnable). That is an internal error, never evidence about the claim.
  if [ "$code" -eq 126 ] || [ "$code" -eq 127 ]; then
    printf 'internal error: %s exited %d (proof command could not run; not claim evidence)\n' "$name" "$code" >&2
    exit 1
  fi
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
