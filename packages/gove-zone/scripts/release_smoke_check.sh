#!/usr/bin/env bash
# release_smoke_check.sh — clean-venv wheel smoke gate for gove-zone (G1.1).
#
# Mechanizes the release-readiness verify step: build the wheel, install it
# ALONE into a throwaway virtualenv (no --editable, no extras, no source tree
# on sys.path), and prove the console entry point runs the allow/deny/audit
# smoke to a passing verdict. Because gove-zone declares `dependencies = []`,
# a wheel-only install with zero extras is the strongest available proof that
# the published artifact is self-contained and importable on a bare
# interpreter — if the package ever grows an accidental runtime import of an
# optional extra (pydantic / cryptography / mcp / pyyaml), this gate fails.
#
# Idempotent and self-cleaning: the temp venv is removed on every exit path.
# Run locally (`bash packages/gove-zone/scripts/release_smoke_check.sh`) or in
# CI (the `wheel-smoke` job in .github/workflows/python-gove-zone.yml).
set -euo pipefail

# --- locate the workspace root (two levels up: scripts/ -> gove-zone/ -> packages/ -> root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${REPO_ROOT}"

PY_VERSION="${GOVE_ZONE_SMOKE_PYTHON:-3.12}"
VENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gz-relcheck.XXXXXX")"

cleanup() {
  rm -rf "${VENV_DIR}"
}
trap cleanup EXIT

echo ">>> [1/4] Building gove-zone wheel from workspace root (${REPO_ROOT})"
# uv ships its own interpreter toolchain; no system python required.
uv python install "${PY_VERSION}"
uv build --package gove-zone

# --- pick the newest wheel (sorted by mtime, newest last)
WHEEL="$(ls -t dist/gove_zone-*.whl 2>/dev/null | head -n1 || true)"
if [[ -z "${WHEEL}" ]]; then
  echo "!!! No gove_zone-*.whl found in dist/ after build" >&2
  exit 1
fi
echo ">>> [2/4] Selected wheel: ${WHEEL}"

echo ">>> [3/4] Installing wheel ONLY into a clean venv (no extras, no --editable)"
uv venv "${VENV_DIR}" --python "${PY_VERSION}"
# Wheel-only install — proves the zero-dependency clean install. Deliberately
# no '[dev]'/'[schema]'/etc. extras and no editable source tree.
uv pip install --python "${VENV_DIR}/bin/python" --no-config "${WHEEL}"

echo ">>> [4/4] Running 'gove-zone smoke' from the clean venv"
# Disable errexit around the smoke call so a non-zero exit is reported by this
# gate (with the captured output) instead of aborting silently mid-substitution.
set +e
SMOKE_OUT="$("${VENV_DIR}/bin/gove-zone" smoke)"
SMOKE_RC=$?
set -e
echo "${SMOKE_OUT}"

if [[ ${SMOKE_RC} -ne 0 ]]; then
  echo "!!! gove-zone smoke exited non-zero (${SMOKE_RC})" >&2
  exit 1
fi
# _emit() prints a single json.dumps(..., sort_keys=True) line, so the status
# field renders as `"status": "pass"` — assert it explicitly rather than
# trusting the exit code alone.
if ! grep -q '"status": "pass"' <<<"${SMOKE_OUT}"; then
  echo "!!! gove-zone smoke did not report status=pass" >&2
  exit 1
fi

echo ">>> PASS — clean-venv wheel smoke succeeded (${WHEEL})"
