#!/usr/bin/env bash
# Clean-room proof for criterion G2.2: an ACGS proof pack verifies WITHOUT
# gove-zone installed.
#
# Builds the acgs-proofpack-verifier wheel, installs ONLY that wheel into a
# throwaway virtualenv (no gove-zone, no network at install time beyond the
# wheel), then asserts:
#   1. `import gove_zone` FAILS in that environment (proving isolation);
#   2. `acgs-verify proofpack verify <golden>` exits 0 (offline verify works);
#   3. a signed pack presented without a verifier key exits 1 (fail-closed).
#
# This is the load-bearing local/CI proof of the criterion.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_DIR/../.." && pwd)"
VENV="$(mktemp -d)/apv-clean"
GOLDEN="$PKG_DIR/tests/fixtures/golden"
SIGNED="$PKG_DIR/tests/fixtures/signed-no-verifier"

cleanup() { rm -rf "$(dirname "$VENV")"; }
trap cleanup EXIT

echo "== [1/5] building acgs-proofpack-verifier wheel =="
uv build --package acgs-proofpack-verifier --wheel --out-dir "$REPO_ROOT/dist"

WHEEL="$(ls -t "$REPO_ROOT"/dist/acgs_proofpack_verifier-*.whl | head -n1)"
if [ -z "${WHEEL:-}" ] || [ ! -f "$WHEEL" ]; then
  echo "FAIL: no acgs_proofpack_verifier wheel produced" >&2
  exit 1
fi
echo "   wheel: $WHEEL"

echo "== [2/5] creating clean virtualenv (python 3.12) =="
uv venv "$VENV" --python 3.12
PY="$VENV/bin/python"

echo "== [3/5] installing ONLY the wheel (no gove-zone, no extras) =="
uv pip install --python "$PY" "$WHEEL"

echo "== [4/5] asserting the environment is gove-zone-free =="
if "$PY" -c "import gove_zone" 2>/dev/null; then
  echo "FAIL: gove_zone is importable in the clean-room — isolation broken" >&2
  exit 1
fi
echo "   OK: import gove_zone fails (as required)"
# And our package IS importable with zero third-party deps installed.
"$PY" -c "import acgs_proofpack_verifier; print('   OK: acgs_proofpack_verifier importable')"

echo "== [5/5] verifying proof packs via the installed console script =="
ACGS_VERIFY="$VENV/bin/acgs-verify"

echo "   -> golden pack must verify (exit 0)"
"$ACGS_VERIFY" proofpack verify "$GOLDEN" --now-iso "2026-01-01T00:00:00+00:00" >/dev/null
echo "   OK: golden pack verified, exit 0"

echo "   -> signed pack without a verifier key must fail closed (exit 1)"
set +e
"$ACGS_VERIFY" proofpack verify "$SIGNED" --now-iso "2026-01-01T00:00:00+00:00" >/dev/null
rc=$?
set -e
if [ "$rc" -ne 1 ]; then
  echo "FAIL: signed-pack-without-key returned exit $rc, expected 1 (fail-closed)" >&2
  exit 1
fi
echo "   OK: signed pack without key refused, exit 1"

echo "== CLEAN-ROOM PASS: proof pack verifies without gove-zone installed =="
