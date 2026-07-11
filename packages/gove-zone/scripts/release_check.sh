#!/usr/bin/env bash
# release_check.sh — gove-zone distribution gate.
# Build sdist+wheel, metadata-check them, assert wheel contents, then install
# the wheel into a THROWAWAY venv (no workspace, no editable path) and run the
# CLI smoke. Exit non-zero on any failure. Run from packages/gove-zone/.
set -euo pipefail

cd "$(dirname "$0")/.."
rm -rf dist
# NOTE: `uv build` alone resolves the uv WORKSPACE root (this package is a
# workspace member of the govern-zone monorepo) and writes dist/ there
# instead of packages/gove-zone/dist/. Pin the output dir explicitly so the
# artifact always lands next to this script, regardless of workspace nesting.
uv build -o dist

uvx twine check dist/*

WHEEL=(dist/gove_zone-*.whl)
[[ -f "${WHEEL[0]}" ]] || { echo "FAIL: no wheel built"; exit 1; }

listing="$(python3 -m zipfile -l "${WHEEL[0]}")"
grep -q "gove_zone/__init__.py" <<<"$listing" || { echo "FAIL: package missing from wheel"; exit 1; }
grep -Eq "dist-info/licenses/LICENSE|dist-info/LICENSE" <<<"$listing" || { echo "FAIL: LICENSE missing from wheel"; exit 1; }
if grep -E "(^| )tests?/" <<<"$listing" | grep -v "dist-info"; then
  echo "FAIL: tests leaked into wheel"; exit 1
fi

SMOKE_DIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DIR"' EXIT
uv venv --python 3.11 "$SMOKE_DIR/venv"
uv pip install --python "$SMOKE_DIR/venv/bin/python" --no-config "${WHEEL[0]}"
"$SMOKE_DIR/venv/bin/gove-zone" smoke --audit "$SMOKE_DIR/audit.jsonl"
"$SMOKE_DIR/venv/bin/python" -c "import gove_zone; print('installed', gove_zone.__version__)"

echo "release_check: OK (${WHEEL[0]##*/})"
