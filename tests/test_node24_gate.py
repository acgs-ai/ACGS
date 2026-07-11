"""Tests for the local acgi-ai exact-toolchain verification wrapper."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_NODE = "24.18.0"
EXPECTED_PNPM = "9.15.4"
EXPECTED_SELECTOR = (
    "pnpm@9.15.4+sha512."
    "b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb"
    "40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0"
)


def test_node24_gate_script_is_executable_and_fail_closed():
    script = ROOT / "scripts" / "run_acgi_node24_gate.sh"
    source = script.read_text()

    assert script.is_file()
    assert os.access(script, os.X_OK)
    assert "set -euo pipefail" in source
    assert 'REQUIRED_NODE_VERSION="24.18.0"' in source
    assert 'REQUIRED_COREPACK_VERSION="0.35.0"' in source
    assert "fnm exec --using" in source
    assert "process.versions.node" in source
    assert 'EXPECTED_PNPM="${ROOT_PNPM_SELECTOR#pnpm@}"' in source
    assert 'EXPECTED_PNPM="${EXPECTED_PNPM%%+sha512.*}"' in source
    assert "pnpm -F acgi-ai run test:all" in source
    assert 'cd "$ROOT_DIR"' in source
    assert "corepack pnpm -v" in source
    assert "COREPACK_INTEGRITY_KEYS must stay unset" in source
    assert source.index('cd "$ROOT_DIR"') < source.index('PNPM_VERSION="')


def test_packagemanager_selector_is_integrity_qualified_and_version_is_derivable():
    root_package = json.loads((ROOT / "package.json").read_text())
    app_package = json.loads((ROOT / "acgi-ai/package.json").read_text())
    selector = root_package["packageManager"]

    assert selector == app_package["packageManager"] == EXPECTED_SELECTOR
    package_and_version, integrity = selector.split("+sha512.", 1)
    assert package_and_version.removeprefix("pnpm@") == EXPECTED_PNPM
    assert len(integrity) == 128
    int(integrity, 16)


def test_node24_gate_uses_repo_root_from_arbitrary_caller_cwd(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_fnm = fake_bin / "fnm"
    fake_fnm.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == exec && "$2" == --using && "$3" == 24.18.0 && "$4" == -- ]]
[[ "$PWD" == "$EXPECTED_REPO_ROOT" ]] || {
  echo "wrong wrapper cwd: $PWD" >&2
  exit 91
}
shift 4
if [[ "$1" == node && "$2" == -p ]]; then
  printf '%s\\n' 24.18.0
elif [[ "$1" == corepack && "$2" == --version ]]; then
  printf '%s\\n' 0.35.0
elif [[ "$1" == corepack && "$2" == pnpm && "$3" == -v ]]; then
  printf '%s\\n' 9.15.4
else
  exec "$@"
fi
"""
    )
    fake_fnm.chmod(0o755)

    caller = tmp_path / "arbitrary-caller"
    caller.mkdir()
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["EXPECTED_REPO_ROOT"] = str(ROOT)
    env.pop("COREPACK_INTEGRITY_KEYS", None)
    result = subprocess.run(
        [
            str(ROOT / "scripts/run_acgi_node24_gate.sh"),
            "python3",
            "-c",
            "import os; print(os.getcwd())",
        ],
        cwd=caller,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == str(ROOT)
    assert "node=v24.18.0, corepack=0.35.0, pnpm=9.15.4" in result.stdout


def test_makefile_exposes_node24_verification_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "verify-js-node24:" in makefile
    assert "bash scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all" in makefile
