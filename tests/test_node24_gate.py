"""Tests for the local acgi-ai exact-toolchain verification wrapper."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/run_acgi_node24_gate.sh"
EXPECTED_NODE = "24.18.0"
EXPECTED_PNPM = "9.15.4"
EXPECTED_NODE_SHA256 = "41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c"
EXPECTED_COREPACK_SHA256 = "3655bc798f300951f2070fee411b337d626b0c3ae80c2d24c46ccac4595d4bf9"
EXPECTED_PNPM_DISPATCHER_SHA256 = "7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"
EXPECTED_SELECTOR = (
    "pnpm@9.15.4+sha512."
    "b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb"
    "40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0"
)


def _gate_env(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path]:
    """Prepend a hostile pnpm 11 while leaving the reviewed fnm runtime available."""

    fake_bin = tmp_path / "ambient-bin"
    fake_bin.mkdir()
    ambient_calls = tmp_path / "ambient-pnpm-calls"
    ambient_pnpm = fake_bin / "pnpm"
    ambient_pnpm.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf 'ambient-pnpm-11\\n' >> "$AMBIENT_CALLS"
printf '%s\\n' 11.1.2
"""
    )
    ambient_pnpm.chmod(0o500)

    launcher_parent = tmp_path / "launcher-parent"
    launcher_parent.mkdir(mode=0o700)
    caller = tmp_path / "arbitrary-caller"
    caller.mkdir()
    launcher_record = tmp_path / "launcher-record"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "AMBIENT_CALLS": str(ambient_calls),
            "LAUNCHER_RECORD": str(launcher_record),
            "TMPDIR": str(launcher_parent),
        }
    )
    env.pop("COREPACK_INTEGRITY_KEYS", None)
    env.pop("COREPACK_ROOT", None)
    return env, caller, launcher_record, ambient_calls


def _run_gate(
    env: dict[str, str], caller: Path, *args: str, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), *args],
        cwd=caller,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _recorded_launcher(launcher_record: Path) -> Path:
    return Path(launcher_record.read_text().strip())


def test_node24_gate_script_is_executable_and_fail_closed():
    source = SCRIPT.read_text()

    assert SCRIPT.is_file()
    assert os.access(SCRIPT, os.X_OK)
    assert "set -euo pipefail" in source
    assert 'REQUIRED_NODE_VERSION="24.18.0"' in source
    assert 'REQUIRED_COREPACK_VERSION="0.35.0"' in source
    assert f'REQUIRED_NODE_SHA256="{EXPECTED_NODE_SHA256}"' in source
    assert f'REQUIRED_COREPACK_SHA256="{EXPECTED_COREPACK_SHA256}"' in source
    assert f'REQUIRED_PNPM_DISPATCHER_SHA256="{EXPECTED_PNPM_DISPATCHER_SHA256}"' in source
    assert "process.execPath" in source
    assert 'EXPECTED_PNPM="${ROOT_PNPM_SELECTOR#pnpm@}"' in source
    assert 'EXPECTED_PNPM="${EXPECTED_PNPM%%+sha512.*}"' in source
    assert 'run_corepack enable --install-directory "$LAUNCHER_DIR" pnpm' in source
    assert 'CONTROLLED_PATH="${LAUNCHER_DIR}:${NODE_BIN_DIR}:/usr/bin:/bin"' in source
    assert "COREPACK_INTEGRITY_KEYS must stay unset" in source
    assert "env -u COREPACK_ROOT" in source
    assert "validate_pnpm_launcher" in source
    assert "trap cleanup_launcher EXIT" in source


def test_packagemanager_selector_is_integrity_qualified_and_version_is_derivable():
    root_package = json.loads((ROOT / "package.json").read_text())
    app_package = json.loads((ROOT / "acgi-ai/package.json").read_text())
    selector = root_package["packageManager"]

    assert selector == app_package["packageManager"] == EXPECTED_SELECTOR
    package_and_version, integrity = selector.split("+sha512.", 1)
    assert package_and_version.removeprefix("pnpm@") == EXPECTED_PNPM
    assert len(integrity) == 128
    int(integrity, 16)


def test_real_nested_pnpm_uses_private_pinned_corepack_not_host_ambient(
    tmp_path: Path,
):
    env, caller, launcher_record, ambient_calls = _gate_env(tmp_path)
    command = 'command -v pnpm > "$LAUNCHER_RECORD"; pnpm -v'

    result = _run_gate(
        env,
        caller,
        "pnpm",
        "-F",
        "acgi-ai",
        "exec",
        "bash",
        "-c",
        command,
    )

    assert result.returncode == 0, result.stderr
    assert "node=v24.18.0, corepack=0.35.0, pnpm=9.15.4" in result.stdout
    assert result.stdout.splitlines()[-1] == EXPECTED_PNPM
    assert not ambient_calls.exists(), "ambient pnpm 11 must never execute"
    launcher = _recorded_launcher(launcher_record)
    assert not launcher.exists()
    assert not launcher.parent.exists(), "ephemeral launcher directory must be removed"


def test_node24_gate_preserves_exact_argv_from_arbitrary_caller_cwd(tmp_path: Path):
    env, caller, _, ambient_calls = _gate_env(tmp_path)
    expected = ["space arg", "*", ";", "", "--literal"]
    program = "import json, os, sys; print(os.getcwd()); print(json.dumps(sys.argv[1:]))"

    result = _run_gate(env, caller, "python3", "-c", program, *expected)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2] == str(ROOT)
    assert json.loads(result.stdout.splitlines()[-1]) == expected
    assert not ambient_calls.exists()


def test_launcher_is_cleaned_when_nested_command_fails(tmp_path: Path):
    env, caller, launcher_record, ambient_calls = _gate_env(tmp_path)
    command = 'command -v pnpm > "$LAUNCHER_RECORD"; exit 47'

    result = _run_gate(
        env,
        caller,
        "pnpm",
        "-F",
        "acgi-ai",
        "exec",
        "bash",
        "-c",
        command,
    )

    assert result.returncode != 0
    assert "Command failed with exit code 47" in result.stdout
    assert not ambient_calls.exists()
    launcher = _recorded_launcher(launcher_record)
    assert not launcher.exists()
    assert not launcher.parent.exists()


def test_launcher_is_cleaned_when_wrapper_receives_term(tmp_path: Path):
    env, caller, launcher_record, _ = _gate_env(tmp_path)
    program = (
        "import os, pathlib, shutil, signal, time; "
        "pathlib.Path(os.environ['LAUNCHER_RECORD']).write_text(shutil.which('pnpm')); "
        "os.kill(os.getppid(), signal.SIGTERM); time.sleep(0.2)"
    )

    result = _run_gate(env, caller, "python3", "-c", program)

    assert result.returncode != 0
    launcher = _recorded_launcher(launcher_record)
    assert not launcher.exists()
    assert not launcher.parent.exists()


def test_corepack_integrity_bypass_is_rejected_before_launcher_creation(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    env["COREPACK_INTEGRITY_KEYS"] = "0"

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "integrity bypasses are forbidden" in result.stderr
    assert not list((tmp_path / "launcher-parent").glob("acgs-node24-gate.*"))


def test_makefile_exposes_node24_verification_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "verify-js-node24:" in makefile
    assert "bash scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all" in makefile
