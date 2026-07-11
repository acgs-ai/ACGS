"""Tests for the local acgi-ai exact-toolchain verification wrapper."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/run_acgi_node24_gate.sh"
EXPECTED_NODE = "24.18.0"
EXPECTED_PNPM = "9.15.4"
EXPECTED_FNM_SHA256 = "2b8810b610654de6914a17e3235d3948fbd5c7d4712815ac45724c3f06e8966f"
EXPECTED_NODE_SHA256 = "41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c"
EXPECTED_COREPACK_SHA256 = "3655bc798f300951f2070fee411b337d626b0c3ae80c2d24c46ccac4595d4bf9"
EXPECTED_PNPM_DISPATCHER_SHA256 = "7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"
EXPECTED_COREPACK_TREE_SHA256 = "6dc22292849f9e176da87530b3c6e7e871b6d153853905472323a30c68e3ef83"
EXPECTED_PNPM_TREE_SHA256 = "f5024c43f73511fd4405a2af8e5284037c7ce9d740ccbc21b48c82a4372a5e1b"
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


def _canonical_runtime() -> tuple[Path, Path, Path]:
    fnm = Path(shutil.which("fnm", path=os.environ["PATH"]) or "").resolve(strict=True)
    prefix = fnm.parent / f"node-versions/v{EXPECTED_NODE}/installation"
    return fnm, prefix / "bin/node", prefix / "lib/node_modules/corepack"


def _copy_runtime_with_tampered_corepack(
    tmp_path: Path, env: dict[str, str], marker: Path
) -> dict[str, str]:
    source_fnm, source_node, source_corepack = _canonical_runtime()
    fake_root = tmp_path / "tampered-fnm-root"
    fake_fnm = fake_root / "fnm"
    fake_node = fake_root / f"node-versions/v{EXPECTED_NODE}/installation/bin/node"
    fake_corepack = (
        fake_root / f"node-versions/v{EXPECTED_NODE}/installation/lib/node_modules/corepack"
    )
    fake_fnm.parent.mkdir(parents=True)
    shutil.copy2(source_fnm, fake_fnm)
    fake_node.parent.mkdir(parents=True)
    subprocess.run(
        ["/usr/bin/cp", "--reflink=auto", "--preserve=mode,timestamps", source_node, fake_node],
        check=True,
    )
    shutil.copytree(source_corepack, fake_corepack, symlinks=True)
    (fake_node.parent / "corepack").symlink_to("../lib/node_modules/corepack/dist/corepack.js")
    library = fake_corepack / "dist/lib/corepack.cjs"
    library.write_text(
        f"require('fs').writeFileSync({json.dumps(str(marker))}, 'executed');\n"
        + library.read_text()
    )
    copied = env.copy()
    copied["PATH"] = f"{fake_root}:{env['PATH']}"
    return copied


def test_node24_gate_script_is_executable_and_fail_closed():
    source = SCRIPT.read_text()

    assert SCRIPT.is_file()
    assert os.access(SCRIPT, os.X_OK)
    assert SCRIPT.stat().st_mode & 0o777 == 0o755
    assert "set -euo pipefail" in source
    assert 'REQUIRED_NODE_VERSION="24.18.0"' in source
    assert 'REQUIRED_COREPACK_VERSION="0.35.0"' in source
    assert f'REQUIRED_FNM_SHA256="{EXPECTED_FNM_SHA256}"' in source
    assert f'REQUIRED_NODE_SHA256="{EXPECTED_NODE_SHA256}"' in source
    assert f'REQUIRED_COREPACK_SHA256="{EXPECTED_COREPACK_SHA256}"' in source
    assert f'REQUIRED_PNPM_DISPATCHER_SHA256="{EXPECTED_PNPM_DISPATCHER_SHA256}"' in source
    assert f'REQUIRED_COREPACK_TREE_SHA256="{EXPECTED_COREPACK_TREE_SHA256}"' in source
    assert f'REQUIRED_PNPM_TREE_SHA256="{EXPECTED_PNPM_TREE_SHA256}"' in source
    assert "process.versions.node" in source
    assert 'EXPECTED_PNPM="${ROOT_PNPM_SELECTOR#pnpm@}"' in source
    assert 'EXPECTED_PNPM="${EXPECTED_PNPM%%+sha512.*}"' in source
    assert 'run_corepack enable --install-directory "$LAUNCHER_DIR" pnpm' in source
    assert 'CONTROLLED_PATH="${LAUNCHER_DIR}:${NODE_BIN_DIR}:/usr/bin:/bin"' in source
    assert "COREPACK_INTEGRITY_KEYS must stay unset" in source
    assert "NODE_COMPILE_CACHE_PORTABLE" in source
    assert "/usr/bin/python3 -I -" in source
    assert 'run_corepack prepare "pnpm@${EXPECTED_PNPM}" --activate' in source
    assert "validate_runtime" in source
    assert "trap cleanup_runtime EXIT" in source
    assert '/usr/bin/setsid --wait "${FINAL_COMMAND[@]}"' in source
    assert '/bin/kill -s "$signal" -- "-$CHILD_PID"' in source


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


def test_absolute_pnpm_argv0_is_mapped_to_private_launcher(tmp_path: Path):
    env, caller, _, ambient_calls = _gate_env(tmp_path)
    ambient_pnpm = Path(env["PATH"].split(":", 1)[0]) / "pnpm"

    result = _run_gate(env, caller, str(ambient_pnpm), "-v")

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == EXPECTED_PNPM
    assert not ambient_calls.exists(), "absolute ambient pnpm must be replaced by the pin"


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


def test_term_kills_entire_child_group_and_cleans_launcher(tmp_path: Path):
    env, caller, launcher_record, _ = _gate_env(tmp_path)
    orphan_marker = tmp_path / "orphan-side-effect"
    env["ORPHAN_MARKER"] = str(orphan_marker)
    child_program = (
        "import os, pathlib, time; time.sleep(0.8); "
        "pathlib.Path(os.environ['ORPHAN_MARKER']).write_text('orphan-ran')"
    )
    parent_program = (
        "import os, pathlib, shutil, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', os.environ['CHILD_PROGRAM']]); "
        "pathlib.Path(os.environ['LAUNCHER_RECORD']).write_text(shutil.which('pnpm')); "
        "time.sleep(10)"
    )
    env["CHILD_PROGRAM"] = child_program
    process = subprocess.Popen(
        [str(SCRIPT), "python3", "-c", parent_program],
        cwd=caller,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(100):
        if launcher_record.exists():
            break
        time.sleep(0.05)
    assert launcher_record.exists(), "child never reached the signal-ready state"
    process.terminate()
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode != 0, (stdout, stderr)
    launcher = _recorded_launcher(launcher_record)
    assert not launcher.exists()
    assert not launcher.parent.exists()
    time.sleep(1.0)
    assert not orphan_marker.exists(), "grandchild survived the wrapper's TERM forwarding"


def test_tampered_corepack_library_fails_before_corepack_execution(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    marker = tmp_path / "tampered-corepack-executed"
    env = _copy_runtime_with_tampered_corepack(tmp_path, env, marker)

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "source Corepack tree digest is not reviewed" in result.stderr
    assert not marker.exists()


def test_tampered_persistent_pnpm_payload_fails_before_execution(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    source = Path.home() / f".cache/node/corepack/v1/pnpm/{EXPECTED_PNPM}"
    fake_home = tmp_path / "tampered-home"
    target = fake_home / f".cache/node/corepack/v1/pnpm/{EXPECTED_PNPM}"
    shutil.copytree(source, target, symlinks=True)
    marker = tmp_path / "tampered-pnpm-executed"
    wrapper = target / "bin/pnpm.cjs"
    lines = wrapper.read_text().splitlines(keepends=True)
    lines.insert(
        1,
        f"require('fs').writeFileSync({json.dumps(str(marker))}, 'executed');\n",
    )
    wrapper.write_text("".join(lines))
    env["HOME"] = str(fake_home)

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "source pnpm tree digest is not reviewed" in result.stderr
    assert not marker.exists()


def test_node_options_preload_is_rejected_before_node_execution(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    preload_marker = tmp_path / "node-preload-executed"
    preload = tmp_path / "preload.cjs"
    preload.write_text(f"require('fs').writeFileSync({json.dumps(str(preload_marker))}, 'ran');\n")
    env["NODE_OPTIONS"] = f"--require={preload}"

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "NODE_OPTIONS must stay unset" in result.stderr
    assert not preload_marker.exists()


def test_fake_fnm_fails_digest_before_it_can_execute(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    attack_bin = tmp_path / "attack-bin"
    attack_bin.mkdir()
    fake_fnm_marker = tmp_path / "fake-fnm-executed"
    fake_fnm = attack_bin / "fnm"
    fake_fnm.write_text(f"#!/usr/bin/env bash\nprintf ran > {shlex.quote(str(fake_fnm_marker))}\n")
    fake_fnm.chmod(0o500)
    env["PATH"] = f"{attack_bin}:{env['PATH']}"

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "fnm digest is not the reviewed digest" in result.stderr
    assert not fake_fnm_marker.exists()


def test_node_compile_cache_injection_controls_are_rejected(tmp_path: Path):
    for variable in ("NODE_COMPILE_CACHE", "NODE_COMPILE_CACHE_PORTABLE"):
        case = tmp_path / variable.lower()
        case.mkdir()
        env, caller, _, _ = _gate_env(case)
        env[variable] = str(case / "injected-cache")

        result = _run_gate(env, caller, "pnpm", "-v")

        assert result.returncode == 1
        assert f"{variable} must stay unset" in result.stderr


def test_unsafe_tmpdir_is_rejected(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    unsafe = tmp_path / "unsafe-tmp"
    unsafe.mkdir(mode=0o755)
    env["TMPDIR"] = str(unsafe)

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 1
    assert "TMPDIR must be caller-owned mode 0700" in result.stderr

    env["TMPDIR"] = "relative-tmp"
    result = _run_gate(env, caller, "pnpm", "-v")
    assert result.returncode == 1
    assert "TMPDIR must be an absolute" in result.stderr


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
