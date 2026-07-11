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
        f"""#!/usr/bin/env bash
set -euo pipefail
printf 'ambient-pnpm-11\\n' >> {shlex.quote(str(ambient_calls))}
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


def _copy_verified_pnpm_cache(destination_home: Path) -> None:
    source = Path.home() / f".cache/node/corepack/v1/pnpm/{EXPECTED_PNPM}"
    target = destination_home / f".cache/node/corepack/v1/pnpm/{EXPECTED_PNPM}"
    assert source.is_dir(), f"reviewed pnpm cache is required for this gate test: {source}"
    target.parent.mkdir(parents=True)
    subprocess.run(
        ["/usr/bin/cp", "-a", "--reflink=auto", f"{source}/.", str(target)],
        check=True,
    )


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
    assert source.splitlines()[0] == "#!/bin/bash -p"
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
    assert "BASH_ENV ENV NODE_OPTIONS" in source
    assert "NODE_COMPILE_CACHE_PORTABLE" in source
    assert "NODE_DISABLE_COMPILE_CACHE=1" in source
    assert "/usr/bin/env -i" in source
    assert 'HOME="$PRIVATE_HOME"' in source
    assert 'TMPDIR="$PRIVATE_TMPDIR"' in source
    assert 'XDG_CACHE_HOME="$PRIVATE_CACHE_HOME"' in source
    assert 'XDG_CONFIG_HOME="$PRIVATE_CONFIG_HOME"' in source
    assert 'XDG_DATA_HOME="$PRIVATE_DATA_HOME"' in source
    assert 'XDG_STATE_HOME="$PRIVATE_STATE_HOME"' in source
    assert 'NPM_CONFIG_USERCONFIG="$PRIVATE_NPM_USERCONFIG"' in source
    assert 'NPM_CONFIG_GLOBALCONFIG="$PRIVATE_NPM_GLOBALCONFIG"' in source
    assert "CI=1" in source
    assert "SHELL=/bin/sh" in source
    assert "LANG=C.UTF-8" in source
    assert "LC_ALL=C.UTF-8" in source
    assert 'PASSTHROUGH_CHILD_ENV+=("ACGI_EVIDENCE_CNAME=${ACGI_EVIDENCE_CNAME}")' in source
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
    command = f"command -v pnpm > {shlex.quote(str(launcher_record))}; pnpm -v"

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
    launcher_parent = Path(env["TMPDIR"])
    assert not (launcher_parent / "node-compile-cache").exists()
    assert list(launcher_parent.iterdir()) == [], "private runtime left caller-TMPDIR residue"


def test_child_uses_private_temp_cache_and_disables_node_compile_cache(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    record = tmp_path / "isolated-child-env.json"
    program = f"""
const fs = require('node:fs');
const moduleApi = require('node:module');
const compileCache = moduleApi.enableCompileCache();
fs.writeFileSync({json.dumps(str(record))}, JSON.stringify({{
  tmpdir: process.env.TMPDIR,
  cacheHome: process.env.XDG_CACHE_HOME,
  disableCompileCache: process.env.NODE_DISABLE_COMPILE_CACHE,
  compileCacheVariable: process.env.NODE_COMPILE_CACHE,
  compileCacheDirectory: compileCache.directory,
}}));
"""

    result = _run_gate(env, caller, "node", "-e", program)

    assert result.returncode == 0, result.stderr
    payload = json.loads(record.read_text())
    private_tmp = Path(payload["tmpdir"])
    private_cache = Path(payload["cacheHome"])
    assert payload["disableCompileCache"] == "1"
    assert "compileCacheVariable" not in payload
    assert "compileCacheDirectory" not in payload
    assert private_tmp.name == "tmp"
    assert private_cache.name == "cache"
    assert private_tmp.parent == private_cache.parent
    assert private_tmp.parent.name.startswith("acgs-node24-gate.")
    assert not private_tmp.parent.exists(), "private runtime must be removed after success"
    launcher_parent = Path(env["TMPDIR"])
    assert not (launcher_parent / "node-compile-cache").exists()
    assert list(launcher_parent.iterdir()) == []


def test_child_environment_is_allowlisted_private_and_preserves_only_valid_cname(
    tmp_path: Path,
):
    env, caller, _, ambient_calls = _gate_env(tmp_path)
    record = tmp_path / "clean-child-env.json"
    env.update(
        {
            "ACGI_EVIDENCE_CNAME": "storybook.acgs.ai",
            "UNRELATED_AMBIENT_SECRET": "must-not-pass",
            "npm_config_script_shell": "/tmp/ambient-lower-shell",
            "NPM_CONFIG_SCRIPT_SHELL": "/tmp/ambient-upper-shell",
            "npm_config_userconfig": "/tmp/ambient-userconfig",
            "NPM_CONFIG_USERCONFIG": "/tmp/ambient-userconfig-upper",
            "npm_config_pnpmfile": "/tmp/ambient-pnpmfile.cjs",
            "NPM_CONFIG_PNPMFILE": "/tmp/ambient-pnpmfile-upper.cjs",
            "PNPM_HOME": "/tmp/ambient-pnpm-home",
            "SHELL": "/tmp/ambient-shell",
            "XDG_CONFIG_HOME": "/tmp/ambient-config",
        }
    )
    program = f"""
const fs = require('node:fs');
const userConfig = process.env.NPM_CONFIG_USERCONFIG;
const globalConfig = process.env.NPM_CONFIG_GLOBALCONFIG;
fs.writeFileSync({json.dumps(str(record))}, JSON.stringify({{
  environment: process.env,
  userConfigContents: fs.readFileSync(userConfig, 'utf8'),
  globalConfigContents: fs.readFileSync(globalConfig, 'utf8'),
  userConfigMode: fs.statSync(userConfig).mode & 0o777,
  globalConfigMode: fs.statSync(globalConfig).mode & 0o777,
}}));
"""

    result = _run_gate(env, caller, "node", "-e", program)

    assert result.returncode == 0, result.stderr
    payload = json.loads(record.read_text())
    child_env = payload["environment"]
    expected_keys = {
        "ACGI_EVIDENCE_CNAME",
        "CI",
        "COREPACK_DEFAULT_TO_LATEST",
        "COREPACK_ENABLE_DOWNLOAD_PROMPT",
        "COREPACK_ENABLE_PROJECT_SPEC",
        "COREPACK_ENABLE_STRICT",
        "COREPACK_ENV_FILE",
        "COREPACK_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "NODE_DISABLE_COMPILE_CACHE",
        "NPM_CONFIG_CACHE",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_USERCONFIG",
        "PATH",
        "PNPM_HOME",
        "SHELL",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "npm_config_cache",
        "npm_config_globalconfig",
        "npm_config_userconfig",
    }
    assert set(child_env) == expected_keys
    assert child_env["ACGI_EVIDENCE_CNAME"] == "storybook.acgs.ai"
    assert child_env["CI"] == "1"
    assert child_env["LANG"] == child_env["LC_ALL"] == "C.UTF-8"
    assert child_env["SHELL"] == "/bin/sh"
    assert child_env["NODE_DISABLE_COMPILE_CACHE"] == "1"
    assert payload["userConfigContents"] == payload["globalConfigContents"] == ""
    assert payload["userConfigMode"] == payload["globalConfigMode"] == 0o600
    private_root = Path(child_env["HOME"]).parent
    assert private_root.name.startswith("acgs-node24-gate.")
    for key in (
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "COREPACK_HOME",
        "NPM_CONFIG_CACHE",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_USERCONFIG",
        "PNPM_HOME",
    ):
        assert Path(child_env[key]).is_relative_to(private_root), key
    assert not private_root.exists(), "clean child runtime must be removed"
    assert not ambient_calls.exists()


def test_invalid_evidence_cname_fails_before_child_or_runtime_creation(tmp_path: Path):
    invalid_values = (
        "",
        "Storybook.acgs.ai",
        "https://storybook.acgs.ai",
        "storybook.acgs.ai.",
        "storybook_acgs.ai",
        "-storybook.acgs.ai",
        f"{'a' * 64}.acgs.ai",
    )
    for index, value in enumerate(invalid_values):
        case = tmp_path / str(index)
        case.mkdir()
        env, caller, _, ambient_calls = _gate_env(case)
        env["ACGI_EVIDENCE_CNAME"] = value

        result = _run_gate(env, caller, "node", "-e", "process.exit(91)")

        assert result.returncode == 1
        assert "must be a lowercase DNS hostname" in result.stderr
        assert not ambient_calls.exists()
        assert not list(Path(env["TMPDIR"]).glob("acgs-node24-gate.*"))


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


def test_ambient_npm_pnpm_and_shell_configs_execute_zero_marker_side_effects(
    tmp_path: Path,
):
    env, caller, _, ambient_calls = _gate_env(tmp_path)
    caller_home = tmp_path / "caller-home"
    _copy_verified_pnpm_cache(caller_home)
    attack_marker = tmp_path / "ambient-config-executed"
    safe_marker = tmp_path / "safe-package-script-executed"
    attack_shell = tmp_path / "attack-script-shell"
    attack_shell.write_text(
        f'#!/bin/sh\nprintf attacked > {shlex.quote(str(attack_marker))}\nexec /bin/sh "$@"\n'
    )
    attack_shell.chmod(0o700)
    attack_pnpmfile = tmp_path / "attack-pnpmfile.cjs"
    attack_pnpmfile.write_text(
        f"require('node:fs').writeFileSync({json.dumps(str(attack_marker))}, 'attacked');\n"
        "module.exports = { hooks: { readPackage(pkg) { return pkg; } } };\n"
    )
    malicious_config = (
        f"script-shell={attack_shell}\n"
        f"pnpmfile={attack_pnpmfile}\n"
        f"global-pnpmfile={attack_pnpmfile}\n"
    )
    (caller_home / ".npmrc").write_text(malicious_config)
    caller_pnpm_config = caller_home / ".config/pnpm/rc"
    caller_pnpm_config.parent.mkdir(parents=True)
    caller_pnpm_config.write_text(malicious_config)
    explicit_userconfig = tmp_path / "attacker-user-npmrc"
    explicit_userconfig.write_text(malicious_config)
    ambient_pnpm_home = tmp_path / "ambient-pnpm-home"
    ambient_pnpm_home.mkdir()
    ambient_pnpm = ambient_pnpm_home / "pnpm"
    ambient_pnpm.write_text(
        f"#!/bin/sh\nprintf attacked > {shlex.quote(str(attack_marker))}\nexit 99\n"
    )
    ambient_pnpm.chmod(0o700)

    package = tmp_path / "probe-package"
    package.mkdir()
    safe_program = f"require('node:fs').writeFileSync({json.dumps(str(safe_marker))}, 'safe')"
    (package / "package.json").write_text(
        json.dumps(
            {
                "name": "clean-env-probe",
                "version": "1.0.0",
                "private": True,
                "scripts": {"probe": f"node -e {shlex.quote(safe_program)}"},
            }
        )
    )
    env.update(
        {
            "HOME": str(caller_home),
            "XDG_CONFIG_HOME": str(caller_home / ".config"),
            "SHELL": str(attack_shell),
            "npm_config_script_shell": str(attack_shell),
            "NPM_CONFIG_SCRIPT_SHELL": str(attack_shell),
            "npm_config_userconfig": str(explicit_userconfig),
            "NPM_CONFIG_USERCONFIG": str(explicit_userconfig),
            "npm_config_pnpmfile": str(attack_pnpmfile),
            "NPM_CONFIG_PNPMFILE": str(attack_pnpmfile),
            "PNPM_HOME": str(ambient_pnpm_home),
        }
    )

    run_result = _run_gate(env, caller, "pnpm", "--dir", str(package), "run", "probe")
    install_result = _run_gate(
        env,
        caller,
        "pnpm",
        "--dir",
        str(package),
        "install",
        "--lockfile=false",
        "--ignore-scripts",
    )

    assert run_result.returncode == 0, run_result.stderr
    assert install_result.returncode == 0, install_result.stderr
    assert safe_marker.read_text() == "safe"
    assert not attack_marker.exists(), "ambient npm/pnpm/shell config executed"
    assert not ambient_calls.exists(), "ambient pnpm 11 executed"
    assert list(Path(env["TMPDIR"]).iterdir()) == []


def test_launcher_is_cleaned_when_nested_command_fails(tmp_path: Path):
    env, caller, launcher_record, ambient_calls = _gate_env(tmp_path)
    command = f"command -v pnpm > {shlex.quote(str(launcher_record))}; exit 47"

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
    child_program = (
        "import os, pathlib, time; time.sleep(0.8); "
        f"pathlib.Path({str(orphan_marker)!r}).write_text('orphan-ran')"
    )
    parent_program = (
        "import os, pathlib, shutil, subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
        f"pathlib.Path({str(launcher_record)!r}).write_text(shutil.which('pnpm')); "
        "time.sleep(10)"
    )
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
    launcher_parent = Path(env["TMPDIR"])
    assert not (launcher_parent / "node-compile-cache").exists()
    assert list(launcher_parent.iterdir()) == [], "signal cleanup left caller-TMPDIR residue"


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


def test_direct_exec_rejects_shell_startup_env_without_running_it(tmp_path: Path):
    for variable in ("BASH_ENV", "ENV"):
        case = tmp_path / variable.lower()
        case.mkdir()
        env, caller, _, _ = _gate_env(case)
        marker = case / "startup-env-executed"
        startup_env = case / "startup-env-attack.sh"
        startup_env.write_text(f"printf ran > {shlex.quote(str(marker))}\n")
        env[variable] = str(startup_env)

        result = _run_gate(env, caller, "pnpm", "-v")

        assert result.returncode == 1
        assert f"{variable} must stay unset" in result.stderr
        assert not marker.exists(), f"{variable} ran before the wrapper's first line"


def test_direct_exec_uses_absolute_privileged_bash_not_path_fake(tmp_path: Path):
    env, caller, _, _ = _gate_env(tmp_path)
    attack_bin = tmp_path / "fake-bash-bin"
    attack_bin.mkdir()
    marker = tmp_path / "fake-bash-executed"
    fake_bash = attack_bin / "bash"
    fake_bash.write_text(f"#!/bin/sh\nprintf ran > {shlex.quote(str(marker))}\nexit 99\n")
    fake_bash.chmod(0o500)
    env["PATH"] = f"{attack_bin}:{env['PATH']}"

    result = _run_gate(env, caller, "pnpm", "-v")

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == EXPECTED_PNPM
    assert not marker.exists(), "PATH fake bash interpreted the wrapper"


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
    assert "./scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all" in makefile
    assert "bash scripts/run_acgi_node24_gate.sh" not in makefile
