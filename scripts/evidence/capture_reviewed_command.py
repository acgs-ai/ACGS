#!/usr/bin/env python3
"""Execute one exact reviewed command inside a closed local-proof environment.

This defends against ambient configuration and ordinary replacement races. Same-user
or root mutation of the running kernel/process remains outside this local proof's
trust boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from _common import (
    BWRAP_EXECUTABLE,
    LEGACY_MEMBRANE_ENVIRONMENT_PROFILE,
    REVIEWED_ENVIRONMENT_PROFILE,
    REVIEWED_HOST_EXECUTABLE_SHA256,
    REVIEWED_UI_ENVIRONMENT_PROFILE,
    REVIEWED_UI_SANDBOX_WRITABLE_PATHS,
    REVIEWED_UI_TOOLCHAIN,
    EvidenceError,
    append_safe_transcript_record,
    assert_evidence_runtime,
    canonical_node_evidence_path,
    fail,
    git_root,
    resolved_executable_identity,
    reviewed_cwd,
    reviewed_environment_profile_sha256,
    reviewed_executable,
    reviewed_node_command,
    reviewed_sandbox_profile_sha256,
    utc_now,
)

FNM_EXECUTABLE = Path("/home/martin/.local/share/fnm/fnm")
UI_TOOL_HASHES = cast(dict[str, str], REVIEWED_UI_TOOLCHAIN["sha256"])
UI_TREE_HASHES = cast(dict[str, str], REVIEWED_UI_TOOLCHAIN["tree_sha256"])


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            kind, payload = b"L", str(path.readlink()).encode()
        elif path.is_file():
            kind = b"F"
            payload = hashlib.sha256(path.read_bytes()).hexdigest().encode()
        elif path.is_dir():
            kind, payload = b"D", b""
        else:
            fail(f"unsupported UI tool tree entry: {path}", phase="B6")
        digest.update(relative + b"\0" + kind + b"\0" + payload + b"\0")
    return digest.hexdigest()


def _require_safe_parent_chain(path: Path, *, trusted_stop: Path | None = None) -> None:
    current = path.parent
    while True:
        mode = current.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail(f"executable parent chain is group/world writable: {current}", phase="B6")
        if trusted_stop is not None and current == trusted_stop:
            return
        if current.parent == current:
            return
        current = current.parent


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _ui_toolchain_digest(repo: Path, trusted_root: Path) -> str:
    node_root = trusted_root / "scratch/fnm/node-versions/v24.18.0/installation"
    pnpm_root = trusted_root / "scratch/corepack/v1/pnpm/9.15.4"
    paths = {
        "node": node_root / "bin/node",
        "corepack_js": node_root / "lib/node_modules/corepack/dist/corepack.js",
        "corepack_package": node_root / "lib/node_modules/corepack/package.json",
        "corepack_library": node_root / "lib/node_modules/corepack/dist/lib/corepack.cjs",
        "pnpm_payload": pnpm_root / "dist/pnpm.cjs",
        "pnpm_wrapper": pnpm_root / "bin/pnpm.cjs",
        "pnpm_package": pnpm_root / "package.json",
        "pnpm_corepack_metadata": pnpm_root / ".corepack",
    }
    identities: dict[str, dict[str, str]] = {}
    for name, path in paths.items():
        canonical = path.resolve(strict=True)
        digest = hashlib.sha256(canonical.read_bytes()).hexdigest()
        if not canonical.is_relative_to(trusted_root / "scratch") or digest != UI_TOOL_HASHES[name]:
            fail(f"UI tool identity mismatch: {name}", phase="B6")
        identities[name] = {"realpath": str(canonical), "sha256": digest}
    for name, root in {
        "corepack": node_root / "lib/node_modules/corepack",
        "pnpm": pnpm_root,
        "chromium-1223": trusted_root / "scratch/playwright/chromium-1223",
        "chromium_headless_shell-1223": (
            trusted_root / "scratch/playwright/chromium_headless_shell-1223"
        ),
        "ffmpeg-1011": trusted_root / "scratch/playwright/ffmpeg-1011",
        "node_modules": repo / "acgi-ai/node_modules",
    }.items():
        digest = _tree_digest(root)
        if name != "node_modules" and digest != UI_TREE_HASHES[name]:
            fail(f"UI tool tree identity mismatch: {name}", phase="B6")
        identities[f"{name}_tree"] = {"realpath": str(root), "sha256": digest}
    for name in ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        path = repo / "acgi-ai" / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identities[name] = {"realpath": str(path.resolve(strict=True)), "sha256": digest}
    root_package = repo / "package.json"
    identities["root-package.json"] = {
        "realpath": str(root_package.resolve(strict=True)),
        "sha256": hashlib.sha256(root_package.read_bytes()).hexdigest(),
    }
    selector = cast(str, REVIEWED_UI_TOOLCHAIN["pnpm_corepack_selector"])
    for package in (root_package, repo / "acgi-ai/package.json"):
        parsed = json.loads(package.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or parsed.get("packageManager") != selector:
            fail("UI packageManager differs from reviewed pnpm selector", phase="B6")
    if (
        identities["pnpm-workspace.yaml"]["sha256"]
        != "50c15b3f4420b77d890a9bd93844462418daa2df5842ffeaa77d7eeab36b8da6"
    ):
        fail("UI workspace lifecycle policy differs from reviewed policy", phase="B6")
    fnm_digest = hashlib.sha256(FNM_EXECUTABLE.read_bytes()).hexdigest()
    if fnm_digest != UI_TOOL_HASHES["fnm"]:
        fail("UI fnm identity mismatch", phase="B6")
    identities["fnm"] = {"realpath": str(FNM_EXECUTABLE), "sha256": fnm_digest}
    return hashlib.sha256(
        json.dumps(identities, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _closed_environment(
    repo: Path,
    cwd: Path,
    temp_root: Path,
    *,
    argv0: str | None = None,
    trusted_root: Path | None = None,
    node_id: str | None = None,
) -> tuple[dict[str, str], Path]:
    if not temp_root.is_absolute() or temp_root.is_symlink() or temp_root.resolve() != temp_root:
        fail("temp root must be an absolute canonical non-symlink directory", phase="B6")
    if not temp_root.is_dir() or temp_root.is_relative_to(repo):
        fail("temp root must exist outside the product repository", phase="B6")
    temp_metadata = temp_root.stat()
    if temp_metadata.st_uid != os.getuid() or temp_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("temp root must be caller-owned and not group/world writable", phase="B6")
    isolated = Path(tempfile.mkdtemp(prefix="acgs-reviewed-command.", dir=temp_root))
    for name in (
        "home",
        "tmp",
        "xdg-cache",
        "xdg-config",
        "xdg-data",
        "xdg-state",
        "ruff",
        "mypy",
        "pytest-tmp",
        "pytest-cache",
        "coverage",
        "npm-cache",
    ):
        (isolated / name).mkdir(mode=0o700)
    tool_roots = [cwd / ".venv/bin", repo / ".venv-evidence/bin", Path("/usr/bin"), Path("/bin")]
    env = {
        "PATH": ":".join(str(path) for path in tool_roots),
        "HOME": str(isolated / "home"),
        "TMPDIR": str(isolated / "tmp"),
        "TMP": str(isolated / "tmp"),
        "TEMP": str(isolated / "tmp"),
        "XDG_CACHE_HOME": str(isolated / "xdg-cache"),
        "XDG_CONFIG_HOME": str(isolated / "xdg-config"),
        "XDG_DATA_HOME": str(isolated / "xdg-data"),
        "XDG_STATE_HOME": str(isolated / "xdg-state"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "UV_OFFLINE": "1",
        "UV_NO_INDEX": "1",
        "UV_NO_CACHE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "RUFF_CACHE_DIR": str(isolated / "ruff"),
        "MYPY_CACHE_DIR": str(isolated / "mypy"),
        "PYTEST_DEBUG_TEMPROOT": str(isolated / "pytest-tmp"),
        "PYTEST_ADDOPTS": f"-o cache_dir={isolated / 'pytest-cache'}",
        "COVERAGE_FILE": str(isolated / "coverage/.coverage"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    profile = (
        LEGACY_MEMBRANE_ENVIRONMENT_PROFILE
        if node_id == "P0-MEMBRANE-001"
        else REVIEWED_UI_ENVIRONMENT_PROFILE
        if argv0 == "fnm"
        else REVIEWED_ENVIRONMENT_PROFILE
    )
    profile_environment = profile.get("environment")
    if not isinstance(profile_environment, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in profile_environment.items()
    ):
        fail("reviewed environment profile is malformed", phase="B6")
    profile_environment = cast(dict[str, str], profile_environment)
    expected = {
        name: value.replace("{ISOLATED_ROOT}", str(isolated))
        .replace("{CWD}", str(cwd))
        .replace("{REPO_ROOT}", str(repo))
        for name, value in profile_environment.items()
    }
    if env != expected:
        fail("constructed environment differs from canonical reviewed profile", phase="B6")
    conditional = profile.get("conditional_environment", {})
    if not isinstance(conditional, dict):
        fail("reviewed conditional environment profile is malformed", phase="B6")
    selected = conditional.get(argv0, {})
    if not isinstance(selected, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in selected.items()
    ):
        fail("reviewed conditional environment entry is malformed", phase="B6")
    env.update(
        {
            name: value.replace("{REPO_ROOT}", str(repo))
            .replace("{CWD}", str(cwd))
            .replace("{TRUSTED_ROOT}", str(trusted_root or temp_root))
            .replace("{ISOLATED_ROOT}", str(isolated))
            for name, value in selected.items()
        }
    )
    return env, isolated


def _cleanup_isolated(isolated: Path) -> None:
    """Remove all tool state and prove absence before evidence publication."""

    shutil.rmtree(isolated)
    if isolated.exists() or isolated.is_symlink():
        fail("isolated tool-state cleanup did not remove the runtime root", phase="B6")


def _sandbox_command(
    sandbox: Path,
    isolated: Path,
    repo: Path,
    cwd: Path,
    env: dict[str, str],
    lexical_command: list[str],
    reviewed_argv: tuple[str, ...],
) -> list[str]:
    masked_roots = tuple(
        path for path in map(Path, ("/home", "/root", "/tmp", "/var/tmp", "/run")) if path.exists()
    )
    command = [
        str(sandbox),
        "--die-with-parent",
        "--unshare-all",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
    ]
    for masked_root in masked_roots:
        command.extend(("--tmpfs", str(masked_root)))
    lexical_path = Path(lexical_command[0])
    visible_paths = [repo, lexical_path]
    link = lexical_path
    seen_links: set[Path] = set()
    while link.is_symlink() and link not in seen_links:
        seen_links.add(link)
        target = link.readlink()
        link = target if target.is_absolute() else link.parent / target
        if link.is_absolute() and link.parent.name == "bin":
            visible_paths.append(link.parent.parent)
    try:
        resolved_lexical = lexical_path.resolve(strict=True)
    except OSError:
        resolved_lexical = lexical_path
    if resolved_lexical != lexical_path:
        visible_paths.append(
            resolved_lexical.parent.parent
            if resolved_lexical.parent.name == "bin"
            else resolved_lexical
        )
    for variable in (
        "FNM_DIR",
        "COREPACK_HOME",
        "PLAYWRIGHT_BROWSERS_PATH",
        "npm_config_userconfig",
    ):
        if variable in env:
            visible_paths.append(Path(env[variable]))
    visible_paths.append(isolated)
    visible_paths = [
        path
        for path in visible_paths
        if path.is_absolute() and any(path.is_relative_to(root) for root in masked_roots)
    ]
    mount_sources: list[Path] = []
    for path in visible_paths:
        if path != isolated and path.is_relative_to(repo):
            path = repo
        if path not in mount_sources:
            mount_sources.append(path)
    directories: set[Path] = set()
    for source in mount_sources:
        masked_root = next(root for root in masked_roots if source.is_relative_to(root))
        parent = source if source.is_dir() else source.parent
        while parent != masked_root:
            directories.add(parent)
            parent = parent.parent
    for directory in sorted(directories, key=lambda item: len(item.parts)):
        command.extend(("--dir", str(directory)))
    for source in mount_sources:
        mode = "--bind" if source == isolated else "--ro-bind"
        command.extend((mode, str(source), str(source)))
    command.extend(("--proc", "/proc", "--dev", "/dev", "--chdir", str(cwd), "--clearenv"))
    for name, value in sorted(env.items()):
        command.extend(("--setenv", name, value))
    if reviewed_argv[:1] == ("fnm",):
        script = reviewed_argv[-1]
        for name in REVIEWED_UI_SANDBOX_WRITABLE_PATHS[script]:
            destination = cwd / name
            source = isolated / f"ui-{name.replace('/', '-')}"
            source.mkdir(mode=0o700)
            if not destination.is_dir() or destination.is_symlink():
                fail(f"UI writable mount destination is unavailable: {name}", phase="B6")
            command.extend(("--bind", str(source), str(destination)))
    return [*command, "--", *lexical_command]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--index", required=True, type=int)
    parser.add_argument("--transcript", required=True, type=Path)
    parser.add_argument("--temp-root", required=True, type=Path)
    parser.add_argument("--trusted-root", type=Path)
    args = parser.parse_args(argv)
    target_fd: int | None = None
    sandbox_fd: int | None = None
    isolated: Path | None = None
    try:
        script_repo = assert_evidence_runtime(require_dependencies=False)
        repo = git_root()
        if repo != script_repo:
            fail("reviewed capture must execute from REPO_ROOT", phase="B6")
        trusted_root: Path | None = None
        if args.trusted_root is not None:
            trusted_root = args.trusted_root
            if (
                not trusted_root.is_absolute()
                or trusted_root.is_symlink()
                or trusted_root.resolve(strict=True) != trusted_root
                or not trusted_root.is_dir()
                or trusted_root.stat().st_uid != os.getuid()
                or stat.S_IMODE(trusted_root.stat().st_mode) != 0o700
                or not repo.is_relative_to(trusted_root)
            ):
                fail("trusted root must be canonical caller-owned mode 0700", phase="B6")
        transcript = canonical_node_evidence_path(
            args.transcript, repo, node_id=args.node, filename="transcript.jsonl", must_exist=False
        )
        selector, reviewed_argv, cwd_scope = reviewed_node_command(args.node, args.index)
        cwd = reviewed_cwd(repo, cwd_scope)
        executable = reviewed_executable(cwd, reviewed_argv[0])
        lexical = cwd / reviewed_argv[0] if "/" in reviewed_argv[0] else executable
        _require_safe_parent_chain(lexical, trusted_stop=repo)
        executable_stop = (
            trusted_root
            if trusted_root is not None and executable.is_relative_to(trusted_root)
            else None
        )
        _require_safe_parent_chain(executable, trusted_stop=executable_stop)
        target_fd = os.open(executable, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(target_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail("resolved executable target must be a non-writable regular file", phase="B6")
        executable_sha256 = _hash_fd(target_fd)
        expected_host_sha256 = REVIEWED_HOST_EXECUTABLE_SHA256.get(reviewed_argv[0])
        if expected_host_sha256 is not None and executable_sha256 != expected_host_sha256:
            fail("reviewed host executable identity mismatch", phase="B6")
        target_identity = resolved_executable_identity(repo, executable, before)
        sandbox = BWRAP_EXECUTABLE.resolve(strict=True)
        if sandbox != BWRAP_EXECUTABLE or not sandbox.is_file() or sandbox.is_symlink():
            fail("reviewed sandbox executable is unavailable or noncanonical", phase="B6")
        _require_safe_parent_chain(sandbox)
        sandbox_fd = os.open(sandbox, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        sandbox_before = os.fstat(sandbox_fd)
        if not stat.S_ISREG(sandbox_before.st_mode) or sandbox_before.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            fail("reviewed sandbox executable must be a non-writable regular file", phase="B6")
        sandbox_sha256 = _hash_fd(sandbox_fd)
        sandbox_identity = resolved_executable_identity(repo, sandbox, sandbox_before)
        ui_toolchain_sha256 = (
            _ui_toolchain_digest(repo, trusted_root)
            if reviewed_argv[0] == "fnm" and trusted_root is not None
            else None
        )
        env, isolated = _closed_environment(
            repo,
            cwd,
            args.temp_root,
            argv0=reviewed_argv[0],
            trusted_root=trusted_root,
            node_id=args.node,
        )
        started = utc_now()
        completed = subprocess.run(
            _sandbox_command(
                sandbox,
                isolated,
                repo,
                cwd,
                env,
                [str(lexical), *reviewed_argv[1:]],
                reviewed_argv,
            ),
            cwd=cwd,
            env={},
            capture_output=True,
            check=False,
        )
        finished = utc_now()
        sys.stdout.buffer.write(completed.stdout)
        sys.stderr.buffer.write(completed.stderr)
        after = os.fstat(target_fd)
        sandbox_after = os.fstat(sandbox_fd)
        if (
            ui_toolchain_sha256 is not None
            and trusted_root is not None
            and _ui_toolchain_digest(repo, trusted_root) != ui_toolchain_sha256
        ):
            fail("UI toolchain changed during command execution", phase="B6")
        resolved_after = lexical.resolve(strict=True)
        if (
            resolved_after != executable
            or executable.stat() != after
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or _hash_fd(target_fd) != executable_sha256
        ):
            fail("reviewed executable changed during command execution", phase="B6")
        if (
            sandbox.resolve(strict=True) != sandbox
            or sandbox.stat() != sandbox_after
            or (
                sandbox_before.st_dev,
                sandbox_before.st_ino,
                sandbox_before.st_size,
                sandbox_before.st_mtime_ns,
            )
            != (
                sandbox_after.st_dev,
                sandbox_after.st_ino,
                sandbox_after.st_size,
                sandbox_after.st_mtime_ns,
            )
            or _hash_fd(sandbox_fd) != sandbox_sha256
        ):
            fail("reviewed sandbox executable changed during command execution", phase="B6")
        if completed.returncode != 0:
            fail(
                f"reviewed command failed index={args.index} exit={completed.returncode}",
                phase="B6",
            )
        staged_record = {
            "argv": list(reviewed_argv),
            "exit_code": 0,
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
            "started_at_utc": started,
            "finished_at_utc": finished,
            "selectors": [selector],
            "cwd_scope": cwd_scope,
            "executable_sha256": executable_sha256,
            "environment_profile_version_sha256": reviewed_environment_profile_sha256(
                args.node, list(reviewed_argv)
            ),
            "resolved_executable_identity_sha256": target_identity,
            "sandbox_executable_sha256": sandbox_sha256,
            "sandbox_profile_version_sha256": reviewed_sandbox_profile_sha256(
                args.node, list(reviewed_argv)
            ),
            "sandbox_resolved_identity_sha256": sandbox_identity,
        }
        if ui_toolchain_sha256 is not None:
            staged_record["ui_toolchain_sha256"] = ui_toolchain_sha256
        _cleanup_isolated(isolated)
        isolated = None
        append_safe_transcript_record(
            transcript,
            staged_record,
            expected_node=args.node,
        )
        return 0
    except (EvidenceError, OSError) as exc:
        if isolated is not None:
            try:
                _cleanup_isolated(isolated)
                isolated = None
            except (EvidenceError, OSError) as cleanup_exc:
                exc = EvidenceError(f"{exc}; isolated cleanup failed: {cleanup_exc}")
        print(f"reviewed command capture failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if sandbox_fd is not None:
            os.close(sandbox_fd)


if __name__ == "__main__":
    raise SystemExit(main())
