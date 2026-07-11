#!/usr/bin/env python3
"""Execute one exact reviewed command inside a closed local-proof environment.

This defends against ambient configuration and ordinary replacement races. Same-user
or root mutation of the running kernel/process remains outside this local proof's
trust boundary.
"""

from __future__ import annotations

import argparse
import hashlib
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
    REVIEWED_ENVIRONMENT_PROFILE,
    REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256,
    REVIEWED_SANDBOX_PROFILE_VERSION_SHA256,
    EvidenceError,
    append_safe_transcript_record,
    assert_evidence_runtime,
    canonical_node_evidence_path,
    fail,
    git_root,
    resolved_executable_identity,
    reviewed_cwd,
    reviewed_executable,
    reviewed_node_command,
    utc_now,
)


def _require_safe_parent_chain(path: Path) -> None:
    current = path.parent
    while True:
        mode = current.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail(f"executable parent chain is group/world writable: {current}", phase="B6")
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


def _closed_environment(repo: Path, cwd: Path, temp_root: Path) -> tuple[dict[str, str], Path]:
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
    profile_environment = REVIEWED_ENVIRONMENT_PROFILE.get("environment")
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
    return env, isolated


def _cleanup_isolated(isolated: Path) -> None:
    """Remove all tool state and prove absence before evidence publication."""

    shutil.rmtree(isolated)
    if isolated.exists() or isolated.is_symlink():
        fail("isolated tool-state cleanup did not remove the runtime root", phase="B6")


def _sandbox_command(
    sandbox: Path,
    isolated: Path,
    cwd: Path,
    env: dict[str, str],
    lexical_command: list[str],
) -> list[str]:
    command = [
        str(sandbox),
        "--die-with-parent",
        "--unshare-all",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(isolated),
        str(isolated),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        str(cwd),
        "--clearenv",
    ]
    for name, value in sorted(env.items()):
        command.extend(("--setenv", name, value))
    return [*command, "--", *lexical_command]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--index", required=True, type=int)
    parser.add_argument("--transcript", required=True, type=Path)
    parser.add_argument("--temp-root", required=True, type=Path)
    args = parser.parse_args(argv)
    target_fd: int | None = None
    sandbox_fd: int | None = None
    isolated: Path | None = None
    try:
        script_repo = assert_evidence_runtime(require_dependencies=False)
        repo = git_root()
        if repo != script_repo:
            fail("reviewed capture must execute from REPO_ROOT", phase="B6")
        transcript = canonical_node_evidence_path(
            args.transcript, repo, node_id=args.node, filename="transcript.jsonl", must_exist=False
        )
        selector, reviewed_argv, cwd_scope = reviewed_node_command(args.node, args.index)
        cwd = reviewed_cwd(repo, cwd_scope)
        lexical = cwd / reviewed_argv[0]
        executable = reviewed_executable(cwd, reviewed_argv[0])
        _require_safe_parent_chain(lexical)
        _require_safe_parent_chain(executable)
        target_fd = os.open(executable, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(target_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail("resolved executable target must be a non-writable regular file", phase="B6")
        executable_sha256 = _hash_fd(target_fd)
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
        env, isolated = _closed_environment(repo, cwd, args.temp_root)
        started = utc_now()
        completed = subprocess.run(
            _sandbox_command(sandbox, isolated, cwd, env, [str(lexical), *reviewed_argv[1:]]),
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
            "environment_profile_version_sha256": REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256,
            "resolved_executable_identity_sha256": target_identity,
            "sandbox_executable_sha256": sandbox_sha256,
            "sandbox_profile_version_sha256": REVIEWED_SANDBOX_PROFILE_VERSION_SHA256,
            "sandbox_resolved_identity_sha256": sandbox_identity,
        }
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
