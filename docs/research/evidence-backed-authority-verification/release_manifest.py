#!/usr/bin/env python3
"""Generate or verify the complete release SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "SHA256SUMS"
EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".omc", ".benchmarks"}
#: Machine-local caches written next to the sources (deployment.py's
#: `.python_image`); they are not release content and would make the manifest
#: fail on any host that has run the tooling.
EXCLUDED_FILES = {".python_image"}


def release_files() -> list[Path]:
    files = []
    for path in HERE.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        if path.name in EXCLUDED_FILES:
            continue
        relative = path.relative_to(HERE)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(HERE).as_posix())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_lines() -> list[str]:
    return [f"{digest(path)}  {path.relative_to(HERE).as_posix()}" for path in release_files()]


def write_manifest() -> None:
    MANIFEST.write_text("\n".join(expected_lines()) + "\n", encoding="utf-8")


def verify_manifest() -> tuple[bool, list[str]]:
    if not MANIFEST.exists():
        return False, ["SHA256SUMS is missing"]
    actual = [line for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line]
    expected = expected_lines()
    errors = []
    if actual != expected:
        actual_set = set(actual)
        expected_set = set(expected)
        errors.extend(f"missing-or-stale: {line}" for line in expected if line not in actual_set)
        errors.extend(f"unexpected: {line}" for line in actual if line not in expected_set)
    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.write:
        write_manifest()
    ok, errors = verify_manifest()
    if not ok:
        for error in errors:
            print(error)
        return 2
    print(f"SHA256SUMS verified: {len(expected_lines())} files; manifest self-excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
