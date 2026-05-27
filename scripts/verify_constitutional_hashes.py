#!/usr/bin/env python3
"""Constitutional-hash drift detector.

Walks the working tree for files containing a `Constitutional Hash: <hash>`
marker and verifies the (path, declared_hash) inventory matches the pinned
baseline at `docs/constitutional-hashes.lock`. Fails on any delta — added,
removed, or changed marker.

This is a *drift detector*, not a hash recomputer. It deliberately does
not know the hashing algorithm used to derive `<hash>`. The algorithm is
owned by `packages/acgs-lite` and verified there. Drift detection here
catches the operational class of failure where a sealed file is edited
without recomputing its hash.

Usage:
    python scripts/verify_constitutional_hashes.py            # verify (CI)
    python scripts/verify_constitutional_hashes.py --update   # regenerate lock
    python scripts/verify_constitutional_hashes.py --print    # print inventory
    python scripts/verify_constitutional_hashes.py --ignore-missing-prefix packages/clinicalguard/
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = REPO_ROOT / "docs" / "constitutional-hashes.lock"
# Marker forms tolerated across packages/acgs-lite/ — placeholders below
# (literal hex omitted so this regex doesn't match its own documentation):
#   <prefix> <hash>                  (bare)
#   <prefix> `<hash>`                (backticked)
#   > <prefix> `<hash>`              (blockquote)
#   "...<prefix> `<hash>`*"          (inside a string literal)
# Optional whitespace, backticks, or quotes are tolerated between colon and hex.
MARKER_RE = re.compile(r"Constitutional Hash:[\s`'\"]*([0-9a-fA-F]+)")

# File extensions worth scanning. Binary formats and large vendored trees
# are excluded for performance — markers belong in source / config / docs.
SCAN_EXTENSIONS = {
    ".py", ".pyi", ".toml", ".yaml", ".yml", ".json", ".md",
    ".rst", ".txt", ".cfg", ".ini", ".sh", ".ts", ".tsx", ".js",
}

# Path prefixes to skip even if extensions match.
SKIP_PREFIXES = (
    ".git/", "node_modules/", ".venv/", "venv/", "dist/", "build/",
    "target/", ".turbo/", "__pycache__/", ".mypy_cache/", ".pytest_cache/",
    ".ruff_cache/", "site-packages/",
)

# Exact file paths to skip. These files embed marker strings as test fixtures
# or drill payloads — they are not governance declarations. Without this skip
# list, regenerating the lock would bake synthetic hashes (e.g. the drill's
# `deadbeefcafebabe`) into the inventory, and any future edit to the fixture
# would trip a false drift alert.
SKIP_FILES = frozenset({
    "scripts/hardening_report.py",        # drill harness — synthetic `deadbeefcafebabe`
    "tests/test_verify_constitutional_hashes.py",  # verifier's own test fixtures
})


def _list_files() -> Iterable[Path]:
    """Enumerate files git knows about, including submodules when present."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--recurse-submodules"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        # Older git, or submodule not initialized. Fall back to single repo.
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    for line in result.stdout.splitlines():
        path = Path(line)
        if line in SKIP_FILES:
            continue
        if any(line.startswith(p) for p in SKIP_PREFIXES):
            continue
        if path.suffix and path.suffix not in SCAN_EXTENSIONS:
            continue
        yield path


def _scan_file(rel_path: Path) -> str | None:
    """Return the first declared hash in `rel_path`, or None."""
    abs_path = REPO_ROOT / rel_path
    try:
        # Markers are typically near the top — read first 4KB only.
        with abs_path.open("r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
    except (OSError, UnicodeDecodeError):
        return None
    match = MARKER_RE.search(head)
    return match.group(1) if match else None


def build_inventory() -> dict[str, str]:
    """Return {posix_path: declared_hash} for every marker-bearing file."""
    inventory: dict[str, str] = {}
    for rel_path in _list_files():
        declared = _scan_file(rel_path)
        if declared is not None:
            inventory[rel_path.as_posix()] = declared
    return dict(sorted(inventory.items()))


def load_lock() -> dict[str, str]:
    if not LOCK_PATH.exists():
        return {}
    with LOCK_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "hashes" not in data:
        raise ValueError(f"{LOCK_PATH} is malformed — missing 'hashes' key")
    return data["hashes"]


def write_lock(inventory: dict[str, str]) -> None:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_comment": (
            "Pinned inventory of `Constitutional Hash:` markers across the "
            "workspace (including submodules when present). Regenerate with "
            "`python scripts/verify_constitutional_hashes.py --update`. "
            "Any drift here is treated as a governance change that needs "
            "explicit review."
        ),
        "hashes": dict(sorted(inventory.items())),
    }
    with LOCK_PATH.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")


def diff_inventories(
    pinned: dict[str, str], actual: dict[str, str]
) -> tuple[list[str], list[str], list[tuple[str, str, str]]]:
    """Return (added, removed, changed)."""
    pinned_keys = set(pinned)
    actual_keys = set(actual)
    added = sorted(actual_keys - pinned_keys)
    removed = sorted(pinned_keys - actual_keys)
    changed = sorted(
        (path, pinned[path], actual[path])
        for path in pinned_keys & actual_keys
        if pinned[path] != actual[path]
    )
    return added, removed, changed


def _filter_ignored_removed(
    removed: list[str], ignored_prefixes: list[str]
) -> tuple[list[str], list[str]]:
    """Split removed paths into enforced and explicitly ignored groups."""
    if not ignored_prefixes:
        return removed, []

    normalized = [
        prefix if prefix.endswith("/") else f"{prefix}/"
        for prefix in ignored_prefixes
    ]
    enforced: list[str] = []
    ignored: list[str] = []
    for path in removed:
        if any(path.startswith(prefix) for prefix in normalized):
            ignored.append(path)
        else:
            enforced.append(path)
    return enforced, ignored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--update",
        action="store_true",
        help="Regenerate the lock file from the current working tree.",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Print the current inventory and exit 0.",
    )
    parser.add_argument(
        "--ignore-missing-prefix",
        action="append",
        default=[],
        metavar="PATH_PREFIX",
        help=(
            "Treat removed lock entries under PATH_PREFIX as explicitly "
            "unavailable. Intended for CI jobs where a credential-gated "
            "submodule cannot be initialized; strict verification remains "
            "the default."
        ),
    )
    args = parser.parse_args()

    inventory = build_inventory()

    if args.print:
        print(json.dumps({"hashes": inventory}, indent=2))
        return 0

    if args.update:
        write_lock(inventory)
        print(f"Wrote {LOCK_PATH.relative_to(REPO_ROOT)} ({len(inventory)} entries)")
        return 0

    pinned = load_lock()
    added, removed, changed = diff_inventories(pinned, inventory)
    removed, ignored_removed = _filter_ignored_removed(
        removed, args.ignore_missing_prefix
    )

    if not (added or removed or changed):
        if ignored_removed:
            print(
                "WARNING — ignored removed constitutional-hash lock entries "
                "under unavailable prefixes:"
            )
            for path in ignored_removed:
                print(f"    ! {path}  ({pinned[path]})")
        print(f"OK — {len(inventory)} constitutional hash markers verified clean.")
        return 0

    print("FAIL — constitutional-hash drift detected:\n")
    if ignored_removed:
        print(f"  IGNORED REMOVED ({len(ignored_removed)}):")
        for path in ignored_removed:
            print(f"    ! {path}  ({pinned[path]})")
    if added:
        print(f"  ADDED ({len(added)}):")
        for path in added:
            print(f"    + {path}  ({inventory[path]})")
    if removed:
        print(f"  REMOVED ({len(removed)}):")
        for path in removed:
            print(f"    - {path}  ({pinned[path]})")
    if changed:
        print(f"  CHANGED ({len(changed)}):")
        for path, old, new in changed:
            print(f"    ~ {path}")
            print(f"        was: {old}")
            print(f"        now: {new}")
    print(
        "\nIf this drift is intentional, regenerate the lock and commit it:\n"
        "  python scripts/verify_constitutional_hashes.py --update\n"
        "  git add docs/constitutional-hashes.lock\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
