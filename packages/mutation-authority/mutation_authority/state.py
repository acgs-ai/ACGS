"""Repository state verification against the audit chain.

The ledger — not the filesystem — is the source of truth for what each
governed resource is supposed to contain. Any divergence means an
unauthorized out-of-band mutation happened (Attack A) and is reported.
"""

from __future__ import annotations

from collections.abc import Iterator
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .canonical import ABSENT, hash_file
from .ledger import EVENT_COMMIT, AuditLedger


class RepositoryScanError(Exception):
    """A governed-tree directory could not be enumerated. Fail closed."""


def governed_match(resource: str, prefixes: list[str]) -> bool:
    """The single governed-resource predicate: a resource is governed when it
    lies under a directory prefix OR matches a glob pattern (fnmatchcase, so
    semantics never vary with platform case-folding). Shared by the
    DecisionEngine and the repository scan — the scan must consider governed
    exactly what the engine considers governed, or files under glob prefixes
    like ``src/*.py`` would be gated on write yet invisible to verification."""
    return any(
        resource.startswith(p.rstrip("/") + "/") or fnmatchcase(resource, p) for p in prefixes
    )


def _scan_entries(base: Path) -> Iterator[Path]:
    """Every non-directory entry under ``base``, WITHOUT following symlinks.

    Symlinks are yielded as entries in their own right — including broken
    ones and links to directories. A follow-the-link walk (``Path.rglob`` +
    ``is_file``) never sees a dangling symlink, so an attacker could plant
    one inside a governed prefix undetected; ``hash_file`` uses ``lstat``
    semantics and classifies the link itself, so enumerating it here is what
    surfaces it as an unauthorized creation. An unreadable directory is a
    fail-closed scan error: files absent from the ledger are discovered ONLY
    by this walk, so silently skipping a subtree would let an attacker hide
    an unauthorized file simply by dropping traversal permission on its
    parent directory."""
    try:
        children = sorted(base.iterdir())
    except OSError as exc:
        raise RepositoryScanError(
            f"cannot enumerate governed-tree directory {base}: {exc} "
            "(an unscannable subtree could conceal unauthorized mutations)"
        ) from exc
    for child in children:
        if child.is_symlink():
            yield child
        elif child.is_dir():
            yield from _scan_entries(child)
        else:
            yield child


def repository_violations(
    ledger: AuditLedger, repo_dir: Path, governed_prefixes: list[str]
) -> list[dict[str, Any]]:
    """Compare disk state to ledger-authorized state for every governed resource.

    Returns one violation record per divergent resource; empty list means
    the repository is exactly the state the audit chain authorizes.
    """
    known: set[str] = set(ledger.genesis().payload["baseline"])
    for event in ledger.events():
        if event.type == EVENT_COMMIT:
            known.add(event.payload["resource"])

    # Entries present on disk that the ledger has never heard of are also
    # unauthorized mutations. The scan walks the whole repository without
    # following symlinks and applies the engine's own governed predicate, so
    # glob prefixes (``src/*.py``) and planted symlinks — dangling or not —
    # are seen exactly as the decision path would see them.
    for path in _scan_entries(repo_dir):
        resource = path.relative_to(repo_dir).as_posix()
        if governed_match(resource, governed_prefixes):
            known.add(resource)

    violations: list[dict[str, Any]] = []
    for resource in sorted(known):
        authorized = ledger.authorized_state(resource)
        actual = hash_file(repo_dir / resource)
        if authorized != actual:
            violations.append(
                {
                    "resource": resource,
                    "authorized_hash": authorized,
                    "actual_hash": actual,
                    "kind": (
                        "unauthorized_create"
                        if authorized == ABSENT
                        else "unauthorized_delete"
                        if actual == ABSENT
                        else "unauthorized_modify"
                    ),
                }
            )
    return violations
