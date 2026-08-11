"""Repository state verification against the audit chain.

The ledger — not the filesystem — is the source of truth for what each
governed resource is supposed to contain. Any divergence means an
unauthorized out-of-band mutation happened (Attack A) and is reported.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import ABSENT, hash_file
from .ledger import EVENT_COMMIT, AuditLedger


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

    # Files present on disk under governed prefixes that the ledger has
    # never heard of are also unauthorized mutations.
    for prefix in governed_prefixes:
        base = repo_dir / prefix
        if base.is_dir():
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    known.add(path.relative_to(repo_dir).as_posix())

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
