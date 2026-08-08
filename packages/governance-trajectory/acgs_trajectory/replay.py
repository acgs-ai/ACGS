"""Deterministic replay path (Phase 1.1 Evidence Freeze).

    fixed JSONL fixture -> adapter -> governance_trajectory/v2 -> canonical bytes

Same input always yields byte-identical canonical output and a stable digest.
The raw fixture is read-only and never mutated. No store side effects — this is
the reproducibility oracle used by the evidence freeze.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex
from .ingest import ingest_text

# A fixed capture time so replay is time-independent (R6). Do NOT read the clock.
FROZEN_CAPTURED_AT = "1970-01-01T00:00:00Z"
# A fixed git join so a fixture can reach a deterministic terminal status.
FROZEN_REPO_GIT = {"head_sha": "0" * 40, "dirty": False, "branch": "master", "remote": None}


@dataclass(frozen=True)
class ReplayArtifact:
    trajectory_id: str
    status: str
    canonical: bytes
    canonical_sha256: str
    normalized_sha256: str
    record: dict[str, Any]


def replay(
    fixture_path: str | Path,
    *,
    captured_at: str = FROZEN_CAPTURED_AT,
    repo_git: dict[str, Any] | None = None,
) -> ReplayArtifact:
    """Replay a fixture to a canonical artifact, deterministically and read-only."""
    path = Path(fixture_path)
    raw_text = path.read_text(encoding="utf-8")
    before = sha256_hex(raw_text)

    result = ingest_text(
        raw_text,
        store=None,  # no side effects
        captured_at=captured_at,
        repo_git=repo_git if repo_git is not None else dict(FROZEN_REPO_GIT),
    )

    # prove non-mutation of the source
    after = sha256_hex(path.read_text(encoding="utf-8"))
    if before != after:
        raise RuntimeError(f"replay mutated the raw fixture {path}")

    canon = canonical_bytes(result.record)
    return ReplayArtifact(
        trajectory_id=result.record["trajectory_id"],
        status=result.status,
        canonical=canon,
        canonical_sha256=sha256_hex(canon),
        normalized_sha256=result.record["integrity"]["normalized_sha256"],
        record=result.record,
    )
