"""Pytest mirror of the regression attack suite.

Each check builds its own sandbox under tmp_path, so tests are
independent and deterministic (logical clock, no wall time).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mutation_authority.verification import CHECKS

_IDS = [
    name.split(":")[0].strip().lower().replace(" ", "-").replace("(", "").replace(")", "")
    for name, _ in CHECKS
]


@pytest.mark.parametrize(("name", "check"), CHECKS, ids=_IDS)
def test_check(name: str, check, tmp_path: Path) -> None:
    # Raises CheckFailure (or any exception) on violation; returns detail on pass.
    detail = check(tmp_path / "sandbox")
    assert isinstance(detail, str) and detail
