"""Pytest mirror of the MUTATION_AUTHORITY_INTEGRATION_V1 boundary attacks.

Fresh sandbox per test under tmp_path; logical clock; deterministic.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mutation_authority.integration_verification import INTEGRATION_CHECKS

_IDS = [
    name.split(":")[0].strip().lower().replace(" ", "-").replace("/", "-")
    for name, _ in INTEGRATION_CHECKS
]


@pytest.mark.parametrize(("name", "check"), INTEGRATION_CHECKS, ids=_IDS)
def test_boundary(name: str, check, tmp_path: Path) -> None:
    detail = check(tmp_path / "sandbox")
    assert isinstance(detail, str) and detail
