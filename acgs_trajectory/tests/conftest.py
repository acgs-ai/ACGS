from __future__ import annotations

from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIX


@pytest.fixture
def read_fixture():
    def _read(name: str) -> str:
        return (FIX / name).read_text(encoding="utf-8")

    return _read


@pytest.fixture
def complete_git():
    # a plausible external git join so a complete record can reach 'complete'
    return {"head_sha": "a" * 40, "dirty": False, "branch": "master", "remote": "origin"}
