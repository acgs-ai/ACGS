from __future__ import annotations

import os
from pathlib import Path

import pytest
from acgs_canary.pool import CanaryPool
from acgs_canary.store import RestrictedFileStore

T = "2026-08-15T00:00:00Z"


@pytest.fixture()
def store_dir(tmp_path: Path) -> Path:
    d = tmp_path / "restricted"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


@pytest.fixture()
def store(store_dir: Path) -> RestrictedFileStore:
    s = RestrictedFileStore(store_dir)
    s.initialize(operator="tests")
    return s


@pytest.fixture()
def pool(store: RestrictedFileStore) -> CanaryPool:
    p = CanaryPool(store)
    p.init_pool(pool_id="test-pool", created_at=T, operator="tests")
    return p
