from __future__ import annotations

import os

import pytest
from acgs_canary.errors import (
    PoolError,
    SelectionError,
    StoreConflictError,
    StoreIntegrityError,
    StoreLocationError,
)
from acgs_canary.pool import CanaryPool
from acgs_canary.store import InMemoryStore, RestrictedFileStore, Secret

T = "2026-08-15T00:00:00Z"


class TestStoreLocation:
    def test_unconfigured_refused(self, monkeypatch):
        monkeypatch.delenv("ACGS_CANARY_STORE", raising=False)
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(None)

    def test_relative_path_refused(self):
        with pytest.raises(StoreLocationError):
            RestrictedFileStore("relative/path")

    def test_missing_path_refused(self, tmp_path):
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(tmp_path / "absent")

    def test_group_readable_refused(self, tmp_path):
        d = tmp_path / "loose"
        d.mkdir(mode=0o750)
        os.chmod(d, 0o750)
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(d)

    def test_world_writable_refused(self, tmp_path):
        d = tmp_path / "world"
        d.mkdir(mode=0o707)
        os.chmod(d, 0o707)
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(d)

    def test_symlink_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(link)

    def test_inside_git_worktree_refused(self, tmp_path):
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir(mode=0o700)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        inner = repo / "store"
        inner.mkdir(mode=0o700)
        with pytest.raises(StoreLocationError):
            RestrictedFileStore(inner)

    def test_env_var_configuration(self, monkeypatch, tmp_path):
        d = tmp_path / "envstore"
        d.mkdir(mode=0o700)
        monkeypatch.setenv("ACGS_CANARY_STORE", str(d))
        store = RestrictedFileStore()
        store.initialize(operator="t")
        store.assert_initialized()


class TestStoreSemantics:
    def test_double_initialize_refused(self, store):
        with pytest.raises(StoreConflictError):
            store.initialize(operator="again")

    def test_uninitialized_reads_refused(self, store_dir):
        s = RestrictedFileStore(store_dir)
        with pytest.raises(StoreIntegrityError):
            s.read_record("x")

    def test_no_silent_overwrite(self, store):
        store.write_record("rec", {"a": 1}, overwrite=False)
        with pytest.raises(StoreConflictError):
            store.write_record("rec", {"a": 2}, overwrite=False)

    def test_record_integrity_tamper_detected(self, store, store_dir):
        store.write_record("rec", {"a": 1}, overwrite=False)
        f = store_dir / "rec"
        f.write_bytes(f.read_bytes().replace(b'"a":1', b'"a":2'))
        with pytest.raises(StoreIntegrityError):
            store.read_record("rec")

    def test_record_files_are_0600(self, store, store_dir):
        store.write_record("rec", {"a": 1}, overwrite=False)
        assert oct((store_dir / "rec").stat().st_mode & 0o777) == "0o600"

    def test_illegal_record_names_refused(self, store):
        for name in ["../evil", ".hidden", "a/b", "UPPER CASE!", ""]:
            with pytest.raises(StoreIntegrityError):
                store.write_record(name, {"a": 1}, overwrite=False)

    def test_secret_repr_redacted(self):
        s = Secret(b"super-secret-bytes")
        assert "super" not in repr(s)
        assert "super" not in str(s)
        with pytest.raises(TypeError):
            hash(s)

    def test_in_memory_store_requires_acknowledgment(self):
        with pytest.raises(StoreLocationError):
            InMemoryStore("production")
        assert InMemoryStore("test-only-not-production").production_safe is False


def _mkpool(store) -> CanaryPool:
    p = CanaryPool(store)
    p.init_pool(pool_id="p", created_at=T, operator="t")
    return p


class TestPool:
    def test_double_init_refused(self, pool):
        with pytest.raises(PoolError):
            pool.init_pool(pool_id="again", created_at=T, operator="t")

    def test_singleton_placement_refused(self, pool):
        with pytest.raises(PoolError):
            pool.generate(tier="T0", count=1, placements=1, created_at=T)

    def test_validate_passes_on_fresh_pool(self, pool):
        pool.generate(tier="T0", count=3, placements=2, created_at=T)
        report = pool.validate()
        assert report["total"] == 3

    def test_burned_never_selected(self, pool):
        ids = pool.generate(tier="T0", count=3, placements=2, created_at=T)
        pool.mark(ids[0], status="burned", at=T)
        selected = pool.select_t0(count=2)
        assert ids[0] not in selected

    def test_contaminated_never_selected(self, pool):
        ids = pool.generate(tier="T1", count=4, placements=2, created_at=T)
        pool.mark(ids[0], status="contaminated", at=T)
        sel = pool.select_t1(variant_id="vt_" + "aa" * 16, shared=1, unique=2)
        assert ids[0] not in sel["shared"] + sel["unique"]

    def test_double_burn_refused(self, pool):
        ids = pool.generate(tier="T0", count=2, placements=2, created_at=T)
        pool.mark(ids[0], status="burned", at=T)
        with pytest.raises(PoolError):
            pool.mark(ids[0], status="retired", at=T)

    def test_selection_insufficient_fails(self, pool):
        pool.generate(tier="T0", count=2, placements=2, created_at=T)
        with pytest.raises(SelectionError):
            pool.select_t0(count=5)

    def test_selection_deterministic(self, pool):
        pool.generate(tier="T0", count=6, placements=2, created_at=T)
        assert pool.select_t0(count=3) == pool.select_t0(count=3)

    def test_t1_unique_not_shared_across_variants(self, pool):
        pool.generate(tier="T1", count=8, placements=2, created_at=T)
        a = pool.select_t1(variant_id="vt_" + "aa" * 16, shared=2, unique=2)
        b = pool.select_t1(variant_id="vt_" + "bb" * 16, shared=2, unique=2)
        assert a["shared"] == b["shared"]  # shared subset is common
        assert not set(a["unique"]) & set(b["unique"])  # uniques disjoint

    def test_tier_crossing_refused_in_commitment(self, pool):
        t0 = pool.generate(tier="T0", count=2, placements=2, created_at=T)
        with pytest.raises(PoolError):
            pool.commitment(t0, tier="T1")

    def test_pool_manifest_carries_no_tokens(self, pool):
        ids = pool.generate(tier="T0", count=2, placements=2, created_at=T)
        manifest = pool.pool_manifest()
        raw = str(manifest)
        for cid in ids:
            token_hex = pool.token(cid).reveal().hex()
            assert token_hex not in raw

    def test_token_tamper_detected_by_validate(self, pool, store):
        ids = pool.generate(tier="T0", count=2, placements=2, created_at=T)
        rec = store.read_record(f"canary-{ids[0]}")
        rec["token_hex"] = "00" * 24
        store.write_record(f"canary-{ids[0]}", rec, overwrite=True)
        with pytest.raises(PoolError):
            pool.validate()


class TestPoolReviewHardening:
    def test_zero_or_negative_counts_refused(self, pool):
        pool.generate(tier="T0", count=2, placements=2, created_at=T)
        pool.generate(tier="T1", count=2, placements=2, created_at=T)
        with pytest.raises(SelectionError):
            pool.select_t0(count=0)
        with pytest.raises(SelectionError):
            pool.select_t0(count=-1)
        with pytest.raises(SelectionError):
            pool.select_t1(variant_id="vt_" + "aa" * 16, shared=-1, unique=2)
        with pytest.raises(SelectionError):
            pool.select_t1(variant_id="vt_" + "aa" * 16, shared=2, unique=-1)
        with pytest.raises(SelectionError):
            pool.select_t1(variant_id="vt_" + "aa" * 16, shared=0, unique=0)

    def test_unique_allocations_excluded_from_all_later_selection(self, pool):
        # A canary allocated as unique (here via shared=0) must never be
        # selected again by any other variant, as shared OR as unique.
        pool.generate(tier="T1", count=8, placements=2, created_at=T)
        a = pool.select_t1(variant_id="vt_" + "aa" * 16, shared=0, unique=3)
        b = pool.select_t1(variant_id="vt_" + "bb" * 16, shared=2, unique=2)
        assert not set(a["unique"]) & set(b["shared"])
        assert not set(a["unique"]) & set(b["unique"])

    def test_shared_allocations_never_become_unique(self, pool):
        # A canary shared by one variant must never later become another
        # variant's unique canary.
        pool.generate(tier="T1", count=8, placements=2, created_at=T)
        a = pool.select_t1(variant_id="vt_" + "aa" * 16, shared=3, unique=0)
        b = pool.select_t1(variant_id="vt_" + "bb" * 16, shared=0, unique=3)
        assert not set(a["shared"]) & set(b["unique"])

    def test_probe_write_failure_leaves_no_orphan_token(self, store):
        # If probe persistence fails (here: uninitialized probe store),
        # generate() must not leave an active canary in the token store that
        # selection could pick up despite having no probe.
        probe = InMemoryStore("test-only-not-production")  # never initialized
        pool = CanaryPool(store, probe_store=probe)
        pool.init_pool(pool_id="p", created_at=T, operator="t")
        with pytest.raises(StoreIntegrityError):
            pool.generate(tier="T0", count=2, placements=2, created_at=T)
        assert store.list_records("canary-") == []

    def test_probe_records_live_only_in_probe_store(self, store):
        # §6.5 custody split: with a separate probe store configured, probe
        # records must never touch the token store.
        probe = InMemoryStore("test-only-not-production")
        probe.initialize(operator="tests")
        pool = CanaryPool(store, probe_store=probe)
        pool.init_pool(pool_id="split", created_at=T, operator="tests")
        ids = pool.generate(tier="T0", count=2, placements=2, created_at=T)
        for cid in ids:
            assert store.read_record(f"probe-{cid}") is None
            assert probe.read_record(f"probe-{cid}") is not None
        assert pool.validate()["total"] == 2

    def test_split_pool_fails_validation_without_probe_store(self, store):
        # A token-store-only view of a custody-split pool must fail closed:
        # probes are simply not there.
        probe = InMemoryStore("test-only-not-production")
        probe.initialize(operator="tests")
        split = CanaryPool(store, probe_store=probe)
        split.init_pool(pool_id="split", created_at=T, operator="tests")
        split.generate(tier="T0", count=2, placements=2, created_at=T)
        merged_view = CanaryPool(store)
        with pytest.raises(PoolError):
            merged_view.validate()
