"""Tenant isolation, idempotency, and tamper tests for normalized storage."""

from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from pydantic import ValidationError

from agent_bus_analyzer.process_mining.collectors.api_collector import APIEventCollector
from agent_bus_analyzer.process_mining.errors import (
    ConflictingDuplicateError,
    EventStoreIntegrityError,
)
from agent_bus_analyzer.process_mining.storage.event_store import AppendStatus, EventStore


def _record(*, event_id: str = "evt-1", tenant_id: str = "tenant-a") -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "case_id": "case-1",
        "process_id": "process-1",
        "kind": "agent",
        "activity": "analyze",
        "occurred_at": "2026-07-09T15:00:00Z",
        "actor_kind": "agent",
        "agent_id": "agent-1",
        "outcome": "success",
        "status": "observed",
    }


def test_append_is_idempotent_and_query_is_tenant_and_case_scoped(tmp_path: Path) -> None:
    collector = APIEventCollector()
    first = collector.collect(_record(), tenant_id="tenant-a")
    retried = collector.collect(_record(), tenant_id="tenant-a")
    other = collector.collect(
        _record(event_id="evt-other", tenant_id="tenant-b"),
        tenant_id="tenant-b",
    )
    store = EventStore(tmp_path)

    assert store.append(first).status is AppendStatus.APPENDED
    assert store.append(retried).status is AppendStatus.DUPLICATE
    assert store.append(other).status is AppendStatus.APPENDED
    assert [
        event.event_id for event in store.query_by_case(tenant_id="tenant-a", case_id="case-1")
    ] == ["evt-1"]
    assert [
        event.event_id for event in store.query_by_case(tenant_id="tenant-b", case_id="case-1")
    ] == ["evt-other"]
    assert store.verify_chain("tenant-a").valid is True
    assert store.verify_chain("tenant-a").checked == 1
    assert [event.event_id for event in store.list_events(tenant_id="tenant-a")] == ["evt-1"]
    assert [
        event.event_id
        for event in store.query_by_process(tenant_id="tenant-a", process_id="process-1")
    ] == ["evt-1"]
    assert store.query_by_process(tenant_id="tenant-b", process_id="missing") == ()


def test_conflicting_duplicate_is_rejected(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    collector = APIEventCollector()
    store.append(collector.collect(_record(), tenant_id="tenant-a"))
    changed = _record()
    changed["activity"] = "export"

    with pytest.raises(ConflictingDuplicateError):
        store.append(collector.collect(changed, tenant_id="tenant-a"))


def test_append_revalidates_hash_after_mutable_attribute_change(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")
    event.attributes["status"] = "tampered-after-normalization"

    with pytest.raises(ValidationError, match="normalization_hash"):
        store.append(event)

    assert store.list_events(tenant_id="tenant-a") == ()


def test_append_and_queries_do_not_share_mutable_event_references(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")

    result = store.append(event)
    event.attributes["status"] = "caller-mutation"
    result.record.event.attributes["status"] = "append-result-mutation"

    first = store.get_event(tenant_id="tenant-a", event_id="evt-1")
    assert first is not None
    assert first.attributes["status"] == "observed"
    first.attributes["status"] = "query-result-mutation"

    second = store.get_event(tenant_id="tenant-a", event_id="evt-1")
    assert second is not None
    assert second.attributes["status"] == "observed"
    assert store.list_events(tenant_id="tenant-a")[0].attributes["status"] == "observed"
    assert (
        store.query_by_case(tenant_id="tenant-a", case_id="case-1")[0].attributes["status"]
        == "observed"
    )


def test_tampered_chain_fails_closed_for_query_and_append(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    collector = APIEventCollector()
    event = collector.collect(_record(), tenant_id="tenant-a")
    store.append(event)
    path = tmp_path / "tenants" / "tenant-a" / "events.jsonl"
    contents = path.read_text(encoding="utf-8")
    path.write_text(
        contents.replace('"activity":"analyze"', '"activity":"tamper"'), encoding="utf-8"
    )

    verification = store.verify_chain("tenant-a")
    assert verification.valid is False
    assert verification.failure_index == 0
    with pytest.raises(EventStoreIntegrityError):
        store.query_by_case(tenant_id="tenant-a", case_id="case-1")
    with pytest.raises(EventStoreIntegrityError):
        store.append(collector.collect(_record(event_id="evt-2"), tenant_id="tenant-a"))


def test_tenant_path_traversal_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        EventStore(tmp_path).verify_chain("../tenant-b")


def test_event_store_enforces_private_directory_file_and_lock_modes(tmp_path: Path) -> None:
    root = tmp_path / "event-store"
    store = EventStore(root)
    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")
    store.append(event)

    for directory in (root, root / "tenants", root / "tenants" / "tenant-a"):
        assert stat.S_IMODE(directory.lstat().st_mode) == 0o700
    for private_file in (
        root / "tenants" / "tenant-a" / "events.jsonl",
        root / "tenants" / "tenant-a" / "events.lock",
    ):
        assert stat.S_ISREG(private_file.lstat().st_mode)
        assert stat.S_IMODE(private_file.lstat().st_mode) == 0o600


@pytest.mark.parametrize("managed_name", ["events.jsonl", "events.lock"])
def test_event_store_rejects_symlinked_managed_files_without_touching_target(
    tmp_path: Path,
    managed_name: str,
) -> None:
    root = tmp_path / "event-store"
    store = EventStore(root)
    tenant_root = root / "tenants" / "tenant-a"
    tenant_root.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-touch", encoding="utf-8")
    os.chmod(victim, 0o600)
    (tenant_root / managed_name).symlink_to(victim)

    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")
    with pytest.raises(EventStoreIntegrityError):
        store.append(event)

    assert victim.read_text(encoding="utf-8") == "do-not-touch"


def test_event_store_rejects_symlinked_tenant_directory(tmp_path: Path) -> None:
    root = tmp_path / "event-store"
    store = EventStore(root)
    victim = tmp_path / "victim-directory"
    victim.mkdir()
    (root / "tenants" / "tenant-a").symlink_to(victim, target_is_directory=True)

    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")
    with pytest.raises(EventStoreIntegrityError):
        store.append(event)

    assert tuple(victim.iterdir()) == ()


def test_event_store_rejects_overpermissive_event_log_on_read(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    event = APIEventCollector().collect(_record(), tenant_id="tenant-a")
    store.append(event)
    event_path = tmp_path / "tenants" / "tenant-a" / "events.jsonl"
    event_path.chmod(0o644)

    with pytest.raises(EventStoreIntegrityError, match="permissions"):
        store.verify_chain("tenant-a")


def test_concurrent_readers_never_observe_partial_concurrent_appends(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    collector = APIEventCollector()
    events = tuple(
        collector.collect(_record(event_id=f"evt-{index}"), tenant_id="tenant-a")
        for index in range(48)
    )
    stop = Event()

    def read_until_complete() -> int:
        reads = 0
        while not stop.is_set() or reads < 4:
            verification = store.verify_chain("tenant-a")
            assert verification.valid is True
            observed = store.list_events(tenant_id="tenant-a")
            assert len({event.event_id for event in observed}) == len(observed)
            reads += 1
        return reads

    with ThreadPoolExecutor(max_workers=4) as reader_pool:
        readers = [reader_pool.submit(read_until_complete) for _ in range(4)]
        with ThreadPoolExecutor(max_workers=12) as writer_pool:
            results = tuple(writer_pool.map(store.append, events))
        stop.set()
        assert all(future.result(timeout=10) > 0 for future in readers)

    assert all(result.status is AppendStatus.APPENDED for result in results)
    verification = store.verify_chain("tenant-a")
    assert verification.valid is True
    assert verification.checked == len(events)
    assert len(store.list_events(tenant_id="tenant-a")) == len(events)
