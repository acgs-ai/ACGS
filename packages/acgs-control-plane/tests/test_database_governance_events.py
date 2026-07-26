"""Database-primary governance event groundwork tests."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from gove_zone import Kernel
from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import AuditError
from gove_zone.tool import ToolCall
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from acgs_control_plane.db import make_engine, make_session_factory
from acgs_control_plane.governance import DatabaseGovernanceEventAppender, _anchor, baseline_policy
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AuditProjectionOutbox,
    GovernanceEvent,
    GovernanceEventHead,
    Organization,
)


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'events.sqlite3'}"


@contextmanager
def _session(tmp_path: Path) -> Iterator[Session]:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _insert_org(session: Session, org_id: str = "org-events") -> None:
    session.add(
        Organization(
            id=org_id,
            name=f"{org_id} Inc.",
            audit_anchor_count=0,
            audit_anchor_hash="",
        )
    )
    session.commit()


def _record(
    event_id: str = "event-1",
    *,
    argument_hash: str | None = None,
    path: tuple[str, ...] = ("org-events",),
) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool="agent.register",
        argument_hash=argument_hash or sha256_json({"name": "bot"}),
        policy_version="policy/v1",
        event_id=event_id,
        matched_rules=("allow",),
        reason="allowed",
        actor="user:admin",
        goal="append database event",
        path=path,
        state_hash=sha256_json({"role": "org_admin"}),
        decision_request_hash=sha256_json({"request": event_id}),
    )


def _counts(session: Session) -> tuple[int, int, int]:
    return (
        session.scalar(sa.select(sa.func.count()).select_from(GovernanceEventHead)) or 0,
        session.scalar(sa.select(sa.func.count()).select_from(GovernanceEvent)) or 0,
        session.scalar(sa.select(sa.func.count()).select_from(AuditProjectionOutbox)) or 0,
    )


def test_database_governance_appender_returns_kernel_validated_payload(tmp_path: Path) -> None:
    with _session(tmp_path) as session:
        _insert_org(session)
        kernel = Kernel(
            policy=baseline_policy(),
            audit=DatabaseGovernanceEventAppender(session, "org-events"),
            actor="user:admin",
        )
        call = ToolCall(
            name="agent.register",
            args={"name": "bot"},
            actor="user:admin",
            goal="append database event",
            path=("org-events",),
            state={"role": "org_admin"},
        )

        audited = kernel.evaluate_and_append(call)
        session.commit()

        assert audited.audit_hash == audited.append_result["event_hash"]
        assert audited.append_result["previous_hash"] == GENESIS_HASH
        assert session.get(GovernanceEventHead, "org-events").last_sequence == 1  # type: ignore[union-attr]
        event = session.scalars(sa.select(GovernanceEvent)).one()
        outbox = session.scalars(sa.select(AuditProjectionOutbox)).one()
        assert event.payload["event_hash"] == audited.audit_hash
        assert sha256_json({k: v for k, v in event.payload.items() if k != "event_hash"}) == (
            audited.audit_hash
        )
        assert outbox.payload == event.payload
        assert outbox.status == "pending"


def test_database_governance_appender_rejects_unknown_tenant_without_side_effect(
    tmp_path: Path,
) -> None:
    with _session(tmp_path) as session:
        appender = DatabaseGovernanceEventAppender(session, "missing-org")

        with pytest.raises(AuditError, match="unknown tenant"):
            appender.append(_record(path=("missing-org",)))

        assert _counts(session) == (0, 0, 0)


def test_database_governance_appender_rejects_malformed_record_hash_without_side_effect(
    tmp_path: Path,
) -> None:
    with _session(tmp_path) as session:
        _insert_org(session)
        appender = DatabaseGovernanceEventAppender(session, "org-events")

        with pytest.raises(AuditError, match="argument_hash"):
            appender.append(_record(argument_hash="not-a-sha"))

        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize(
    ("path", "match"),
    [
        ((), "empty decision path"),
        (("other-org",), "tenant path mismatch"),
    ],
)
def test_database_governance_appender_rejects_unbound_path_without_side_effect(
    tmp_path: Path, path: tuple[str, ...], match: str
) -> None:
    with _session(tmp_path) as session:
        _insert_org(session)
        appender = DatabaseGovernanceEventAppender(session, "org-events")

        with pytest.raises(AuditError, match=match):
            appender.append(_record(path=path))

        assert _counts(session) == (0, 0, 0)
        org = session.get(Organization, "org-events")
        assert org is not None
        assert (org.audit_anchor_count, org.audit_anchor_hash) == (0, "")


def test_database_governance_appender_rollback_removes_event_head_and_outbox(
    tmp_path: Path,
) -> None:
    with _session(tmp_path) as session:
        _insert_org(session)
        with session.begin():
            DatabaseGovernanceEventAppender(session, "org-events").append(_record())
            assert _counts(session) == (1, 1, 1)
            session.rollback()

        assert _counts(session) == (0, 0, 0)


def test_database_governance_appender_flush_failure_leaves_no_durable_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _session(tmp_path) as session:
        _insert_org(session)
        original_flush = session.flush
        calls = {"n": 0}

        def fail_after_head(*args: Any, **kwargs: Any) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("injected flush failure")
            original_flush(*args, **kwargs)

        monkeypatch.setattr(session, "flush", fail_after_head)
        with pytest.raises(RuntimeError, match="injected flush failure"):
            DatabaseGovernanceEventAppender(session, "org-events").append(_record())
        session.rollback()

        assert _counts(session) == (0, 0, 0)


def test_database_governance_appender_concurrent_sqlite_chain_is_monotonic(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    try:
        with factory() as session:
            _insert_org(session)

        errors: list[BaseException] = []

        def worker(index: int) -> None:
            try:
                with factory() as session:
                    with session.begin():
                        DatabaseGovernanceEventAppender(session, "org-events").append(
                            _record(f"event-{index}")
                        )
            except BaseException as exc:  # pragma: no cover - assertion reports below.
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(1, 6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        with factory() as session:
            events = session.scalars(
                sa.select(GovernanceEvent).order_by(GovernanceEvent.sequence)
            ).all()
            assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
            previous = GENESIS_HASH
            for event in events:
                assert event.previous_hash == previous
                assert event.event_hash == sha256_json(
                    {key: value for key, value in event.payload.items() if key != "event_hash"}
                )
                previous = event.event_hash
            assert len({event.event_hash for event in events}) == 5
            assert session.get(GovernanceEventHead, "org-events").last_sequence == 5  # type: ignore[union-attr]
    finally:
        engine.dispose()


def test_database_governance_appender_sqlite_lock_lasts_until_outer_commit(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    try:
        with factory() as session:
            _insert_org(session)

        first_appended = threading.Event()
        allow_first_commit = threading.Event()
        second_finished = threading.Event()
        errors: list[BaseException] = []

        def first_writer() -> None:
            try:
                with factory() as session:
                    with session.begin():
                        DatabaseGovernanceEventAppender(session, "org-events").append(
                            _record("event-1")
                        )
                        first_appended.set()
                        assert allow_first_commit.wait(timeout=5)
            except BaseException as exc:  # pragma: no cover - assertion reports below.
                errors.append(exc)

        def second_writer() -> None:
            try:
                assert first_appended.wait(timeout=5)
                with factory() as session:
                    with session.begin():
                        DatabaseGovernanceEventAppender(session, "org-events").append(
                            _record("event-2")
                        )
                second_finished.set()
            except BaseException as exc:  # pragma: no cover - assertion reports below.
                errors.append(exc)

        first = threading.Thread(target=first_writer)
        second = threading.Thread(target=second_writer)
        first.start()
        assert first_appended.wait(timeout=5)
        second.start()
        assert not second_finished.wait(timeout=0.2)
        allow_first_commit.set()
        first.join(timeout=5)
        second.join(timeout=5)

        assert errors == []
        assert not first.is_alive()
        assert not second.is_alive()
        with factory() as session:
            events = session.scalars(
                sa.select(GovernanceEvent).order_by(GovernanceEvent.sequence)
            ).all()
            assert [(event.event_id, event.sequence) for event in events] == [
                ("event-1", 1),
                ("event-2", 2),
            ]
            assert events[1].previous_hash == events[0].event_hash
            assert session.get(GovernanceEventHead, "org-events").last_sequence == 2  # type: ignore[union-attr]
            outbox = session.scalars(
                sa.select(AuditProjectionOutbox).order_by(AuditProjectionOutbox.sequence)
            ).all()
            assert [(item.governance_event_id, item.sequence) for item in outbox] == [
                (events[0].id, 1),
                (events[1].id, 2),
            ]
    finally:
        engine.dispose()


def test_database_governance_appender_locking_selects_bypass_identity_map(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    locking_selects: list[tuple[tuple[str, ...], bool]] = []

    def capture_locking_select(
        _connection: sa.Connection,
        clauseelement: object,
        _multiparams: object,
        _params: object,
        execution_options: sa.util.immutabledict[str, object],
    ) -> None:
        if not isinstance(clauseelement, sa.sql.Select):
            return
        if getattr(clauseelement, "_for_update_arg", None) is None:
            return
        locking_selects.append(
            (
                tuple(from_.name for from_ in clauseelement.get_final_froms()),
                execution_options.get("populate_existing") is True,
            )
        )

    sa.event.listen(engine, "before_execute", capture_locking_select)
    try:
        with factory() as session:
            _insert_org(session)
            DatabaseGovernanceEventAppender(session, "org-events").append(_record("event-1"))
            session.commit()

            assert session.get(Organization, "org-events") is not None
            assert session.get(GovernanceEventHead, "org-events") is not None
            DatabaseGovernanceEventAppender(session, "org-events").append(_record("event-2"))
            session.commit()

        assert (("organizations",), True) in locking_selects
        assert (("governance_event_heads",), True) in locking_selects
    finally:
        sa.event.remove(engine, "before_execute", capture_locking_select)
        engine.dispose()


def test_anchor_locking_select_bypasses_preloaded_identity_map(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    factory = make_session_factory(engine)
    locking_selects: list[tuple[tuple[str, ...], bool]] = []

    def capture_locking_select(
        _connection: sa.Connection,
        clauseelement: object,
        _multiparams: object,
        _params: object,
        execution_options: sa.util.immutabledict[str, object],
    ) -> None:
        if not isinstance(clauseelement, sa.sql.Select):
            return
        if getattr(clauseelement, "_for_update_arg", None) is None:
            return
        locking_selects.append(
            (
                tuple(from_.name for from_ in clauseelement.get_final_froms()),
                execution_options.get("populate_existing") is True,
            )
        )

    sa.event.listen(engine, "before_execute", capture_locking_select)
    try:
        with factory() as session:
            _insert_org(session)
            assert session.get(Organization, "org-events") is not None
            store = ChainHashAuditStore(tmp_path / "audit" / "org-events.audit.jsonl")
            store.append(_record("event-1"))
            _anchor(session, "org-events", store)
            session.commit()

        assert (("organizations",), True) in locking_selects
    finally:
        sa.event.remove(engine, "before_execute", capture_locking_select)
        engine.dispose()


def test_audit_projection_outbox_rejects_cross_tenant_event_reference(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()
            with connection.begin():
                created_at = "2026-07-24T00:00:00+00:00"
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO organizations (
                            id, name, created_at, audit_anchor_count, audit_anchor_hash
                        ) VALUES
                            ('org-a', 'Organization A', :created_at, 0, ''),
                            ('org-b', 'Organization B', :created_at, 0, '')
                        """
                    ),
                    {"created_at": created_at},
                )
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO governance_events (
                            id, org_id, sequence, event_id, previous_hash, event_hash,
                            decision, tool, actor, policy_version, payload, created_at
                        ) VALUES (
                            'event-a', 'org-a', 1, 'decision-a', :genesis, :event_hash,
                            'allow', 'agent.register', 'user:admin', 'policy/v1', '{}',
                            :created_at
                        )
                        """
                    ),
                    {
                        "created_at": created_at,
                        "event_hash": "1" * 64,
                        "genesis": GENESIS_HASH,
                    },
                )

            with pytest.raises(IntegrityError):
                with connection.begin():
                    connection.execute(
                        sa.text(
                            """
                            INSERT INTO audit_projection_outbox (
                                id, org_id, governance_event_id, sequence, event_hash, payload,
                                status, attempts, created_at, available_at, delivered_at
                            ) VALUES (
                                'outbox-cross', 'org-b', 'event-a', 1, :event_hash, '{}',
                                'pending', 0, :created_at, :created_at, NULL
                            )
                            """
                        ),
                        {"created_at": created_at, "event_hash": "1" * 64},
                    )

            with connection.begin():
                assert (
                    connection.scalar(sa.text("SELECT count(*) FROM audit_projection_outbox")) == 0
                )
    finally:
        engine.dispose()
