"""Opt-in PostgreSQL migration tests for the controlled operator path.

These tests intentionally require ``ACP_TEST_POSTGRES_URL``, an explicit
``ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1`` acknowledgement, and the exact
dedicated disposable database ``acgs_control_plane_test`` before they reset its
``public`` schema.  They never infer or use an application/runtime database URL.
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

import acgs_control_plane.migrations as migration_module
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    _POSTGRES_MIGRATION_LOCK_STATEMENT,
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    DatabaseSchemaState,
    MigrationLockUnavailable,
    MigrationPreflightError,
    inspect_schema,
    migration_config,
    upgrade_database,
)

_TEST_POSTGRES_URL = os.environ.get("ACP_TEST_POSTGRES_URL")
if not _TEST_POSTGRES_URL:
    pytest.skip(
        "set ACP_TEST_POSTGRES_URL to run disposable PostgreSQL migration tests",
        allow_module_level=True,
    )
if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
    raise RuntimeError(
        "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that this test "
        "will reset the exact disposable PostgreSQL public schema."
    )

pytest.importorskip("psycopg")
_TEST_URL = sa.engine.make_url(_TEST_POSTGRES_URL)
_DISPOSABLE_DATABASE_NAME = "acgs_control_plane_test"
if _TEST_URL.get_backend_name() != "postgresql":
    raise RuntimeError("ACP_TEST_POSTGRES_URL must use a PostgreSQL URL.")
if _TEST_URL.database != _DISPOSABLE_DATABASE_NAME:
    raise RuntimeError(
        "ACP_TEST_POSTGRES_URL must name exactly the dedicated disposable database "
        f"{_DISPOSABLE_DATABASE_NAME!r} before this test may reset its public schema."
    )

_LOCK_PARAMETERS = {
    "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
}


def _assert_disposable_database(connection: Connection) -> None:
    database_name = connection.scalar(sa.text("SELECT current_database()"))
    if database_name != _DISPOSABLE_DATABASE_NAME:
        raise RuntimeError(
            "Refusing to reset PostgreSQL public schema outside the exact dedicated test database."
        )


def _reset_public_schema() -> None:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _isolated_postgresql_schema() -> Iterator[None]:
    """Reset only the explicitly named disposable database before and after a test."""
    _reset_public_schema()
    try:
        yield
    finally:
        _reset_public_schema()


def _table_names() -> set[str]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            return set(sa.inspect(connection).get_table_names(schema="public"))
    finally:
        engine.dispose()


def _try_advisory_xact_lock(connection: Connection) -> bool:
    return bool(connection.scalar(_POSTGRES_MIGRATION_LOCK_STATEMENT, _LOCK_PARAMETERS))


def _seed_exact_legacy_v0_schema() -> None:
    """Create only the frozen legacy tables for an adoption/rollback probe."""
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def test_postgresql_clean_install_has_types_and_cross_org_parent_constraint() -> None:
    result = upgrade_database(_TEST_POSTGRES_URL)

    assert result.before.state is DatabaseSchemaState.EMPTY
    assert result.after.state is DatabaseSchemaState.VERSION_0002
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0002

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            inspector = sa.inspect(connection)
            version_numbers = (
                connection.execute(sa.text("SELECT version_num FROM alembic_version"))
                .scalars()
                .all()
            )
            assert version_numbers == [HEAD_REVISION]

            receipt_columns = {
                column["name"]: column for column in inspector.get_columns("receipts")
            }
            assert isinstance(receipt_columns["payload"]["type"], postgresql.JSONB)
            assert isinstance(receipt_columns["created_at"]["type"], postgresql.TIMESTAMP)
            assert receipt_columns["created_at"]["type"].timezone is True

            project_columns = {
                column["name"]: column for column in inspector.get_columns("projects")
            }
            assert isinstance(project_columns["created_at"]["type"], postgresql.TIMESTAMP)
            assert project_columns["created_at"]["type"].timezone is True

            environment_foreign_keys = {
                (
                    tuple(foreign_key["constrained_columns"]),
                    foreign_key["referred_table"],
                    tuple(foreign_key["referred_columns"]),
                )
                for foreign_key in inspector.get_foreign_keys("environments")
            }
            assert (("org_id", "project_id"), "projects", ("org_id", "id")) in (
                environment_foreign_keys
            )

        with engine.begin() as connection:
            created_at = "2026-07-13T00:00:00+00:00"
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
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-a', 'org-a', 'core', 'Core Project', :created_at)
                    """
                ),
                {"created_at": created_at},
            )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                        VALUES (
                            'environment-cross-org', 'org-b', 'project-a', 'production',
                            'Cross-org Attempt', :created_at
                        )
                        """
                    ),
                    {"created_at": "2026-07-13T00:00:00+00:00"},
                )
    finally:
        engine.dispose()


def test_postgresql_lock_contention_rejects_before_schema_mutation_then_retries() -> None:
    holder_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with holder_engine.connect() as holder:
            with holder.begin():
                assert _try_advisory_xact_lock(holder)
                with pytest.raises(MigrationLockUnavailable, match="migration lock is held"):
                    upgrade_database(_TEST_POSTGRES_URL)

                assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
                assert _table_names() == set()

        result = upgrade_database(_TEST_POSTGRES_URL)
    finally:
        holder_engine.dispose()

    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_postgresql_injected_stamp_and_upgrade_rollback_atomically_and_release_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_exact_legacy_v0_schema()
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.LEGACY_V0

    original_upgrade = migration_module.command.upgrade

    def _run_actual_upgrade_then_fail(config: object, revision: str, **kwargs: object) -> None:
        assert isinstance(config, migration_module.Config)
        injected_connection = config.attributes["connection"]
        assert isinstance(injected_connection, Connection)
        assert injected_connection.in_transaction()
        assert (
            injected_connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            == LEGACY_V0_REVISION
        )

        observer_engine = make_engine(_TEST_POSTGRES_URL)
        try:
            with observer_engine.connect() as observer:
                # The legacy stamp is inside the outer transaction and cannot
                # be observed/committed by another PostgreSQL session.
                with observer.begin():
                    assert (
                        observer.scalar(sa.text("SELECT to_regclass('public.alembic_version')"))
                        is None
                    )
                    assert not _try_advisory_xact_lock(observer)
        finally:
            observer_engine.dispose()

        original_upgrade(config, revision, **kwargs)
        assert (
            injected_connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            == HEAD_REVISION
        )
        raise RuntimeError("injected failure after actual PostgreSQL Alembic upgrade")

    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(migration_module.command, "upgrade", _run_actual_upgrade_then_fail)
        with pytest.raises(
            RuntimeError, match="injected failure after actual PostgreSQL Alembic upgrade"
        ):
            upgrade_database(_TEST_POSTGRES_URL)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.LEGACY_V0
    assert _table_names() == {
        "agents",
        "compliance_exports",
        "organizations",
        "policy_bundles",
        "receipts",
        "users",
    }

    lock_probe_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with lock_probe_engine.connect() as connection:
            with connection.begin():
                assert _try_advisory_xact_lock(connection)
    finally:
        lock_probe_engine.dispose()

    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_raw_postgresql_alembic_commands_reject_before_schema_or_version_mutation() -> None:
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(_TEST_POSTGRES_URL), "head")
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(_TEST_POSTGRES_URL), LEGACY_V0_REVISION)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()


_WORKER_SCRIPT = Path(__file__).with_name("_postgresql_migration_worker.py")
_WORKER_EVENT_TIMEOUT_SECONDS = 15.0
_WORKER_EXIT_TIMEOUT_SECONDS = 15.0
_WORKER_TERMINATE_TIMEOUT_SECONDS = 3.0
_SENSITIVE_WORKER_VALUES = tuple(
    value for value in (_TEST_POSTGRES_URL, _TEST_URL.password) if isinstance(value, str) and value
)


@dataclass
class _MigrationWorker:
    process: subprocess.Popen[str]
    stdout_text: str = ""
    stderr_text: str = ""
    drained: bool = False
    events: list[dict[str, object]] = field(default_factory=list)


def _assert_secret_free(value: str) -> None:
    for sensitive_value in _SENSITIVE_WORKER_VALUES:
        if sensitive_value in value:
            raise AssertionError("worker argv or output contained a configured sensitive value")


def _assert_worker_secret_safe(worker: _MigrationWorker) -> None:
    args = worker.process.args
    argv = args if isinstance(args, str) else " ".join(str(argument) for argument in args)
    _assert_secret_free(argv)
    _assert_secret_free(worker.stdout_text)
    _assert_secret_free(worker.stderr_text)


def _launch_migration_worker(workers: list[_MigrationWorker], mode: str) -> _MigrationWorker:
    environment = os.environ.copy()
    environment["ACP_TEST_POSTGRES_URL"] = _TEST_POSTGRES_URL
    process = subprocess.Popen(
        [sys.executable, str(_WORKER_SCRIPT), mode],
        cwd=_WORKER_SCRIPT.parents[1],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        start_new_session=True,
    )
    worker = _MigrationWorker(process=process)
    workers.append(worker)
    _assert_worker_secret_safe(worker)
    return worker


def _read_worker_event(
    worker: _MigrationWorker, timeout: float = _WORKER_EVENT_TIMEOUT_SECONDS
) -> dict[str, object]:
    stdout = worker.process.stdout
    assert stdout is not None
    selector = selectors.DefaultSelector()
    try:
        selector.register(stdout, selectors.EVENT_READ)
        ready = selector.select(timeout)
    finally:
        selector.close()
    assert ready, f"worker event timed out with return code {worker.process.poll()}"

    line = stdout.readline()
    assert line, f"worker closed stdout with return code {worker.process.poll()}"
    worker.stdout_text += line
    _assert_secret_free(line)
    event = json.loads(line)
    assert isinstance(event, dict)
    worker.events.append(event)
    return event


def _drain_worker(worker: _MigrationWorker) -> None:
    if worker.drained:
        return
    stdout = worker.process.stdout
    stderr = worker.process.stderr
    if stdout is not None:
        worker.stdout_text += stdout.read()
    if stderr is not None:
        worker.stderr_text += stderr.read()
    worker.drained = True
    _assert_worker_secret_safe(worker)


def _stop_worker(worker: _MigrationWorker) -> None:
    process = worker.process
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=_WORKER_TERMINATE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_WORKER_TERMINATE_TIMEOUT_SECONDS)
    stdin = process.stdin
    if stdin is not None and not stdin.closed:
        stdin.close()
    _drain_worker(worker)


def _wait_worker(worker: _MigrationWorker, timeout: float = _WORKER_EXIT_TIMEOUT_SECONDS) -> int:
    try:
        return_code = worker.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_worker(worker)
        raise AssertionError("migration worker did not exit within its bounded timeout") from None
    _drain_worker(worker)
    return return_code


def _release_worker(worker: _MigrationWorker) -> None:
    stdin = worker.process.stdin
    assert stdin is not None
    stdin.write("release\n")
    stdin.flush()


@pytest.fixture
def migration_workers() -> Iterator[list[_MigrationWorker]]:
    workers: list[_MigrationWorker] = []
    try:
        yield workers
    finally:
        for worker in workers:
            _stop_worker(worker)


def _observe_migration_lock() -> tuple[int, set[int]]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            observer_pid = connection.scalar(sa.text("SELECT pg_backend_pid()"))
            assert isinstance(observer_pid, int)
            lock_pids = {
                int(pid)
                for pid in connection.execute(
                    sa.text(
                        """
                        SELECT pid
                        FROM pg_catalog.pg_locks
                        WHERE locktype = 'advisory'
                          AND database = (
                              SELECT oid FROM pg_catalog.pg_database
                              WHERE datname = current_database()
                          )
                          AND classid::bigint = :class_id
                          AND objid::bigint = :object_id
                          AND objsubid = 2
                          AND granted
                        """
                    ),
                    _LOCK_PARAMETERS,
                ).scalars()
            }
            return observer_pid, lock_pids
    finally:
        engine.dispose()


def _backend_is_active(backend_pid: int) -> bool:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            return bool(
                connection.scalar(
                    sa.text(
                        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity "
                        "WHERE pid = :backend_pid)"
                    ),
                    {"backend_pid": backend_pid},
                )
            )
    finally:
        engine.dispose()


def _wait_for_backend_and_lock_release(backend_pid: int) -> None:
    deadline = time.monotonic() + _WORKER_EXIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        _, lock_pids = _observe_migration_lock()
        if backend_pid not in lock_pids and not _backend_is_active(backend_pid):
            return
        time.sleep(0.05)
    raise AssertionError("PostgreSQL backend or advisory lock outlived the bounded wait")


def _assert_ready_event(worker: _MigrationWorker, event: dict[str, object], stage: str) -> int:
    assert event["event"] == "ready"
    assert event["stage"] == stage
    assert event["os_pid"] == worker.process.pid
    backend_pid = event["backend_pid"]
    assert isinstance(backend_pid, int)
    assert backend_pid > 0
    _assert_worker_secret_safe(worker)
    return backend_pid


def _assert_success_event(worker: _MigrationWorker, event: dict[str, object]) -> int:
    assert event == {
        "event": "result",
        "status": "success",
        "mode": "ordinary",
        "os_pid": worker.process.pid,
        "backend_pid": event["backend_pid"],
        "before": DatabaseSchemaState.EMPTY.value,
        "after": DatabaseSchemaState.VERSION_0002.value,
    }
    backend_pid = event["backend_pid"]
    assert isinstance(backend_pid, int)
    return backend_pid


def test_postgresql_independent_process_lock_owner_rejects_contender_then_retries(
    migration_workers: list[_MigrationWorker],
) -> None:
    owner = _launch_migration_worker(migration_workers, "pause-before-upgrade")
    owner_ready = _read_worker_event(owner)
    owner_backend_pid = _assert_ready_event(owner, owner_ready, "after-lock-before-upgrade")

    observer_pid, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}
    assert observer_pid != owner_backend_pid

    contender = _launch_migration_worker(migration_workers, "ordinary")
    contender_result = _read_worker_event(contender)
    assert contender_result["event"] == "result"
    assert contender_result["status"] == "error"
    assert contender_result["error_type"] == MigrationLockUnavailable.__name__
    assert contender_result["os_pid"] == contender.process.pid
    contender_backend_pid = contender_result["backend_pid"]
    assert isinstance(contender_backend_pid, int)
    assert contender.process.pid != owner.process.pid
    assert contender_backend_pid not in {owner_backend_pid, observer_pid}
    assert _wait_worker(contender) == 3

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()
    _, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}

    _release_worker(owner)
    owner_result = _read_worker_event(owner)
    assert owner_result["event"] == "result"
    assert owner_result["status"] == "released"
    assert owner_result["backend_pid"] == owner_backend_pid
    assert _wait_worker(owner) == 0
    _wait_for_backend_and_lock_release(owner_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()

    retry = _launch_migration_worker(migration_workers, "ordinary")
    retry_result = _read_worker_event(retry)
    retry_backend_pid = _assert_success_event(retry, retry_result)
    assert retry.process.pid not in {owner.process.pid, contender.process.pid}
    assert retry_backend_pid not in {
        owner_backend_pid,
        contender_backend_pid,
        observer_pid,
    }
    assert _wait_worker(retry) == 0
    _wait_for_backend_and_lock_release(retry_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0002
    assert all(worker.process.poll() is not None for worker in migration_workers)
    for worker in migration_workers:
        _assert_worker_secret_safe(worker)


def test_postgresql_sigkill_rolls_back_uncommitted_ddl_and_releases_lock(
    migration_workers: list[_MigrationWorker],
) -> None:
    owner = _launch_migration_worker(migration_workers, "pause-after-upgrade")
    owner_ready = _read_worker_event(owner)
    owner_backend_pid = _assert_ready_event(owner, owner_ready, "after-ddl-before-commit")
    assert owner_ready["transaction_state"] == DatabaseSchemaState.VERSION_0002.value

    observer_pid, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}
    assert observer_pid != owner_backend_pid
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()

    owner.process.kill()
    assert _wait_worker(owner) == -signal.SIGKILL
    _wait_for_backend_and_lock_release(owner_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()
    _, lock_pids = _observe_migration_lock()
    assert lock_pids == set()

    retry = _launch_migration_worker(migration_workers, "ordinary")
    retry_result = _read_worker_event(retry)
    retry_backend_pid = _assert_success_event(retry, retry_result)
    assert retry.process.pid != owner.process.pid
    assert retry_backend_pid not in {owner_backend_pid, observer_pid}
    assert _wait_worker(retry) == 0
    _wait_for_backend_and_lock_release(retry_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0002
    assert all(worker.process.poll() is not None for worker in migration_workers)
    for worker in migration_workers:
        _assert_worker_secret_safe(worker)
