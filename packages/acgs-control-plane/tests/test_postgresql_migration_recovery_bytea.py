"""Opt-in PostgreSQL evidence for bytea recovery-fingerprint preflight.

The URL must identify the exact disposable database named below.  Nothing is
inferred from an application URL, and its public schema is reset only after the
explicit destructive-test acknowledgement.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.pool import NullPool

from acgs_control_plane import migration_recovery as recovery
from acgs_control_plane.db import make_engine
from acgs_control_plane.migration_recovery import RecoveryRefused
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    inspect_schema,
    upgrade_database,
)

DATABASE = "acgs_control_plane_recovery_bytea_test"
DATABASE_ENV = "ACP_TEST_RECOVERY_BYTEA_URL"
TEMP_TABLE = "acgs_recovery_bytea_fingerprint_fixture"

DATABASE_URL = os.environ.get(DATABASE_ENV)
if not DATABASE_URL:
    pytest.skip(
        f"set {DATABASE_ENV} to run PostgreSQL bytea recovery tests",
        allow_module_level=True,
    )
if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
    raise RuntimeError(
        "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that these tests "
        "reset the exactly named disposable PostgreSQL public schema."
    )

pytest.importorskip("psycopg")


def _validated_url(raw: str) -> str:
    url = sa.engine.make_url(raw)
    if url.get_backend_name() != "postgresql" or url.database != DATABASE:
        raise RuntimeError(f"{DATABASE_ENV} must use PostgreSQL and name exactly {DATABASE!r}.")
    return raw


DATABASE_URL = _validated_url(DATABASE_URL)


def _reset_public_schema() -> None:
    engine = make_engine(DATABASE_URL)
    try:
        with engine.begin() as connection:
            current = connection.scalar(sa.text("SELECT current_database()"))
            if current != DATABASE:
                raise RuntimeError("refusing to reset a database whose runtime name changed")
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _public_tables_and_other_sessions() -> tuple[list[str], int]:
    engine = make_engine(DATABASE_URL)
    try:
        with engine.connect() as connection:
            tables = sa.inspect(connection).get_table_names(schema="public")
            other_sessions = connection.scalar(
                sa.text(
                    """
                    SELECT count(*)
                    FROM pg_stat_activity
                    WHERE datname = current_database()
                      AND pid <> pg_backend_pid()
                    """
                )
            )
            return tables, int(other_sessions or 0)
    finally:
        engine.dispose()


@pytest.fixture()
def _isolated_database() -> Iterator[None]:
    _reset_public_schema()
    try:
        yield
    finally:
        _reset_public_schema()
        tables, other_sessions = _public_tables_and_other_sessions()
        assert tables == []
        assert other_sessions == 0


def _table() -> sa.Table:
    return sa.Table(
        TEMP_TABLE,
        sa.MetaData(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("payload", sa.LargeBinary, nullable=False),
    )


def _set_payload_and_measure_logical_bytes(
    connection: sa.Connection, table: sa.Table, payload_bytes: int
) -> int:
    connection.execute(
        sa.update(table).values(payload=sa.func.decode(sa.func.repeat("ff", payload_bytes), "hex"))
    )
    logical_bytes = connection.scalar(
        sa.select(
            sa.func.octet_length(sa.cast(sa.func.row_to_json(table.table_valued()), sa.Text))
        ).select_from(table)
    )
    assert logical_bytes is not None
    return int(logical_bytes)


def _adjacent_payload_sizes_at_logical_boundary(
    connection: sa.Connection, table: sa.Table
) -> tuple[tuple[int, int], tuple[int, int]]:
    limit = recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW
    below_size = 0
    above_size = limit + 1
    below_logical = _set_payload_and_measure_logical_bytes(connection, table, below_size)
    above_logical = _set_payload_and_measure_logical_bytes(connection, table, above_size)
    assert below_logical <= limit < above_logical

    while above_size - below_size > 1:
        candidate = (below_size + above_size) // 2
        logical_bytes = _set_payload_and_measure_logical_bytes(connection, table, candidate)
        if logical_bytes <= limit:
            below_size, below_logical = candidate, logical_bytes
        else:
            above_size, above_logical = candidate, logical_bytes

    assert above_size == below_size + 1
    assert below_logical <= limit < above_logical
    return (below_size, below_logical), (above_size, above_logical)


def _expected_fingerprint(identifier: int, payload: bytes) -> dict[str, Any]:
    canonical = recovery._canonical_bytes(
        {
            "id": identifier,
            "payload": {"base64": base64.b64encode(payload).decode("ascii")},
        }
    )
    return {"row_count": 1, "rows_sha256": hashlib.sha256(canonical).hexdigest()}


@pytest.mark.parametrize(
    "unsafe_url",
    [
        f"sqlite:///{DATABASE}",
        "postgresql+psycopg://operator:secret@127.0.0.1/not_the_bytea_database",
    ],
)
def test_fixture_guard_refuses_wrong_backend_or_database_before_reset(
    unsafe_url: str,
) -> None:
    reset_attempted = False

    def guarded_reset(raw: str) -> None:
        nonlocal reset_attempted
        _validated_url(raw)
        reset_attempted = True

    with pytest.raises(RuntimeError, match="must use PostgreSQL and name exactly"):
        guarded_reset(unsafe_url)

    assert not reset_attempted


@pytest.mark.usefixtures("_isolated_database")
def test_live_bytea_fingerprint_and_oversize_preflight_are_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upgrade_database(DATABASE_URL)
    assert inspect_schema(DATABASE_URL).state is DatabaseSchemaState.VERSION_0002

    engine = sa.create_engine(DATABASE_URL, poolclass=NullPool, future=True)
    table = _table()
    backend_pid: int | None = None
    try:
        with engine.connect() as connection, connection.begin():
            backend_pid = int(connection.scalar(sa.text("SELECT pg_backend_pid()")))
            connection.execute(
                sa.text(
                    f"""
                    CREATE TEMPORARY TABLE {TEMP_TABLE} (
                        id integer PRIMARY KEY,
                        payload bytea NOT NULL
                    )
                    """
                )
            )
            sentinel = b"\x00\x01\x7f\x80\xfe\xff\x00"
            connection.execute(sa.insert(table).values(id=1, payload=sentinel))
            live_value = connection.scalar(sa.select(table.c.payload))
            assert type(live_value) is bytes
            assert live_value == sentinel
            assert recovery._fingerprint_table(
                connection, table, recovery._FingerprintCaptureBudget()
            ) == _expected_fingerprint(1, sentinel)

            (below_size, below_logical), (above_size, above_logical) = (
                _adjacent_payload_sizes_at_logical_boundary(connection, table)
            )
            assert below_size + 1 == above_size
            assert below_logical <= recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW
            assert above_logical > recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW

            _set_payload_and_measure_logical_bytes(connection, table, below_size)
            below_payload = bytes([0xFF]) * below_size
            assert recovery._fingerprint_table(
                connection, table, recovery._FingerprintCaptureBudget()
            ) == _expected_fingerprint(1, below_payload)

            _set_payload_and_measure_logical_bytes(connection, table, above_size)
            payload_before = connection.execute(
                sa.select(
                    sa.func.octet_length(table.c.payload),
                    sa.func.md5(table.c.payload),
                )
            ).one()
            public_before = recovery._capture_database_state(connection, expected_database=DATABASE)
            version_before = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            public_tables_before = tuple(sa.inspect(connection).get_table_names(schema="public"))
            artifact_entries_before = tuple(sorted(tmp_path.rglob("*")))
            stream_attempts = 0

            def forbidden_stream(*_args: object, **_kwargs: object) -> Iterator[dict[str, object]]:
                nonlocal stream_attempts
                stream_attempts += 1
                raise AssertionError("oversized bytea reached the raw-row stream")

            with monkeypatch.context() as patch:
                patch.setattr(recovery, "_stream_table_rows", forbidden_stream)
                with pytest.raises(RecoveryRefused) as refused:
                    recovery._fingerprint_table(
                        connection, table, recovery._FingerprintCaptureBudget()
                    )

            assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL
            assert stream_attempts == 0
            assert connection.in_transaction()
            assert int(connection.scalar(sa.text("SELECT pg_backend_pid()"))) == backend_pid
            assert connection.scalar(sa.text("SELECT current_database()")) == DATABASE
            assert (
                connection.execute(
                    sa.select(
                        sa.func.octet_length(table.c.payload),
                        sa.func.md5(table.c.payload),
                    )
                ).one()
                == payload_before
            )
            assert (
                recovery._capture_database_state(connection, expected_database=DATABASE)
                == public_before
            )
            assert (
                connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == version_before
            )
            assert (
                tuple(sa.inspect(connection).get_table_names(schema="public"))
                == public_tables_before
            )
            assert "outbox" not in public_tables_before
            assert connection.scalar(sa.text("SELECT count(*) FROM organizations")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM receipts")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM compliance_exports")) == 0
            assert tuple(sorted(tmp_path.rglob("*"))) == artifact_entries_before
    finally:
        engine.dispose()

    assert backend_pid is not None
    probe = sa.create_engine(DATABASE_URL, poolclass=NullPool, future=True)
    try:
        with probe.connect() as connection:
            assert (
                connection.scalar(
                    sa.text(
                        """
                    SELECT count(*)
                    FROM pg_class
                    WHERE relname = :table_name
                      AND relpersistence = 't'
                    """
                    ),
                    {"table_name": TEMP_TABLE},
                )
                == 0
            )
            assert (
                connection.scalar(
                    sa.text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"),
                    {"pid": backend_pid},
                )
                == 0
            )
    finally:
        probe.dispose()
