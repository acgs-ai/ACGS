"""Unit evidence for the fail-closed local migration recovery drill."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import make_url

import acgs_control_plane.migration_recovery as recovery
from acgs_control_plane.migration_recovery import (
    ARCHIVE_NAME,
    DRILL_LABEL,
    EXPECTED_TABLES,
    MANIFEST_NAME,
    DatabaseState,
    RecoveryRefused,
    create_recovery_bundle,
    restore_recovery_bundle,
    verify_recovery_bundle,
)

ZERO_HASH = "0" * 64
SOURCE_URL = "postgresql+psycopg://operator:super-secret@db.invalid/source_drill"
TARGET_URL = "postgresql+psycopg://operator:target-secret@db.invalid/target_drill"


def _tables() -> dict[str, dict[str, Any]]:
    return {name: {"row_count": 0, "rows_sha256": ZERO_HASH} for name in EXPECTED_TABLES}


def _state(*, schema: str = ZERO_HASH) -> DatabaseState:
    return DatabaseState(schema_fingerprint=schema, tables=_tables(), audit_anchors={})


def _write_bundle(root: Path, *, archive: bytes = b"PGDMP-test") -> dict[str, Any]:
    root.mkdir(mode=0o700)
    archive_path = root / ARCHIVE_NAME
    archive_path.write_bytes(archive)
    os.chmod(archive_path, 0o600)
    manifest: dict[str, Any] = {
        "manifest_version": 1,
        "assurance_class": DRILL_LABEL,
        "integrity": "unkeyed_sha256",
        "source_database_name": "source_drill",
        "schema_fingerprint": ZERO_HASH,
        "table_fingerprints": _tables(),
        "artifacts": [
            {
                "path": ARCHIVE_NAME,
                "size": len(archive),
                "sha256": recovery._sha256_bytes(archive),
            }
        ],
        "audit_chains": [],
        "limitations": [
            "not_atomic_across_database_and_filesystem",
            "not_authenticated",
            "not_encrypted",
            "not_pitr",
            "not_production_dr_evidence",
        ],
    }
    (root / MANIFEST_NAME).write_bytes(recovery._canonical_bytes(manifest))
    os.chmod(root / MANIFEST_NAME, 0o600)
    return manifest


class _FakeTransaction:
    def __enter__(self) -> _FakeTransaction:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _FakeConnection:
    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execution_options(self, **_kwargs: object) -> _FakeConnection:
        return self

    def begin(self) -> _FakeTransaction:
        return _FakeTransaction()

    def execute(self, _statement: object) -> None:
        return None

    def scalar(self, _statement: object) -> str:
        return "00000003-0000001B-1"


class _FakeEngine:
    def connect(self) -> _FakeConnection:
        return _FakeConnection()

    def dispose(self) -> None:
        return None


def _patch_restore_boundary(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: DatabaseState | None = None,
) -> dict[str, Any]:
    boundary: dict[str, Any] = {"locked": False, "checks": 0}
    connection = object()

    @contextmanager
    def lock(_url: str, _database: str) -> Iterator[object]:
        assert not boundary["locked"]
        boundary["locked"] = True
        try:
            yield connection
        finally:
            boundary["locked"] = False

    def assert_empty(candidate: object, _database: str) -> None:
        assert candidate is connection
        assert boundary["locked"]
        boundary["checks"] += 1

    def capture(candidate: object, **_kwargs: object) -> DatabaseState:
        assert candidate is connection
        assert boundary["locked"]
        return state or _state()

    monkeypatch.setattr(recovery, "_target_migration_session_lock", lock)
    monkeypatch.setattr(recovery, "_assert_empty_target_connection", assert_empty)
    monkeypatch.setattr(recovery, "_capture_database_state", capture)
    return boundary


def test_create_publishes_canonical_private_bundle_without_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "bundle"
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setattr(recovery, "make_engine", lambda _url: _FakeEngine())
    monkeypatch.setattr(recovery, "_capture_database_state_url", lambda _url: _state())
    monkeypatch.setattr(
        recovery, "_capture_database_state", lambda _connection, **_kwargs: _state()
    )
    commands: list[list[str]] = []

    def runner(command: list[str], environment: dict[str, str]) -> None:
        commands.append(list(command))
        assert SOURCE_URL not in " ".join(command)
        assert "super-secret" not in " ".join(command)
        if command[0] == "pg_dump":
            file_argument = next(item for item in command if item.startswith("--file="))
            Path(file_argument.removeprefix("--file=")).write_bytes(b"PGDMP-test")
            assert "PGPASSWORD" not in environment
            passfile = Path(environment["PGPASSFILE"])
            assert stat.S_IMODE(passfile.stat().st_mode) == 0o600
            assert "super-secret" in passfile.read_text(encoding="utf-8")

    manifest = create_recovery_bundle(
        source_url_env="RECOVERY_SOURCE_URL",
        audit_dir=audit_dir,
        output=output,
        runner=runner,
    )

    assert output.is_dir()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / MANIFEST_NAME).stat().st_mode) == 0o600
    assert stat.S_IMODE((output / ARCHIVE_NAME).stat().st_mode) == 0o600
    assert (output / MANIFEST_NAME).read_bytes() == recovery._canonical_bytes(manifest)
    manifest_text = json.dumps(manifest)
    assert "super-secret" not in manifest_text
    assert SOURCE_URL not in manifest_text
    assert "raw_rows" not in manifest_text
    assert manifest["assurance_class"] == DRILL_LABEL
    assert [command[0] for command in commands] == ["pg_dump", "pg_restore"]
    dump = commands[0]
    assert "--format=custom" in dump
    assert "--no-owner" in dump
    assert "--no-acl" in dump
    assert any(item.startswith("--snapshot=") for item in dump)


def test_create_rejects_source_drift_and_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "bundle"
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setattr(recovery, "make_engine", lambda _url: _FakeEngine())
    states = iter([_state(), _state(schema="1" * 64)])
    monkeypatch.setattr(recovery, "_capture_database_state_url", lambda _url: next(states))
    monkeypatch.setattr(
        recovery, "_capture_database_state", lambda _connection, **_kwargs: _state()
    )

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if command[0] == "pg_dump":
            file_argument = next(item for item in command if item.startswith("--file="))
            Path(file_argument.removeprefix("--file=")).write_bytes(b"PGDMP-test")

    with pytest.raises(RecoveryRefused, match="before/snapshot/after"):
        create_recovery_bundle(
            source_url_env="RECOVERY_SOURCE_URL",
            audit_dir=audit_dir,
            output=output,
            runner=runner,
        )

    assert not output.exists()
    assert list(tmp_path.glob(".bundle.staging-*")) == []


def test_pg_environment_excludes_hostile_ambient_controls_and_unrelated_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setenv("PGHOST", "attacker.invalid")
    monkeypatch.setenv("PGSERVICE", "attacker-service")
    monkeypatch.setenv("PGPASSFILE", "/tmp/attacker-passfile")
    monkeypatch.setenv("PGOPTIONS", "-c search_path=attacker")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-cross-boundary")
    real_open = os.open
    initial_modes: list[tuple[int, int, int]] = []

    def observed_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if Path(path).name == ".pgpass":
            initial_modes.append((flags, mode, stat.S_IMODE(os.fstat(descriptor).st_mode)))
        return descriptor

    monkeypatch.setattr(recovery.os, "open", observed_open)

    with recovery._pg_environment(make_url(SOURCE_URL), tmp_path) as environment:
        assert environment["PGHOST"] == "db.invalid"
        assert environment["PGPORT"] == "5432"
        assert environment["PGDATABASE"] == "source_drill"
        assert environment["PGUSER"] == "operator"
        assert "PGSERVICE" not in environment
        assert "PGOPTIONS" not in environment
        assert "UNRELATED_SECRET" not in environment
        assert "RECOVERY_SOURCE_URL" not in environment
        passfile = Path(environment["PGPASSFILE"])
        assert passfile.parent == tmp_path
        assert stat.S_IMODE(passfile.stat().st_mode) == 0o600
    assert not passfile.exists()
    assert initial_modes == [
        (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            0o600,
        )
    ]


def test_pg_environment_never_removes_a_passfile_it_did_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passfile = tmp_path / ".pgpass"
    passfile.write_text("preserve", encoding="utf-8")

    with pytest.raises(RecoveryRefused, match="already exists"):
        with recovery._pg_environment(make_url(SOURCE_URL), tmp_path):
            pass

    assert passfile.read_text(encoding="utf-8") == "preserve"


def test_pg_environment_enforces_exact_mode_under_restrictive_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if getattr(recovery.os, "fchmod", None) is None:
        pytest.skip("platform has no descriptor chmod capability")
    real_open = os.open

    def restrictive_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        previous_umask = os.umask(0o777)
        try:
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)
        finally:
            os.umask(previous_umask)

    monkeypatch.setattr(recovery.os, "open", restrictive_open)

    with recovery._pg_environment(make_url(SOURCE_URL), tmp_path) as environment:
        passfile = Path(environment["PGPASSFILE"])
        assert stat.S_IMODE(passfile.stat().st_mode) == 0o600

    assert not passfile.exists()


def test_pg_environment_fails_closed_when_descriptor_chmod_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_close = os.close
    closed_descriptors: list[int] = []

    def close_descriptor(descriptor: int) -> None:
        closed_descriptors.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(
        recovery.os,
        "fchmod",
        lambda _descriptor, _mode: (_ for _ in ()).throw(OSError("chmod failed")),
        raising=False,
    )
    monkeypatch.setattr(recovery.os, "close", close_descriptor)

    with pytest.raises(OSError, match="chmod failed"):
        with recovery._pg_environment(make_url(SOURCE_URL), tmp_path):
            pass

    assert len(closed_descriptors) == 1
    assert not (tmp_path / ".pgpass").exists()


def test_pg_environment_remains_available_without_descriptor_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(recovery.os, "fchmod", raising=False)

    with recovery._pg_environment(make_url(SOURCE_URL), tmp_path) as environment:
        passfile = Path(environment["PGPASSFILE"])
        assert passfile.read_text(encoding="utf-8").endswith(":super-secret\n")

    assert not passfile.exists()


def test_fsync_directory_is_a_noop_without_directory_open_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(recovery.os, "O_DIRECTORY", raising=False)
    monkeypatch.setattr(
        recovery.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("directory open must not be attempted")
        ),
    )

    recovery._fsync_directory(tmp_path)


def test_fsync_directory_preserves_supported_posix_durability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory_flag = getattr(recovery.os, "O_DIRECTORY", None)
    if directory_flag is None:
        pytest.skip("platform has no POSIX directory-open capability")
    events: list[tuple[str, int]] = []

    def opened(path: Path, flags: int) -> int:
        assert path == tmp_path
        events.append(("open", flags))
        return 41

    monkeypatch.setattr(recovery.os, "open", opened)
    monkeypatch.setattr(
        recovery.os, "fsync", lambda descriptor: events.append(("fsync", descriptor))
    )
    monkeypatch.setattr(
        recovery.os, "close", lambda descriptor: events.append(("close", descriptor))
    )

    recovery._fsync_directory(tmp_path)

    assert events == [
        ("open", os.O_RDONLY | directory_flag),
        ("fsync", 41),
        ("close", 41),
    ]


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://operator@/source_drill",
        "postgresql+psycopg://db.invalid/source_drill",
    ],
)
def test_database_url_requires_explicit_endpoint_identity(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setenv("RECOVERY_URL", url)
    with pytest.raises(RecoveryRefused, match="explicitly identify"):
        recovery._url_from_named_environment("RECOVERY_URL")


def test_connection_database_identity_is_bound_before_state_use() -> None:
    class WrongDatabaseConnection:
        def scalar(self, _statement: object) -> str:
            return "wrong_database"

    with pytest.raises(RecoveryRefused, match="identity does not match"):
        recovery._assert_connection_database(  # type: ignore[arg-type]
            WrongDatabaseConnection(), "expected_database"
        )


class _RepeatableReadTransaction:
    def __init__(self, connection: _RepeatableReadConnection) -> None:
        self._connection = connection

    def __enter__(self) -> _RepeatableReadTransaction:
        self._connection.events.append("transaction_enter")
        return self

    def __exit__(self, *_args: object) -> None:
        self._connection.events.append("transaction_exit")
        self._connection.in_transaction = False


class _RepeatableReadConnection:
    def __init__(self, events: list[str], committed: dict[str, int]) -> None:
        self.events = events
        self._committed = committed
        self._snapshot_version: int | None = None
        self.isolation_level: str | None = None
        self.in_transaction = False
        self.read_only = False

    def execution_options(self, *, isolation_level: str) -> _RepeatableReadConnection:
        self.events.append("set_isolation")
        self.isolation_level = isolation_level
        return self

    def __enter__(self) -> _RepeatableReadConnection:
        self.events.append("connection_enter")
        return self

    def __exit__(self, *_args: object) -> None:
        self.events.append("connection_exit")

    def begin(self) -> _RepeatableReadTransaction:
        assert self.isolation_level == "REPEATABLE READ"
        self.events.append("begin")
        self._snapshot_version = self._committed["version"]
        self.in_transaction = True
        return _RepeatableReadTransaction(self)

    def execute(self, statement: object) -> None:
        assert self.in_transaction
        assert str(statement) == "SET TRANSACTION READ ONLY"
        self.events.append("set_read_only")
        self.read_only = True

    def observed_version(self) -> int:
        assert self.in_transaction and self.read_only
        assert self._snapshot_version is not None
        return self._snapshot_version


class _RepeatableReadEngine:
    def __init__(self, events: list[str], committed: dict[str, int]) -> None:
        self.connection = _RepeatableReadConnection(events, committed)
        self.events = events

    def connect(self) -> _RepeatableReadConnection:
        self.events.append("connect")
        return self.connection

    def dispose(self) -> None:
        self.events.append("dispose")


def test_url_capture_uses_one_read_only_repeatable_read_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    committed = {"version": 1}
    engine = _RepeatableReadEngine(events, committed)
    observed: list[int] = []
    monkeypatch.setattr(recovery, "make_engine", lambda _url: engine)

    def capture(connection: _RepeatableReadConnection, *, expected_database: str) -> DatabaseState:
        assert expected_database == "source_drill"
        events.append("preflight")
        observed.append(connection.observed_version())
        committed["version"] = 2
        events.append("concurrent_commit")
        events.append("raw_select")
        observed.append(connection.observed_version())
        return _state()

    monkeypatch.setattr(recovery, "_capture_database_state", capture)

    assert recovery._capture_database_state_url(SOURCE_URL) == _state()
    assert observed == [1, 1]
    assert events == [
        "connect",
        "set_isolation",
        "connection_enter",
        "begin",
        "transaction_enter",
        "set_read_only",
        "preflight",
        "concurrent_commit",
        "raw_select",
        "transaction_exit",
        "connection_exit",
        "dispose",
    ]


def test_url_capture_failure_closes_transaction_connection_and_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    engine = _RepeatableReadEngine(events, {"version": 1})
    monkeypatch.setattr(recovery, "make_engine", lambda _url: engine)

    def fail_capture(
        _connection: _RepeatableReadConnection, *, expected_database: str
    ) -> DatabaseState:
        assert expected_database == "source_drill"
        events.append("capture_failure")
        raise OSError("injected capture failure")

    monkeypatch.setattr(recovery, "_capture_database_state", fail_capture)

    with pytest.raises(RecoveryRefused, match="database state inspection failed"):
        recovery._capture_database_state_url(SOURCE_URL)

    assert events[-4:] == [
        "capture_failure",
        "transaction_exit",
        "connection_exit",
        "dispose",
    ]
    assert not engine.connection.in_transaction


def test_fingerprint_beta_envelope_constants_are_fixed() -> None:
    assert recovery.FINGERPRINT_MAX_ROWS_PER_TABLE == 100_000
    assert recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW == 1 * 1024 * 1024
    assert recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_TABLE == 64 * 1024 * 1024
    assert recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_CAPTURE == 128 * 1024 * 1024
    assert recovery.FINGERPRINT_FETCH_BATCH_SIZE == 1


def test_manifest_v1_fingerprint_golden_preserves_canonical_byte_sort(
    tmp_path: Path,
) -> None:
    budget = recovery._FingerprintCaptureBudget()
    fingerprint = recovery._fingerprint_canonical_rows(
        iter(
            [
                {"id": "1", "aaa": "z"},
                {"id": "2", "aaa": "a"},
            ]
        ),
        budget,
    )

    assert fingerprint == {
        "row_count": 2,
        "rows_sha256": "3c351d0d3de75ed523dc95b1903011306281aeca202cd7b7d792cbba042eab3c",
    }
    assert budget.canonical_bytes == 42
    assert list(tmp_path.iterdir()) == []


def test_fingerprint_row_count_accepts_exact_limit_and_refuses_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recovery, "FINGERPRINT_MAX_ROWS_PER_TABLE", 2)
    budget = recovery._FingerprintCaptureBudget()
    assert (
        recovery._fingerprint_canonical_rows(iter([{"value": "x"}, {"value": "x"}]), budget)[
            "row_count"
        ]
        == 2
    )

    with pytest.raises(RecoveryRefused) as refused:
        recovery._fingerprint_canonical_rows(
            iter([{"value": "x"}, {"value": "x"}, {"value": "x"}]),
            recovery._FingerprintCaptureBudget(),
        )
    assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL


def test_fingerprint_row_bytes_accept_exact_limit_and_refuse_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recovery, "FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW", 14)
    assert (
        recovery._fingerprint_canonical_rows(
            iter([{"value": "x"}]), recovery._FingerprintCaptureBudget()
        )["row_count"]
        == 1
    )

    with pytest.raises(RecoveryRefused) as refused:
        recovery._fingerprint_canonical_rows(
            iter([{"value": "xx"}]), recovery._FingerprintCaptureBudget()
        )
    assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL


def test_fingerprint_table_bytes_accept_exact_limit_and_refuse_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recovery, "FINGERPRINT_MAX_CANONICAL_BYTES_PER_TABLE", 28)
    assert (
        recovery._fingerprint_canonical_rows(
            iter([{"value": "x"}, {"value": "x"}]),
            recovery._FingerprintCaptureBudget(),
        )["row_count"]
        == 2
    )

    with pytest.raises(RecoveryRefused) as refused:
        recovery._fingerprint_canonical_rows(
            iter([{"value": "x"}, {"value": "xx"}]),
            recovery._FingerprintCaptureBudget(),
        )
    assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL


def test_fingerprint_capture_bytes_accept_exact_limit_and_refuse_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recovery, "FINGERPRINT_MAX_CANONICAL_BYTES_PER_CAPTURE", 28)
    exact_budget = recovery._FingerprintCaptureBudget()
    recovery._fingerprint_canonical_rows(iter([{"value": "x"}]), exact_budget)
    recovery._fingerprint_canonical_rows(iter([{"value": "x"}]), exact_budget)
    assert exact_budget.canonical_bytes == 28

    over_budget = recovery._FingerprintCaptureBudget()
    recovery._fingerprint_canonical_rows(iter([{"value": "x"}]), over_budget)
    with pytest.raises(RecoveryRefused) as refused:
        recovery._fingerprint_canonical_rows(iter([{"value": "xx"}]), over_budget)
    assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL


def test_table_rows_use_statement_scoped_fixed_streaming_options() -> None:
    class Result:
        def mappings(self) -> Iterator[dict[str, str]]:
            return iter([{"id": "one"}])

    class StreamingConnection:
        statement: Any = None

        def execute(self, statement: object) -> Result:
            self.statement = statement
            return Result()

    connection = StreamingConnection()
    table = sa.table("example", sa.column("id"))

    assert list(recovery._stream_table_rows(connection, table)) == [{"id": "one"}]  # type: ignore[arg-type]
    assert connection.statement.get_execution_options() == {
        "stream_results": True,
        "yield_per": 1,
        "max_row_buffer": 1,
    }


class _AggregateMappings:
    def __init__(self, row_count: int, max_logical_row_bytes: int) -> None:
        self._aggregate = {
            "row_count": row_count,
            "max_logical_row_bytes": max_logical_row_bytes,
        }

    def one(self) -> dict[str, int]:
        return self._aggregate


class _AggregateResult:
    def __init__(self, row_count: int, max_logical_row_bytes: int) -> None:
        self._mappings = _AggregateMappings(row_count, max_logical_row_bytes)

    def mappings(self) -> _AggregateMappings:
        return self._mappings


class _AggregateConnection:
    def __init__(self, row_count: int, max_logical_row_bytes: int) -> None:
        self._result = _AggregateResult(row_count, max_logical_row_bytes)
        self.statements: list[Any] = []

    def execute(self, statement: object) -> _AggregateResult:
        self.statements.append(statement)
        return self._result


def test_postgresql_preflight_is_aggregate_only_and_quotes_table_identity() -> None:
    table = sa.Table(
        'table"; DROP TABLE evidence; --',
        sa.MetaData(),
        sa.Column("payload", sa.LargeBinary),
        schema="public",
    )
    statement = recovery._fingerprint_preflight_statement(table)
    compiled = str(
        statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )

    assert tuple(statement.selected_columns.keys()) == (
        "row_count",
        "max_logical_row_bytes",
    )
    assert "SELECT count(*) AS row_count" in compiled
    assert "max(octet_length(CAST(row_to_json(" in compiled
    assert 'FROM public."table""; DROP TABLE evidence; --"' in compiled
    assert "payload" not in compiled


@pytest.mark.parametrize("column_type", [sa.JSON(), sa.LargeBinary()])
def test_postgresql_preflight_refuses_oversized_json_or_bytea_before_raw_stream(
    column_type: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    table = sa.Table(
        "typed_evidence",
        sa.MetaData(),
        sa.Column("payload", column_type),
        schema="public",
    )
    connection = _AggregateConnection(
        row_count=1,
        max_logical_row_bytes=recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW + 1,
    )
    stream_attempted = False

    def raw_stream(_connection: object, _table: object) -> Iterator[dict[str, Any]]:
        nonlocal stream_attempted
        stream_attempted = True
        return iter([{"payload": "must not be returned"}])

    monkeypatch.setattr(recovery, "_stream_table_rows", raw_stream)

    with pytest.raises(RecoveryRefused) as refused:
        recovery._fingerprint_table(  # type: ignore[arg-type]
            connection, table, recovery._FingerprintCaptureBudget()
        )

    assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL
    assert not stream_attempted
    assert len(connection.statements) == 1
    compiled = str(connection.statements[0].compile(dialect=postgresql.dialect()))
    assert "row_to_json(typed_evidence)" in compiled


def test_postgresql_preflight_accepts_exact_limits_and_refuses_one_over() -> None:
    table = sa.table("evidence", sa.column("payload"), schema="public")
    exact = _AggregateConnection(
        recovery.FINGERPRINT_MAX_ROWS_PER_TABLE,
        recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW,
    )
    recovery._preflight_table_fingerprint(exact, table)  # type: ignore[arg-type]

    for row_count, max_logical_row_bytes in (
        (recovery.FINGERPRINT_MAX_ROWS_PER_TABLE + 1, 0),
        (0, recovery.FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW + 1),
    ):
        over = _AggregateConnection(row_count, max_logical_row_bytes)
        with pytest.raises(RecoveryRefused) as refused:
            recovery._preflight_table_fingerprint(over, table)  # type: ignore[arg-type]
        assert str(refused.value) == recovery._FINGERPRINT_ENVELOPE_REFUSAL


@pytest.mark.parametrize("phase", ["before", "snapshot", "after"])
def test_fingerprint_envelope_refusal_never_publishes_and_cleans_staging(
    phase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "bundle"
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setattr(recovery, "make_engine", lambda _url: _FakeEngine())
    monkeypatch.setattr(recovery, "FINGERPRINT_MAX_ROWS_PER_TABLE", 0)
    url_captures = 0

    def refuse_from_envelope() -> None:
        recovery._fingerprint_canonical_rows(
            iter([{"value": "never serialized"}]),
            recovery._FingerprintCaptureBudget(),
        )

    def capture_url(_url: str) -> DatabaseState:
        nonlocal url_captures
        url_captures += 1
        if phase == "before" or (phase == "after" and url_captures == 2):
            refuse_from_envelope()
        return _state()

    def capture_snapshot(_connection: object, **_kwargs: object) -> DatabaseState:
        if phase == "snapshot":
            refuse_from_envelope()
        return _state()

    monkeypatch.setattr(recovery, "_capture_database_state_url", capture_url)
    monkeypatch.setattr(recovery, "_capture_database_state", capture_snapshot)
    commands: list[str] = []

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        commands.append(command[0])
        if command[0] == "pg_dump":
            file_argument = next(item for item in command if item.startswith("--file="))
            Path(file_argument.removeprefix("--file=")).write_bytes(b"PGDMP-test")

    with pytest.raises(RecoveryRefused, match=recovery._FINGERPRINT_ENVELOPE_REFUSAL):
        create_recovery_bundle(
            source_url_env="RECOVERY_SOURCE_URL",
            audit_dir=audit_dir,
            output=output,
            runner=runner,
        )

    assert not output.exists()
    assert list(tmp_path.glob(".bundle.staging-*")) == []
    assert commands == ([] if phase in {"before", "snapshot"} else ["pg_dump", "pg_restore"])


def test_create_fsyncs_artifacts_and_parent_in_durable_publish_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "bundle"
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setattr(recovery, "make_engine", lambda _url: _FakeEngine())
    monkeypatch.setattr(recovery, "_capture_database_state_url", lambda _url: _state())
    monkeypatch.setattr(
        recovery, "_capture_database_state", lambda _connection, **_kwargs: _state()
    )
    original_file = recovery._fsync_file
    original_directory = recovery._fsync_directory
    events: list[tuple[str, str, bool]] = []

    def fsync_file(path: Path) -> None:
        events.append(("file", path.name, output.exists()))
        original_file(path)

    def fsync_directory(path: Path) -> None:
        events.append(("directory", path.name, output.exists()))
        original_directory(path)

    monkeypatch.setattr(recovery, "_fsync_file", fsync_file)
    monkeypatch.setattr(recovery, "_fsync_directory", fsync_directory)

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if command[0] == "pg_dump":
            file_argument = next(item for item in command if item.startswith("--file="))
            Path(file_argument.removeprefix("--file=")).write_bytes(b"PGDMP-test")

    create_recovery_bundle(
        source_url_env="RECOVERY_SOURCE_URL",
        audit_dir=audit_dir,
        output=output,
        runner=runner,
    )

    audit_fsync = events.index(("directory", "audit", False))
    archive_fsync = events.index(("file", ARCHIVE_NAME, False))
    manifest_fsync = events.index(("file", MANIFEST_NAME, False))
    staging_fsync = next(
        index
        for index, event in enumerate(events)
        if event[0] == "directory" and event[1].startswith(".bundle.staging-")
    )
    parent_after_rename = next(
        index for index, event in enumerate(events) if event == ("directory", tmp_path.name, True)
    )
    assert audit_fsync < archive_fsync < manifest_fsync < staging_fsync < parent_after_rename


def test_create_fsync_failure_reports_refusal_and_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    output = tmp_path / "bundle"
    monkeypatch.setenv("RECOVERY_SOURCE_URL", SOURCE_URL)
    monkeypatch.setattr(recovery, "make_engine", lambda _url: _FakeEngine())
    monkeypatch.setattr(recovery, "_capture_database_state_url", lambda _url: _state())
    monkeypatch.setattr(
        recovery, "_capture_database_state", lambda _connection, **_kwargs: _state()
    )
    original_directory = recovery._fsync_directory

    def fail_staging_fsync(path: Path) -> None:
        if path.name.startswith(".bundle.staging-") and (path / MANIFEST_NAME).exists():
            raise OSError("injected fsync failure")
        original_directory(path)

    monkeypatch.setattr(recovery, "_fsync_directory", fail_staging_fsync)

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if command[0] == "pg_dump":
            file_argument = next(item for item in command if item.startswith("--file="))
            Path(file_argument.removeprefix("--file=")).write_bytes(b"PGDMP-test")

    with pytest.raises(RecoveryRefused, match="creation failed"):
        create_recovery_bundle(
            source_url_env="RECOVERY_SOURCE_URL",
            audit_dir=audit_dir,
            output=output,
            runner=runner,
        )
    assert not output.exists()
    assert list(tmp_path.glob(".bundle.staging-*")) == []


def test_publication_never_replaces_an_existing_destination(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    output = tmp_path / "bundle"
    output.mkdir()
    marker = output / "owner-data"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(RecoveryRefused, match="appeared"):
        recovery._publish_directory_no_replace(staging, output)
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert staging.is_dir()
    assert not (tmp_path / ".bundle.publish.lock").exists()


@pytest.mark.parametrize("unsafe_name", ["nested/escape.audit.jsonl", "bad.org.audit.jsonl"])
def test_audit_snapshot_rejects_unsafe_or_unexpected_artifacts(
    tmp_path: Path, unsafe_name: str
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    candidate = audit_dir / unsafe_name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("not trusted", encoding="utf-8")
    destination = tmp_path / "snapshot"

    with pytest.raises(RecoveryRefused):
        with recovery._locked_audit_snapshot(audit_dir, destination, {}):
            pass


def test_audit_snapshot_rejects_symlink_without_copying(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("payload", encoding="utf-8")
    (audit_dir / "org.audit.jsonl").symlink_to(outside)

    with pytest.raises(RecoveryRefused, match="symlink"):
        with recovery._locked_audit_snapshot(audit_dir, tmp_path / "snapshot", {}):
            pass


def _append_audit_event(audit_dir: Path, org_id: str = "org-audit") -> tuple[Path, str]:
    chain = audit_dir / f"{org_id}.audit.jsonl"
    event = ChainHashAuditStore(chain).append(
        DecisionRecord(
            decision=Decision.ALLOW,
            tool="recovery.test",
            argument_hash="a" * 64,
            policy_version="policy-v1",
            event_id="event-recovery-1",
            actor="operator",
        )
    )
    return chain, str(event["event_hash"])


def test_nonempty_audit_snapshot_matches_anchor_and_holds_lock_during_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    chain, anchor = _append_audit_event(audit_dir)
    lock_state = {"held": False}
    original_verify = ChainHashAuditStore.verify_chain

    @contextmanager
    def observed_lock(_stream: object) -> Iterator[None]:
        assert not lock_state["held"]
        lock_state["held"] = True
        try:
            yield
        finally:
            lock_state["held"] = False

    def observed_verify(store: ChainHashAuditStore, **kwargs: object) -> dict[str, Any]:
        assert lock_state["held"]
        return original_verify(store, **kwargs)

    monkeypatch.setattr(recovery, "_exclusive_file_lock", observed_lock)
    monkeypatch.setattr(ChainHashAuditStore, "verify_chain", observed_verify)
    destination = tmp_path / "snapshot"
    with recovery._locked_audit_snapshot(
        audit_dir, destination, {"org-audit": (1, anchor)}
    ) as descriptors:
        assert descriptors[0]["event_count"] == 1
        assert descriptors[0]["last_hash"] == anchor
        assert (destination / chain.name).read_bytes() == chain.read_bytes()
        assert lock_state["held"]
    assert not lock_state["held"]


def test_audit_snapshot_rejects_corruption_and_anchor_mismatch(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    chain, anchor = _append_audit_event(audit_dir)

    with pytest.raises(RecoveryRefused, match="does not match"):
        with recovery._locked_audit_snapshot(
            audit_dir, tmp_path / "wrong-anchor", {"org-audit": (1, "b" * 64)}
        ):
            pass

    payload = json.loads(chain.read_text(encoding="utf-8"))
    payload["actor"] = "tampered"
    chain.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(RecoveryRefused, match="does not match"):
        with recovery._locked_audit_snapshot(
            audit_dir, tmp_path / "corrupt", {"org-audit": (1, anchor)}
        ):
            pass


@pytest.mark.parametrize("zero_anchor", ["", ZERO_HASH])
def test_zero_event_audit_uses_genesis_consistently(tmp_path: Path, zero_anchor: str) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    with recovery._locked_audit_snapshot(
        audit_dir, tmp_path / "snapshot", {"org-empty": (0, zero_anchor)}
    ) as descriptors:
        assert descriptors == [
            {
                "org_id": "org-empty",
                "path": "audit/org-empty.audit.jsonl",
                "event_count": 0,
                "last_hash": ZERO_HASH,
                "size": 0,
                "sha256": recovery._sha256_bytes(b""),
            }
        ]


def test_verify_rejects_corruption_before_archive_tool_runs(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    (bundle / ARCHIVE_NAME).write_bytes(b"tampered")
    commands: list[list[str]] = []

    with pytest.raises(RecoveryRefused, match="integrity"):
        verify_recovery_bundle(
            bundle=bundle,
            runner=lambda command, _environment: commands.append(list(command)),
        )

    assert commands == []


def test_verify_rejects_symlink_and_unexpected_artifact(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (bundle / "extra").symlink_to(outside)

    with pytest.raises(RecoveryRefused, match="symlink"):
        verify_recovery_bundle(bundle=bundle, runner=lambda *_args: None)


def test_restore_prohibits_unacknowledged_untrusted_bundle_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    monkeypatch.setenv("RECOVERY_TARGET_URL", TARGET_URL)
    destructive: list[list[str]] = []

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if "--list" not in command:
            destructive.append(command)

    with pytest.raises(RecoveryRefused, match="untrusted bundles are prohibited"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env="RECOVERY_TARGET_URL",
            target_database_name="target_drill",
            target_audit_dir=tmp_path / "target-audit",
            runner=runner,
        )
    assert destructive == []


@pytest.mark.parametrize(
    ("target_name", "target_url", "audit_entry", "expected"),
    [
        ("not_the_url_name", TARGET_URL, None, "does not match"),
        ("source_drill", TARGET_URL.replace("target_drill", "source_drill"), None, "distinct"),
        ("target_drill", TARGET_URL, "existing.jsonl", "must be empty"),
    ],
)
def test_restore_negative_preflights_invoke_no_destructive_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
    target_url: str,
    audit_entry: str | None,
    expected: str,
) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    audit_target = tmp_path / "target-audit"
    audit_target.mkdir()
    if audit_entry:
        (audit_target / audit_entry).write_text("occupied", encoding="utf-8")
    monkeypatch.setenv("RECOVERY_TARGET_URL", target_url)
    destructive: list[list[str]] = []

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if "--list" not in command:
            destructive.append(list(command))

    with pytest.raises(RecoveryRefused, match=expected):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env="RECOVERY_TARGET_URL",
            target_database_name=target_name,
            target_audit_dir=audit_target,
            acknowledge_operator_controlled_bundle=True,
            runner=runner,
        )

    assert destructive == []


def test_restore_rejects_nonempty_database_before_destructive_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    monkeypatch.setenv("RECOVERY_TARGET_URL", TARGET_URL)
    _patch_restore_boundary(monkeypatch)

    def reject_nonempty(_connection: object, _database: str) -> None:
        raise RecoveryRefused("target database must be empty")

    monkeypatch.setattr(recovery, "_assert_empty_target_connection", reject_nonempty)
    destructive: list[list[str]] = []

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if "--list" not in command:
            destructive.append(list(command))

    with pytest.raises(RecoveryRefused, match="must be empty"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env="RECOVERY_TARGET_URL",
            target_database_name="target_drill",
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            runner=runner,
        )
    assert destructive == []
    assert not (tmp_path / "target-audit").exists()


def test_restore_uses_fail_closed_flags_and_publishes_audits_only_after_equivalence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    manifest = _write_bundle(bundle)
    monkeypatch.setenv("RECOVERY_TARGET_URL", TARGET_URL)
    boundary = _patch_restore_boundary(monkeypatch)
    commands: list[list[str]] = []

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if "--list" not in command:
            assert boundary["locked"]
            assert boundary["checks"] == 2
        commands.append(list(command))

    restore_recovery_bundle(
        bundle=bundle,
        target_url_env="RECOVERY_TARGET_URL",
        target_database_name="target_drill",
        target_audit_dir=tmp_path / "target-audit",
        acknowledge_operator_controlled_bundle=True,
        runner=runner,
    )

    destructive = [command for command in commands if "--list" not in command]
    assert len(destructive) == 1
    command = destructive[0]
    assert command[0] == "pg_restore"
    assert "--single-transaction" in command
    assert "--exit-on-error" in command
    assert "--no-owner" in command
    assert "--no-acl" in command
    assert "--dbname=target_drill" in command
    assert (tmp_path / "target-audit").is_dir()
    assert manifest["assurance_class"] == DRILL_LABEL
    assert boundary == {"locked": False, "checks": 2}


def test_restore_failure_leaves_audit_target_unpublished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    monkeypatch.setenv("RECOVERY_TARGET_URL", TARGET_URL)
    _patch_restore_boundary(monkeypatch)

    def runner(command: list[str], _environment: dict[str, str]) -> None:
        if "--list" not in command:
            raise RecoveryRefused("pg_restore failed")

    with pytest.raises(RecoveryRefused, match="failed"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env="RECOVERY_TARGET_URL",
            target_database_name="target_drill",
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            runner=runner,
        )

    assert not (tmp_path / "target-audit").exists()
    assert list(tmp_path.glob(".target-audit.restore-*")) == []


def test_cli_redacts_unexpected_secret_bearing_exception(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        recovery,
        "verify_recovery_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError(SOURCE_URL)),
    )

    assert recovery.main(["verify", "--bundle", "unused"]) == 2
    captured = capsys.readouterr()
    assert "super-secret" not in captured.err
    assert SOURCE_URL not in captured.err
    assert "without exposing sensitive details" in captured.err
