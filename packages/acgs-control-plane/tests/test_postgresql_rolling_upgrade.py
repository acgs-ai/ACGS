"""Candidate-local PostgreSQL rolling-upgrade evidence.

This module deliberately does not fetch or build an old application.  The old
implementation must be supplied as an immutable wheel path plus its expected
SHA-256.  Missing or mismatched artifacts are explicit blockers, never a
fallback to the source tree, a network package, or a mutable Git reference.

The currently supported candidate is the locally built wheel for the exact,
repository-unaccepted draft PR #337 head below: the pinned pre-G101 repair
candidate. Passing these tests is therefore local compatibility evidence, not
accepted-artifact or production rolling-upgrade evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine

# isort: split

from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    HEAD_REVISION,
    DatabaseSchemaState,
    inspect_schema,
    upgrade_database,
)

_OLD_CANDIDATE_COMMIT = "4f0c685b5d2ffac0e6a71810b77c6357b8d56a94"
_OLD_CANDIDATE_SHA256 = "40ff7b40f27a2b698d3b607c710f1866f11850a9a2c42a7c0eb51a6fe8be3d93"
_ARTIFACT_ENV = "ACP_TEST_OLD_APP_ARTIFACT"
_ARTIFACT_SHA_ENV = "ACP_TEST_OLD_APP_ARTIFACT_SHA256"
_POSTGRES_ENV = "ACP_TEST_POSTGRES_URL"
_EXPECTED_DATABASE = "acgs_control_plane_rolling_upgrade_test"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROBE = Path(__file__).with_name("_rolling_upgrade_app_probe.py")
_SOURCE = Path(__file__).parents[1] / "src"
_SYNTHETIC_API_KEY = "acp_test_rolling_upgrade_key_not_a_real_secret"
_BOOTSTRAP_TOKEN = "acp_test_rolling_bootstrap_not_a_real_secret"
_STREAM_CHUNK_BYTES = 4096
_MAX_PROTOCOL_LINE_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_PROTOCOL_TIMEOUT_SECONDS = 10.0
_OPERATOR_TIMEOUT_SECONDS = 20.0
_PROTOCOL_QUEUE_RECORDS = 8
_G009_ALLOWED_OLD_TABLE_CATALOG_ADDITIONS = frozenset({"uq_users_org_id_id"})
_G038_ALLOWED_AGENT_CATALOG_CHANGES = frozenset(
    {
        "project_id",
        "environment_id",
        "fk_agents_scope_environment",
        "ck_agents_scope_both_null_or_set",
        "uq_agents_scope_id",
        "uq_agents_org_name",
        "uq_agents_legacy_org_name",
        "uq_agents_scope_name",
    }
)
_G038_ALLOWED_POLICY_BUNDLE_CATALOG_CHANGES = frozenset({"uq_policy_bundles_one_active_per_org"})


class ArtifactRefusal(RuntimeError):
    """Stable, secret-free immutable-artifact refusal."""


@dataclass(frozen=True)
class OldArtifact:
    path: Path
    sha256: str
    source_commit: str


def _without_allowed_old_table_catalog_additions(
    rows: tuple[tuple[Any, ...], ...],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        row
        for row in rows
        if not (
            len(row) >= 7
            and row[1] == "users"
            and (
                row[4] in _G009_ALLOWED_OLD_TABLE_CATALOG_ADDITIONS
                or row[6] in _G009_ALLOWED_OLD_TABLE_CATALOG_ADDITIONS
            )
        )
        and not (
            len(row) >= 7
            and row[1] == "agents"
            and (
                row[2] in _G038_ALLOWED_AGENT_CATALOG_CHANGES
                or row[4] in _G038_ALLOWED_AGENT_CATALOG_CHANGES
                or row[6] in _G038_ALLOWED_AGENT_CATALOG_CHANGES
            )
        )
        and not (
            len(row) >= 7
            and row[1] == "policy_bundles"
            and row[6] in _G038_ALLOWED_POLICY_BUNDLE_CATALOG_CHANGES
        )
    )


def _decode_json_object(raw: str | bytes) -> tuple[str, dict[str, Any] | None]:
    """Decode without propagating decoder objects that retain hostile input."""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "invalid", None
    if not isinstance(value, dict):
        return "non-object", None
    return "object", value


def _sha256_file(path: Path, *, maximum_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_STREAM_CHUNK_BYTES):
            total += len(chunk)
            if total > maximum_bytes:
                raise ArtifactRefusal("bounded artifact or evidence size exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def _validate_old_artifact(path_value: str | None, digest_value: str | None) -> OldArtifact:
    if not path_value or not digest_value:
        raise ArtifactRefusal("immutable old app artifact path and SHA-256 are required")
    if _SHA256.fullmatch(digest_value) is None:
        raise ArtifactRefusal("old app artifact SHA-256 must be 64 lowercase hex characters")
    path = Path(path_value)
    if path.suffix != ".whl" or path.is_symlink() or not path.is_file():
        raise ArtifactRefusal("old app artifact must be an existing non-symlink wheel")
    if _sha256_file(path, maximum_bytes=_MAX_ARTIFACT_BYTES) != digest_value:
        raise ArtifactRefusal("old app artifact SHA-256 mismatch")
    if digest_value != _OLD_CANDIDATE_SHA256:
        raise ArtifactRefusal("old app artifact is not the pinned pre-G101 repair candidate build")
    return OldArtifact(
        path=path.resolve(),
        sha256=digest_value,
        source_commit=_OLD_CANDIDATE_COMMIT,
    )


def test_old_artifact_gate_refuses_absent_invalid_or_mismatched_inputs(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    wheel.write_bytes(b"candidate-local-old-app")
    digest = _sha256_file(wheel, maximum_bytes=_MAX_ARTIFACT_BYTES)

    with pytest.raises(ArtifactRefusal, match="path and SHA-256"):
        _validate_old_artifact(None, None)
    with pytest.raises(ArtifactRefusal, match="64 lowercase hex"):
        _validate_old_artifact(str(wheel), "not-a-digest")
    with pytest.raises(ArtifactRefusal, match="mismatch"):
        _validate_old_artifact(str(wheel), "0" * 64)
    with pytest.raises(ArtifactRefusal, match="not the pinned pre-G101 repair candidate"):
        _validate_old_artifact(str(wheel), digest)


def test_protocol_reader_refuses_queue_overflow_and_overlong_records() -> None:
    overflowing = _ProtocolReader(io.BytesIO(b"{}\n" * (_PROTOCOL_QUEUE_RECORDS + 1)), timeout=0.05)
    overflowing.finish()
    with pytest.raises(AssertionError, match="bounded response queue"):
        overflowing.payload()

    overlong = _ProtocolReader(
        io.BytesIO(b"x" * (_MAX_PROTOCOL_LINE_BYTES + 1) + b"\n"), timeout=0.05
    )
    overlong.finish()
    with pytest.raises(AssertionError, match="bounded line size"):
        overlong.payload()

    for hostile in (b"sentinel-not-json\n", b"\xffsentinel-binary\n"):
        invalid = _ProtocolReader(io.BytesIO(hostile), timeout=0.05)
        invalid.finish()
        with pytest.raises(AssertionError, match="returned invalid JSON") as caught:
            invalid.payload()
        diagnostics = "\n".join(
            (
                str(caught.value),
                repr(caught.value),
                repr(caught.value.args),
                repr(caught.value.__cause__),
                repr(caught.value.__context__),
                "".join(traceback.format_exception(caught.value)),
            )
        )
        assert "sentinel" not in diagnostics
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert invalid._items.empty()


def test_protocol_reader_enforces_deadline_without_waiting_for_eof() -> None:
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb", buffering=0)
    reader = _ProtocolReader(stream, timeout=0.02)
    try:
        with pytest.raises(AssertionError, match="response deadline exceeded"):
            reader.payload()
    finally:
        os.close(write_fd)
        reader.finish()
        stream.close()


def test_cleanup_is_bounded_and_attempts_every_collector_and_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Collector:
        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        def finish(self) -> None:
            calls.append(f"finish:{self.name}")
            if self.fail:
                raise RuntimeError("synthetic collector failure")

    with pytest.raises(AssertionError, match="one or more probe collectors"):
        _finish_collectors(Collector("first", fail=True), Collector("second"))  # type: ignore[arg-type]
    assert calls == ["finish:first", "finish:second"]

    class Probe:
        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        def close(self) -> None:
            calls.append(f"close:{self.name}")
            if self.fail:
                raise RuntimeError("synthetic probe failure")

    with pytest.raises(AssertionError, match="one or more rolling-upgrade processes"):
        _close_upgrade_processes(
            None,
            Probe("new", fail=True),  # type: ignore[arg-type]
            Probe("old"),  # type: ignore[arg-type]
        )
    assert calls[-2:] == ["close:new", "close:old"]

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    started = time.monotonic()
    _terminate_process(process)
    assert process.poll() is not None
    assert time.monotonic() - started < 4

    timeout_process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            ("import sys,time; print('sentinel-timeout-secret', flush=True); time.sleep(60)"),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    monkeypatch.setattr(sys.modules[__name__], "_OPERATOR_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(
        sys.modules[__name__], "_start_operator", lambda _database_url: timeout_process
    )
    with pytest.raises(AssertionError, match="operator response deadline") as caught:
        _operator("not-a-real-database-url")
    diagnostics = "\n".join(
        (
            str(caught.value),
            repr(caught.value),
            repr(caught.value.args),
            repr(caught.value.__cause__),
            repr(caught.value.__context__),
            "".join(traceback.format_exception(caught.value)),
        )
    )
    assert "sentinel-timeout-secret" not in diagnostics
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert timeout_process.poll() is not None
    assert timeout_process.stdout is not None and timeout_process.stdout.closed
    assert timeout_process.stderr is not None and timeout_process.stderr.closed


def _required_old_artifact() -> OldArtifact:
    try:
        return _validate_old_artifact(
            os.environ.get(_ARTIFACT_ENV), os.environ.get(_ARTIFACT_SHA_ENV)
        )
    except ArtifactRefusal as exc:
        pytest.skip(f"candidate-local rolling-upgrade blocker: {exc}")


def _required_postgres_url() -> str:
    database_url = os.environ.get(_POSTGRES_ENV)
    if not database_url:
        pytest.skip(f"set {_POSTGRES_ENV} to the dedicated disposable PostgreSQL database")
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        raise RuntimeError("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required")
    url = sa.engine.make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != _EXPECTED_DATABASE:
        raise RuntimeError(
            f"{_POSTGRES_ENV} must name exactly the disposable database {_EXPECTED_DATABASE!r}"
        )
    return database_url


@pytest.fixture()
def pg_engine() -> Iterator[Engine]:
    pytest.importorskip("psycopg")
    engine = make_engine(_required_postgres_url())
    with engine.begin() as connection:
        assert connection.scalar(sa.text("SELECT current_database()")) == _EXPECTED_DATABASE
        assert connection.scalar(sa.text("SHOW server_version_num")) == "170010"
        connection.execute(sa.text("DROP SCHEMA public CASCADE"))
        connection.execute(sa.text("CREATE SCHEMA public"))
    try:
        yield engine
    finally:
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT current_database()")) == _EXPECTED_DATABASE
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
        engine.dispose()


def _upgrade_to(database_url: str, revision: str) -> None:
    if revision == HEAD_REVISION:
        upgrade_database(database_url)
        return
    if revision != "0001":
        raise AssertionError(f"unsupported test setup revision: {revision}")
    engine = make_engine(database_url)
    try:
        # Base.metadata deliberately excludes Alembic-owned scope tables, so
        # this reconstructs the frozen v0/0001 application contract only.
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(
                sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)")
            )
            connection.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES ('0001')"))
    finally:
        engine.dispose()


def _catalog(connection: Connection) -> tuple[tuple[str, ...], ...]:
    rows = connection.execute(
        sa.text(
            """
            SELECT c.relkind::text, c.relname, coalesce(a.attname, ''),
                   coalesce(pg_catalog.format_type(a.atttypid, a.atttypmod), ''),
                   coalesce(con.conname, ''),
                   coalesce(pg_catalog.pg_get_constraintdef(con.oid, true), ''),
                   coalesce(idx.relname, ''),
                   coalesce(pg_catalog.pg_get_indexdef(idx.oid), '')
              FROM pg_catalog.pg_class AS c
              JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         LEFT JOIN pg_catalog.pg_attribute AS a
                ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
         LEFT JOIN pg_catalog.pg_constraint AS con ON con.conrelid = c.oid
         LEFT JOIN pg_catalog.pg_index AS ix ON ix.indrelid = c.oid
         LEFT JOIN pg_catalog.pg_class AS idx ON idx.oid = ix.indexrelid
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          ORDER BY c.relkind, c.relname, a.attnum, con.conname, idx.relname
            """
        )
    ).all()
    return tuple(tuple(str(value) for value in row) for row in rows)


def _rows(connection: Connection, table: str) -> tuple[tuple[str, ...], ...]:
    quoted = connection.dialect.identifier_preparer.quote(table)
    if table == "agents":
        select_list = "id, org_id, name, description, trust_tier, allowed_tools, status, created_at"
    else:
        select_list = "*"
    rows = connection.execute(sa.text(f"SELECT {select_list} FROM {quoted} ORDER BY 1")).all()
    return tuple(tuple(repr(value) for value in row) for row in rows)


def _state(engine: Engine) -> dict[str, Any]:
    with engine.connect() as connection:
        tables = tuple(sorted(sa.inspect(connection).get_table_names(schema="public")))
        version = (
            connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            if "alembic_version" in tables
            else None
        )
        return {
            "catalog": _catalog(connection),
            "rows": {table: _rows(connection, table) for table in tables},
            "tables": tables,
            "version": version,
        }


def _audit_state(audit_dir: Path) -> tuple[tuple[str, str], ...]:
    if not audit_dir.exists():
        return ()
    return tuple(
        (
            str(path.relative_to(audit_dir)),
            _sha256_file(path, maximum_bytes=_MAX_ARTIFACT_BYTES),
        )
        for path in sorted(audit_dir.rglob("*"))
        if path.is_file()
    )


def _audit_records(audit_dir: Path, org_id: str) -> tuple[dict[str, Any], ...]:
    path = audit_dir / f"{org_id}.audit.jsonl"
    records: list[dict[str, Any]] = []
    total = 0
    with path.open("rb") as stream:
        for raw_line in stream:
            total += len(raw_line)
            assert total <= _MAX_ARTIFACT_BYTES
            assert len(raw_line) <= _MAX_PROTOCOL_LINE_BYTES
            status, value = _decode_json_object(raw_line)
            raw_line = b""
            if status != "object" or value is None:
                raise AssertionError("audit evidence contained invalid JSON object")
            records.append(value)
    return tuple(records)


def _probe_env(database_url: str, audit_dir: Path, pythonpath: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"ACP_DATABASE_URL", "ACP_AUDIT_DIR", "ACP_BOOTSTRAP_TOKEN"}
    }
    env.update(
        {
            "ACP_PROBE_API_KEY": _SYNTHETIC_API_KEY,
            "ACP_PROBE_AUDIT_DIR": str(audit_dir),
            "ACP_PROBE_BOOTSTRAP_TOKEN": _BOOTSTRAP_TOKEN,
            "ACP_PROBE_DATABASE_URL": database_url,
            "PYTHONPATH": str(pythonpath),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONWARNINGS": "ignore",
        }
    )
    return env


class _ProtocolReader:
    """Continuously drain newline JSON with bounded per-record memory."""

    def __init__(self, stream: BinaryIO, *, timeout: float = _PROTOCOL_TIMEOUT_SECONDS) -> None:
        self._stream = stream
        self._timeout = timeout
        self._items: queue.Queue[tuple[str, bytes]] = queue.Queue(maxsize=_PROTOCOL_QUEUE_RECORDS)
        self._overflow = threading.Event()
        self._eof = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _emit(self, kind: str, payload: bytes = b"") -> None:
        try:
            self._items.put_nowait((kind, payload))
        except queue.Full:
            # Keep draining the pipe, retain nothing further, and make every
            # consumer fail closed on the bounded-queue overflow signal.
            self._overflow.set()

    def _run(self) -> None:
        buffer = bytearray()
        discarding = False
        read_chunk = getattr(self._stream, "read1", self._stream.read)
        try:
            while chunk := read_chunk(_STREAM_CHUNK_BYTES):
                for byte in chunk:
                    if discarding:
                        if byte == 10:
                            discarding = False
                            self._emit("error")
                        continue
                    if byte == 10:
                        self._emit("line", bytes(buffer))
                        buffer.clear()
                    elif len(buffer) == _MAX_PROTOCOL_LINE_BYTES:
                        buffer.clear()
                        discarding = True
                    else:
                        buffer.append(byte)
            if buffer or discarding:
                self._emit("error")
        except BaseException:
            self._emit("error")
        finally:
            self._eof.set()

    def _discard_items(self) -> None:
        while True:
            try:
                self._items.get_nowait()
            except queue.Empty:
                return

    def payload(self) -> dict[str, Any]:
        if self._overflow.is_set():
            self._discard_items()
            raise AssertionError("probe protocol exceeded its bounded response queue")
        try:
            kind, raw = self._items.get(timeout=self._timeout)
        except queue.Empty as exc:
            if self._eof.is_set():
                raise AssertionError("probe protocol ended without a response") from exc
            raise AssertionError("probe protocol response deadline exceeded") from exc
        if self._overflow.is_set():
            raw = b""
            self._discard_items()
            raise AssertionError("probe protocol exceeded its bounded response queue")
        if kind != "line":
            raw = b""
            self._discard_items()
            raise AssertionError("probe protocol ended or exceeded its bounded line size")
        status, value = _decode_json_object(raw)
        raw = b""
        if status == "invalid":
            self._discard_items()
            raise AssertionError("probe protocol returned invalid JSON")
        if status != "object" or value is None:
            self._discard_items()
            raise AssertionError("probe protocol returned a non-object")
        return value

    def finish(self) -> None:
        self._thread.join(timeout=3)
        assert not self._thread.is_alive(), "probe stdout collector did not stop"


class _DigestDrain:
    """Drain a diagnostic stream without retaining or redisplaying its content."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.bytes_seen = 0
        self.digest = hashlib.sha256()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        read_chunk = getattr(self._stream, "read1", self._stream.read)
        try:
            while chunk := read_chunk(_STREAM_CHUNK_BYTES):
                self.bytes_seen += len(chunk)
                self.digest.update(chunk)
        except BaseException:
            self.bytes_seen += 1

    def finish(self) -> None:
        self._thread.join(timeout=3)
        assert not self._thread.is_alive(), "probe stderr collector did not stop"


def _finish_collectors(*collectors: _ProtocolReader | _DigestDrain) -> None:
    failures = 0
    for collector in collectors:
        try:
            collector.finish()
        except BaseException:
            failures += 1
    if failures:
        raise AssertionError("one or more probe collectors did not stop")


class ProbeProcess:
    def __init__(self, database_url: str, audit_dir: Path, pythonpath: Path) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-P", str(_PROBE), "server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=_probe_env(database_url, audit_dir, pythonpath),
            cwd=Path(os.environ.get("TMPDIR", "/tmp")),
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._stdout = _ProtocolReader(self.process.stdout)
        self._stderr = _DigestDrain(self.process.stderr)
        try:
            self.started = self.read()
        except BaseException as exc:
            cleanup_failed = False
            try:
                _terminate_process(self.process)
            except BaseException:
                cleanup_failed = True
            try:
                _finish_collectors(self._stdout, self._stderr)
            except BaseException:
                cleanup_failed = True
            if cleanup_failed:
                raise AssertionError("probe startup cleanup failed") from exc
            raise

    def read(self) -> dict[str, Any]:
        return self._stdout.payload()

    def request(self, command_name: str, **payload: str) -> dict[str, Any]:
        assert self.process.stdin is not None
        encoded = json.dumps({"command": command_name, **payload}).encode() + b"\n"
        assert len(encoded) <= _MAX_PROTOCOL_LINE_BYTES
        self.process.stdin.write(encoded)
        self.process.stdin.flush()
        return self.read()

    def close(self) -> None:
        failed = False
        try:
            if self.process.poll() is None:
                assert self.request("stop") == {"status": "stopped"}
            self.process.wait(timeout=_PROTOCOL_TIMEOUT_SECONDS)
        except BaseException:
            failed = True
        try:
            _terminate_process(self.process)
        except BaseException:
            failed = True
        try:
            _finish_collectors(self._stdout, self._stderr)
        except BaseException:
            failed = True
        if failed:
            raise AssertionError("probe process shutdown failed")
        assert self.process.returncode == 0
        assert self._stderr.bytes_seen == 0, "probe stderr was non-empty"


def _start_once(database_url: str, audit_dir: Path, pythonpath: Path) -> dict[str, Any]:
    process = subprocess.Popen(
        [sys.executable, "-P", str(_PROBE), "start-once"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=_probe_env(database_url, audit_dir, pythonpath),
        cwd=Path(os.environ.get("TMPDIR", "/tmp")),
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout = _ProtocolReader(process.stdout)
    stderr = _DigestDrain(process.stderr)
    try:
        payload = stdout.payload()
        process.wait(timeout=_PROTOCOL_TIMEOUT_SECONDS)
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        _finish_collectors(stdout, stderr)
    assert process.returncode == 0
    assert stderr.bytes_seen == 0, "probe stderr was non-empty"
    return payload


def _start_operator(database_url: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["ACP_ROLLING_UPGRADE_DATABASE_URL"] = database_url
    return subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-m",
            "acgs_control_plane.migration_cli",
            "upgrade",
            "--database-url-env",
            "ACP_ROLLING_UPGRADE_DATABASE_URL",
            "--expected-database",
            _EXPECTED_DATABASE,
            "--acknowledge-forward-only",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=Path(os.environ.get("TMPDIR", "/tmp")),
    )


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _close_operator_streams(process: subprocess.Popen[str]) -> bool:
    clean = True
    for stream in (process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        try:
            stream.close()
        except BaseException:
            clean = False
    return clean


def _finish_operator(process: subprocess.Popen[str]) -> subprocess.CompletedProcess[str]:
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=_OPERATOR_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout = ""
        stderr = ""
    if timed_out:
        cleanup_failed = False
        try:
            _terminate_process(process)
        except BaseException:
            cleanup_failed = True
        try:
            # Drain through the public subprocess API after termination.  Do
            # not inspect CPython's private output-retention implementation.
            process.communicate(timeout=3)
        except BaseException:
            cleanup_failed = True
        if not _close_operator_streams(process):
            cleanup_failed = True
        if cleanup_failed:
            raise AssertionError("migration operator timeout cleanup failed")
        raise AssertionError("migration operator response deadline exceeded")
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def _operator(database_url: str) -> subprocess.CompletedProcess[str]:
    return _finish_operator(_start_operator(database_url))


def _close_upgrade_processes(
    operator: subprocess.Popen[str] | None,
    new_probe: ProbeProcess | None,
    old_probe: ProbeProcess | None,
) -> None:
    failures = 0
    if operator is not None:
        try:
            _terminate_process(operator)
        except BaseException:
            failures += 1
    for probe in (new_probe, old_probe):
        if probe is None:
            continue
        try:
            probe.close()
        except BaseException:
            failures += 1
    if failures:
        raise AssertionError("one or more rolling-upgrade processes did not stop")


def _replace_admin_key(engine: Engine, admin_user_id: str) -> None:
    digest = hashlib.sha256(_SYNTHETIC_API_KEY.encode()).hexdigest()
    with engine.begin() as connection:
        connection.execute(
            sa.text("UPDATE users SET api_key_hash=:digest WHERE id=:user_id"),
            {"digest": digest, "user_id": admin_user_id},
        )


def _connection_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return int(
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname=current_database() AND pid <> pg_backend_pid()"
                )
            )
            or 0
        )


def _assert_no_connections(engine: Engine) -> None:
    # The fixture pool may legitimately have opened multiple connections while
    # one connection held the deterministic DDL blocker.  Close those local
    # idle connections before measuring subprocess/interpreter leakage.
    engine.dispose()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if _connection_count(engine) == 0:
            return
        time.sleep(0.05)
    assert _connection_count(engine) == 0


def _wait_for_blocked_scope_ddl(engine: Engine, operator: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    statement = "%CREATE TABLE projects%"
    while time.monotonic() < deadline:
        assert operator.poll() is None, "migration operator exited before reaching blocked 0002 DDL"
        with engine.connect() as connection:
            blocked = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname=current_database() AND wait_event_type='Lock' "
                    "AND query LIKE :statement"
                ),
                {"statement": statement},
            )
        if blocked:
            return
        time.sleep(0.02)
    raise AssertionError("migration operator did not reach the deterministically blocked 0002 DDL")


def test_new_app_refuses_noncurrent_and_wrong_search_path_without_mutation(
    pg_engine: Engine, tmp_path: Path
) -> None:
    database_url = _required_postgres_url()
    cases = ("0001", "partial", "future", "unknown", "wrong-search-path")
    for case in cases:
        with pg_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
        if case == "unknown":
            with pg_engine.begin() as connection:
                connection.execute(sa.text("CREATE TABLE unexpected (id INTEGER PRIMARY KEY)"))
                connection.execute(sa.text("INSERT INTO unexpected (id) VALUES (17)"))
        else:
            _upgrade_to(database_url, "0001" if case == "0001" else HEAD_REVISION)
        if case == "partial":
            with pg_engine.begin() as connection:
                # Revision 0003, 0004, and 0005 tables reference environments,
                # so seeding the partial revision 0001 shape must remove them
                # first. Dropping environments with CASCADE instead would leave
                # them in place minus their foreign keys, which is not a shape
                # any real 0001 database has. One statement drops the whole set
                # together, so dependencies among the listed tables (the 0005
                # bootstrap tables all reference platform_bootstrap_invitations)
                # do not constrain the order.
                connection.execute(
                    sa.text(
                        "DROP TABLE tenant_bootstrap_refusal_events, "
                        "tenant_bootstrap_pending_outbox, pending_approvals, "
                        "tenant_bootstrap_policy_artifacts, "
                        "tenant_bootstrap_idempotency, "
                        "platform_bootstrap_invitations, organization_memberships, "
                        "managed_trust_keys, managed_trust_scopes, "
                        "managed_outbox, managed_governance_events, "
                        "managed_governance_event_heads, managed_receipt_consumptions, "
                        "managed_mutation_attempts, managed_decision_receipts"
                    )
                )
                # Revision 0006 puts the scope columns on agents, so agents now
                # references environments too. Dropping those columns takes the
                # scope foreign key and check constraint with them and restores
                # the pre-0006 unique constraint, which is the shape a real 0001
                # agents table has. Doing it this way rather than CASCADE keeps
                # the same invariant the comment above relies on: no table is
                # left behind minus its constraints.
                connection.execute(sa.text("DROP INDEX uq_agents_scope_name"))
                connection.execute(sa.text("DROP INDEX uq_agents_legacy_org_name"))
                connection.execute(sa.text("DROP INDEX uq_policy_bundles_one_active_per_org"))
                connection.execute(
                    sa.text(
                        "ALTER TABLE agents "
                        "DROP COLUMN project_id, DROP COLUMN environment_id, "
                        "ADD CONSTRAINT uq_agents_org_name UNIQUE (org_id, name)"
                    )
                )
                connection.execute(sa.text("DROP TABLE environments"))
                connection.execute(sa.text("UPDATE alembic_version SET version_num='0001'"))
        elif case == "future":
            with pg_engine.begin() as connection:
                connection.execute(sa.text("UPDATE alembic_version SET version_num='9999'"))
        before = _state(pg_engine)
        audit_dir = tmp_path / f"audit-{case}"
        url = database_url
        if case == "wrong-search-path":
            url = str(
                sa.engine.make_url(database_url).update_query_dict(
                    {"options": "-csearch_path=missing"}
                )
            )
        result = _start_once(url, audit_dir, _SOURCE)
        assert result["status"] == "refused"
        expected_error = (
            "database-operation-refused"
            if case == "wrong-search-path"
            else "schema-preflight-refused"
        )
        assert result["error_code"] == expected_error
        assert str(_SOURCE.resolve()) in result["module_origin"]
        assert _state(pg_engine) == before
        assert _audit_state(audit_dir) == ()
        _assert_no_connections(pg_engine)


def test_operator_refuses_held_migration_lock_without_mutation(
    pg_engine: Engine, tmp_path: Path
) -> None:
    database_url = _required_postgres_url()
    _upgrade_to(database_url, "0001")
    before = _state(pg_engine)
    audit_before = _audit_state(tmp_path / "audit-lock")
    with pg_engine.connect() as lock_connection:
        lock_connection.execute(sa.text("BEGIN"))
        assert lock_connection.scalar(
            sa.text("SELECT pg_try_advisory_xact_lock(:class_id, :object_id)"),
            {
                "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
                "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
            },
        )
        completed = _operator(database_url)
        lock_connection.rollback()
    assert completed.returncode == 75
    assert completed.stdout == ""
    error_status, error = _decode_json_object(completed.stderr)
    assert error_status == "object" and error is not None
    assert error["error"]["code"] == "migration_lock_unavailable"
    if database_url in completed.stderr:
        raise AssertionError("migration operator stderr exposed its database URL")
    assert _state(pg_engine) == before
    assert _audit_state(tmp_path / "audit-lock") == audit_before
    _assert_no_connections(pg_engine)


def test_candidate_old_app_remains_org_scoped_across_exact_operator_upgrade(
    pg_engine: Engine, tmp_path: Path
) -> None:
    old = _required_old_artifact()
    database_url = _required_postgres_url()
    _upgrade_to(database_url, "0001")
    seeded_0001 = _state(pg_engine)
    audit_dir = tmp_path / "audit"
    old_probe = ProbeProcess(database_url, audit_dir, old.path)
    operator: subprocess.Popen[str] | None = None
    new_probe: ProbeProcess | None = None
    try:
        assert old.sha256 == os.environ[_ARTIFACT_SHA_ENV]
        assert old.source_commit == _OLD_CANDIDATE_COMMIT
        assert str(old.path) in old_probe.started["module_origin"]
        assert old_probe.request("health") == {"body": {"status": "ok"}, "status_code": 200}
        assert _state(pg_engine) == seeded_0001
        bootstrapped = old_probe.request("bootstrap", name="Rolling Upgrade Candidate Org")
        assert bootstrapped["status_code"] == 201
        _replace_admin_key(pg_engine, bootstrapped["admin_user_id"])
        selected = old_probe.request("use_org", org_id=bootstrapped["org_id"])
        assert selected["status"] == "selected"
        before = _state(pg_engine)
        audit_before = _audit_state(audit_dir)
        assert before["version"] == "0001"
        assert "projects" not in before["tables"]
        assert "environments" not in before["tables"]
        assert old_probe.request("get_org")["status_code"] == 200

        started = time.monotonic()
        with pg_engine.connect() as ddl_blocker:
            transaction = ddl_blocker.begin()
            ddl_blocker.execute(sa.text("LOCK TABLE organizations IN ACCESS EXCLUSIVE MODE"))
            operator = _start_operator(database_url)
            _wait_for_blocked_scope_ddl(pg_engine, operator)
            during = old_probe.request("health")
            assert during == {"body": {"status": "ok"}, "status_code": 200}
            assert operator.poll() is None
            assert old_probe.process.poll() is None
            transaction.rollback()
        operator_completed = _finish_operator(operator)
        operator_stdout = operator_completed.stdout
        operator_stderr = operator_completed.stderr
        elapsed = time.monotonic() - started
        assert elapsed < 20
        if operator_completed.returncode != 0:
            raise AssertionError("migration operator returned a nonzero status")
        if operator_stderr:
            raise AssertionError("migration operator emitted unexpected diagnostics")
        operator_status, operator_payload = _decode_json_object(operator_stdout)
        assert operator_status == "object"
        assert operator_payload == {
            "after": DatabaseSchemaState.VERSION_0007.value,
            "before": "version_0001",
            "command": "upgrade",
            "ok": True,
            "target_revision": HEAD_REVISION,
        }
        assert old_probe.process.poll() is None
        assert old_probe.request("health") == {"body": {"status": "ok"}, "status_code": 200}

        migrated = _state(pg_engine)
        assert migrated["version"] == HEAD_REVISION
        assert set(migrated["tables"]) - set(before["tables"]) == {
            "agent_registration_idempotency",
            "environments",
            "managed_decision_receipts",
            "managed_governance_event_heads",
            "managed_governance_events",
            "managed_mutation_attempts",
            "managed_outbox",
            "managed_receipt_consumptions",
            "managed_trust_keys",
            "managed_trust_scopes",
            "organization_memberships",
            "pending_approvals",
            "platform_bootstrap_invitations",
            "projects",
            "tenant_bootstrap_idempotency",
            "tenant_bootstrap_pending_outbox",
            "tenant_bootstrap_policy_artifacts",
            "tenant_bootstrap_refusal_events",
        }
        for table in before["tables"]:
            before_catalog = tuple(row for row in before["catalog"] if row[1] == table)
            migrated_catalog = tuple(row for row in migrated["catalog"] if row[1] == table)
            assert _without_allowed_old_table_catalog_additions(
                migrated_catalog
            ) == _without_allowed_old_table_catalog_additions(before_catalog)
            if table == "alembic_version":
                continue
            assert migrated["rows"][table] == before["rows"][table]
        assert migrated["rows"]["agent_registration_idempotency"] == ()
        assert migrated["rows"]["projects"] == ()
        assert migrated["rows"]["environments"] == ()
        assert _audit_state(audit_dir) == audit_before

        new_probe = ProbeProcess(database_url, audit_dir, _SOURCE)
        assert old_probe.process.poll() is None
        assert new_probe.process.poll() is None
        assert old_probe.started["pid"] != new_probe.started["pid"]
        assert str(_SOURCE.resolve()) in new_probe.started["module_origin"]
        assert new_probe.request("use_org", org_id=bootstrapped["org_id"])["status"] == "selected"
        ready = new_probe.request("ready")
        assert ready["status_code"] == 503
        assert ready["body"]["schema_current"] is True
        assert ready["body"]["schema_state"] == DatabaseSchemaState.VERSION_0007.value
        assert old_probe.request("get_org")["status_code"] == 200
        assert new_probe.request("get_org")["status_code"] == 200

        audit_records_before_write = _audit_records(audit_dir, bootstrapped["org_id"])
        with pg_engine.connect() as connection:
            anchor_before_write = connection.execute(
                sa.text(
                    "SELECT audit_anchor_count, audit_anchor_hash "
                    "FROM organizations WHERE id=:org_id"
                ),
                {"org_id": bootstrapped["org_id"]},
            ).one()
        created = old_probe.request(
            "create_user",
            name="Post Upgrade Viewer",
            email="post-upgrade-viewer@example.com",
        )
        assert created["status_code"] == 201
        assert old_probe.request("get_org")["status_code"] == 200
        old_users = old_probe.request("list_users")
        new_users = new_probe.request("list_users")
        assert old_users["status_code"] == 200
        assert new_users["status_code"] == 200
        assert len(old_users["body"]) == 2
        assert len(new_users["body"]) == 2
        assert old_probe.process.poll() is None
        assert new_probe.process.poll() is None
        after_old_write = _state(pg_engine)
        assert len(after_old_write["rows"]["users"]) == len(migrated["rows"]["users"]) + 1
        assert len(after_old_write["rows"]["receipts"]) == len(migrated["rows"]["receipts"]) + 1
        assert after_old_write["rows"]["projects"] == ()
        assert after_old_write["rows"]["environments"] == ()
        assert after_old_write["rows"]["organization_memberships"] == ()
        assert after_old_write["rows"]["platform_bootstrap_invitations"] == ()
        assert after_old_write["rows"]["tenant_bootstrap_idempotency"] == ()
        assert after_old_write["rows"]["tenant_bootstrap_pending_outbox"] == ()
        assert after_old_write["rows"]["tenant_bootstrap_policy_artifacts"] == ()
        assert after_old_write["rows"]["tenant_bootstrap_refusal_events"] == ()
        receipt_id = created["body"]["receipt_id"]
        audit_records_after_write = _audit_records(audit_dir, bootstrapped["org_id"])
        assert len(audit_records_after_write) == len(audit_records_before_write) + 1
        event = audit_records_after_write[-1]
        assert event["event_id"] == receipt_id
        assert event["tool"] == "user.create"
        assert event["decision"] == "allow"
        assert event["path"] == ["control-plane", "users"]
        assert event["previous_hash"] == audit_records_before_write[-1]["event_hash"]
        with pg_engine.connect() as connection:
            receipt = (
                connection.execute(
                    sa.text(
                        "SELECT id, org_id, tool, decision, actor, argument_hash, audit_hash "
                        "FROM receipts WHERE id=:receipt_id"
                    ),
                    {"receipt_id": receipt_id},
                )
                .mappings()
                .one()
            )
            anchor_after_write = connection.execute(
                sa.text(
                    "SELECT audit_anchor_count, audit_anchor_hash "
                    "FROM organizations WHERE id=:org_id"
                ),
                {"org_id": bootstrapped["org_id"]},
            ).one()
        assert receipt["org_id"] == bootstrapped["org_id"]
        assert receipt["tool"] == event["tool"]
        assert receipt["decision"] == event["decision"]
        assert receipt["actor"] == event["actor"]
        assert receipt["argument_hash"] == event["argument_hash"]
        assert receipt["audit_hash"] == event["event_hash"]
        assert anchor_after_write[0] == anchor_before_write[0] + 1
        assert anchor_after_write[1] == event["event_hash"]
    finally:
        _close_upgrade_processes(operator, new_probe, old_probe)

    _assert_no_connections(pg_engine)
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0007
    assert _OLD_CANDIDATE_COMMIT == "4f0c685b5d2ffac0e6a71810b77c6357b8d56a94"
