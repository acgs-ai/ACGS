"""Bounded subprocess driver for real PostgreSQL migration coordination tests.

The database URL is accepted only through ``ACP_TEST_POSTGRES_URL``.  Events are
secret-free NDJSON on stdout; stdin carries the single ``release`` control word.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from queue import Empty, Queue
from threading import Thread
from typing import Any, Final, Literal, Protocol, cast

import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy.engine import Connection, make_url

import acgs_control_plane.migrations as migration_module
from acgs_control_plane.migrations import (
    HEAD_REVISION,
    DatabaseSchemaState,
    MigrationLockUnavailable,
    upgrade_database,
)

_DATABASE_URL_ENV: Final = "ACP_TEST_POSTGRES_URL"
_DISPOSABLE_DATABASE: Final = "acgs_control_plane_test"
_RELEASE_TIMEOUT_SECONDS: Final = 30.0
_MODES: Final = frozenset({"ordinary", "pause-before-upgrade", "pause-after-upgrade"})


@dataclass(frozen=True)
class _ReaderMessage:
    kind: Literal["line", "error", "eof"]
    line: str = ""
    error: BaseException | None = None


class _ReadableTextStream(Protocol):
    def readline(self, size: int = -1, /) -> str: ...


class _ReleasedBeforeUpgrade(RuntimeError):
    """Release the lock-only worker without performing migration DDL."""


def _emit(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def _connection_identity(connection: Connection) -> tuple[str, int]:
    database = connection.scalar(sa.text("SELECT current_database()"))
    backend_pid = connection.scalar(sa.text("SELECT pg_backend_pid()"))
    if database != _DISPOSABLE_DATABASE:
        raise RuntimeError("refusing a non-disposable PostgreSQL database")
    if not isinstance(backend_pid, int) or backend_pid <= 0:
        raise RuntimeError("PostgreSQL did not return a valid backend PID")
    return database, backend_pid


def _read_release_control(stream: _ReadableTextStream, messages: Queue[_ReaderMessage]) -> None:
    try:
        line = stream.readline(64)
    except Exception as exc:
        messages.put(_ReaderMessage(kind="error", error=exc))
        return
    if line:
        messages.put(_ReaderMessage(kind="line", line=line))
    else:
        messages.put(_ReaderMessage(kind="eof"))


def _wait_for_release() -> None:
    messages: Queue[_ReaderMessage] = Queue(maxsize=1)
    reader = Thread(
        target=_read_release_control,
        args=(sys.stdin, messages),
        name="acgs-migration-release-reader",
        daemon=True,
    )
    reader.start()
    try:
        message = messages.get(timeout=_RELEASE_TIMEOUT_SECONDS)
    except Empty:
        raise TimeoutError("timed out waiting for bounded worker release") from None

    reader.join(timeout=1.0)
    if reader.is_alive():
        raise RuntimeError("worker release reader did not finish after producing a message")
    if message.kind == "error":
        error = message.error
        raise RuntimeError(f"worker release reader failed with {type(error).__name__}") from error
    if message.kind == "eof":
        raise RuntimeError("worker release control stream reached EOF")

    if message.line.rstrip("\r\n") != "release":
        raise RuntimeError("worker release control word was not received")


def _main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in _MODES:
        _emit({"event": "result", "status": "error", "error_type": "InvalidWorkerMode"})
        return 64
    mode = sys.argv[1]

    database_url = os.environ.get(_DATABASE_URL_ENV)
    if not database_url:
        _emit({"event": "result", "status": "error", "error_type": "MissingDatabaseURL"})
        return 64
    parsed_url = make_url(database_url)
    if parsed_url.get_backend_name() != "postgresql" or parsed_url.database != _DISPOSABLE_DATABASE:
        _emit({"event": "result", "status": "error", "error_type": "UnsafeDatabaseURL"})
        return 64

    identity: dict[str, object] = {"mode": mode, "os_pid": os.getpid()}
    original_acquire = migration_module._acquire_postgresql_migration_lock
    original_upgrade = migration_module.command.upgrade

    def capture_and_acquire(connection: Connection) -> None:
        _, backend_pid = _connection_identity(connection)
        identity["backend_pid"] = backend_pid
        original_acquire(connection)

    def controlled_upgrade(config: Config, revision: str, **kwargs: object) -> None:
        connection = config.attributes.get("connection")
        if not isinstance(connection, Connection):
            raise RuntimeError("worker requires the canonical injected PostgreSQL connection")
        _, backend_pid = _connection_identity(connection)
        identity["backend_pid"] = backend_pid

        if mode == "pause-before-upgrade":
            _emit(
                {
                    "event": "ready",
                    "stage": "after-lock-before-upgrade",
                    **identity,
                }
            )
            _wait_for_release()
            raise _ReleasedBeforeUpgrade

        cast(Callable[..., Any], original_upgrade)(config, revision, **kwargs)
        if mode == "pause-after-upgrade":
            state = migration_module.inspect_connection(connection).state
            if state is not DatabaseSchemaState.VERSION_0012:
                raise RuntimeError(
                    f"migration DDL did not reach revision {HEAD_REVISION} inside transaction"
                )
            _emit(
                {
                    "event": "ready",
                    "stage": "after-ddl-before-commit",
                    "transaction_state": state.value,
                    **identity,
                }
            )
            _wait_for_release()

    migration_module._acquire_postgresql_migration_lock = capture_and_acquire
    migration_module.command.upgrade = cast(Any, controlled_upgrade)
    try:
        result = upgrade_database(database_url)
    except _ReleasedBeforeUpgrade:
        _emit({"event": "result", "status": "released", **identity})
        return 0
    except MigrationLockUnavailable as exc:
        _emit(
            {
                "event": "result",
                "status": "error",
                "error_type": type(exc).__name__,
                **identity,
            }
        )
        return 3
    except Exception as exc:
        _emit(
            {
                "event": "result",
                "status": "error",
                "error_type": type(exc).__name__,
                **identity,
            }
        )
        return 1
    finally:
        migration_module._acquire_postgresql_migration_lock = original_acquire
        migration_module.command.upgrade = original_upgrade

    _emit(
        {
            "event": "result",
            "status": "success",
            "before": result.before.state.value,
            "after": result.after.state.value,
            **identity,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
