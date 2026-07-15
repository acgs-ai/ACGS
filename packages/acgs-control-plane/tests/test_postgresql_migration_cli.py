"""Opt-in PostgreSQL subprocess tests for the migration operator CLI.

These tests require the same exact disposable database and destructive-test
acknowledgement as the package's other PostgreSQL migration tests. The target
URL reaches the child process only through an explicitly named environment
variable and is never passed in argv.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection

from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    _POSTGRES_MIGRATION_LOCK_STATEMENT,
    HEAD_REVISION,
)

_TEST_POSTGRES_URL = os.environ.get("ACP_TEST_POSTGRES_URL")
if not _TEST_POSTGRES_URL:
    pytest.skip(
        "set ACP_TEST_POSTGRES_URL to run disposable PostgreSQL migration CLI tests",
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

_CHILD_DATABASE_URL_ENV = "ACP_TEST_MIGRATION_CLI_TARGET_URL"
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
    _reset_public_schema()
    try:
        yield
    finally:
        _reset_public_schema()


def _table_names() -> set[str]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            return set(sa.inspect(connection).get_table_names(schema="public"))
    finally:
        engine.dispose()


def _version_rows() -> list[str]:
    if "alembic_version" not in _table_names():
        return []
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            return list(
                connection.execute(sa.text("SELECT version_num FROM alembic_version"))
                .scalars()
                .all()
            )
    finally:
        engine.dispose()


def _assert_secret_free(value: str) -> None:
    password = _TEST_URL.password
    sensitive_values = [_TEST_POSTGRES_URL]
    if password:
        sensitive_values.append(password)
    for sensitive_value in sensitive_values:
        if sensitive_value in value:
            raise AssertionError("migration CLI subprocess exposed configured credentials")


def _invoke_cli(
    command: str,
    *,
    expected_database: str = _DISPOSABLE_DATABASE_NAME,
    acknowledge_forward_only: bool = False,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    package_root = Path(__file__).resolve().parents[1]
    arguments = [
        sys.executable,
        "-m",
        "acgs_control_plane.migration_cli",
        command,
        "--database-url-env",
        _CHILD_DATABASE_URL_ENV,
        "--expected-database",
        expected_database,
    ]
    if acknowledge_forward_only:
        arguments.append("--acknowledge-forward-only")

    for argument in arguments:
        _assert_secret_free(argument)

    environment = os.environ.copy()
    environment[_CHILD_DATABASE_URL_ENV] = _TEST_POSTGRES_URL
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    source_root = str(package_root / "src")
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = source_root + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )

    result = subprocess.run(
        arguments,
        cwd=package_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    _assert_secret_free(result.stdout)
    _assert_secret_free(result.stderr)
    output = result.stdout if result.stdout else result.stderr
    payload = json.loads(output)
    assert isinstance(payload, dict)
    return result, payload


def test_status_is_read_only_and_reports_empty_schema() -> None:
    result, payload = _invoke_cli("status")

    assert result.returncode == 0
    assert result.stderr == ""
    assert payload == {
        "command": "status",
        "ok": True,
        "schema_state": "empty",
        "target_revision": HEAD_REVISION,
    }
    assert _table_names() == set()
    assert _version_rows() == []


def test_upgrade_requires_forward_only_acknowledgement_without_mutation() -> None:
    result, payload = _invoke_cli("upgrade")

    assert result.returncode == 2
    assert result.stdout == ""
    assert payload["ok"] is False
    error = payload["error"]
    assert isinstance(error, dict)
    assert error["code"] == "usage_error"
    assert _table_names() == set()
    assert _version_rows() == []


def test_status_wrong_expected_database_fails_without_mutation() -> None:
    result, payload = _invoke_cli("status", expected_database="not_the_disposable_database")

    assert result.returncode == 65
    assert result.stdout == ""
    assert payload["ok"] is False
    error = payload["error"]
    assert isinstance(error, dict)
    assert error == {
        "code": "database_identity_mismatch",
        "message": "The connected PostgreSQL database did not match the operator expectation.",
        "retryable": False,
    }
    assert _table_names() == set()
    assert _version_rows() == []


def test_wrong_expected_database_fails_before_schema_mutation() -> None:
    result, payload = _invoke_cli(
        "upgrade",
        expected_database="not_the_disposable_database",
        acknowledge_forward_only=True,
    )

    assert result.returncode == 65
    assert result.stdout == ""
    assert payload["ok"] is False
    error = payload["error"]
    assert isinstance(error, dict)
    assert error == {
        "code": "database_identity_mismatch",
        "message": "The connected PostgreSQL database did not match the operator expectation.",
        "retryable": False,
    }
    assert _table_names() == set()
    assert _version_rows() == []


def test_lock_contention_is_retryable_and_retry_upgrades_once() -> None:
    holder_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with holder_engine.connect() as holder:
            with holder.begin():
                _assert_disposable_database(holder)
                acquired = holder.scalar(_POSTGRES_MIGRATION_LOCK_STATEMENT, _LOCK_PARAMETERS)
                assert acquired

                blocked, payload = _invoke_cli("upgrade", acknowledge_forward_only=True)
                assert blocked.returncode == 75
                assert blocked.stdout == ""
                assert payload["ok"] is False
                error = payload["error"]
                assert isinstance(error, dict)
                assert error["code"] == "migration_lock_unavailable"
                assert error["retryable"] is True
                assert _table_names() == set()
                assert _version_rows() == []
    finally:
        holder_engine.dispose()

    retried, payload = _invoke_cli("upgrade", acknowledge_forward_only=True)
    assert retried.returncode == 0
    assert retried.stderr == ""
    assert payload == {
        "after": "version_0002",
        "before": "empty",
        "command": "upgrade",
        "ok": True,
        "target_revision": HEAD_REVISION,
    }
    assert _version_rows() == [HEAD_REVISION]


def test_successful_upgrade_is_forward_only_and_idempotent() -> None:
    first, first_payload = _invoke_cli("upgrade", acknowledge_forward_only=True)
    assert first.returncode == 0
    assert first_payload["before"] == "empty"
    assert first_payload["after"] == "version_0002"

    second, second_payload = _invoke_cli("upgrade", acknowledge_forward_only=True)
    assert second.returncode == 0
    assert second_payload["before"] == "version_0002"
    assert second_payload["after"] == "version_0002"
    assert _version_rows() == [HEAD_REVISION]

    downgrade, payload = _invoke_cli("downgrade")
    assert downgrade.returncode == 2
    assert payload["ok"] is False
    error = payload["error"]
    assert isinstance(error, dict)
    assert error["code"] == "usage_error"
    assert _version_rows() == [HEAD_REVISION]
