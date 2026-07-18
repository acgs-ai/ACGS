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
    database_name = connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
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
    return _schema_table_names("public")


def _schema_table_names(schema: str) -> set[str]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            return set(sa.inspect(connection).get_table_names(schema=schema))
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
    database_url: str = _TEST_POSTGRES_URL,
    extra_arguments: tuple[str, ...] = (),
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
    arguments.extend(extra_arguments)

    for argument in arguments:
        _assert_secret_free(argument)

    environment = os.environ.copy()
    environment.pop("ACP_TEST_POSTGRES_URL", None)
    environment[_CHILD_DATABASE_URL_ENV] = database_url
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


@pytest.mark.parametrize(
    "duplicate_arguments",
    [
        ("--database-url-env", _CHILD_DATABASE_URL_ENV),
        ("--expected-database", _DISPOSABLE_DATABASE_NAME),
        (
            "--database-url-env",
            _CHILD_DATABASE_URL_ENV,
            "--expected-database",
            _DISPOSABLE_DATABASE_NAME,
        ),
    ],
)
def test_duplicate_target_options_fail_before_database_access_without_mutation(
    duplicate_arguments: tuple[str, ...],
) -> None:
    result, payload = _invoke_cli("status", extra_arguments=duplicate_arguments)

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


def test_rogue_public_schema_fails_without_version_or_table_mutation() -> None:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("CREATE TABLE rogue_marker (id INTEGER PRIMARY KEY)"))
            connection.execute(sa.text("INSERT INTO rogue_marker (id) VALUES (7)"))
    finally:
        engine.dispose()

    result, payload = _invoke_cli("upgrade", acknowledge_forward_only=True)

    assert result.returncode == 65
    assert result.stdout == ""
    assert payload["ok"] is False
    error = payload["error"]
    assert isinstance(error, dict)
    assert error["code"] == "unsafe_schema_state"
    assert _table_names() == {"rogue_marker"}
    assert _version_rows() == []

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            assert connection.scalar(sa.text("SELECT id FROM rogue_marker")) == 7
    finally:
        engine.dispose()


def test_public_function_hijack_cannot_mutate_during_status() -> None:
    upgraded, payload = _invoke_cli("upgrade", acknowledge_forward_only=True)
    assert upgraded.returncode == 0
    assert payload["after"] == "version_0002"

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES (
                        'function-hijack-sentinel', 'unchanged', CURRENT_TIMESTAMP, 0, 'GENESIS'
                    )
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION public.current_setting(setting_name text)
                    RETURNS text
                    LANGUAGE plpgsql
                    AS $function$
                    BEGIN
                        UPDATE organizations
                        SET name = 'malicious-function-executed'
                        WHERE id = 'function-hijack-sentinel';
                        RETURN setting_name;
                    END
                    $function$
                    """
                )
            )

        status, payload = _invoke_cli("status")

        assert status.returncode == 0
        assert status.stderr == ""
        assert payload == {
            "command": "status",
            "ok": True,
            "schema_state": "version_0002",
            "target_revision": HEAD_REVISION,
        }
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            sentinel_name = connection.scalar(
                sa.text("SELECT name FROM organizations WHERE id = 'function-hijack-sentinel'")
            )
            assert sentinel_name == "unchanged"
    finally:
        engine.dispose()


def test_noncanonical_search_path_is_refused_without_public_or_shadow_mutation() -> None:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA shadow"))
            connection.execute(sa.text("CREATE TABLE shadow.sentinel (id INTEGER PRIMARY KEY)"))
            connection.execute(sa.text("INSERT INTO shadow.sentinel (id) VALUES (11)"))
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION shadow.current_database()
                    RETURNS name
                    LANGUAGE plpgsql
                    AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 12 WHERE id = 11;
                        RETURN 'acgs_control_plane_test';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION shadow.current_schema()
                    RETURNS name
                    LANGUAGE plpgsql
                    AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 13 WHERE id = 11;
                        RETURN 'shadow';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION shadow.current_setting(setting_name text)
                    RETURNS text
                    LANGUAGE plpgsql
                    AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 14 WHERE id = 11;
                        RETURN setting_name;
                    END
                    $function$
                    """
                )
            )

        shadow_url = _TEST_URL.update_query_dict(
            {"options": "-csearch_path=shadow,pg_catalog"}
        ).render_as_string(hide_password=False)
        result, payload = _invoke_cli(
            "upgrade",
            acknowledge_forward_only=True,
            database_url=shadow_url,
        )

        assert result.returncode == 65
        assert result.stdout == ""
        assert payload["ok"] is False
        error = payload["error"]
        assert isinstance(error, dict)
        assert error["code"] == "unsafe_schema_state"
        assert _table_names() == set()
        assert _schema_table_names("shadow") == {"sentinel"}

        with engine.connect() as connection:
            _assert_disposable_database(connection)
            assert connection.scalar(sa.text("SELECT id FROM shadow.sentinel")) == 11
    finally:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
        engine.dispose()


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
