"""Unit, subprocess, and packaged-artifact tests for the migration operator CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

import acgs_control_plane.migration_cli as migration_cli
import acgs_control_plane.migrations as migrations
from acgs_control_plane.migrations import (
    DatabaseIdentityMismatch,
    DatabaseSchemaState,
    MigrationLockUnavailable,
    MigrationResult,
    SchemaPreflight,
    UnsupportedMigrationDialect,
    inspect_schema,
    upgrade_database,
)

_DATABASE_URL_ENV = "ACP_TEST_MIGRATION_CLI_URL"
_EXPECTED_DATABASE = "acgs_control_plane_test"
_SECRET_URL = (
    f"postgresql+psycopg://migration_operator:operator-secret@db.invalid/{_EXPECTED_DATABASE}"
)


def _source_environment(package_root: Path) -> dict[str, str]:
    """Return an environment that resolves this package and its workspace dependency."""
    environment = os.environ.copy()
    repository_root = package_root.parents[1]
    source_paths = [
        str(package_root / "src"),
        str(repository_root / "packages" / "gove-zone" / "src"),
    ]
    existing_pythonpath = environment.get("PYTHONPATH")
    if existing_pythonpath:
        source_paths.append(existing_pythonpath)
    environment["PYTHONPATH"] = os.pathsep.join(source_paths)
    return environment


def _assert_secret_free(value: str) -> None:
    for sensitive_value in (_SECRET_URL, "operator-secret"):
        if sensitive_value in value:
            raise AssertionError("migration CLI output contained a configured sensitive value")


def _invoke(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, object] | None, dict[str, object] | None]:
    exit_code = migration_cli.main(arguments)
    captured = capsys.readouterr()
    _assert_secret_free(captured.out)
    _assert_secret_free(captured.err)
    stdout = json.loads(captured.out) if captured.out else None
    stderr = json.loads(captured.err) if captured.err else None
    return exit_code, stdout, stderr


def _target_arguments(command: str) -> list[str]:
    return [
        command,
        "--database-url-env",
        _DATABASE_URL_ENV,
        "--expected-database",
        _EXPECTED_DATABASE,
    ]


def test_status_reads_url_only_from_named_environment_and_emits_stable_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_DATABASE_URL_ENV, _SECRET_URL)
    observed: dict[str, str] = {}

    def inspect(database_url: str, *, expected_database: str | None = None) -> SchemaPreflight:
        observed.update(url=database_url, expected=expected_database or "")
        return SchemaPreflight(DatabaseSchemaState.EMPTY, "not emitted")

    monkeypatch.setattr(migration_cli, "inspect_schema", inspect)

    exit_code, stdout, stderr = _invoke(_target_arguments("status"), capsys)

    assert exit_code == 0
    assert stderr is None
    assert stdout == {
        "command": "status",
        "ok": True,
        "schema_state": "empty",
        "target_revision": "0002",
    }
    assert observed == {"url": _SECRET_URL, "expected": _EXPECTED_DATABASE}


def test_upgrade_requires_forward_only_acknowledgement_before_reading_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_DATABASE_URL_ENV, _SECRET_URL)
    called = False

    def fail_if_called(*args: object, **kwargs: object) -> MigrationResult:
        del args, kwargs
        nonlocal called
        called = True
        raise AssertionError("upgrade must not run")

    monkeypatch.setattr(migration_cli, "upgrade_database", fail_if_called)

    exit_code, stdout, stderr = _invoke(_target_arguments("upgrade"), capsys)

    assert exit_code == 2
    assert stdout is None
    assert stderr == {
        "command": "upgrade",
        "error": {
            "code": "usage_error",
            "message": "The migration operator arguments are invalid.",
            "retryable": False,
        },
        "ok": False,
    }
    assert called is False


def test_upgrade_forwards_expected_database_and_emits_no_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_DATABASE_URL_ENV, _SECRET_URL)
    observed: dict[str, str] = {}

    def upgrade(database_url: str, *, expected_database: str | None = None) -> MigrationResult:
        observed.update(url=database_url, expected=expected_database or "")
        return MigrationResult(
            before=SchemaPreflight(DatabaseSchemaState.EMPTY, "not emitted"),
            after=SchemaPreflight(DatabaseSchemaState.VERSION_0002, "not emitted"),
        )

    monkeypatch.setattr(migration_cli, "upgrade_database", upgrade)
    arguments = [*_target_arguments("upgrade"), "--acknowledge-forward-only"]

    exit_code, stdout, stderr = _invoke(arguments, capsys)

    assert exit_code == 0
    assert stderr is None
    assert stdout == {
        "after": "version_0002",
        "before": "empty",
        "command": "upgrade",
        "ok": True,
        "target_revision": "0002",
    }
    assert observed == {"url": _SECRET_URL, "expected": _EXPECTED_DATABASE}


@pytest.mark.parametrize(
    "duplicate_arguments",
    [
        ["--database-url-env", _DATABASE_URL_ENV],
        ["--expected-database", _EXPECTED_DATABASE],
        [
            "--database-url-env",
            _DATABASE_URL_ENV,
            "--expected-database",
            _EXPECTED_DATABASE,
        ],
    ],
)
def test_duplicate_target_options_fail_before_environment_or_database_access(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    duplicate_arguments: list[str],
) -> None:
    called = False

    def fail_if_called(*args: object, **kwargs: object) -> str:
        del args, kwargs
        nonlocal called
        called = True
        raise AssertionError("target loading must not run")

    monkeypatch.setattr(migration_cli, "_load_database_url", fail_if_called)
    monkeypatch.setattr(migration_cli, "inspect_schema", fail_if_called)

    exit_code, stdout, stderr = _invoke(
        [*_target_arguments("status"), *duplicate_arguments], capsys
    )

    assert exit_code == 2
    assert stdout is None
    assert stderr == {
        "command": "status",
        "error": {
            "code": "usage_error",
            "message": "The migration operator arguments are invalid.",
            "retryable": False,
        },
        "ok": False,
    }
    assert called is False


def test_url_database_mismatch_fails_before_operator_database_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_DATABASE_URL_ENV, _SECRET_URL)
    called = False

    def fail_if_called(*args: object, **kwargs: object) -> SchemaPreflight:
        del args, kwargs
        nonlocal called
        called = True
        raise AssertionError("database inspection must not run")

    monkeypatch.setattr(migration_cli, "inspect_schema", fail_if_called)
    arguments = [
        "status",
        "--database-url-env",
        _DATABASE_URL_ENV,
        "--expected-database",
        "a_different_database",
    ]

    exit_code, stdout, stderr = _invoke(arguments, capsys)

    assert exit_code == 65
    assert stdout is None
    assert stderr is not None
    assert isinstance(stderr["error"], dict)
    assert stderr["error"]["code"] == "database_identity_mismatch"
    assert called is False


@pytest.mark.parametrize("operation", ["inspect", "upgrade"])
def test_bound_library_url_mismatch_fails_before_engine_creation(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    called = False

    def fail_if_called(*args: object, **kwargs: object) -> object:
        del args, kwargs
        nonlocal called
        called = True
        raise AssertionError("engine creation must not run")

    monkeypatch.setattr(migrations, "make_engine", fail_if_called)

    with pytest.raises(DatabaseIdentityMismatch):
        if operation == "inspect":
            migrations.inspect_schema(_SECRET_URL, expected_database="a_different_database")
        else:
            migrations.upgrade_database(_SECRET_URL, expected_database="a_different_database")
    assert called is False


@pytest.mark.parametrize(
    ("exception_factory", "expected_code", "expected_exit", "retryable"),
    [
        (
            lambda: MigrationLockUnavailable(_SECRET_URL),
            "migration_lock_unavailable",
            75,
            True,
        ),
        (
            lambda: DatabaseIdentityMismatch(_SECRET_URL),
            "database_identity_mismatch",
            65,
            False,
        ),
        (
            lambda: RuntimeError(_SECRET_URL),
            "internal_error",
            70,
            False,
        ),
    ],
)
def test_upgrade_errors_are_typed_stable_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exception_factory: Callable[[], Exception],
    expected_code: str,
    expected_exit: int,
    retryable: bool,
) -> None:
    monkeypatch.setenv(_DATABASE_URL_ENV, _SECRET_URL)

    def fail(*args: object, **kwargs: object) -> MigrationResult:
        del args, kwargs
        raise exception_factory()

    monkeypatch.setattr(migration_cli, "upgrade_database", fail)
    arguments = [*_target_arguments("upgrade"), "--acknowledge-forward-only"]

    exit_code, stdout, stderr = _invoke(arguments, capsys)

    assert exit_code == expected_exit
    assert stdout is None
    assert stderr is not None
    error = stderr["error"]
    assert isinstance(error, dict)
    assert error["code"] == expected_code
    assert error["retryable"] is retryable


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        (["downgrade"], "usage_error"),
        (
            [
                "status",
                "--database-url",
                _SECRET_URL,
                "--expected-database",
                _EXPECTED_DATABASE,
            ],
            "usage_error",
        ),
        (
            [
                "status",
                "--database-url-env",
                "NOT-AN-ENV-NAME",
                "--expected-database",
                _EXPECTED_DATABASE,
            ],
            "invalid_environment_name",
        ),
    ],
)
def test_invalid_or_downgrade_invocations_fail_without_echoing_input(
    arguments: list[str],
    expected_code: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, stdout, stderr = _invoke(arguments, capsys)

    assert exit_code in {2, 64}
    assert stdout is None
    assert stderr is not None
    error = stderr["error"]
    assert isinstance(error, dict)
    assert error["code"] == expected_code


def test_missing_environment_and_non_postgresql_url_fail_before_database_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(_DATABASE_URL_ENV, raising=False)
    exit_code, stdout, stderr = _invoke(_target_arguments("status"), capsys)
    assert exit_code == 64
    assert stdout is None
    assert stderr is not None
    assert isinstance(stderr["error"], dict)
    assert stderr["error"]["code"] == "database_url_unavailable"

    monkeypatch.setenv(_DATABASE_URL_ENV, "sqlite:////tmp/not-used.sqlite3")
    exit_code, stdout, stderr = _invoke(_target_arguments("status"), capsys)
    assert exit_code == 64
    assert stdout is None
    assert stderr is not None
    assert isinstance(stderr["error"], dict)
    assert stderr["error"]["code"] == "unsupported_database_dialect"


def test_existing_unbound_sqlite_upgrade_remains_compatible_but_identity_bound_rejects(
    tmp_path: Path,
) -> None:
    compatible_url = f"sqlite:///{tmp_path / 'compatible.sqlite3'}"
    result = upgrade_database(compatible_url)
    assert result.before.state is DatabaseSchemaState.EMPTY
    assert result.after.state is DatabaseSchemaState.VERSION_0002

    rejected_url = f"sqlite:///{tmp_path / 'rejected.sqlite3'}"
    with pytest.raises(UnsupportedMigrationDialect):
        upgrade_database(rejected_url, expected_database="rejected")
    assert inspect_schema(rejected_url).state is DatabaseSchemaState.EMPTY


def test_module_subprocess_help_and_missing_environment_are_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = Path(__file__).resolve().parents[1]
    environment = _source_environment(package_root)
    environment.pop(_DATABASE_URL_ENV, None)
    help_result = subprocess.run(
        [sys.executable, "-m", "acgs_control_plane.migration_cli", "--help"],
        cwd=package_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "status" in help_result.stdout
    assert "upgrade" in help_result.stdout
    assert "downgrade" not in help_result.stdout

    missing = subprocess.run(
        [sys.executable, "-m", "acgs_control_plane.migration_cli", *_target_arguments("status")],
        cwd=package_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode == 64
    _assert_secret_free(missing.stdout)
    _assert_secret_free(missing.stderr)
    assert json.loads(missing.stderr)["error"]["code"] == "database_url_unavailable"
    monkeypatch.delenv(_DATABASE_URL_ENV, raising=False)


def _wheel_build_command(dist_dir: Path) -> list[str]:
    uv_bin = os.environ.get("UV_BIN")
    if uv_bin:
        return [
            uv_bin,
            "build",
            "--no-build-isolation",
            "--python",
            sys.executable,
            "--offline",
            "--no-index",
            "--no-cache",
            "--wheel",
            "--out-dir",
            str(dist_dir),
            ".",
        ]
    return ["uv", "build", "--wheel", "--out-dir", str(dist_dir), "."]


def test_wheel_contains_cli_and_extracted_module_help_runs(tmp_path: Path) -> None:
    package_root = Path(__file__).resolve().parents[1]
    dist_dir = tmp_path / "dist"
    build = subprocess.run(
        _wheel_build_command(dist_dir),
        cwd=package_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr

    wheels = list(dist_dir.glob("acgs_control_plane-*.whl"))
    assert len(wheels) == 1
    extracted_root = tmp_path / "wheel-extract"
    with zipfile.ZipFile(wheels[0]) as archive:
        assert "acgs_control_plane/migration_cli.py" in archive.namelist()
        archive.extractall(extracted_root)

    artifact_check = """
from pathlib import Path
import runpy
import sys
import acgs_control_plane
artifact_root = Path(sys.argv[1]).resolve()
assert Path(acgs_control_plane.__file__).resolve().is_relative_to(artifact_root)
sys.argv = ["python -m acgs_control_plane.migration_cli", "--help"]
runpy.run_module("acgs_control_plane.migration_cli", run_name="__main__")
"""
    environment = _source_environment(package_root)
    environment["PYTHONPATH"] = os.pathsep.join([str(extracted_root), environment["PYTHONPATH"]])
    verification = subprocess.run(
        [sys.executable, "-c", artifact_check, str(extracted_root)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verification.returncode == 0, verification.stderr
    assert "status" in verification.stdout
    assert "upgrade" in verification.stdout
