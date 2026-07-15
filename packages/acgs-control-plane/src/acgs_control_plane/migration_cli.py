"""Secret-safe, forward-only operator CLI for control-plane migrations.

Database URLs are read only from an explicitly named environment variable. The
CLI never accepts, prints, or interpolates a URL or credential on the command
line or in its machine-readable output.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Final, Never, TextIO

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError

from acgs_control_plane.migrations import (
    HEAD_REVISION,
    DatabaseIdentityMismatch,
    MigrationLockUnavailable,
    MigrationPreflightError,
    UnsupportedMigrationDialect,
    inspect_schema,
    upgrade_database,
)

_EXIT_USAGE: Final = 2
_EXIT_CONFIGURATION: Final = 64
_EXIT_DATABASE_STATE: Final = 65
_EXIT_SOFTWARE: Final = 70
_EXIT_RETRYABLE: Final = 75
_ENVIRONMENT_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_COMMANDS: Final = frozenset({"status", "upgrade"})


class _UsageError(RuntimeError):
    """Argparse rejected an invocation without echoing untrusted input."""


class _OperatorError(RuntimeError):
    def __init__(self, code: str, message: str, exit_code: int, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.retryable = retryable


class _MachineParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise _UsageError


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database-url-env",
        required=True,
        metavar="ENV_VAR",
        help="name of the environment variable containing the PostgreSQL URL",
    )
    parser.add_argument(
        "--expected-database",
        required=True,
        metavar="NAME",
        help="exact PostgreSQL current_database() value expected by the operator",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = _MachineParser(
        prog="python -m acgs_control_plane.migration_cli",
        description="Inspect or advance the control-plane schema without accepting a URL in argv.",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="inspect schema state without mutation")
    status.allow_abbrev = False
    _add_target_arguments(status)

    upgrade = subparsers.add_parser("upgrade", help="advance schema to the packaged head")
    upgrade.allow_abbrev = False
    _add_target_arguments(upgrade)
    upgrade.add_argument(
        "--acknowledge-forward-only",
        action="store_true",
        required=True,
        help="acknowledge that this command never performs a downgrade",
    )
    return parser


def _write_json(stream: TextIO, payload: Mapping[str, object]) -> None:
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def _command_hint(arguments: Sequence[str]) -> str | None:
    if arguments and arguments[0] in _COMMANDS:
        return arguments[0]
    return None


def _error_payload(
    command: str | None, *, code: str, message: str, retryable: bool
) -> dict[str, object]:
    return {
        "command": command,
        "error": {"code": code, "message": message, "retryable": retryable},
        "ok": False,
    }


def _load_database_url(environment_name: str) -> str:
    if _ENVIRONMENT_NAME.fullmatch(environment_name) is None:
        raise _OperatorError(
            "invalid_environment_name",
            "Database URL environment variable name is invalid.",
            _EXIT_CONFIGURATION,
        )
    database_url = os.environ.get(environment_name)
    if not database_url:
        raise _OperatorError(
            "database_url_unavailable",
            "The named database URL environment variable is unset or empty.",
            _EXIT_CONFIGURATION,
        )
    try:
        backend_name = make_url(database_url).get_backend_name()
    except (ArgumentError, ValueError) as exc:
        raise _OperatorError(
            "database_url_invalid",
            "The named environment variable does not contain a valid database URL.",
            _EXIT_CONFIGURATION,
        ) from exc
    if backend_name != "postgresql":
        raise _OperatorError(
            "unsupported_database_dialect",
            "The migration operator CLI requires PostgreSQL.",
            _EXIT_CONFIGURATION,
        )
    return database_url


def _validate_expected_database(expected_database: str) -> None:
    if not expected_database or "\x00" in expected_database:
        raise _OperatorError(
            "expected_database_invalid",
            "The expected PostgreSQL database name is invalid.",
            _EXIT_CONFIGURATION,
        )


def _run_command(arguments: argparse.Namespace) -> dict[str, object]:
    environment_name = str(arguments.database_url_env)
    expected_database = str(arguments.expected_database)
    _validate_expected_database(expected_database)
    database_url = _load_database_url(environment_name)

    if arguments.command == "status":
        preflight = inspect_schema(database_url, expected_database=expected_database)
        return {
            "command": "status",
            "ok": True,
            "schema_state": preflight.state.value,
            "target_revision": HEAD_REVISION,
        }

    result = upgrade_database(database_url, expected_database=expected_database)
    return {
        "after": result.after.state.value,
        "before": result.before.state.value,
        "command": "upgrade",
        "ok": True,
        "target_revision": HEAD_REVISION,
    }


def _mapped_operator_error(exc: Exception) -> _OperatorError:
    if isinstance(exc, MigrationLockUnavailable):
        return _OperatorError(
            "migration_lock_unavailable",
            "Another migration operator holds the PostgreSQL migration lock.",
            _EXIT_RETRYABLE,
            retryable=True,
        )
    if isinstance(exc, DatabaseIdentityMismatch):
        return _OperatorError(
            "database_identity_mismatch",
            "The connected PostgreSQL database did not match the operator expectation.",
            _EXIT_DATABASE_STATE,
        )
    if isinstance(exc, UnsupportedMigrationDialect):
        return _OperatorError(
            "unsupported_database_dialect",
            "The migration operator CLI requires PostgreSQL.",
            _EXIT_CONFIGURATION,
        )
    if isinstance(exc, MigrationPreflightError):
        return _OperatorError(
            "unsafe_schema_state",
            "The database schema is not safe for the requested operation.",
            _EXIT_DATABASE_STATE,
        )
    if isinstance(exc, SQLAlchemyError):
        return _OperatorError(
            "database_operation_failed",
            "The database operation failed.",
            _EXIT_SOFTWARE,
        )
    return _OperatorError(
        "internal_error",
        "The migration operator failed.",
        _EXIT_SOFTWARE,
    )


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    command = _command_hint(raw_arguments)
    try:
        arguments = _build_parser().parse_args(raw_arguments)
    except _UsageError:
        _write_json(
            sys.stderr,
            _error_payload(
                command,
                code="usage_error",
                message="The migration operator arguments are invalid.",
                retryable=False,
            ),
        )
        return _EXIT_USAGE

    command = str(arguments.command)
    previous_logging_disable = logging.getLogger().manager.disable
    logging.disable(logging.CRITICAL)
    try:
        payload = _run_command(arguments)
    except _OperatorError as exc:
        _write_json(
            sys.stderr,
            _error_payload(
                command,
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            ),
        )
        return exc.exit_code
    except Exception as exc:
        operator_error = _mapped_operator_error(exc)
        _write_json(
            sys.stderr,
            _error_payload(
                command,
                code=operator_error.code,
                message=operator_error.message,
                retryable=operator_error.retryable,
            ),
        )
        return operator_error.exit_code
    finally:
        logging.disable(previous_logging_disable)

    _write_json(sys.stdout, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
