"""Fail-closed local recovery drill for control-plane schema migrations.

This module deliberately implements a narrow ``local_disposable_recovery_drill``.
It is not a production backup system, PITR, an encrypted archive, or an
authenticated proof.  The canonical manifest contains unkeyed SHA-256 digests;
it detects accidental corruption but cannot prove who produced a bundle.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

import sqlalchemy as sa
from gove_zone._locking import _exclusive_file_lock
from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from sqlalchemy.engine import URL, Connection, Engine, make_url

from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    DatabaseSchemaState,
    MigrationPreflightError,
    _bind_postgresql_operator_target,
    _install_postgresql_operator_connection_guard,
    inspect_connection,
)

DRILL_LABEL: Final = "local_disposable_recovery_drill"
MANIFEST_VERSION: Final = 1
MANIFEST_NAME: Final = "manifest.json"
ARCHIVE_NAME: Final = "database.dump"
AUDIT_DIRECTORY_NAME: Final = "audit"
FINGERPRINT_MAX_ROWS_PER_TABLE: Final = 100_000
FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW: Final = 1 * 1024 * 1024
FINGERPRINT_MAX_CANONICAL_BYTES_PER_TABLE: Final = 64 * 1024 * 1024
FINGERPRINT_MAX_CANONICAL_BYTES_PER_CAPTURE: Final = 128 * 1024 * 1024
FINGERPRINT_FETCH_BATCH_SIZE: Final = 1
EXPECTED_TABLES: Final = (
    "agents",
    "alembic_version",
    "compliance_exports",
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
    "organizations",
    "pending_approvals",
    "platform_bootstrap_invitations",
    "policy_bundles",
    "projects",
    "receipts",
    "tenant_bootstrap_idempotency",
    "tenant_bootstrap_pending_outbox",
    "tenant_bootstrap_policy_artifacts",
    "tenant_bootstrap_refusal_events",
    "users",
)
_ORG_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_DATABASE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_$-]{0,62}\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_AUDIT_SUFFIX = ".audit.jsonl"
_AUDIT_LOCK_SUFFIX = ".audit.jsonl.lock"
_FINGERPRINT_ENVELOPE_REFUSAL: Final = (
    "database fingerprint exceeds the fixed beta capture envelope"
)
_MANIFEST_KEYS: Final = frozenset(
    {
        "manifest_version",
        "assurance_class",
        "integrity",
        "source_database_name",
        "schema_fingerprint",
        "table_fingerprints",
        "artifacts",
        "audit_chains",
        "limitations",
    }
)
_LIMITATIONS: Final = (
    "not_atomic_across_database_and_filesystem",
    "not_authenticated",
    "not_encrypted",
    "not_pitr",
    "not_production_dr_evidence",
)
_PG_QUERY_ENV: Final = {
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "application_name": "PGAPPNAME",
}
_CHILD_ENV_ALLOWLIST: Final = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
)
_CANONICAL_PGOPTIONS: Final = "-csearch_path=public"

CommandRunner = Callable[[Sequence[str], Mapping[str, str]], None]


class RecoveryRefused(RuntimeError):
    """A safe, operator-correctable fail-closed refusal."""


@dataclass(frozen=True)
class DatabaseState:
    """No-row database evidence used for drift and restore equivalence."""

    schema_fingerprint: str
    tables: dict[str, dict[str, Any]]
    audit_anchors: dict[str, tuple[int, str]]


@dataclass
class _FingerprintCaptureBudget:
    canonical_bytes: int = 0


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    descriptor = os.open(path, os.O_RDONLY | directory_flag)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_directory_no_replace(staging: Path, output: Path) -> None:
    """Publish under an exclusive cooperating-writer lock and fsync the parent.

    Python has no portable rename-no-replace operation for directories. The
    O_EXCL sidecar closes races between this command's instances; an arbitrary
    same-user process that deliberately ignores the lock remains out of scope.
    """
    parent = output.parent.resolve(strict=True)
    lock_path = parent / f".{output.name}.publish.lock"
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RecoveryRefused("another bundle publication is already in progress") from exc
    try:
        if os.path.lexists(output):
            raise RecoveryRefused("bundle output appeared during publication")
        os.rename(staging, output)
        _fsync_directory(parent)
    finally:
        os.close(lock_fd)
        try:
            lock_path.unlink()
        finally:
            _fsync_directory(parent)


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return str(value)


def _safe_existing_directory(path: Path, *, label: str) -> Path:
    if path.is_symlink():
        raise RecoveryRefused(f"{label} must not be a symlink")
    try:
        info = path.stat()
    except OSError as exc:
        raise RecoveryRefused(f"{label} must be an existing directory") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RecoveryRefused(f"{label} must be an existing directory")
    return path.resolve(strict=True)


def _safe_regular_file(path: Path, *, label: str) -> Path:
    if path.is_symlink():
        raise RecoveryRefused(f"{label} must not be a symlink")
    try:
        info = path.stat()
    except OSError as exc:
        raise RecoveryRefused(f"{label} must be a regular file") from exc
    if not stat.S_ISREG(info.st_mode):
        raise RecoveryRefused(f"{label} must be a regular file")
    return path


def _contained(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _url_from_named_environment(name: str) -> tuple[str, URL]:
    if not name or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", name):
        raise RecoveryRefused("database URL environment variable name is invalid")
    raw = os.environ.get(name)
    if not raw:
        raise RecoveryRefused("named database URL environment variable is unset")
    try:
        url = make_url(raw)
    except Exception as exc:
        raise RecoveryRefused("named database URL is invalid") from exc
    if (
        url.get_backend_name() != "postgresql"
        or not url.database
        or not url.host
        or not url.username
    ):
        raise RecoveryRefused(
            "named database URL must explicitly identify a PostgreSQL host, user, and database"
        )
    if not _DATABASE_NAME.fullmatch(url.database):
        raise RecoveryRefused("database name is outside the supported safe character set")
    unknown = set(url.query) - set(_PG_QUERY_ENV)
    if unknown:
        raise RecoveryRefused("named database URL contains unsupported connection options")
    return raw, url


@contextmanager
def _pg_environment(url: URL, credential_directory: Path) -> Iterator[dict[str, str]]:
    """Yield a minimal libpq environment with an ephemeral private passfile."""
    env = _minimal_child_environment()
    env["PGDATABASE"] = str(url.database)
    env["PGUSER"] = str(url.username)
    env["PGHOST"] = str(url.host)
    env["PGPORT"] = str(url.port or 5432)
    env["PGCONNECT_TIMEOUT"] = "10"
    for key, destination in _PG_QUERY_ENV.items():
        value = url.query.get(key)
        if isinstance(value, str):
            env[destination] = value
    passfile: Path | None = None
    try:
        if url.password is not None:
            candidate = credential_directory / ".pgpass"

            def escape(value: str) -> str:
                return value.replace("\\", "\\\\").replace(":", "\\:")

            line = ":".join(
                escape(value)
                for value in (
                    str(url.host),
                    str(url.port or 5432),
                    str(url.database),
                    str(url.username),
                    url.password,
                )
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                raise RecoveryRefused("private PostgreSQL credential file already exists") from exc
            passfile = candidate
            try:
                descriptor_chmod = getattr(os, "fchmod", None)
                if descriptor_chmod is not None:
                    descriptor_chmod(descriptor, 0o600)
                stream = os.fdopen(descriptor, "w", encoding="utf-8")
            except Exception:
                os.close(descriptor)
                raise
            with stream:
                stream.write(line + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            env["PGPASSFILE"] = str(passfile)
        yield env
    finally:
        if passfile is not None:
            try:
                passfile.unlink()
            except FileNotFoundError:
                pass


def _minimal_child_environment() -> dict[str, str]:
    environment = {key: os.environ[key] for key in _CHILD_ENV_ALLOWLIST if key in os.environ}
    # libpq clients establish independent connections outside SQLAlchemy's
    # guarded session. Override, rather than inherit, ambient or role defaults
    # so pg_catalog remains implicitly ahead of the sole explicit public schema.
    environment["PGOPTIONS"] = _CANONICAL_PGOPTIONS
    return environment


def _run_command(command: Sequence[str], environment: Mapping[str, str]) -> None:
    try:
        subprocess.run(
            list(command),
            env=dict(environment),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        tool = Path(command[0]).name if command else "database tool"
        raise RecoveryRefused(f"{tool} failed; sensitive subprocess output was suppressed") from exc


def _defer_command_validation(_command: Sequence[str], _environment: Mapping[str, str]) -> None:
    """Defer archive-tool validation until the target connection is bound."""


def _schema_description(connection: Connection) -> dict[str, Any]:
    inspector = sa.inspect(connection)
    tables: dict[str, Any] = {}
    for table_name in EXPECTED_TABLES:
        columns = []
        for column in inspector.get_columns(table_name, schema="public"):
            columns.append(
                {
                    "name": column["name"],
                    "type": str(column["type"]).lower(),
                    "nullable": bool(column["nullable"]),
                    "default": str(column.get("default") or ""),
                }
            )
        tables[table_name] = {
            "columns": columns,
            "primary_key": sorted(
                inspector.get_pk_constraint(table_name, schema="public").get("constrained_columns")
                or []
            ),
            "foreign_keys": sorted(
                [
                    {
                        "columns": list(item.get("constrained_columns") or []),
                        "target_table": item.get("referred_table"),
                        "target_columns": list(item.get("referred_columns") or []),
                    }
                    for item in inspector.get_foreign_keys(table_name, schema="public")
                ],
                key=lambda item: json.dumps(item, sort_keys=True),
            ),
            "unique_constraints": sorted(
                [
                    sorted(item.get("column_names") or [])
                    for item in inspector.get_unique_constraints(table_name, schema="public")
                ]
            ),
            "indexes": sorted(
                [
                    {
                        "columns": list(item.get("column_names") or []),
                        "unique": bool(item.get("unique")),
                    }
                    for item in inspector.get_indexes(table_name, schema="public")
                ],
                key=lambda item: json.dumps(item, sort_keys=True),
            ),
        }
    return {"schema": "public", "tables": tables}


def _assert_connection_database(connection: Connection, expected_database: str) -> None:
    actual = connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
    if actual != expected_database:
        raise RecoveryRefused("database connection identity does not match the named URL")


def _install_recovery_connection_guard(engine: Engine) -> None:
    """Install the canonical migration operator's pre-dialect search-path guard."""
    _install_postgresql_operator_connection_guard(engine)


def _bind_recovery_connection(connection: Connection, expected_database: str) -> None:
    """Bind one recovery transaction to its exact database and public schema."""
    try:
        _bind_postgresql_operator_target(connection, expected_database)
    except MigrationPreflightError as exc:
        raise RecoveryRefused(
            "database connection is not bound to the named canonical public schema"
        ) from exc


def _stream_table_rows(connection: Connection, table: sa.Table) -> Iterator[Mapping[Any, Any]]:
    statement = sa.select(table).execution_options(
        stream_results=True,
        yield_per=FINGERPRINT_FETCH_BATCH_SIZE,
        max_row_buffer=FINGERPRINT_FETCH_BATCH_SIZE,
    )
    return iter(connection.execute(statement).mappings())


def _fingerprint_preflight_statement(table: sa.Table) -> sa.Select[Any]:
    logical_row_bytes = sa.func.octet_length(
        sa.cast(sa.func.row_to_json(table.table_valued()), sa.Text)
    )
    return sa.select(
        sa.func.count().label("row_count"),
        sa.func.coalesce(sa.func.max(logical_row_bytes), 0).label("max_logical_row_bytes"),
    ).select_from(table)


def _preflight_table_fingerprint(connection: Connection, table: sa.Table) -> None:
    aggregate = connection.execute(_fingerprint_preflight_statement(table)).mappings().one()
    row_count = int(aggregate["row_count"])
    max_logical_row_bytes = int(aggregate["max_logical_row_bytes"])
    if (
        row_count > FINGERPRINT_MAX_ROWS_PER_TABLE
        or max_logical_row_bytes > FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW
    ):
        raise RecoveryRefused(_FINGERPRINT_ENVELOPE_REFUSAL)


def _fingerprint_canonical_rows(
    rows: Iterator[Mapping[Any, Any]], capture_budget: _FingerprintCaptureBudget
) -> dict[str, Any]:
    digest = hashlib.sha256()
    canonical_rows: list[bytes] = []
    row_count = 0
    table_bytes = 0
    for row in rows:
        row_count += 1
        if row_count > FINGERPRINT_MAX_ROWS_PER_TABLE:
            raise RecoveryRefused(_FINGERPRINT_ENVELOPE_REFUSAL)
        canonical_row = _canonical_bytes(_normalize(dict(row)))
        row_bytes = len(canonical_row)
        if row_bytes > FINGERPRINT_MAX_CANONICAL_BYTES_PER_ROW:
            raise RecoveryRefused(_FINGERPRINT_ENVELOPE_REFUSAL)
        table_bytes += row_bytes
        if table_bytes > FINGERPRINT_MAX_CANONICAL_BYTES_PER_TABLE:
            raise RecoveryRefused(_FINGERPRINT_ENVELOPE_REFUSAL)
        capture_budget.canonical_bytes += row_bytes
        if capture_budget.canonical_bytes > FINGERPRINT_MAX_CANONICAL_BYTES_PER_CAPTURE:
            raise RecoveryRefused(_FINGERPRINT_ENVELOPE_REFUSAL)
        canonical_rows.append(canonical_row)

    canonical_rows.sort()
    for canonical_row in canonical_rows:
        digest.update(canonical_row)
    canonical_rows.clear()
    return {"row_count": row_count, "rows_sha256": digest.hexdigest()}


def _fingerprint_table(
    connection: Connection,
    table: sa.Table,
    capture_budget: _FingerprintCaptureBudget,
) -> dict[str, Any]:
    _preflight_table_fingerprint(connection, table)
    return _fingerprint_canonical_rows(_stream_table_rows(connection, table), capture_budget)


def _capture_database_state(
    connection: Connection, *, expected_database: str | None = None
) -> DatabaseState:
    if expected_database is not None:
        _assert_connection_database(connection, expected_database)
    preflight = inspect_connection(connection)
    if preflight.state is not DatabaseSchemaState.VERSION_0006:
        raise RecoveryRefused("database is not the exact supported migration head schema")
    inspector = sa.inspect(connection)
    observed = tuple(sorted(inspector.get_table_names(schema="public")))
    if observed != EXPECTED_TABLES:
        raise RecoveryRefused("database contains an unknown or incomplete table set")

    table_fingerprints: dict[str, dict[str, Any]] = {}
    capture_budget = _FingerprintCaptureBudget()
    for table_name in EXPECTED_TABLES:
        table = sa.Table(table_name, sa.MetaData(), autoload_with=connection, schema="public")
        table_fingerprints[table_name] = _fingerprint_table(connection, table, capture_budget)

    anchors: dict[str, tuple[int, str]] = {}
    rows = connection.execute(
        sa.text(
            "SELECT id, audit_anchor_count, audit_anchor_hash FROM public.organizations ORDER BY id"
        )
    ).mappings()
    for row in rows:
        org_id = str(row["id"])
        if not _ORG_ID.fullmatch(org_id):
            raise RecoveryRefused("source database contains an unsafe organization identifier")
        count = int(row["audit_anchor_count"])
        anchor = str(row["audit_anchor_hash"] or "")
        anchor_is_valid = (count == 0 and anchor in {"", GENESIS_HASH}) or (
            count > 0 and bool(_HEX_SHA256.fullmatch(anchor))
        )
        if count < 0 or not anchor_is_valid:
            raise RecoveryRefused("source database contains an invalid audit anchor")
        anchors[org_id] = (count, anchor)

    schema_fingerprint = _sha256_bytes(_canonical_bytes(_schema_description(connection)))
    return DatabaseState(schema_fingerprint, table_fingerprints, anchors)


def _capture_database_state_url(database_url: str) -> DatabaseState:
    try:
        expected_database = make_url(database_url).database
    except Exception as exc:
        raise RecoveryRefused("database state inspection URL is invalid") from exc
    if not expected_database:
        raise RecoveryRefused("database state inspection URL has no database name")
    engine = make_engine(database_url)
    _install_recovery_connection_guard(engine)
    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            with connection.begin():
                _bind_recovery_connection(connection, str(expected_database))
                connection.execute(sa.text("SET TRANSACTION READ ONLY"))
                return _capture_database_state(connection, expected_database=str(expected_database))
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("database state inspection failed") from exc
    finally:
        engine.dispose()


def _audit_source_entries(audit_dir: Path) -> dict[str, Path]:
    chains: dict[str, Path] = {}
    lock_orgs: set[str] = set()
    try:
        entries = list(audit_dir.iterdir())
    except OSError as exc:
        raise RecoveryRefused("audit source directory could not be read") from exc
    for entry in entries:
        if entry.is_symlink():
            raise RecoveryRefused("audit source contains a symlink")
        name = entry.name
        if name.endswith(_AUDIT_LOCK_SUFFIX):
            org_id = name[: -len(_AUDIT_LOCK_SUFFIX)]
            if not _ORG_ID.fullmatch(org_id) or not entry.is_file():
                raise RecoveryRefused("audit source contains an unsafe lock artifact")
            lock_orgs.add(org_id)
            continue
        if not name.endswith(_AUDIT_SUFFIX) or not entry.is_file():
            raise RecoveryRefused("audit source contains an unexpected artifact")
        org_id = name[: -len(_AUDIT_SUFFIX)]
        if not _ORG_ID.fullmatch(org_id):
            raise RecoveryRefused("audit source contains an unsafe organization identifier")
        chains[org_id] = entry
    if lock_orgs - set(chains):
        raise RecoveryRefused("audit source contains an orphan lock artifact")
    return chains


@contextmanager
def _locked_audit_snapshot(
    audit_dir: Path,
    destination: Path,
    anchors: Mapping[str, tuple[int, str]],
) -> Iterator[list[dict[str, Any]]]:
    chains = _audit_source_entries(audit_dir)
    if set(chains) - set(anchors):
        raise RecoveryRefused("audit source contains a chain absent from the database snapshot")
    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700)

    descriptors: list[dict[str, Any]] = []
    with ExitStack() as locks:
        for org_id in sorted(anchors):
            count, anchor = anchors[org_id]
            chain_path = chains.get(org_id)
            if chain_path is None:
                if count != 0 or anchor not in {"", GENESIS_HASH}:
                    raise RecoveryRefused("database audit anchor has no corresponding chain")
                target = destination / f"{org_id}{_AUDIT_SUFFIX}"
                target.touch(mode=0o600)
                os.chmod(target, 0o600)
                _fsync_file(target)
                descriptors.append(
                    {
                        "org_id": org_id,
                        "path": f"{AUDIT_DIRECTORY_NAME}/{target.name}",
                        "event_count": 0,
                        "last_hash": GENESIS_HASH,
                        "size": 0,
                        "sha256": _sha256_file(target),
                    }
                )
                continue

            _safe_regular_file(chain_path, label="audit chain")
            lock_path = chain_path.with_suffix(chain_path.suffix + ".lock")
            _safe_regular_file(lock_path, label="audit chain lock")
            lock_stream = locks.enter_context(lock_path.open("r+", encoding="utf-8"))
            locks.enter_context(_exclusive_file_lock(lock_stream))

        # Every chain is now frozen. Re-enumerate to catch a concurrent new chain.
        chains = _audit_source_entries(audit_dir)
        if set(chains) - set(anchors):
            raise RecoveryRefused("audit source changed while the snapshot was being acquired")

        for org_id in sorted(anchors):
            count, anchor = anchors[org_id]
            chain_path = chains.get(org_id)
            if chain_path is None:
                continue
            store = ChainHashAuditStore(chain_path)
            verification = store.verify_chain(
                expected_count=count,
                expected_last_hash=anchor or (GENESIS_HASH if count == 0 else None),
            )
            if not verification["valid"]:
                raise RecoveryRefused("audit chain does not match its database anchor")
            target = destination / chain_path.name
            with chain_path.open("rb") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
                output.flush()
            os.chmod(target, 0o600)
            _fsync_file(target)
            descriptors.append(
                {
                    "org_id": org_id,
                    "path": f"{AUDIT_DIRECTORY_NAME}/{target.name}",
                    "event_count": int(verification["checked"]),
                    "last_hash": str(verification["last_hash"]),
                    "size": target.stat().st_size,
                    "sha256": _sha256_file(target),
                }
            )
        _fsync_directory(destination)
        yield descriptors


def _artifact_descriptor(path: Path, relative_path: str) -> dict[str, Any]:
    return {"path": relative_path, "size": path.stat().st_size, "sha256": _sha256_file(path)}


def _write_manifest(staging: Path, manifest: dict[str, Any]) -> None:
    path = staging / MANIFEST_NAME
    with path.open("xb") as stream:
        stream.write(_canonical_bytes(manifest))
        stream.flush()
    os.chmod(path, 0o600)
    _fsync_file(path)


def create_recovery_bundle(
    *,
    source_url_env: str,
    audit_dir: Path,
    output: Path,
    runner: CommandRunner = _run_command,
) -> dict[str, Any]:
    """Create and atomically publish one integrity-labelled recovery bundle."""
    source_url, parsed_url = _url_from_named_environment(source_url_env)
    audit_root = _safe_existing_directory(audit_dir, label="audit source")
    output_parent = _safe_existing_directory(output.parent, label="bundle output parent")
    if output.exists() or output.is_symlink():
        raise RecoveryRefused("bundle output must not already exist")
    if output.parent.resolve(strict=True) != output_parent:
        raise RecoveryRefused("bundle output must be a direct child of its real parent")

    before = _capture_database_state_url(source_url)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output_parent))
    os.chmod(staging, 0o700)
    published = False
    engine: Engine | None = None
    try:
        archive = staging / ARCHIVE_NAME
        audit_destination = staging / AUDIT_DIRECTORY_NAME
        engine = make_engine(source_url)
        _install_recovery_connection_guard(engine)
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            with connection.begin():
                _bind_recovery_connection(connection, str(parsed_url.database))
                connection.execute(sa.text("SET TRANSACTION READ ONLY"))
                snapshot_id = str(
                    connection.scalar(sa.text("SELECT pg_catalog.pg_export_snapshot()"))
                )
                snapshot = _capture_database_state(
                    connection, expected_database=str(parsed_url.database)
                )
                with _locked_audit_snapshot(
                    audit_root, audit_destination, snapshot.audit_anchors
                ) as audit_descriptors:
                    with _pg_environment(parsed_url, staging) as pg_environment:
                        runner(
                            [
                                "pg_dump",
                                "--format=custom",
                                f"--file={archive}",
                                f"--snapshot={snapshot_id}",
                                "--schema=public",
                                "--no-owner",
                                "--no-acl",
                            ],
                            pg_environment,
                        )
                    _safe_regular_file(archive, label="database archive")
                    os.chmod(archive, 0o600)
                    _fsync_file(archive)
                    runner(
                        ["pg_restore", "--list", str(archive)],
                        _minimal_child_environment(),
                    )
                    after = _capture_database_state_url(source_url)
                    if before != snapshot or snapshot != after:
                        raise RecoveryRefused(
                            "source changed across before/snapshot/after checks; "
                            "retry in a maintenance window"
                        )

        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "assurance_class": DRILL_LABEL,
            "integrity": "unkeyed_sha256",
            "source_database_name": str(parsed_url.database),
            "schema_fingerprint": snapshot.schema_fingerprint,
            "table_fingerprints": snapshot.tables,
            "artifacts": [_artifact_descriptor(archive, ARCHIVE_NAME)],
            "audit_chains": audit_descriptors,
            "limitations": list(_LIMITATIONS),
        }
        _write_manifest(staging, manifest)
        _fsync_directory(staging)
        _publish_directory_no_replace(staging, output)
        published = True
        return manifest
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("recovery bundle creation failed") from exc
    finally:
        if engine is not None:
            engine.dispose()
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def _load_and_verify_manifest(bundle: Path, *, runner: CommandRunner) -> dict[str, Any]:
    root = _safe_existing_directory(bundle, label="recovery bundle")
    manifest_path = _safe_regular_file(root / MANIFEST_NAME, label="recovery manifest")
    if not _contained(root, manifest_path):
        raise RecoveryRefused("manifest escapes the recovery bundle")
    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryRefused("recovery manifest is unreadable") from exc
    if not isinstance(manifest, dict) or raw != _canonical_bytes(manifest):
        raise RecoveryRefused("recovery manifest is not canonical JSON")
    if set(manifest) != _MANIFEST_KEYS:
        raise RecoveryRefused("recovery manifest contains an unexpected field")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise RecoveryRefused("recovery manifest version is unsupported")
    if (
        manifest.get("assurance_class") != DRILL_LABEL
        or manifest.get("integrity") != "unkeyed_sha256"
    ):
        raise RecoveryRefused("recovery manifest assurance label is invalid")
    source_database_name = manifest.get("source_database_name")
    if not isinstance(source_database_name, str) or not _DATABASE_NAME.fullmatch(
        source_database_name
    ):
        raise RecoveryRefused("recovery manifest database name is invalid")
    if not isinstance(manifest.get("schema_fingerprint"), str) or not _HEX_SHA256.fullmatch(
        manifest["schema_fingerprint"]
    ):
        raise RecoveryRefused("recovery manifest schema fingerprint is invalid")
    table_fingerprints = manifest.get("table_fingerprints")
    if not isinstance(table_fingerprints, dict) or set(table_fingerprints) != set(EXPECTED_TABLES):
        raise RecoveryRefused("recovery manifest table set is invalid")
    for fingerprint in table_fingerprints.values():
        if not isinstance(fingerprint, dict) or set(fingerprint) != {
            "row_count",
            "rows_sha256",
        }:
            raise RecoveryRefused("recovery manifest table fingerprint is invalid")
        if not isinstance(fingerprint["row_count"], int) or fingerprint["row_count"] < 0:
            raise RecoveryRefused("recovery manifest table row count is invalid")
        if not isinstance(fingerprint["rows_sha256"], str) or not _HEX_SHA256.fullmatch(
            fingerprint["rows_sha256"]
        ):
            raise RecoveryRefused("recovery manifest table hash is invalid")
    if manifest.get("limitations") != list(_LIMITATIONS):
        raise RecoveryRefused("recovery manifest limitations are incomplete")

    permitted = {MANIFEST_NAME}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise RecoveryRefused("recovery manifest artifact set is invalid")
    audit_descriptors = manifest.get("audit_chains")
    if not isinstance(audit_descriptors, list):
        raise RecoveryRefused("recovery manifest audit set is invalid")

    for descriptor in [*artifacts, *audit_descriptors]:
        if not isinstance(descriptor, dict):
            raise RecoveryRefused("recovery manifest contains an invalid artifact")
        expected_keys = (
            {"path", "size", "sha256"}
            if descriptor in artifacts
            else {"org_id", "path", "event_count", "last_hash", "size", "sha256"}
        )
        if set(descriptor) != expected_keys:
            raise RecoveryRefused("recovery manifest artifact fields are invalid")
        relative = descriptor.get("path")
        if not isinstance(relative, str):
            raise RecoveryRefused("recovery manifest contains an invalid artifact path")
        candidate_relative = Path(relative)
        if candidate_relative.is_absolute() or ".." in candidate_relative.parts:
            raise RecoveryRefused("recovery manifest contains path traversal")
        candidate = root / candidate_relative
        _safe_regular_file(candidate, label="recovery artifact")
        if not _contained(root, candidate):
            raise RecoveryRefused("recovery artifact escapes the bundle")
        expected_hash = descriptor.get("sha256")
        expected_size = descriptor.get("size")
        if not isinstance(expected_hash, str) or not _HEX_SHA256.fullmatch(expected_hash):
            raise RecoveryRefused("recovery artifact hash is invalid")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise RecoveryRefused("recovery artifact size is invalid")
        if candidate.stat().st_size != expected_size or _sha256_file(candidate) != expected_hash:
            raise RecoveryRefused("recovery artifact integrity check failed")
        permitted.add(relative)

    archive = root / ARCHIVE_NAME
    if artifacts[0].get("path") != ARCHIVE_NAME:
        raise RecoveryRefused("recovery database archive path is invalid")
    runner(["pg_restore", "--list", str(archive)], _minimal_child_environment())

    seen_orgs: set[str] = set()
    for descriptor in audit_descriptors:
        org_id = descriptor.get("org_id")
        if not isinstance(org_id, str) or not _ORG_ID.fullmatch(org_id) or org_id in seen_orgs:
            raise RecoveryRefused("recovery manifest audit identity is invalid")
        seen_orgs.add(org_id)
        expected_path = f"{AUDIT_DIRECTORY_NAME}/{org_id}{_AUDIT_SUFFIX}"
        if descriptor.get("path") != expected_path:
            raise RecoveryRefused("recovery manifest audit path is invalid")
        count = descriptor.get("event_count")
        last_hash = descriptor.get("last_hash")
        if (
            not isinstance(count, int)
            or count < 0
            or not isinstance(last_hash, str)
            or not _HEX_SHA256.fullmatch(last_hash)
        ):
            raise RecoveryRefused("recovery manifest audit anchor is invalid")
        verification = ChainHashAuditStore(root / expected_path).verify_chain(
            expected_count=count, expected_last_hash=last_hash
        )
        if not verification["valid"]:
            raise RecoveryRefused("recovery audit chain verification failed")

    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RecoveryRefused("recovery bundle contains a symlink")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
        elif path.is_dir() and path != root / AUDIT_DIRECTORY_NAME:
            raise RecoveryRefused("recovery bundle contains an unexpected directory")
    if actual != permitted:
        raise RecoveryRefused("recovery bundle contains an unexpected artifact")
    return manifest


def verify_recovery_bundle(*, bundle: Path, runner: CommandRunner = _run_command) -> dict[str, Any]:
    """Verify unkeyed bundle integrity without mutating a database."""
    return _load_and_verify_manifest(bundle, runner=runner)


@contextmanager
def _target_migration_session_lock(
    database_url: str, expected_database: str
) -> Iterator[Connection]:
    """Hold the canonical migration advisory lock for the restore boundary."""
    engine = make_engine(database_url)
    _install_recovery_connection_guard(engine)
    try:
        with engine.connect() as connection:
            with connection.begin():
                _bind_recovery_connection(connection, expected_database)
                locked = bool(
                    connection.scalar(
                        sa.text("SELECT pg_catalog.pg_try_advisory_lock(:class_id, :object_id)"),
                        {
                            "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
                            "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
                        },
                    )
                )
            if not locked:
                raise RecoveryRefused("canonical migration lock is held by another operator")
            try:
                yield connection
            finally:
                if connection.in_transaction():
                    connection.rollback()
                connection.execute(
                    sa.text("SELECT pg_catalog.pg_advisory_unlock(:class_id, :object_id)"),
                    {
                        "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
                        "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
                    },
                )
                connection.commit()
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("target migration lock operation failed") from exc
    finally:
        engine.dispose()


def _assert_empty_target_connection(connection: Connection, expected_database: str) -> None:
    if connection.in_transaction():
        raise RecoveryRefused("target preflight requires a clean lock connection")
    with connection.begin():
        _bind_recovery_connection(connection, expected_database)
        public_tables = tuple(sorted(sa.inspect(connection).get_table_names(schema="public")))
        if public_tables:
            raise RecoveryRefused("target database must have an exact empty isolated schema")
        preflight = inspect_connection(connection)
        if preflight.state is not DatabaseSchemaState.EMPTY:
            raise RecoveryRefused("target database must have an exact empty isolated schema")


def _assert_empty_audit_target(path: Path) -> None:
    if path.is_symlink():
        raise RecoveryRefused("target audit directory must not be a symlink")
    if path.exists():
        if not path.is_dir():
            raise RecoveryRefused("target audit path must be an empty directory")
        try:
            if any(path.iterdir()):
                raise RecoveryRefused("target audit directory must be empty")
        except OSError as exc:
            raise RecoveryRefused("target audit directory could not be inspected") from exc
    parent = _safe_existing_directory(path.parent, label="target audit parent")
    if path.parent.resolve(strict=True) != parent:
        raise RecoveryRefused("target audit directory must be a direct child of its real parent")


def _stage_restore_inputs(
    bundle: Path, target: Path, manifest: Mapping[str, Any]
) -> tuple[Path, Path, Path]:
    parent = target.parent.resolve(strict=True)
    work = Path(tempfile.mkdtemp(prefix=f".{target.name}.restore-", dir=parent))
    os.chmod(work, 0o700)
    staged_audits = work / AUDIT_DIRECTORY_NAME
    staged_audits.mkdir(mode=0o700)
    staged_archive = work / ARCHIVE_NAME
    try:
        source_archive = bundle / ARCHIVE_NAME
        with source_archive.open("rb") as incoming, staged_archive.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
        os.chmod(staged_archive, 0o600)
        _fsync_file(staged_archive)
        archive_descriptor = manifest["artifacts"][0]
        if (
            staged_archive.stat().st_size != archive_descriptor["size"]
            or _sha256_file(staged_archive) != archive_descriptor["sha256"]
        ):
            raise RecoveryRefused("database archive changed while staging restore inputs")

        for descriptor in manifest["audit_chains"]:
            source = bundle / str(descriptor["path"])
            destination = staged_audits / source.name
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
                outgoing.flush()
            os.chmod(destination, 0o600)
            _fsync_file(destination)
            if (
                destination.stat().st_size != descriptor["size"]
                or _sha256_file(destination) != descriptor["sha256"]
            ):
                raise RecoveryRefused("audit chain changed while staging restore inputs")
            verification = ChainHashAuditStore(destination).verify_chain(
                expected_count=descriptor["event_count"],
                expected_last_hash=descriptor["last_hash"],
            )
            if not verification["valid"]:
                raise RecoveryRefused("staged audit chain verification failed")
        _fsync_directory(staged_audits)
        _fsync_directory(work)
        return work, staged_archive, staged_audits
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise


def restore_recovery_bundle(
    *,
    bundle: Path,
    target_url_env: str,
    target_database_name: str,
    target_audit_dir: Path,
    acknowledge_operator_controlled_bundle: bool = False,
    runner: CommandRunner = _run_command,
) -> dict[str, Any]:
    """Restore only into an explicitly named empty disposable target."""
    if not acknowledge_operator_controlled_bundle:
        raise RecoveryRefused(
            "untrusted bundles are prohibited; explicitly acknowledge an operator-controlled bundle"
        )
    target_url, parsed_url = _url_from_named_environment(target_url_env)
    if not _DATABASE_NAME.fullmatch(target_database_name):
        raise RecoveryRefused("explicit target database name is invalid")
    if parsed_url.database != target_database_name:
        raise RecoveryRefused("target URL database does not match the explicit target name")
    preflight_manifest = _load_and_verify_manifest(bundle, runner=_defer_command_validation)
    if target_database_name == preflight_manifest["source_database_name"]:
        raise RecoveryRefused("target database must be distinct from the source database")
    _assert_empty_audit_target(target_audit_dir)

    bundle_root = bundle.resolve(strict=True)
    with _target_migration_session_lock(target_url, target_database_name) as target_connection:
        _assert_empty_target_connection(target_connection, target_database_name)
        manifest = _load_and_verify_manifest(bundle_root, runner=runner)
        restore_work, staged_archive, staged_audits = _stage_restore_inputs(
            bundle_root, target_audit_dir, manifest
        )
        try:
            # Immediate cooperative-boundary TOCTOU recheck. Arbitrary writers
            # that ignore the canonical advisory lock remain outside this drill.
            _assert_empty_target_connection(target_connection, target_database_name)
            with _pg_environment(parsed_url, restore_work) as pg_environment:
                runner(
                    [
                        "pg_restore",
                        "--single-transaction",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-acl",
                        "--schema=public",
                        f"--dbname={target_database_name}",
                        str(staged_archive),
                    ],
                    pg_environment,
                )
            restored = _capture_database_state(
                target_connection, expected_database=target_database_name
            )
            if (
                restored.schema_fingerprint != manifest["schema_fingerprint"]
                or restored.tables != manifest["table_fingerprints"]
            ):
                raise RecoveryRefused("restored database does not match the recovery manifest")
            restored_orgs = set(restored.audit_anchors)
            manifest_orgs = {str(item["org_id"]) for item in manifest["audit_chains"]}
            if restored_orgs != manifest_orgs:
                raise RecoveryRefused("restored database and audit identities differ")
            for descriptor in manifest["audit_chains"]:
                org_id = str(descriptor["org_id"])
                expected_count, expected_anchor = restored.audit_anchors[org_id]
                if expected_count != descriptor["event_count"]:
                    raise RecoveryRefused("restored audit count does not match the database anchor")
                expected_last = expected_anchor or GENESIS_HASH
                if expected_last != descriptor["last_hash"]:
                    raise RecoveryRefused("restored audit hash does not match the database anchor")

            if target_audit_dir.exists():
                # Preflight proved it empty; publication occurs only post-restore.
                target_audit_dir.rmdir()
            os.replace(staged_audits, target_audit_dir)
            _fsync_directory(target_audit_dir)
            _fsync_directory(target_audit_dir.parent)
            return manifest
        finally:
            shutil.rmtree(restore_work, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ACGS local disposable migration recovery drill")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    create = subparsers.add_parser("create", help="create a recovery bundle")
    create.add_argument("--source-url-env", required=True)
    create.add_argument("--audit-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a recovery bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    restore = subparsers.add_parser("restore", help="restore into an empty disposable target")
    restore.add_argument("--bundle", type=Path, required=True)
    restore.add_argument("--target-url-env", required=True)
    restore.add_argument("--target-database-name", required=True)
    restore.add_argument("--target-audit-dir", type=Path, required=True)
    restore.add_argument(
        "--acknowledge-operator-controlled-bundle",
        action="store_true",
        help="assert the unkeyed bundle came from an operator-controlled local path",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.operation == "create":
            print(
                "WARNING: use a maintenance window; database/filesystem snapshots are not atomic."
            )
            create_recovery_bundle(
                source_url_env=args.source_url_env,
                audit_dir=args.audit_dir,
                output=args.output,
            )
        elif args.operation == "verify":
            verify_recovery_bundle(bundle=args.bundle)
        else:
            print("WARNING: restore is only for a distinct empty disposable target.")
            restore_recovery_bundle(
                bundle=args.bundle,
                target_url_env=args.target_url_env,
                target_database_name=args.target_database_name,
                target_audit_dir=args.target_audit_dir,
                acknowledge_operator_controlled_bundle=(
                    args.acknowledge_operator_controlled_bundle
                ),
            )
    except RecoveryRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print(
            "REFUSED: recovery operation failed without exposing sensitive details", file=sys.stderr
        )
        return 2
    print(f"PASS assurance_class={DRILL_LABEL} operation={args.operation}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the module CLI.
    raise SystemExit(main())
