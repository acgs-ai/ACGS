"""SQLAlchemy engine/session plumbing.

PostgreSQL is the production backend (JSONB columns via dialect variant);
the same ORM runs on SQLite for tests. Legacy v0 tables may be created only by
the explicit local-development bootstrap. Schema-managed startup is read-only
and requires the exact Alembic head; production remains separately blocked
until the canonical signed governance membrane replaces legacy writes.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    MetaData,
    Table,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

ALEMBIC_MANAGED_TABLE_INFO_KEY = "acgs_alembic_managed"
"""Explicit metadata marker for tables that legacy ``create_all`` must not create."""

_ALEMBIC_MANAGED_TABLE_NAMES = frozenset(
    {
        "projects",
        "environments",
        "managed_decision_receipts",
        "managed_receipt_consumptions",
        "managed_mutation_attempts",
        "managed_governance_event_heads",
        "managed_governance_events",
        "managed_outbox",
        "managed_trust_scopes",
        "managed_trust_keys",
        "organization_memberships",
        "platform_bootstrap_invitations",
        "tenant_bootstrap_idempotency",
        "tenant_bootstrap_policy_artifacts",
        "pending_approvals",
        "tenant_bootstrap_pending_outbox",
        "tenant_bootstrap_refusal_events",
        "agent_registration_idempotency",
        "policy_versions",
        "environment_policy_heads",
        "policy_registry_idempotency",
        "approval_requests",
        "approval_votes",
        "approval_outcomes",
        "approval_resume_authorizations",
    }
)
_LEGACY_CREATE_ALL_TABLE_NAMES = frozenset(
    {
        "organizations",
        "users",
        "agents",
        "policy_bundles",
        "receipts",
        "compliance_exports",
    }
)


class LegacyCreateAllMetaData(MetaData):
    """Preserve v0 ``create_all`` only for the explicit legacy table set.

    The app factory exposes this only behind its explicit local-development
    posture. Project and environment tables are created only by Alembic
    revision 0002. A future migration-managed table
    must be both explicitly marked and added to the finite allowlist; an
    unknown marker or an unmarked allowlisted table raises rather than silently
    changing startup schema behaviour.
    """

    def create_all(
        self,
        bind: Any,
        tables: Sequence[Table] | None = None,
        checkfirst: bool = True,
    ) -> None:
        if tables is not None:
            msg = (
                "Legacy create_all does not accept the SQLAlchemy tables= argument; "
                "use the complete frozen v0 bootstrap or an Alembic migration."
            )
            raise RuntimeError(msg)

        supplied_connection_was_clean = isinstance(bind, Connection) and not bind.in_transaction()
        self._assert_legacy_create_all_preflight(bind)
        self._assert_legacy_metadata_contract()

        legacy_metadata, legacy_tables = self._legacy_create_all_tables()
        if supplied_connection_was_clean:
            # The preflight has released its read transaction.  Own and close
            # the subsequent DDL transaction so a clean caller can immediately
            # begin its own transaction; never touch a caller-owned one.
            with bind.begin():
                legacy_metadata.create_all(bind, tables=legacy_tables, checkfirst=checkfirst)
        else:
            legacy_metadata.create_all(bind, tables=legacy_tables, checkfirst=checkfirst)

    def _legacy_create_all_tables(self) -> tuple[MetaData, list[Table]]:
        """Clone only the frozen v0 table surface for transitional ``create_all``.

        Some ORM models now carry Alembic-managed columns/indexes on tables
        that existed in v0.  The explicit local-development bootstrap must not
        leak those partial managed shapes, because that would create a schema
        the migration adoption guard cannot safely classify.
        """
        legacy_metadata = MetaData()
        legacy_source_tables = [
            table for table in self.sorted_tables if table.name in _LEGACY_CREATE_ALL_TABLE_NAMES
        ]
        legacy_table_names = {table.name for table in legacy_source_tables}
        managed_constraint_names = {
            source_table.name: {
                constraint.name
                for constraint in source_table.constraints
                if constraint.info.get(ALEMBIC_MANAGED_TABLE_INFO_KEY) is True
            }
            for source_table in legacy_source_tables
        }
        managed_index_names = {
            source_table.name: {
                index.name
                for index in source_table.indexes
                if index.info.get(ALEMBIC_MANAGED_TABLE_INFO_KEY) is True
            }
            for source_table in legacy_source_tables
        }

        for source_table in legacy_source_tables:
            source_table.to_metadata(
                legacy_metadata,
                referred_schema_fn=lambda _table, _to_schema, constraint, _referred_schema: (
                    None
                    if constraint.referred_table.name in legacy_table_names
                    else "__acgs_legacy_create_all_invalid__"
                ),
            )

        for table_name in legacy_table_names:
            table = legacy_metadata.tables[table_name]
            managed_column_names = {
                column.name
                for column in table.columns
                if column.info.get(ALEMBIC_MANAGED_TABLE_INFO_KEY) is True
            }
            for column_name in managed_column_names:
                table._columns.remove(table.c[column_name])

            for constraint in list(table.constraints):
                if constraint.name in managed_constraint_names[table_name]:
                    _discard_constraint(table, constraint)
                    continue
                if isinstance(constraint, UniqueConstraint) and any(
                    column.name in managed_column_names for column in constraint.columns
                ):
                    msg = (
                        "Legacy create_all cannot clone an unmarked unique constraint that "
                        f"references migration-managed columns: {table.name}.{constraint.name}"
                    )
                    raise RuntimeError(msg)
                if isinstance(constraint, CheckConstraint) and managed_column_names:
                    sqltext = str(constraint.sqltext)
                    if any(column_name in sqltext for column_name in managed_column_names):
                        msg = (
                            "Legacy create_all cannot clone an unmarked check constraint that "
                            f"references migration-managed columns: {table.name}.{constraint.name}"
                        )
                        raise RuntimeError(msg)

            for constraint in list(table.foreign_key_constraints):
                if constraint.name in managed_constraint_names[table_name]:
                    _discard_constraint(table, constraint)

            for index in list(table.indexes):
                if index.name in managed_index_names[table_name]:
                    table.indexes.remove(index)
                    continue
                if any(column.name in managed_column_names for column in index.columns):
                    msg = (
                        "Legacy create_all cannot clone an unmarked index that references "
                        f"migration-managed columns: {table.name}.{index.name}"
                    )
                    raise RuntimeError(msg)

            if table_name == "agents":
                table.append_constraint(
                    UniqueConstraint("org_id", "name", name="uq_agents_org_name")
                )

        legacy_tables = [legacy_metadata.tables[table.name] for table in legacy_source_tables]
        return legacy_metadata, legacy_tables

    def _assert_legacy_metadata_contract(self) -> None:
        """Keep the transitional bootstrap table set finite and explicit."""
        expected_table_names = _LEGACY_CREATE_ALL_TABLE_NAMES | _ALEMBIC_MANAGED_TABLE_NAMES
        metadata_table_names = set(self.tables)
        unexpected_tables = metadata_table_names - expected_table_names
        missing_tables = expected_table_names - metadata_table_names
        if unexpected_tables or missing_tables:
            details: list[str] = []
            if unexpected_tables:
                details.append(f"unexpected={sorted(unexpected_tables)}")
            if missing_tables:
                details.append(f"missing={sorted(missing_tables)}")
            msg = (
                "Legacy create_all metadata table set is not the frozen v0-plus-managed contract: "
            )
            raise RuntimeError(msg + ", ".join(details))

        marked_tables = {
            table.name
            for table in self.tables.values()
            if table.info.get(ALEMBIC_MANAGED_TABLE_INFO_KEY) is True
        }
        unexpected_markers = marked_tables - _ALEMBIC_MANAGED_TABLE_NAMES
        if unexpected_markers:
            msg = (
                "A migration-managed table is not explicitly allowlisted for legacy create_all: "
                f"{sorted(unexpected_markers)}"
            )
            raise RuntimeError(msg)

        unmarked_managed_tables = _ALEMBIC_MANAGED_TABLE_NAMES - marked_tables
        if unmarked_managed_tables:
            msg = (
                "An Alembic-managed table is missing its explicit metadata marker: "
                f"{sorted(unmarked_managed_tables)}"
            )
            raise RuntimeError(msg)

    @staticmethod
    def _assert_legacy_create_all_preflight(bind: Any) -> None:
        """Allow legacy schema creation only on a clean or exact v0 database.

        This import is intentionally runtime-only: ``migrations`` imports the
        ORM metadata during module setup, while app startup reaches this method
        only after that import graph is complete.  Reusing the same classifier
        means a view, trigger, malformed scope table, or versioned database
        cannot be changed incidentally by the transitional ``create_all`` path.
        """
        from acgs_control_plane.migrations import DatabaseSchemaState, inspect_connection

        if isinstance(bind, Connection):
            supplied_connection_was_clean = not bind.in_transaction()
            try:
                preflight = inspect_connection(bind)
                if preflight.state in {DatabaseSchemaState.EMPTY, DatabaseSchemaState.LEGACY_V0}:
                    return

                msg = (
                    "Refusing legacy create_all on a control-plane database that is not empty or "
                    f"exact legacy v0: {preflight.state} ({preflight.detail}). "
                    "Use upgrade_database() for migration-managed states."
                )
                raise RuntimeError(msg)
            finally:
                # SQLAlchemy inspection uses autobegin.  Roll back only a
                # transaction known to have started in this preflight, never a
                # transaction that belonged to the caller before entry.
                if supplied_connection_was_clean and bind.in_transaction():
                    bind.rollback()
        else:
            with bind.connect() as connection:
                preflight = inspect_connection(connection)
                if preflight.state in {DatabaseSchemaState.EMPTY, DatabaseSchemaState.LEGACY_V0}:
                    return

                msg = (
                    "Refusing legacy create_all on a control-plane database that is not empty or "
                    f"exact legacy v0: {preflight.state} ({preflight.detail}). "
                    "Use upgrade_database() for migration-managed states."
                )
                raise RuntimeError(msg)


class Base(DeclarativeBase):
    metadata = LegacyCreateAllMetaData()


def _discard_constraint(table: Table, constraint: Any) -> None:
    table.constraints.discard(constraint)
    if isinstance(constraint, ForeignKeyConstraint):
        table.foreign_key_constraints.discard(constraint)
        for element in constraint.elements:
            table.foreign_keys.discard(element)
            element.parent.foreign_keys.discard(element)


def _enable_sqlite_foreign_key_pragma(dbapi_connection: Any) -> None:
    previous_autocommit = getattr(dbapi_connection, "autocommit", None)
    if previous_autocommit is not None:
        dbapi_connection.autocommit = True
    try:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()
    finally:
        if previous_autocommit is not None:
            dbapi_connection.autocommit = previous_autocommit


def make_engine(database_url: str) -> Engine:
    connect_args: dict[str, object] = {}
    sqlite = database_url.startswith("sqlite")
    if sqlite:
        connect_args["check_same_thread"] = False
    engine = create_engine(database_url, connect_args=connect_args, future=True)
    if sqlite:

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
            _enable_sqlite_foreign_key_pragma(dbapi_connection)

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """FastAPI dependency: one session per request, closed afterwards.

    Commit/rollback is owned by the governance membrane (receipts and
    side effects must commit together), not by this dependency.
    """
    session = factory()
    try:
        yield session
    finally:
        session.close()
