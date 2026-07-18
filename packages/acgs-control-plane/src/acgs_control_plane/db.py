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

from sqlalchemy import MetaData, Table, create_engine
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

ALEMBIC_MANAGED_TABLE_INFO_KEY = "acgs_alembic_managed"
"""Explicit metadata marker for tables that legacy ``create_all`` must not create."""

_ALEMBIC_MANAGED_TABLE_NAMES = frozenset({"projects", "environments"})
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

        legacy_tables = [
            table for table in self.sorted_tables if table.name in _LEGACY_CREATE_ALL_TABLE_NAMES
        ]
        if supplied_connection_was_clean:
            # The preflight has released its read transaction.  Own and close
            # the subsequent DDL transaction so a clean caller can immediately
            # begin its own transaction; never touch a caller-owned one.
            with bind.begin():
                super().create_all(bind, tables=legacy_tables, checkfirst=checkfirst)
        else:
            super().create_all(bind, tables=legacy_tables, checkfirst=checkfirst)

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


def make_engine(database_url: str) -> Engine:
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, connect_args=connect_args, future=True)


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
