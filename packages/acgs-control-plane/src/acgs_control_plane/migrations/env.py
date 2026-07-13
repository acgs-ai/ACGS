"""Alembic environment for the control-plane schema.

The target URL is intentionally explicit.  A migration must receive either
``ACP_DATABASE_URL`` or ``-x database_url=<url>``; silently migrating an
arbitrary local default would be unsafe.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from acgs_control_plane import models as _models  # noqa: F401  # load metadata
from acgs_control_plane.db import Base
from acgs_control_plane.migrations import assert_online_migration_operation

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    x_arguments = context.get_x_argument(as_dictionary=True)
    database_url = (
        x_arguments.get("database_url")
        or os.environ.get("ACP_DATABASE_URL")
        or config.get_main_option("sqlalchemy.url")
    )
    if not database_url:
        msg = "Set ACP_DATABASE_URL or pass -x database_url=<database-url> before migrating."
        raise RuntimeError(msg)
    return database_url


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        assert_online_migration_operation(connection, config)
        # The fail-closed inspection performs read queries.  End its implicit
        # transaction before Alembic owns the migration transaction; otherwise
        # SQLite can roll back the version-table update while retaining DDL.
        if connection.in_transaction():
            connection.rollback()
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
