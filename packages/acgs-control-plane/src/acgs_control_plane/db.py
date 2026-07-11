"""SQLAlchemy engine/session plumbing.

PostgreSQL is the production backend (JSONB columns via dialect variant);
the same ORM runs on SQLite for tests. Schema creation is idempotent
``create_all`` for now — migrations move to Alembic when the schema
stabilises past v0.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


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
