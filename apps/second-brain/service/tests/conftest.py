import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker

from second_brain.config import Settings

ADMIN_SERVER_URL = (
    "postgresql+psycopg://second_brain_owner:second_brain_owner_dev@127.0.0.1:55439/postgres"
)
TEST_DATABASE_PATTERN = re.compile(r"second_brain_test_[0-9a-f]{32}")


@dataclass(frozen=True)
class DatabaseUrls:
    name: str
    admin: str
    app: str
    worker: str
    worker_sessions: sessionmaker[Session]


class AppModule(Protocol):
    create_database_engine: Callable[[Settings], Engine]


@pytest.fixture(autouse=True)
def dispose_test_app_engines(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Dispose app-owned pools when ASGITransport omits FastAPI lifespan."""
    app_module = cast(AppModule, import_module("second_brain.app"))
    created_engines: list[Engine] = []
    create_engine_for_app = app_module.create_database_engine

    def tracked_create_database_engine(settings: Settings) -> Engine:
        engine = create_engine_for_app(settings)
        created_engines.append(engine)
        return engine

    monkeypatch.setattr(app_module, "create_database_engine", tracked_create_database_engine)
    try:
        yield
    finally:
        for engine in reversed(created_engines):
            engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def temporary_worker_role() -> Iterator[None]:
    """Emulate the fresh-Compose role bootstrap without retaining cluster state."""
    engine = create_engine(ADMIN_SERVER_URL, isolation_level="AUTOCOMMIT")
    created = False
    try:
        with engine.connect() as connection:
            role = connection.execute(
                text(
                    "SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls "
                    "FROM pg_roles WHERE rolname='second_brain_worker'"
                )
            ).one_or_none()
            if role is None:
                connection.exec_driver_sql(
                    "CREATE ROLE second_brain_worker LOGIN PASSWORD "
                    "'second_brain_worker_dev' NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOBYPASSRLS"
                )
                created = True
            else:
                assert tuple(role) == (False, False, False, False)
        yield
    finally:
        if created:
            with engine.connect() as connection:
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE usename='second_brain_worker' AND pid <> pg_backend_pid()"
                    )
                )
                connection.exec_driver_sql("DROP ROLE second_brain_worker")
        engine.dispose()


def _guarded_database_url() -> URL:
    base = make_url(ADMIN_SERVER_URL)
    assert base.host in {"127.0.0.1", "localhost"}
    database = f"second_brain_test_{uuid4().hex}"
    assert TEST_DATABASE_PATTERN.fullmatch(database)
    return base.set(database=database)


def _alembic_config(database_url: URL) -> Config:
    root = Path(__file__).parents[1]
    config = Config(root / "alembic.ini")
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.render_as_string(hide_password=False))
    return config


def _database_exists(name: str) -> bool:
    engine = create_engine(ADMIN_SERVER_URL)
    try:
        with engine.connect() as connection:
            return bool(
                connection.scalar(
                    text("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=:name)"),
                    {"name": name},
                )
            )
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def database_urls(temporary_worker_role: None) -> Iterator[DatabaseUrls]:
    database_url = _guarded_database_url()
    assert database_url.database is not None
    name = database_url.database
    server_engine = create_engine(ADMIN_SERVER_URL, isolation_level="AUTOCOMMIT")
    try:
        with server_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    finally:
        server_engine.dispose()

    try:
        command.upgrade(_alembic_config(database_url), "head")
        worker_url = database_url.set(
            username="second_brain_worker", password="second_brain_worker_dev"
        ).render_as_string(hide_password=False)
        worker_engine: Engine = create_engine(worker_url, pool_pre_ping=True)
        urls = DatabaseUrls(
            name=name,
            admin=database_url.render_as_string(hide_password=False),
            app=database_url.set(
                username="second_brain_app", password="second_brain_app_dev"
            ).render_as_string(hide_password=False),
            worker=worker_url,
            worker_sessions=sessionmaker(bind=worker_engine, expire_on_commit=False),
        )
        try:
            yield urls
        finally:
            worker_engine.dispose()
    finally:
        server_engine = create_engine(ADMIN_SERVER_URL, isolation_level="AUTOCOMMIT")
        try:
            with server_engine.connect() as connection:
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=:name AND pid <> pg_backend_pid()"
                    ),
                    {"name": name},
                )
                connection.exec_driver_sql(f'DROP DATABASE "{name}"')
        finally:
            server_engine.dispose()
        assert not _database_exists(name)
