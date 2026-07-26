"""Tenant-scoped repository tests for project/environment groundwork."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import NoReturn

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.db import (
    _enable_sqlite_foreign_key_pragma,
    make_engine,
    make_session_factory,
)
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import Environment, Organization, Project
from acgs_control_plane.repositories import ScopeRepository


@pytest.fixture()
def session_factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    database_url = f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        yield make_session_factory(engine)
    finally:
        engine.dispose()


def _seed_orgs(session: Session) -> None:
    session.add_all(
        [
            Organization(id="org-a", name="Organization A"),
            Organization(id="org-b", name="Organization B"),
        ]
    )
    session.flush()


def _seed_scope(session: Session) -> None:
    _seed_orgs(session)
    ScopeRepository(session, "org-a").create_project(
        project_id="project-a",
        slug="core",
        name="Core Project",
    )
    ScopeRepository(session, "org-a").create_environment(
        environment_id="environment-a",
        project_id="project-a",
        slug="production",
        name="Production",
    )


def test_prospective_scope_ids_persist_exactly_without_commit(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory() as session:

        def commit_forbidden() -> NoReturn:
            raise AssertionError("ScopeRepository must not own commits")

        monkeypatch.setattr(session, "commit", commit_forbidden)
        _seed_orgs(session)

        repo = ScopeRepository(session, "org-a")
        project = repo.create_project(
            project_id="project-prospective",
            slug="dispatch",
            name="Dispatch",
        )
        environment = repo.create_environment(
            environment_id="environment-prospective",
            project_id=project.id,
            slug="staging",
            name="Staging",
        )

        assert project.id == "project-prospective"
        assert project.org_id == "org-a"
        assert environment.id == "environment-prospective"
        assert environment.org_id == "org-a"
        assert environment.project_id == "project-prospective"
        assert session.get(Project, "project-prospective") is project
        assert session.get(Environment, "environment-prospective") is environment
        assert session.in_transaction()
        with pytest.raises(FrozenInstanceError):
            repo.org_id = "org-b"


def test_cross_tenant_reads_are_non_enumerating(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as session:
        _seed_scope(session)

    with session_factory() as session:
        org_b = ScopeRepository(session, "org-b")

        assert org_b.get_project("project-a") is None
        assert org_b.get_environment("environment-a") is None


def test_cross_tenant_updates_and_deletes_mutate_zero_rows(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as session:
        _seed_scope(session)

    with session_factory.begin() as session:
        org_b = ScopeRepository(session, "org-b")

        assert org_b.rename_project("project-a", name="Compromised") == 0
        assert org_b.rename_environment("environment-a", name="Compromised") == 0
        assert org_b.delete_environment("environment-a") == 0
        assert org_b.delete_project("project-a") == 0

    with session_factory() as session:
        project = session.get(Project, "project-a")
        environment = session.get(Environment, "environment-a")

        assert project is not None
        assert project.name == "Core Project"
        assert environment is not None
        assert environment.name == "Production"


def test_prospective_id_conflicts_fail_atomically(
    session_factory: sessionmaker[Session],
) -> None:
    class FakeCursor:
        def __init__(self) -> None:
            self.statements: list[str] = []
            self.closed = False

        def execute(self, statement: str) -> None:
            self.statements.append(statement)

        def close(self) -> None:
            self.closed = True

    class FakeConnection:
        def __init__(self) -> None:
            self.autocommit = False
            self.cursor_obj = FakeCursor()

        def cursor(self) -> FakeCursor:
            assert self.autocommit is True
            return self.cursor_obj

    fake = FakeConnection()
    _enable_sqlite_foreign_key_pragma(fake)
    assert fake.autocommit is False
    assert fake.cursor_obj.statements == ["PRAGMA foreign_keys=ON"]
    assert fake.cursor_obj.closed

    with session_factory.begin() as session:
        _seed_scope(session)

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            repo = ScopeRepository(session, "org-b")
            repo.create_project(
                project_id="project-before-conflict",
                slug="before-conflict",
                name="Before Conflict",
            )
            repo.create_project(
                project_id="project-a",
                slug="duplicate",
                name="Duplicate",
            )

    with session_factory() as session:
        assert session.get(Project, "project-before-conflict") is None
        assert ScopeRepository(session, "org-a").get_project("project-a") is not None

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            repo = ScopeRepository(session, "org-a")
            repo.create_environment(
                environment_id="environment-before-conflict",
                project_id="project-a",
                slug="before-conflict",
                name="Before Conflict",
            )
            repo.create_environment(
                environment_id="environment-a",
                project_id="project-a",
                slug="duplicate",
                name="Duplicate",
            )

    with session_factory() as session:
        assert session.get(Environment, "environment-before-conflict") is None
        assert ScopeRepository(session, "org-a").get_environment("environment-a") is not None

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            repo = ScopeRepository(session, "org-b")
            repo.create_environment(
                environment_id="environment-cross-tenant",
                project_id="project-a",
                slug="cross-tenant",
                name="Cross Tenant",
            )

    with session_factory() as session:
        assert session.get(Environment, "environment-cross-tenant") is None
