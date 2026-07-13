"""Database-level scope constraints for projects and environments."""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import configure_mappers

from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import Environment, Organization, Project


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"


def test_environment_cannot_reference_a_project_from_another_org(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    created_at = "2026-07-13T00:00:00+00:00"

    try:
        with engine.connect() as connection:
            # SQLite does not enforce FKs unless each connection enables them.
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()

            with connection.begin():
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO organizations (
                            id, name, created_at, audit_anchor_count, audit_anchor_hash
                        ) VALUES (
                            :id, :name, :created_at, :audit_anchor_count, :audit_anchor_hash
                        )
                        """
                    ),
                    [
                        {
                            "id": "org-a",
                            "name": "Organization A",
                            "created_at": created_at,
                            "audit_anchor_count": 0,
                            "audit_anchor_hash": "",
                        },
                        {
                            "id": "org-b",
                            "name": "Organization B",
                            "created_at": created_at,
                            "audit_anchor_count": 0,
                            "audit_anchor_hash": "",
                        },
                    ],
                )
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO projects (id, org_id, slug, name, created_at)
                        VALUES (:id, :org_id, :slug, :name, :created_at)
                        """
                    ),
                    {
                        "id": "project-a",
                        "org_id": "org-a",
                        "slug": "core",
                        "name": "Core Project",
                        "created_at": created_at,
                    },
                )
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                        VALUES (:id, :org_id, :project_id, :slug, :name, :created_at)
                        """
                    ),
                    {
                        "id": "environment-a",
                        "org_id": "org-a",
                        "project_id": "project-a",
                        "slug": "staging",
                        "name": "Staging",
                        "created_at": created_at,
                    },
                )

            with pytest.raises(IntegrityError):
                with connection.begin():
                    connection.execute(
                        sa.text(
                            """
                            INSERT INTO environments (
                                id, org_id, project_id, slug, name, created_at
                            ) VALUES (
                                :id, :org_id, :project_id, :slug, :name, :created_at
                            )
                            """
                        ),
                        {
                            "id": "environment-cross-org",
                            "org_id": "org-b",
                            "project_id": "project-a",
                            "slug": "production",
                            "name": "Cross-org Attempt",
                            "created_at": created_at,
                        },
                    )
    finally:
        engine.dispose()


def test_orm_models_use_the_same_composite_parent_join() -> None:
    """ORM ergonomics do not replace the database constraint under test above."""
    configure_mappers()

    assert Organization.projects.property.mapper.class_ is Project
    assert Project.environments.property.mapper.class_ is Environment
    assert "projects.org_id = environments.org_id" in str(Project.environments.property.primaryjoin)
    assert "projects.id = environments.project_id" in str(Project.environments.property.primaryjoin)
