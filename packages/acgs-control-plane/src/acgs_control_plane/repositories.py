"""Tenant-scoped repository helpers for control-plane scope rows.

These helpers are internal groundwork for project/environment-aware control-plane
flows. They deliberately do not own transactions: callers must wrap the session
in the same governance membrane that will later receipt the mutation.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from acgs_control_plane.models import Environment, Project


def _rowcount(result: object) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


@dataclass(frozen=True)
class ScopeRepository:
    """Repository constrained to one immutable organization scope."""

    session: Session
    org_id: str

    def create_project(self, *, project_id: str, slug: str, name: str) -> Project:
        project = Project(id=project_id, org_id=self.org_id, slug=slug, name=name)
        self.session.add(project)
        self.session.flush()
        return project

    def get_project(self, project_id: str) -> Project | None:
        return self.session.execute(
            select(Project).where(Project.org_id == self.org_id, Project.id == project_id)
        ).scalar_one_or_none()

    def rename_project(self, project_id: str, *, name: str) -> int:
        result = self.session.execute(
            update(Project)
            .where(Project.org_id == self.org_id, Project.id == project_id)
            .values(name=name)
        )
        self.session.flush()
        return _rowcount(result)

    def delete_project(self, project_id: str) -> int:
        result = self.session.execute(
            delete(Project).where(Project.org_id == self.org_id, Project.id == project_id)
        )
        self.session.flush()
        return _rowcount(result)

    def create_environment(
        self,
        *,
        environment_id: str,
        project_id: str,
        slug: str,
        name: str,
    ) -> Environment:
        environment = Environment(
            id=environment_id,
            org_id=self.org_id,
            project_id=project_id,
            slug=slug,
            name=name,
        )
        self.session.add(environment)
        self.session.flush()
        return environment

    def get_environment(self, environment_id: str) -> Environment | None:
        return self.session.execute(
            select(Environment).where(
                Environment.org_id == self.org_id,
                Environment.id == environment_id,
            )
        ).scalar_one_or_none()

    def rename_environment(self, environment_id: str, *, name: str) -> int:
        result = self.session.execute(
            update(Environment)
            .where(Environment.org_id == self.org_id, Environment.id == environment_id)
            .values(name=name)
        )
        self.session.flush()
        return _rowcount(result)

    def delete_environment(self, environment_id: str) -> int:
        result = self.session.execute(
            delete(Environment).where(
                Environment.org_id == self.org_id,
                Environment.id == environment_id,
            )
        )
        self.session.flush()
        return _rowcount(result)
