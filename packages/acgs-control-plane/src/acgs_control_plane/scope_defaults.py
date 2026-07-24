"""Canonical default scope helpers for legacy organization-level records."""

from __future__ import annotations

import hashlib
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.models import Environment, Project, utcnow

LEGACY_DEFAULT_PROJECT_SLUG: Final = "legacy-default"
LEGACY_DEFAULT_PROJECT_NAME: Final = "Legacy default project"
LEGACY_DEFAULT_ENVIRONMENT_SLUG: Final = "legacy-default"
LEGACY_DEFAULT_ENVIRONMENT_NAME: Final = "Legacy default environment"


class LegacyDefaultScopeConflict(RuntimeError):
    """The canonical default scope cannot be created or trusted safely."""


def legacy_default_project_id(org_id: str) -> str:
    return f"legacy-default-project-{_org_digest(org_id)}"


def legacy_default_environment_id(org_id: str) -> str:
    return f"legacy-default-environment-{_org_digest(org_id)}"


def ensure_legacy_default_scope(session: Session, org_id: str) -> tuple[str, str]:
    """Create or verify the org's canonical default project/environment.

    Existing rows are reused only when they match the deterministic IDs,
    canonical slugs, and display names. Any mismatch is refused so a migration
    or org bootstrap cannot attach legacy rows to an attacker-controlled or
    misleading scope.
    """
    project_id = legacy_default_project_id(org_id)
    environment_id = legacy_default_environment_id(org_id)
    project = _resolve_project(session, org_id, project_id)
    if project is None:
        project = Project(
            id=project_id,
            org_id=org_id,
            slug=LEGACY_DEFAULT_PROJECT_SLUG,
            name=LEGACY_DEFAULT_PROJECT_NAME,
        )
        session.add(project)
        session.flush()

    environment = _resolve_environment(session, org_id, project_id, environment_id)
    if environment is None:
        environment = Environment(
            id=environment_id,
            org_id=org_id,
            project_id=project_id,
            slug=LEGACY_DEFAULT_ENVIRONMENT_SLUG,
            name=LEGACY_DEFAULT_ENVIRONMENT_NAME,
        )
        session.add(environment)
        session.flush()
    return project_id, environment_id


def legacy_default_project_values(org_id: str) -> dict[str, object]:
    return {
        "id": legacy_default_project_id(org_id),
        "org_id": org_id,
        "slug": LEGACY_DEFAULT_PROJECT_SLUG,
        "name": LEGACY_DEFAULT_PROJECT_NAME,
        "created_at": utcnow(),
    }


def legacy_default_environment_values(org_id: str) -> dict[str, object]:
    return {
        "id": legacy_default_environment_id(org_id),
        "org_id": org_id,
        "project_id": legacy_default_project_id(org_id),
        "slug": LEGACY_DEFAULT_ENVIRONMENT_SLUG,
        "name": LEGACY_DEFAULT_ENVIRONMENT_NAME,
        "created_at": utcnow(),
    }


def _resolve_project(session: Session, org_id: str, project_id: str) -> Project | None:
    candidates = session.execute(
        select(Project).where(
            (Project.id == project_id)
            | ((Project.org_id == org_id) & (Project.slug == LEGACY_DEFAULT_PROJECT_SLUG))
        )
    ).scalars()
    rows = list(candidates)
    if not rows:
        return None
    if len(rows) != 1:
        raise LegacyDefaultScopeConflict("conflicting legacy default project rows")
    project = rows[0]
    if (
        project.id != project_id
        or project.org_id != org_id
        or project.slug != LEGACY_DEFAULT_PROJECT_SLUG
        or project.name != LEGACY_DEFAULT_PROJECT_NAME
    ):
        raise LegacyDefaultScopeConflict("legacy default project slug/id/name conflict")
    return project


def _resolve_environment(
    session: Session, org_id: str, project_id: str, environment_id: str
) -> Environment | None:
    candidates = session.execute(
        select(Environment).where(
            (Environment.id == environment_id)
            | (
                (Environment.org_id == org_id)
                & (Environment.slug == LEGACY_DEFAULT_ENVIRONMENT_SLUG)
            )
        )
    ).scalars()
    rows = list(candidates)
    if not rows:
        return None
    if len(rows) != 1:
        raise LegacyDefaultScopeConflict("conflicting legacy default environment rows")
    environment = rows[0]
    if (
        environment.id != environment_id
        or environment.org_id != org_id
        or environment.project_id != project_id
        or environment.slug != LEGACY_DEFAULT_ENVIRONMENT_SLUG
        or environment.name != LEGACY_DEFAULT_ENVIRONMENT_NAME
    ):
        raise LegacyDefaultScopeConflict("legacy default environment slug/id/name conflict")
    return environment


def _org_digest(org_id: str) -> str:
    return hashlib.sha256(org_id.encode("utf-8")).hexdigest()[:32]
