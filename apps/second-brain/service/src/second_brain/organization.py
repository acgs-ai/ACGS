from __future__ import annotations

import re
import unicodedata
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

_WHITESPACE = re.compile(r"\s+")


class OrganizationNotFound(LookupError):
    """The scoped project, tag, or source does not exist."""


def normalize_name(name: str) -> tuple[str, str]:
    display_name = _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", name).strip())
    if not 1 <= len(display_name) <= 200:
        raise ValueError("name must contain between 1 and 200 characters")
    return display_name, display_name.casefold()


def _scope(session: Session) -> tuple[UUID, UUID]:
    row = session.execute(
        text(
            "SELECT nullif(current_setting('app.owner_id',true),'')::uuid,"
            "nullif(current_setting('app.workspace_id',true),'')::uuid"
        )
    ).one()
    if row[0] is None or row[1] is None:
        raise OrganizationNotFound("database scope is unavailable")
    return row[0], row[1]


def create_project(session: Session, name: str) -> dict[str, Any]:
    owner_id, workspace_id = _scope(session)
    display_name, _ = normalize_name(name)
    row = (
        session.execute(
            text(
                "INSERT INTO projects (id,owner_id,workspace_id,name) "
                "VALUES (:id,:owner_id,:workspace_id,:name) "
                "RETURNING id AS project_id,name,normalized_name,is_active,created_at,updated_at"
            ),
            {
                "id": uuid4(),
                "owner_id": owner_id,
                "workspace_id": workspace_id,
                "name": display_name,
            },
        )
        .mappings()
        .one()
    )
    return dict(row)


def list_projects(session: Session, *, active_only: bool = False) -> list[dict[str, Any]]:
    rows = session.execute(
        text(
            "SELECT id AS project_id,name,normalized_name,is_active,created_at,updated_at "
            "FROM projects WHERE (:active_only=false OR is_active=true) "
            "ORDER BY normalized_name,id"
        ),
        {"active_only": active_only},
    ).mappings()
    return [dict(row) for row in rows]


def update_project(
    session: Session,
    project_id: UUID,
    *,
    name: str | None = None,
    is_active: bool | None = None,
) -> dict[str, Any]:
    display_name = normalize_name(name)[0] if name is not None else None
    row = (
        session.execute(
            text(
                "UPDATE projects SET "
                "name=COALESCE(:name,name),is_active=COALESCE(:is_active,is_active) "
                "WHERE id=:project_id "
                "RETURNING id AS project_id,name,normalized_name,is_active,created_at,updated_at"
            ),
            {"project_id": project_id, "name": display_name, "is_active": is_active},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise OrganizationNotFound("project not found")
    return dict(row)


def delete_project(session: Session, project_id: UUID) -> bool:
    return bool(
        session.execute(
            text("DELETE FROM projects WHERE id=:project_id RETURNING id"),
            {"project_id": project_id},
        ).scalar_one_or_none()
    )


def create_tag(session: Session, name: str) -> dict[str, Any]:
    owner_id, workspace_id = _scope(session)
    display_name, _ = normalize_name(name)
    row = (
        session.execute(
            text(
                "INSERT INTO tags (id,owner_id,workspace_id,name) "
                "VALUES (:id,:owner_id,:workspace_id,:name) "
                "RETURNING id AS tag_id,name,normalized_name,created_at"
            ),
            {
                "id": uuid4(),
                "owner_id": owner_id,
                "workspace_id": workspace_id,
                "name": display_name,
            },
        )
        .mappings()
        .one()
    )
    return dict(row)


def list_tags(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(
        text(
            "SELECT id AS tag_id,name,normalized_name,created_at FROM tags "
            "ORDER BY normalized_name,id"
        )
    ).mappings()
    return [dict(row) for row in rows]


def update_tag(session: Session, tag_id: UUID, *, name: str) -> dict[str, Any]:
    display_name, _ = normalize_name(name)
    row = (
        session.execute(
            text(
                "UPDATE tags SET name=:name WHERE id=:tag_id "
                "RETURNING id AS tag_id,name,normalized_name,created_at"
            ),
            {"tag_id": tag_id, "name": display_name},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise OrganizationNotFound("tag not found")
    return dict(row)


def delete_tag(session: Session, tag_id: UUID) -> bool:
    return bool(
        session.execute(
            text("DELETE FROM tags WHERE id=:tag_id RETURNING id"), {"tag_id": tag_id}
        ).scalar_one_or_none()
    )


def organize_source(
    session: Session,
    source_id: UUID,
    *,
    project_id: UUID | None,
    tag_ids: list[UUID],
) -> dict[str, Any]:
    owner_id, workspace_id = _scope(session)
    unique_tag_ids = sorted(set(tag_ids), key=str)
    if (
        project_id is not None
        and session.scalar(
            text("SELECT EXISTS (SELECT 1 FROM projects WHERE id=:project_id)"),
            {"project_id": project_id},
        )
        is not True
    ):
        raise OrganizationNotFound("project not found")
    if unique_tag_ids:
        visible_tag_count = session.scalar(
            text("SELECT count(*) FROM tags WHERE id=ANY(:tag_ids)"),
            {"tag_ids": unique_tag_ids},
        )
        if visible_tag_count != len(unique_tag_ids):
            raise OrganizationNotFound("tag not found")
    updated = session.execute(
        text("UPDATE sources SET project_id=:project_id WHERE id=:source_id RETURNING id"),
        {"source_id": source_id, "project_id": project_id},
    ).scalar_one_or_none()
    if updated is None:
        raise OrganizationNotFound("source not found")
    session.execute(
        text("DELETE FROM source_tags WHERE source_id=:source_id"),
        {"source_id": source_id},
    )
    for tag_id in unique_tag_ids:
        session.execute(
            text(
                "INSERT INTO source_tags (owner_id,workspace_id,source_id,tag_id) "
                "VALUES (:owner_id,:workspace_id,:source_id,:tag_id)"
            ),
            {
                "owner_id": owner_id,
                "workspace_id": workspace_id,
                "source_id": source_id,
                "tag_id": tag_id,
            },
        )
    return {"source_id": source_id, "project_id": project_id, "tag_ids": unique_tag_ids}
