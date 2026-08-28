from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

EMPTY_MESSAGES = {
    "recent_captures": "No recent captures",
    "failed_jobs": "No failed processing jobs",
    "recent_approved_memories": "No approved memories yet",
    "active_project_sources": "No active-project sources",
    "resurfacing": "Nothing scheduled to resurface today",
}


def _items(session: Session, query: str, parameters: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in session.execute(text(query), parameters).mappings()]


def _section(name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"items": items, "empty_message": EMPTY_MESSAGES[name] if not items else None}


def today_view(session: Session, *, as_of: datetime) -> dict[str, Any]:
    """Build all five deterministic sections from one caller-supplied instant."""
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    instant = as_of.astimezone(UTC)
    parameters: dict[str, Any] = {"as_of": instant, "utc_date": instant.date()}
    recent_captures = _items(
        session,
        "SELECT id AS source_id,display_title,source_type,processing_state,project_id,ingested_at "
        "FROM sources WHERE deleted_at IS NULL AND processing_state<>'purged' "
        "AND ingested_at<=:as_of ORDER BY ingested_at DESC,id ASC LIMIT 5",
        parameters,
    )
    failed_jobs = _items(
        session,
        "SELECT job.id AS job_id,job.source_id,source.display_title,job.state,job.error_code,"
        "job.finished_at FROM ingestion_jobs AS job JOIN sources AS source "
        "ON source.id=job.source_id "
        "WHERE job.state IN ('failed','dead') AND job.finished_at<=:as_of "
        "AND source.processing_state='failed' AND source.deleted_at IS NULL "
        "ORDER BY job.finished_at DESC,job.id ASC LIMIT 5",
        parameters,
    )
    recent_memories = _items(
        session,
        "SELECT memory.id AS memory_id,memory.status,memory.approved_at,"
        "revision.normalized_statement,revision.revision_number "
        "FROM approved_memories AS memory JOIN memory_revisions AS revision "
        "ON revision.id=memory.current_revision_id "
        "WHERE memory.status<>'purged' AND memory.approved_at<=:as_of "
        "ORDER BY memory.approved_at DESC,memory.id ASC LIMIT 5",
        parameters,
    )
    active_project_sources = _items(
        session,
        "WITH ranked AS ("
        "SELECT project.id AS project_id,project.name AS project_name,project.updated_at,"
        "source.id AS source_id,source.display_title,source.source_type,source.ingested_at,"
        "row_number() OVER (PARTITION BY project.id "
        "ORDER BY source.ingested_at DESC,source.id ASC) AS source_rank "
        "FROM projects AS project JOIN sources AS source ON source.project_id=project.id "
        "WHERE project.is_active=true AND source.processing_state='ready' "
        "AND source.deleted_at IS NULL AND source.ingested_at<=:as_of) "
        "SELECT project_id,project_name,source_id,display_title,source_type,ingested_at "
        "FROM ranked WHERE source_rank=1 "
        "ORDER BY updated_at DESC,ingested_at DESC,source_id ASC LIMIT 5",
        parameters,
    )
    resurfacing = _items(
        session,
        "SELECT memory.id AS memory_id,revision.normalized_statement,"
        "revision.revision_number,memory.approved_at "
        "FROM approved_memories AS memory JOIN memory_revisions AS revision "
        "ON revision.id=memory.current_revision_id "
        "WHERE memory.status='active' AND memory.approved_at<=:as_of "
        "AND NOT EXISTS (SELECT 1 FROM memory_resurfacing_events AS event "
        "WHERE event.memory_id=memory.id AND event.resurfaced_at>=:as_of-interval '7 days') "
        "ORDER BY encode(digest("
        "current_setting('app.owner_id')||'|'||current_setting('app.workspace_id')||'|'||"
        "CAST(:utc_date AS text)||'|'||CAST(memory.id AS text),'sha256'),'hex'),"
        "memory.id ASC LIMIT 3",
        parameters,
    )
    return {
        "as_of": instant,
        "recent_captures": _section("recent_captures", recent_captures),
        "failed_jobs": _section("failed_jobs", failed_jobs),
        "recent_approved_memories": _section("recent_approved_memories", recent_memories),
        "active_project_sources": _section("active_project_sources", active_project_sources),
        "resurfacing": _section("resurfacing", resurfacing),
    }
