from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


def source_detail(session: Session, source_id: UUID) -> dict[str, Any] | None:
    source = (
        session.execute(
            text(
                "SELECT id AS source_id,display_title,source_type,original_uri,object_key,"
                "original_filename,source_metadata,content_sha256,mime_type,processing_state,"
                "semantic_state,processing_error_code,processing_error_message,ingested_at,"
                "project_id FROM sources WHERE id=:source_id "
                "AND processing_state<>'purged' AND deleted_at IS NULL FOR KEY SHARE"
            ),
            {"source_id": source_id},
        )
        .mappings()
        .one_or_none()
    )
    if source is None:
        return None
    versions = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT id AS source_version_id,version_number,parser_name,parser_version,"
                "parser_mime_type,fetcher_version,chunker_version,content_sha256,created_at "
                "FROM source_versions WHERE source_id=:source_id "
                "ORDER BY version_number DESC,id ASC"
            ),
            {"source_id": source_id},
        ).mappings()
    ]
    is_ready = source["processing_state"] == "ready"
    documents = (
        [
            dict(row)
            for row in session.execute(
                text(
                    "SELECT document.id AS document_id,document.source_version_id,"
                    "document.extracted_text,document.character_count,document.created_at "
                    "FROM documents AS document JOIN source_versions AS version "
                    "ON version.id=document.source_version_id WHERE version.source_id=:source_id "
                    "ORDER BY version.version_number DESC"
                ),
                {"source_id": source_id},
            ).mappings()
        ]
        if is_ready
        else []
    )
    chunks = (
        [
            dict(row)
            for row in session.execute(
                text(
                    "SELECT chunk.id AS chunk_id,chunk.source_version_id,chunk.ordinal,"
                    "chunk.chunk_text,chunk.char_start,chunk.char_end,chunk.page_number,"
                    "chunk.section,chunk.paragraph_number,chunk.location,chunk.chunker_version "
                    "FROM chunks AS chunk JOIN source_versions AS version "
                    "ON version.id=chunk.source_version_id WHERE version.source_id=:source_id "
                    "ORDER BY version.version_number DESC,chunk.ordinal ASC,chunk.id ASC"
                ),
                {"source_id": source_id},
            ).mappings()
        ]
        if is_ready
        else []
    )
    jobs = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT id AS job_id,source_version_id,state,attempts,pipeline_checkpoint,"
                "semantic_state,semantic_error_class,error_code,error_message,created_at,"
                "updated_at "
                "FROM ingestion_jobs WHERE source_id=:source_id ORDER BY created_at DESC,id ASC"
            ),
            {"source_id": source_id},
        ).mappings()
    ]
    job_history = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT event.job_id,event.attempt,event.from_state,event.to_state,"
                "event.reason_class,event.occurred_at FROM ingestion_job_events AS event "
                "JOIN ingestion_jobs AS job ON job.id=event.job_id "
                "WHERE job.source_id=:source_id ORDER BY event.occurred_at,event.id"
            ),
            {"source_id": source_id},
        ).mappings()
    ]
    tags = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT tag.id AS tag_id,tag.name FROM source_tags AS source_tag "
                "JOIN tags AS tag ON tag.id=source_tag.tag_id "
                "WHERE source_tag.source_id=:source_id ORDER BY tag.name,tag.id"
            ),
            {"source_id": source_id},
        ).mappings()
    ]
    return {
        **dict(source),
        "tags": tags,
        "versions": versions,
        "documents": documents,
        "chunks": chunks,
        "jobs": jobs,
        "ingestion_history": job_history,
    }


def citation_context(
    session: Session,
    source_id: UUID,
    chunk_id: UUID,
    *,
    surrounding_chars: int = 600,
    max_chars: int = 2000,
) -> dict[str, Any] | None:
    row = (
        session.execute(
            text(
                "SELECT source.id AS source_id,source.display_title,"
                "version.id AS source_version_id,"
                "version.version_number,document.extracted_text,chunk.id AS chunk_id,"
                "chunk.chunk_text,chunk.char_start,chunk.char_end,chunk.page_number,chunk.section,"
                "chunk.paragraph_number,chunk.location,chunk.chunker_version "
                "FROM sources AS source JOIN source_versions AS version "
                "ON version.source_id=source.id "
                "JOIN documents AS document ON document.source_version_id=version.id "
                "JOIN chunks AS chunk ON chunk.document_id=document.id "
                "WHERE source.id=:source_id AND chunk.id=:chunk_id "
                "AND source.processing_state='ready' AND source.deleted_at IS NULL "
                "AND version.id=(SELECT current_version.id FROM source_versions AS current_version "
                "WHERE current_version.source_id=source.id "
                "ORDER BY current_version.version_number DESC,current_version.id ASC LIMIT 1)"
            ),
            {"source_id": source_id, "chunk_id": chunk_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    extracted = str(row["extracted_text"])
    context_start = max(0, int(row["char_start"]) - surrounding_chars)
    context_end = min(len(extracted), int(row["char_end"]) + surrounding_chars)
    if context_end - context_start > max_chars:
        context_end = min(len(extracted), context_start + max_chars)
    result = dict(row)
    result.pop("extracted_text")
    result.update(
        {
            "context_text": extracted[context_start:context_end],
            "context_char_start": context_start,
            "context_char_end": context_end,
        }
    )
    return result
