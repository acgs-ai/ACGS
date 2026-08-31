from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from second_brain.providers import EmbeddingProvider, ProviderUnavailable

LEXICAL_CANDIDATES = 50
SEMANTIC_CANDIDATES = 50
RRF_K = 60


@dataclass(frozen=True)
class SearchFilters:
    project_id: UUID | None = None
    tag_id: UUID | None = None
    source_type: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


def reciprocal_rank_fusion(
    lexical: list[tuple[str, int]],
    semantic: list[tuple[str, int]],
    *,
    k: int = RRF_K,
) -> list[tuple[str, float]]:
    scores: dict[str, float] = {}
    for chunk_id, rank in lexical:
        scores[chunk_id] = scores.get(chunk_id, 0.0) + 1 / (k + rank)
    for chunk_id, rank in semantic:
        scores[chunk_id] = scores.get(chunk_id, 0.0) + 1 / (k + rank)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def _filter_sql(filters: SearchFilters) -> tuple[str, dict[str, Any]]:
    clauses = [
        "source.processing_state = 'ready'",
        "source.deleted_at IS NULL",
        "version.id = (SELECT current_version.id FROM source_versions AS current_version "
        "WHERE current_version.source_id=source.id "
        "ORDER BY current_version.version_number DESC,current_version.id ASC LIMIT 1)",
    ]
    parameters: dict[str, Any] = {}
    for name, expression, value in (
        ("project_id", "source.project_id = :project_id", filters.project_id),
        ("source_type", "source.source_type = :source_type", filters.source_type),
        ("date_from", "source.ingested_at >= :date_from", filters.date_from),
        ("date_to", "source.ingested_at <= :date_to", filters.date_to),
    ):
        if value is not None:
            clauses.append(expression)
            parameters[name] = value
    if filters.tag_id is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM source_tags AS filtered_tag "
            "WHERE filtered_tag.source_id=source.id AND filtered_tag.tag_id=:tag_id)"
        )
        parameters["tag_id"] = filters.tag_id
    return " AND ".join(clauses), parameters


def _base_projection() -> str:
    return (
        "chunk.id AS chunk_id,source.id AS source_id,version.id AS source_version_id,"
        "source.display_title,source.source_type,source.project_id,source.ingested_at,"
        "source.semantic_state,source.mime_type,source.source_metadata,"
        "version.parser_name,version.parser_version,version.chunker_version,"
        "chunk.chunk_text,chunk.char_start,chunk.char_end,chunk.page_number,"
        "chunk.section,chunk.paragraph_number,chunk.location,"
        "COALESCE((SELECT jsonb_agg(jsonb_build_object('tag_id',tag.id,'name',tag.name) "
        "ORDER BY tag.name,tag.id) FROM source_tags AS source_tag "
        "JOIN tags AS tag ON tag.id=source_tag.tag_id "
        "WHERE source_tag.source_id=source.id),'[]'::jsonb) AS tags"
    )


def _lexical_rows(session: Session, query: str, filters: SearchFilters) -> list[dict[str, Any]]:
    where_sql, parameters = _filter_sql(filters)
    parameters["query"] = query
    rows = session.execute(
        text(
            f"SELECT {_base_projection()},"
            "ts_rank_cd(chunk.search_vector,websearch_to_tsquery('english',:query)) "
            "AS channel_score FROM chunks AS chunk "
            "JOIN source_versions AS version ON version.id=chunk.source_version_id "
            "JOIN sources AS source ON source.id=version.source_id "
            f"WHERE {where_sql} "
            "AND chunk.search_vector @@ websearch_to_tsquery('english',:query) "
            "ORDER BY channel_score DESC,chunk.id ASC LIMIT 50"
        ),
        parameters,
    ).mappings()
    return [dict(row) for row in rows]


def _semantic_rows(
    session: Session,
    query_vector: list[float],
    provider: EmbeddingProvider,
    filters: SearchFilters,
) -> list[dict[str, Any]]:
    where_sql, parameters = _filter_sql(filters)
    parameters.update(
        {
            "query_embedding": "[" + ",".join(str(value) for value in query_vector) + "]",
            "dimensions": provider.dimensions,
            "model_identifier": provider.model_identifier,
            "profile_provider": type(provider).__name__,
            "profile_version": provider.profile_version,
        }
    )
    rows = session.execute(
        text(
            f"SELECT {_base_projection()},"
            "1 - (embedding.embedding <=> CAST(:query_embedding AS vector)) AS channel_score "
            "FROM embeddings AS embedding "
            "JOIN embedding_profiles AS profile ON profile.id=embedding.profile_id "
            "JOIN chunks AS chunk ON chunk.id=embedding.chunk_id "
            "JOIN source_versions AS version ON version.id=chunk.source_version_id "
            "JOIN sources AS source ON source.id=version.source_id "
            f"WHERE {where_sql} "
            "AND profile.provider=:profile_provider "
            "AND profile.dimensions=:dimensions "
            "AND profile.model_identifier=:model_identifier "
            "AND profile.profile_version=:profile_version "
            "AND (embedding.embedding <#> embedding.embedding) < 0 "
            "ORDER BY embedding.embedding <=> CAST(:query_embedding AS vector),chunk.id ASC "
            "LIMIT 50"
        ),
        parameters,
    ).mappings()
    resolved = [dict(row) for row in rows]
    if any(
        row["channel_score"] is None or not math.isfinite(float(row["channel_score"]))
        for row in resolved
    ):
        raise ProviderUnavailable("embedding provider unavailable")
    return resolved


def _excerpt(chunk_text: str, query: str, limit: int = 360) -> str:
    normalized = query.casefold().split()
    lowered = chunk_text.casefold()
    positions = [lowered.find(token) for token in normalized if lowered.find(token) >= 0]
    center = min(positions) if positions else 0
    start = max(0, center - limit // 3)
    end = min(len(chunk_text), start + limit)
    if end - start < limit:
        start = max(0, end - limit)
    prefix = "…" if start else ""
    suffix = "…" if end < len(chunk_text) else ""
    return f"{prefix}{chunk_text[start:end]}{suffix}"


def hybrid_search(
    session: Session,
    query: str,
    embedding_provider: EmbeddingProvider,
    *,
    filters: SearchFilters | None = None,
    limit: int = 20,
) -> tuple[list[dict[str, Any]], str]:
    resolved_filters = filters or SearchFilters()
    lexical_rows = _lexical_rows(session, query, resolved_filters)
    semantic_status = "available"
    try:
        query_vectors = embedding_provider.embed([query])
        if len(query_vectors) != 1 or len(query_vectors[0]) != embedding_provider.dimensions:
            raise ProviderUnavailable("embedding provider unavailable")
        if not all(math.isfinite(value) for value in query_vectors[0]) or math.isclose(
            sum(value * value for value in query_vectors[0]), 0.0, abs_tol=1e-15
        ):
            raise ProviderUnavailable("embedding provider unavailable")
        semantic_rows = _semantic_rows(
            session, query_vectors[0], embedding_provider, resolved_filters
        )
    except ProviderUnavailable:
        semantic_status = "unavailable"
        semantic_rows = []

    lexical_by_id = {str(row["chunk_id"]): (rank, row) for rank, row in enumerate(lexical_rows, 1)}
    semantic_by_id = {
        str(row["chunk_id"]): (rank, row) for rank, row in enumerate(semantic_rows, 1)
    }
    fused = reciprocal_rank_fusion(
        [(chunk_id, value[0]) for chunk_id, value in lexical_by_id.items()],
        [(chunk_id, value[0]) for chunk_id, value in semantic_by_id.items()],
    )
    results: list[dict[str, Any]] = []
    for fused_rank, (chunk_id, fused_score) in enumerate(fused[:limit], 1):
        lexical = lexical_by_id.get(chunk_id)
        semantic = semantic_by_id.get(chunk_id)
        channel = lexical if lexical is not None else semantic
        assert channel is not None
        row = dict(channel[1])
        row.pop("channel_score", None)
        row.update(
            {
                "excerpt": _excerpt(str(row["chunk_text"]), query),
                "lexical_rank": lexical[0] if lexical else None,
                "lexical_score": float(lexical[1]["channel_score"]) if lexical else None,
                "semantic_rank": semantic[0] if semantic else None,
                "semantic_score": float(semantic[1]["channel_score"]) if semantic else None,
                "semantic_status": semantic_status,
                "fused_rank": fused_rank,
                "fused_score": fused_score,
            }
        )
        results.append(row)
    return results, semantic_status
