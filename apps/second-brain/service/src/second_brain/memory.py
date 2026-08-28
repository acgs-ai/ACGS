from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.db import scoped_session
from second_brain.ingestion import IdempotencyConflict

MEMORY_CATEGORIES = {
    "fact",
    "preference",
    "commitment",
    "project_fact",
    "person_fact",
    "reference",
    "other",
}
EVIDENCE_QUALITIES = {"low", "medium", "high"}


class MemoryNotFound(LookupError):
    pass


class MemoryEvidenceUnavailable(ValueError):
    pass


class MemoryStateConflict(ValueError):
    pass


def _fingerprint(action: str, payload: dict[str, Any]) -> str:
    material = json.dumps(
        {"action": action, **payload},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _validate_statement(statement: str) -> str:
    normalized = " ".join(statement.split())
    if not normalized or len(normalized) > 4000:
        raise ValueError("memory statement must contain between 1 and 4000 characters")
    return normalized


def _validate_metadata(category: str, confidence: float, evidence_quality: str) -> None:
    if category not in MEMORY_CATEGORIES:
        raise ValueError("unsupported memory category")
    if not 0 <= confidence <= 1:
        raise ValueError("memory confidence must be between zero and one")
    if evidence_quality not in EVIDENCE_QUALITIES:
        raise ValueError("unsupported memory evidence quality")


def _lock_idempotency(
    session: Session, owner_id: UUID, workspace_id: UUID, idempotency_key: str
) -> None:
    if not 1 <= len(idempotency_key) <= 200:
        raise ValueError("idempotency key must contain between 1 and 200 characters")
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:scope_key AS text),0))"),
        {"scope_key": f"{owner_id}:{workspace_id}:memory:{idempotency_key}"},
    )


def _existing_action(
    session: Session, idempotency_key: str, fingerprint: str
) -> dict[str, Any] | None:
    row = (
        session.execute(
            text(
                "SELECT action,proposal_id,memory_id,result_resource_id,request_fingerprint "
                "FROM memory_actions WHERE idempotency_key=:key"
            ),
            {"key": idempotency_key},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    if row["request_fingerprint"] != fingerprint:
        raise IdempotencyConflict("memory idempotency payload mismatch")
    return dict(row)


def _record_action(
    session: Session,
    *,
    owner_id: UUID,
    workspace_id: UUID,
    action: str,
    idempotency_key: str,
    fingerprint: str,
    result_resource_id: UUID,
    proposal_id: UUID | None = None,
    memory_id: UUID | None = None,
) -> None:
    session.execute(
        text(
            "INSERT INTO memory_actions "
            "(owner_id,workspace_id,proposal_id,memory_id,action,idempotency_key,"
            "request_fingerprint,result_resource_id) VALUES "
            "(:owner,:workspace,:proposal,:memory,:action,:key,:fingerprint,:result)"
        ),
        {
            "owner": owner_id,
            "workspace": workspace_id,
            "proposal": proposal_id,
            "memory": memory_id,
            "action": action,
            "key": idempotency_key,
            "fingerprint": fingerprint,
            "result": result_resource_id,
        },
    )


def _resolve_evidence(
    session: Session, chunk_ids: list[UUID], *, lock_sources: bool = False
) -> list[dict[str, UUID]]:
    ordered_ids = list(dict.fromkeys(chunk_ids))
    if not ordered_ids:
        raise MemoryEvidenceUnavailable("memory evidence is required")
    lock_clause = " FOR UPDATE OF source" if lock_sources else ""
    rows = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT chunk.id AS chunk_id,version.source_id,version.id AS source_version_id "
                "FROM chunks AS chunk "
                "JOIN source_versions AS version ON version.id=chunk.source_version_id "
                "JOIN sources AS source ON source.id=version.source_id "
                "WHERE chunk.id=ANY(CAST(:chunks AS uuid[])) "
                "AND source.processing_state='ready' AND source.deleted_at IS NULL "
                "AND version.id=(SELECT current_version.id FROM source_versions AS current_version "
                "WHERE current_version.source_id=source.id "
                "ORDER BY current_version.version_number DESC,current_version.id ASC LIMIT 1)"
                + lock_clause
            ),
            {"chunks": ordered_ids},
        ).mappings()
    ]
    by_chunk = {row["chunk_id"]: row for row in rows}
    if set(by_chunk) != set(ordered_ids):
        raise MemoryEvidenceUnavailable("memory evidence is not current and accessible")
    return [by_chunk[chunk_id] for chunk_id in ordered_ids]


def _proposal_result(session: Session, proposal_id: UUID) -> dict[str, Any]:
    proposal = (
        session.execute(
            text(
                "SELECT id,normalized_statement,category,confidence,evidence_quality_label,"
                "status,proposed_at,decided_at FROM memory_proposals WHERE id=:proposal"
            ),
            {"proposal": proposal_id},
        )
        .mappings()
        .one()
    )
    evidence = [
        dict(row)
        for row in session.execute(
            text(
                "SELECT chunk_id,source_id,source_version_id "
                "FROM memory_proposal_evidence WHERE proposal_id=:proposal "
                "ORDER BY created_at,id"
            ),
            {"proposal": proposal_id},
        ).mappings()
    ]
    return {
        "proposal_id": proposal["id"],
        "statement": proposal["normalized_statement"],
        "category": proposal["category"],
        "confidence": proposal["confidence"],
        "evidence_quality": proposal["evidence_quality_label"],
        "status": proposal["status"],
        "proposed_at": proposal["proposed_at"],
        "decided_at": proposal["decided_at"],
        "evidence": evidence,
    }


def _memory_result(session: Session, memory_id: UUID) -> dict[str, Any]:
    row = (
        session.execute(
            text(
                "SELECT memory.id AS memory_id,memory.proposal_id,memory.status,"
                "memory.approved_at,memory.supersedes_memory_id,memory.superseded_by_id,"
                "revision.id AS revision_id,revision.revision_number,"
                "revision.normalized_statement,revision.category,revision.confidence,"
                "revision.evidence_quality_label "
                "FROM approved_memories AS memory "
                "JOIN memory_revisions AS revision ON revision.id=memory.current_revision_id "
                "WHERE memory.id=:memory"
            ),
            {"memory": memory_id},
        )
        .mappings()
        .one()
    )
    return dict(row)


def propose_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    statement: str,
    category: str,
    evidence_chunk_ids: list[UUID],
    confidence: float,
    evidence_quality: str,
    idempotency_key: str,
) -> dict[str, Any]:
    normalized = _validate_statement(statement)
    _validate_metadata(category, confidence, evidence_quality)
    fingerprint = _fingerprint(
        "propose",
        {
            "statement": normalized,
            "category": category,
            "evidence_chunk_ids": sorted(str(value) for value in set(evidence_chunk_ids)),
            "confidence": confidence,
            "evidence_quality": evidence_quality,
        },
    )
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _proposal_result(session, existing["result_resource_id"])
        evidence = _resolve_evidence(session, evidence_chunk_ids)
        proposal_id = uuid4()
        session.execute(
            text(
                "INSERT INTO memory_proposals "
                "(id,owner_id,workspace_id,normalized_statement,category,evidence_quality,"
                "confidence,evidence_quality_label) VALUES "
                "(:id,:owner,:workspace,:statement,:category,:numeric_quality,:confidence,"
                ":quality)"
            ),
            {
                "id": proposal_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "statement": normalized,
                "category": category,
                "numeric_quality": confidence,
                "confidence": confidence,
                "quality": evidence_quality,
            },
        )
        for item in evidence:
            session.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id,source_id,source_version_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk_id,:source_id,"
                    ":source_version_id)"
                ),
                {"owner": owner_id, "workspace": workspace_id, "proposal": proposal_id, **item},
            )
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action="propose",
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=proposal_id,
            proposal_id=proposal_id,
        )
        return _proposal_result(session, proposal_id)


def _approve(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    proposal_id: UUID,
    idempotency_key: str,
    edited: dict[str, Any] | None,
) -> dict[str, Any]:
    action = "edit_and_approve" if edited is not None else "approve"
    fingerprint = _fingerprint(action, {"proposal_id": proposal_id, "edited": edited})
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _memory_result(session, existing["result_resource_id"])
        proposal = (
            session.execute(
                text(
                    "SELECT id,normalized_statement,category,confidence,evidence_quality_label "
                    "FROM memory_proposals WHERE id=:proposal AND status='proposed' FOR UPDATE"
                ),
                {"proposal": proposal_id},
            )
            .mappings()
            .one_or_none()
        )
        if proposal is None:
            raise MemoryNotFound("memory proposal is unavailable")
        proposal_chunk_ids = list(
            session.scalars(
                text(
                    "SELECT chunk_id FROM memory_proposal_evidence "
                    "WHERE proposal_id=:proposal ORDER BY created_at,id"
                ),
                {"proposal": proposal_id},
            )
        )
        _resolve_evidence(session, proposal_chunk_ids, lock_sources=True)
        statement = proposal["normalized_statement"]
        category = proposal["category"]
        confidence = proposal["confidence"]
        quality = proposal["evidence_quality_label"]
        if edited is not None:
            statement = _validate_statement(str(edited["statement"]))
            category = str(edited["category"])
            confidence = float(edited["confidence"])
            quality = str(edited["evidence_quality"])
            _validate_metadata(category, confidence, quality)
        memory_id, revision_id = uuid4(), uuid4()
        session.execute(
            text(
                "INSERT INTO approved_memories "
                "(id,owner_id,workspace_id,proposal_id,status,approved_at) "
                "VALUES (:id,:owner,:workspace,:proposal,'active',clock_timestamp())"
            ),
            {
                "id": memory_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "proposal": proposal_id,
            },
        )
        session.execute(
            text(
                "INSERT INTO memory_revisions "
                "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement,"
                "category,confidence,evidence_quality_label,created_by) VALUES "
                "(:id,:owner,:workspace,:memory,1,:statement,:category,:confidence,:quality,"
                ":created_by)"
            ),
            {
                "id": revision_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "memory": memory_id,
                "statement": statement,
                "category": category,
                "confidence": confidence,
                "quality": quality,
                "created_by": owner_id,
            },
        )
        session.execute(
            text(
                "INSERT INTO memory_revision_evidence "
                "(owner_id,workspace_id,revision_id,chunk_id,source_id,source_version_id) "
                "SELECT owner_id,workspace_id,:revision,chunk_id,source_id,source_version_id "
                "FROM memory_proposal_evidence WHERE proposal_id=:proposal"
            ),
            {"revision": revision_id, "proposal": proposal_id},
        )
        session.execute(
            text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
            {"revision": revision_id, "memory": memory_id},
        )
        session.execute(
            text(
                "UPDATE memory_proposals SET status='approved',decided_at=clock_timestamp() "
                "WHERE id=:proposal"
            ),
            {"proposal": proposal_id},
        )
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action=action,
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=memory_id,
            proposal_id=proposal_id,
            memory_id=memory_id,
        )
        return _memory_result(session, memory_id)


def approve_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    proposal_id: UUID,
    idempotency_key: str,
) -> dict[str, Any]:
    return _approve(
        session_factory,
        owner_id=owner_id,
        workspace_id=workspace_id,
        proposal_id=proposal_id,
        idempotency_key=idempotency_key,
        edited=None,
    )


def edit_and_approve_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    proposal_id: UUID,
    statement: str,
    category: str,
    confidence: float,
    evidence_quality: str,
    idempotency_key: str,
) -> dict[str, Any]:
    return _approve(
        session_factory,
        owner_id=owner_id,
        workspace_id=workspace_id,
        proposal_id=proposal_id,
        idempotency_key=idempotency_key,
        edited={
            "statement": statement,
            "category": category,
            "confidence": confidence,
            "evidence_quality": evidence_quality,
        },
    )


def reject_memory_proposal(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    proposal_id: UUID,
    idempotency_key: str,
) -> dict[str, Any]:
    fingerprint = _fingerprint("reject", {"proposal_id": proposal_id})
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _proposal_result(session, existing["result_resource_id"])
        proposal = session.scalar(
            text(
                "UPDATE memory_proposals SET status='rejected',decided_at=clock_timestamp() "
                "WHERE id=:proposal AND status='proposed' RETURNING id"
            ),
            {"proposal": proposal_id},
        )
        if proposal is None:
            raise MemoryNotFound("memory proposal is unavailable")
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action="reject",
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=proposal_id,
            proposal_id=proposal_id,
        )
        return _proposal_result(session, proposal_id)


def revise_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    memory_id: UUID,
    statement: str,
    category: str,
    evidence_chunk_ids: list[UUID],
    confidence: float,
    evidence_quality: str,
    idempotency_key: str,
) -> dict[str, Any]:
    normalized = _validate_statement(statement)
    _validate_metadata(category, confidence, evidence_quality)
    fingerprint = _fingerprint(
        "revise",
        {
            "memory_id": memory_id,
            "statement": normalized,
            "category": category,
            "evidence_chunk_ids": sorted(str(value) for value in set(evidence_chunk_ids)),
            "confidence": confidence,
            "evidence_quality": evidence_quality,
        },
    )
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _memory_result(session, existing["result_resource_id"])
        memory = session.scalar(
            text(
                "SELECT id FROM approved_memories WHERE id=:memory AND status='active' FOR UPDATE"
            ),
            {"memory": memory_id},
        )
        if memory is None:
            raise MemoryNotFound("approved memory is unavailable")
        evidence = _resolve_evidence(session, evidence_chunk_ids)
        revision_number = int(
            session.scalar(
                text(
                    "SELECT coalesce(max(revision_number),0)+1 FROM memory_revisions "
                    "WHERE memory_id=:memory"
                ),
                {"memory": memory_id},
            )
        )
        revision_id = uuid4()
        session.execute(
            text(
                "INSERT INTO memory_revisions "
                "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement,"
                "category,confidence,evidence_quality_label,created_by) VALUES "
                "(:id,:owner,:workspace,:memory,:number,:statement,:category,:confidence,"
                ":quality,:created_by)"
            ),
            {
                "id": revision_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "memory": memory_id,
                "number": revision_number,
                "statement": normalized,
                "category": category,
                "confidence": confidence,
                "quality": evidence_quality,
                "created_by": owner_id,
            },
        )
        for item in evidence:
            session.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id,source_id,source_version_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk_id,:source_id,"
                    ":source_version_id)"
                ),
                {"owner": owner_id, "workspace": workspace_id, "revision": revision_id, **item},
            )
        session.execute(
            text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
            {"revision": revision_id, "memory": memory_id},
        )
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action="revise",
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=memory_id,
            memory_id=memory_id,
        )
        return _memory_result(session, memory_id)


def supersede_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    memory_id: UUID,
    superseding_memory_id: UUID,
    idempotency_key: str,
) -> dict[str, Any]:
    fingerprint = _fingerprint(
        "supersede", {"memory_id": memory_id, "superseding_memory_id": superseding_memory_id}
    )
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _memory_result(session, existing["result_resource_id"])
        locked_rows = {
            row["id"]: row
            for row in session.execute(
                text(
                    "SELECT id,status,supersedes_memory_id,superseded_by_id "
                    "FROM approved_memories WHERE id=ANY(CAST(:ids AS uuid[])) "
                    "ORDER BY id FOR UPDATE"
                ),
                {"ids": [memory_id, superseding_memory_id]},
            ).mappings()
        }
        if (
            set(locked_rows) != {memory_id, superseding_memory_id}
            or memory_id == superseding_memory_id
        ):
            raise MemoryNotFound("approved memory is unavailable")
        predecessor = locked_rows[memory_id]
        replacement = locked_rows[superseding_memory_id]
        if (
            predecessor["status"] != "active"
            or predecessor["superseded_by_id"] is not None
            or replacement["status"] != "active"
            or replacement["supersedes_memory_id"] is not None
            or replacement["superseded_by_id"] is not None
        ):
            raise MemoryStateConflict("memory supersession lineage is already linked")
        predecessor_updates = list(
            session.scalars(
                text(
                    "UPDATE approved_memories SET status='superseded',superseded_by_id=:new "
                    "WHERE id=:old AND status='active' AND superseded_by_id IS NULL "
                    "RETURNING id"
                ),
                {"new": superseding_memory_id, "old": memory_id},
            )
        )
        if predecessor_updates != [memory_id]:
            raise MemoryStateConflict("memory supersession predecessor changed")
        replacement_updates = list(
            session.scalars(
                text(
                    "UPDATE approved_memories SET supersedes_memory_id=:old WHERE id=:new "
                    "AND status='active' AND supersedes_memory_id IS NULL "
                    "AND superseded_by_id IS NULL RETURNING id"
                ),
                {"old": memory_id, "new": superseding_memory_id},
            )
        )
        if replacement_updates != [superseding_memory_id]:
            raise MemoryStateConflict("memory supersession replacement changed")
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action="supersede",
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=memory_id,
            memory_id=memory_id,
        )
        return _memory_result(session, memory_id)


def archive_memory(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    memory_id: UUID,
    idempotency_key: str,
) -> dict[str, Any]:
    fingerprint = _fingerprint("archive", {"memory_id": memory_id})
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        _lock_idempotency(session, owner_id, workspace_id, idempotency_key)
        existing = _existing_action(session, idempotency_key, fingerprint)
        if existing is not None:
            return _memory_result(session, existing["result_resource_id"])
        updated = session.scalar(
            text(
                "UPDATE approved_memories SET status='archived' "
                "WHERE id=:memory AND status='active' RETURNING id"
            ),
            {"memory": memory_id},
        )
        if updated is None:
            raise MemoryNotFound("approved memory is unavailable")
        _record_action(
            session,
            owner_id=owner_id,
            workspace_id=workspace_id,
            action="archive",
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            result_resource_id=memory_id,
            memory_id=memory_id,
        )
        return _memory_result(session, memory_id)
