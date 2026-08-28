from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.db import scoped_session
from second_brain.ingestion import IdempotencyConflict

PURGE_REASON_CODES = frozenset({"user_requested", "privacy_request", "retention_expired"})


class PurgeNotFound(LookupError):
    pass


def _fingerprint(resource_type: str, resource_id: UUID, reason_code: str) -> str:
    material = json.dumps(
        {
            "resource_type": resource_type,
            "resource_id": str(resource_id),
            "reason_code": reason_code,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _request(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    resource_type: Literal["source", "memory"],
    resource_id: UUID,
    reason_code: str,
    idempotency_key: str,
) -> dict[str, Any]:
    if reason_code not in PURGE_REASON_CODES:
        raise ValueError("unknown purge reason code")
    if not 1 <= len(idempotency_key) <= 200:
        raise ValueError("purge idempotency key must be bounded")
    fingerprint = _fingerprint(resource_type, resource_id, reason_code)
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:key AS text),0))"),
            {"key": f"{owner_id}:{workspace_id}:purge:{idempotency_key}"},
        )
        existing = (
            session.execute(
                text(
                    "SELECT id,state,request_fingerprint FROM purge_operations "
                    "WHERE idempotency_key=:key"
                ),
                {"key": idempotency_key},
            )
            .mappings()
            .one_or_none()
        )
        if existing is not None:
            if existing["request_fingerprint"] != fingerprint:
                raise IdempotencyConflict("purge idempotency payload mismatch")
            return {"operation_id": existing["id"], "state": existing["state"]}

        if resource_type == "source":
            found = session.scalar(
                text(
                    "UPDATE sources SET processing_state='purge_pending',"
                    "deleted_at=COALESCE(deleted_at,clock_timestamp()) "
                    "WHERE id=:resource AND deleted_at IS NULL RETURNING id"
                ),
                {"resource": resource_id},
            )
        else:
            found = session.scalar(
                text(
                    "UPDATE approved_memories SET status='purge_pending' "
                    "WHERE id=:resource AND status IN ('active','superseded','archived') "
                    "RETURNING id"
                ),
                {"resource": resource_id},
            )
        if found is None:
            raise PurgeNotFound(f"{resource_type} is unavailable")
        operation_id = uuid4()
        session.execute(
            text(
                "INSERT INTO purge_operations "
                "(id,owner_id,workspace_id,resource_type,resource_id,reason_code,"
                "idempotency_key,request_fingerprint) VALUES "
                "(:id,:owner,:workspace,:type,:resource,:reason,:key,:fingerprint)"
            ),
            {
                "id": operation_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "type": resource_type,
                "resource": resource_id,
                "reason": reason_code,
                "key": idempotency_key,
                "fingerprint": fingerprint,
            },
        )
        session.execute(
            text(
                "INSERT INTO purge_operation_events "
                "(owner_id,workspace_id,operation_id,attempt,from_state,to_state,reason_class) "
                "VALUES (:owner,:workspace,:operation,0,NULL,'queued','purge_requested')"
            ),
            {"owner": owner_id, "workspace": workspace_id, "operation": operation_id},
        )
        return {"operation_id": operation_id, "state": "queued"}


def request_source_purge(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    source_id: UUID,
    reason_code: str,
    idempotency_key: str,
) -> dict[str, Any]:
    return _request(
        session_factory,
        owner_id=owner_id,
        workspace_id=workspace_id,
        resource_type="source",
        resource_id=source_id,
        reason_code=reason_code,
        idempotency_key=idempotency_key,
    )


def request_memory_purge(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    memory_id: UUID,
    reason_code: str,
    idempotency_key: str,
) -> dict[str, Any]:
    return _request(
        session_factory,
        owner_id=owner_id,
        workspace_id=workspace_id,
        resource_type="memory",
        resource_id=memory_id,
        reason_code=reason_code,
        idempotency_key=idempotency_key,
    )
