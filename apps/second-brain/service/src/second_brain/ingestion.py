import hashlib
from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from second_brain.chunking import CHUNKER_VERSION
from second_brain.db import scoped_session
from second_brain.storage import ObjectStorage, StoredObjectMismatch, object_key, sanitize_filename
from second_brain.upload_validation import canonical_text_bytes

PARSER_VERSION = "1"
TEXT_SOURCE_TYPES = frozenset({"note", "markdown", "txt"})
CrashPoint = Literal[
    "after_lineage", "after_partial", "after_stored", "after_promotion", "before_final_db"
]


@dataclass(frozen=True)
class CaptureResult:
    source_id: UUID
    source_version_id: UUID | None
    job_id: UUID
    state: str
    duplicate: bool


@dataclass(frozen=True)
class CaptureLineage:
    source_id: UUID
    source_version_id: UUID
    job_id: UUID
    job_state: str
    stage_id: UUID | None
    stage_state: str | None
    object_key: str
    object_sha256: str | None
    object_size: int | None


class IdempotencyConflict(ValueError):
    """The same idempotency key was reused for a different capture request."""


class CaptureStorageError(RuntimeError):
    """Capture lineage was retained, but its object could not be reconciled."""


class InjectedCaptureCrash(RuntimeError):
    """Test-only deterministic crash after a durable capture boundary."""


def canonical_content(data: bytes, source_type: str) -> bytes:
    return canonical_text_bytes(data) if source_type in TEXT_SOURCE_TYPES else data


def normalized_hash(data: bytes, source_type: str) -> str:
    return hashlib.sha256(canonical_content(data, source_type)).hexdigest()


def _capture_url(
    session_factory: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    title: str,
    normalized_uri: str,
    idempotency_key: str | None,
) -> CaptureResult:
    request_hash = hashlib.sha256(normalized_uri.encode()).hexdigest()
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        existing = None
        if idempotency_key is not None:
            existing = (
                session.execute(
                    text(
                        "SELECT id,display_title,original_uri FROM sources "
                        "WHERE idempotency_key=:key AND deleted_at IS NULL "
                        "AND processing_state NOT IN ('purge_pending','purged')"
                    ),
                    {"key": idempotency_key},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None and (existing["display_title"], existing["original_uri"]) != (
                title[:300],
                normalized_uri,
            ):
                raise IdempotencyConflict("idempotency key conflicts with an earlier request")
            if existing is not None:
                job = (
                    session.execute(
                        text(
                            "SELECT id,source_version_id,state FROM ingestion_jobs "
                            "WHERE source_id=:source ORDER BY created_at,id LIMIT 1"
                        ),
                        {"source": existing["id"]},
                    )
                    .mappings()
                    .one()
                )
                return CaptureResult(
                    existing["id"], job["source_version_id"], job["id"], job["state"], True
                )
        existing_id = session.scalar(
            text(
                "SELECT id FROM sources WHERE normalized_dedup_sha256=:hash "
                "AND deleted_at IS NULL AND processing_state NOT IN ('purge_pending','purged')"
            ),
            {"hash": request_hash},
        )
        source_id = existing_id or uuid4()
        duplicate = existing_id is not None
        if not duplicate:
            session.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,original_uri,object_key,"
                    "idempotency_key,content_sha256,normalized_dedup_sha256,mime_type) VALUES "
                    "(:id,:owner,:workspace,'url',:title,:uri,NULL,:key,NULL,:hash,'text/uri-list')"
                ),
                {
                    "id": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "title": title[:300],
                    "uri": normalized_uri,
                    "key": idempotency_key,
                    "hash": request_hash,
                },
            )
        else:
            session.execute(
                text(
                    "UPDATE sources SET processing_state='queued',processing_error_code=NULL,"
                    "processing_error_message=NULL WHERE id=:id"
                ),
                {"id": source_id},
            )
        job_id = uuid4()
        session.execute(
            text(
                "INSERT INTO ingestion_jobs "
                "(id,owner_id,workspace_id,source_id,source_version_id,requested_uri) "
                "VALUES (:id,:owner,:workspace,:source,NULL,:uri)"
            ),
            {
                "id": job_id,
                "owner": owner_id,
                "workspace": workspace_id,
                "source": source_id,
                "uri": normalized_uri,
            },
        )
    return CaptureResult(source_id, None, job_id, "queued", duplicate)


def _lineage(row: RowMapping) -> CaptureLineage:
    return CaptureLineage(
        row["id"],
        row["version_id"],
        row["job_id"],
        row["state"],
        row["stage_id"],
        row["stage_state"],
        row["object_key"],
        row["object_sha256"],
        row["object_size"],
    )


def _existing_capture(
    session_factory: sessionmaker[Session],
    owner_id: UUID,
    workspace_id: UUID,
    dedupe_hash: str,
    content_hash: str,
    source_type: str,
    title: str,
    mime_type: str,
    filename: str | None,
    original_uri: str | None,
    idempotency_key: str | None,
) -> CaptureLineage | None:
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        query = (
            "SELECT source.id,version.id AS version_id,job.id AS job_id,job.state,"
            "source.content_sha256,source.source_type,source.display_title,source.mime_type,"
            "source.original_filename,source.original_uri,source.object_key,"
            "stage.id AS stage_id,stage.state AS stage_state,"
            "stage.intended_content_sha256 AS object_sha256,stage.intended_size AS object_size "
            "FROM sources AS source JOIN source_versions AS version ON version.source_id=source.id "
            "JOIN ingestion_jobs AS job ON job.source_version_id=version.id "
            "LEFT JOIN capture_stages AS stage ON stage.job_id=job.id "
        )
        existing = None
        if idempotency_key is not None:
            existing = (
                session.execute(
                    text(
                        query + "WHERE source.idempotency_key=:key "
                        "AND source.deleted_at IS NULL "
                        "AND source.processing_state NOT IN ('purge_pending','purged') LIMIT 1"
                    ),
                    {"key": idempotency_key},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None and (
                existing["content_sha256"],
                existing["source_type"],
                existing["display_title"],
                existing["mime_type"],
                existing["original_filename"],
                existing["original_uri"],
            ) != (
                content_hash,
                source_type,
                title[:300],
                mime_type,
                sanitize_filename(filename),
                original_uri,
            ):
                raise IdempotencyConflict("idempotency key conflicts with an earlier request")
        if existing is None:
            existing = (
                session.execute(
                    text(
                        query + "WHERE source.normalized_dedup_sha256=:hash "
                        "AND source.deleted_at IS NULL "
                        "AND source.processing_state NOT IN ('purge_pending','purged') "
                        "ORDER BY version.version_number DESC LIMIT 1"
                    ),
                    {"hash": dedupe_hash},
                )
                .mappings()
                .one_or_none()
            )
    return None if existing is None else _lineage(existing)


def _abandon(
    session_factory: sessionmaker[Session],
    storage: ObjectStorage,
    owner_id: UUID,
    workspace_id: UUID,
    lineage: CaptureLineage,
    reason: str,
) -> None:
    storage.delete(lineage.object_key)
    assert lineage.stage_id is not None
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        session.scalar(
            text("SELECT abandon_capture_stage(:stage,:reason)"),
            {"stage": lineage.stage_id, "reason": reason},
        )


def _reconcile(
    session_factory: sessionmaker[Session],
    storage: ObjectStorage,
    owner_id: UUID,
    workspace_id: UUID,
    lineage: CaptureLineage,
    data: bytes,
    duplicate: bool,
    crash_after: CrashPoint | None,
) -> CaptureResult:
    if lineage.stage_id is None or lineage.object_sha256 is None or lineage.object_size is None:
        raise CaptureStorageError("capture object has no storage lineage")
    if lineage.stage_state == "abandoned":
        return CaptureResult(
            lineage.source_id, lineage.source_version_id, lineage.job_id, "failed", True
        )
    status = storage.inspect(lineage.object_key, lineage.object_sha256, lineage.object_size)
    if status == "mismatch":
        try:
            storage.write_partial(lineage.object_key, data, lineage.object_sha256)
            status = "partial"
        except (OSError, StoredObjectMismatch):
            _abandon(
                session_factory,
                storage,
                owner_id,
                workspace_id,
                lineage,
                "capture_object_mismatch",
            )
            raise CaptureStorageError("capture object failed integrity verification") from None
    if status == "missing":
        storage.write_partial(lineage.object_key, data, lineage.object_sha256)
        status = "partial"
    if crash_after == "after_partial":
        raise InjectedCaptureCrash(crash_after)

    if lineage.stage_state == "pending":
        with scoped_session(session_factory, owner_id, workspace_id) as session:
            session.execute(
                text(
                    "UPDATE capture_stages SET state='stored',stored_at=clock_timestamp() "
                    "WHERE id=:id AND job_id=:job AND state='pending'"
                ),
                {"id": lineage.stage_id, "job": lineage.job_id},
            )
    if crash_after == "after_stored":
        raise InjectedCaptureCrash(crash_after)
    if status == "partial":
        storage.promote(lineage.object_key, lineage.object_sha256, lineage.object_size)
    if crash_after == "after_promotion":
        raise InjectedCaptureCrash(crash_after)
    if crash_after == "before_final_db":
        raise InjectedCaptureCrash(crash_after)
    with scoped_session(session_factory, owner_id, workspace_id) as session:
        session.execute(
            text(
                "UPDATE capture_stages SET state='finalized',finalized_at=clock_timestamp(),"
                "source_version_id=:version WHERE id=:id AND job_id=:job AND state='stored'"
            ),
            {
                "id": lineage.stage_id,
                "job": lineage.job_id,
                "version": lineage.source_version_id,
            },
        )
    return CaptureResult(
        lineage.source_id,
        lineage.source_version_id,
        lineage.job_id,
        lineage.job_state,
        duplicate,
    )


def capture_source(
    session_factory: sessionmaker[Session],
    storage: ObjectStorage,
    *,
    owner_id: UUID,
    workspace_id: UUID,
    source_type: str,
    title: str,
    mime_type: str,
    data: bytes,
    filename: str | None = None,
    original_uri: str | None = None,
    idempotency_key: str | None = None,
    crash_after: CrashPoint | None = None,
) -> CaptureResult:
    if source_type == "url":
        if original_uri is None:
            raise ValueError("URL capture requires its normalized URI")
        return _capture_url(
            session_factory,
            owner_id=owner_id,
            workspace_id=workspace_id,
            title=title,
            normalized_uri=original_uri,
            idempotency_key=idempotency_key,
        )
    content_hash = hashlib.sha256(canonical_content(data, source_type)).hexdigest()
    dedupe_hash = normalized_hash(data, source_type)
    existing = _existing_capture(
        session_factory,
        owner_id,
        workspace_id,
        dedupe_hash,
        content_hash,
        source_type,
        title,
        mime_type,
        filename,
        original_uri,
        idempotency_key,
    )
    if existing is not None:
        if source_type == "url":
            return CaptureResult(
                existing.source_id,
                existing.source_version_id,
                existing.job_id,
                existing.job_state,
                True,
            )
        return _reconcile(
            session_factory, storage, owner_id, workspace_id, existing, data, True, crash_after
        )

    source_id, version_id, job_id, stage_id = uuid4(), uuid4(), uuid4(), uuid4()
    key = object_key(owner_id, workspace_id, source_id)
    raw_hash = hashlib.sha256(data).hexdigest()
    try:
        with scoped_session(session_factory, owner_id, workspace_id) as session:
            session.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,original_uri,object_key,"
                    "original_filename,idempotency_key,content_sha256,"
                    "normalized_dedup_sha256,mime_type) "
                    "VALUES (:id,:owner,:workspace,:type,:title,:uri,:key,:filename,:idempotency,"
                    ":content_hash,:dedupe_hash,:mime)"
                ),
                {
                    "id": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "type": source_type,
                    "title": title[:300],
                    "uri": original_uri,
                    "key": key,
                    "filename": sanitize_filename(filename),
                    "idempotency": idempotency_key,
                    "content_hash": content_hash,
                    "dedupe_hash": dedupe_hash,
                    "mime": mime_type,
                },
            )
            session.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id,owner_id,workspace_id,source_id,version_number,parser_name,parser_version,"
                    "chunker_version,content_sha256) VALUES "
                    "(:id,:owner,:workspace,:source,1,:parser,:parser_version,:chunker,:hash)"
                ),
                {
                    "id": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "parser": source_type,
                    "parser_version": PARSER_VERSION,
                    "chunker": CHUNKER_VERSION,
                    "hash": content_hash,
                },
            )
            session.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,source_version_id) "
                    "VALUES (:id,:owner,:workspace,:source,:version)"
                ),
                {
                    "id": job_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "version": version_id,
                },
            )
            if source_type != "url":
                session.execute(
                    text(
                        "INSERT INTO capture_stages "
                        "(id,owner_id,workspace_id,object_key,kind,intended_content_sha256,"
                        "intended_size,source_id,job_id) VALUES "
                        "(:id,:owner,:workspace,:key,:kind,:hash,:size,:source,:job)"
                    ),
                    {
                        "id": stage_id,
                        "owner": owner_id,
                        "workspace": workspace_id,
                        "key": key,
                        "kind": source_type,
                        "hash": raw_hash,
                        "size": len(data),
                        "source": source_id,
                        "job": job_id,
                    },
                )
    except IntegrityError:
        existing = _existing_capture(
            session_factory,
            owner_id,
            workspace_id,
            dedupe_hash,
            content_hash,
            source_type,
            title,
            mime_type,
            filename,
            original_uri,
            idempotency_key,
        )
        if existing is None:
            raise
        if source_type == "url":
            return CaptureResult(
                existing.source_id,
                existing.source_version_id,
                existing.job_id,
                existing.job_state,
                True,
            )
        return _reconcile(
            session_factory, storage, owner_id, workspace_id, existing, data, True, crash_after
        )

    if source_type == "url":
        return CaptureResult(source_id, version_id, job_id, "queued", False)
    lineage = CaptureLineage(
        source_id, version_id, job_id, "queued", stage_id, "pending", key, raw_hash, len(data)
    )
    if crash_after == "after_lineage":
        raise InjectedCaptureCrash(crash_after)
    return _reconcile(
        session_factory, storage, owner_id, workspace_id, lineage, data, False, crash_after
    )
