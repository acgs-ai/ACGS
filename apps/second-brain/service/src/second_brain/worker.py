import argparse
import hashlib
import json
import logging
import math
import signal
import threading
import time
from dataclasses import dataclass, replace
from uuid import UUID, uuid4, uuid5

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.chunking import Chunk, chunk_document
from second_brain.config import Settings, WorkerSettings, get_worker_settings
from second_brain.db import (
    attest_runtime_role,
    attest_worker_role,
    create_session_factory,
    create_worker_content_engine,
    create_worker_dispatcher_engine,
    scoped_session,
)
from second_brain.parser_subprocess import parse_document_isolated
from second_brain.parsers import ParseFailure
from second_brain.providers import (
    EmbeddingProvider,
    FakeEmbeddingProvider,
    OpenAICompatibleEmbeddingProvider,
    ProviderUnavailable,
)
from second_brain.storage import FilesystemStorage, ObjectStorage, job_object_key
from second_brain.url_ingest import (
    BoundTransport,
    FetchResult,
    Resolver,
    SafeUrlError,
    fetch_safe_url,
)

LOGGER = logging.getLogger("second_brain.worker")
URL_FETCHER_VERSION = "http-v1"
URL_PARSER_VERSION = "1"


class LeaseLost(RuntimeError):
    pass


class ProcessingDeadline(RuntimeError):
    pass


@dataclass(frozen=True)
class ClaimedJob:
    job_id: UUID
    owner_id: UUID
    workspace_id: UUID
    source_id: UUID
    source_version_id: UUID | None
    attempts: int


@dataclass(frozen=True)
class ClaimedPurge:
    operation_id: UUID
    owner_id: UUID
    workspace_id: UUID
    resource_type: str
    resource_id: UUID
    reason_code: str
    attempts: int


@dataclass(frozen=True)
class UrlObjectLineage:
    version_id: UUID
    stage_id: UUID
    stage_state: str
    object_key: str
    sha256: str
    size: int
    parser_type: str


class LeaseHeartbeat:
    def __init__(self, worker: "IngestionWorker", job: ClaimedJob, lease_seconds: int) -> None:
        self.worker, self.job, self.lease_seconds = worker, job, lease_seconds
        self.stop_requested = threading.Event()
        self.lost = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name=f"ingestion-heartbeat-{job.job_id}",
            daemon=True,
        )

    def _run(self) -> None:
        interval = min(5.0, self.lease_seconds / 3)
        while not self.stop_requested.wait(interval):
            try:
                if not self.worker.heartbeat(self.job, self.lease_seconds):
                    self.lost.set()
                    return
            except Exception:
                self.lost.set()
                return

    def __enter__(self) -> "LeaseHeartbeat":
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.stop_requested.set()
        self.thread.join(timeout=2)

    def assert_active(self) -> None:
        if self.lost.is_set() or not self.worker.heartbeat(self.job, self.lease_seconds):
            self.lost.set()
            raise LeaseLost("ingestion lease was lost")


def provider_from_settings(settings: WorkerSettings) -> EmbeddingProvider:
    if settings.model_provider == "fake":
        return FakeEmbeddingProvider(
            settings.embedding_dimensions,
            profile_version=settings.embedding_profile_version,
        )
    if settings.model_api_key is None:
        from second_brain.providers import UnavailableEmbeddingProvider

        return UnavailableEmbeddingProvider(
            dimensions=settings.embedding_dimensions,
            profile_version=settings.embedding_profile_version,
        )
    return OpenAICompatibleEmbeddingProvider(
        settings.model_base_url,
        settings.model_api_key.get_secret_value(),
        settings.embedding_model,
        settings.embedding_dimensions,
        profile_version=settings.embedding_profile_version,
    )


class IngestionWorker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        storage: ObjectStorage,
        provider: EmbeddingProvider,
        settings: Settings | WorkerSettings,
        worker_id: str,
        *,
        dispatcher_session_factory: sessionmaker[Session],
        url_resolver: Resolver | None = None,
        url_transport: BoundTransport | None = None,
        lease_seconds: int = 30,
    ) -> None:
        self.sessions = session_factory
        self.dispatcher_sessions = dispatcher_session_factory
        self.storage, self.provider = storage, provider
        self.settings, self.worker_id = settings, worker_id
        self.url_resolver, self.url_transport = url_resolver, url_transport
        self.lease_seconds = lease_seconds

    def claim(self, lease_seconds: int = 30) -> ClaimedJob | None:
        with self.dispatcher_sessions.begin() as session:
            row = (
                session.execute(
                    text("SELECT * FROM claim_ingestion_job(:worker,:lease)"),
                    {"worker": self.worker_id, "lease": lease_seconds},
                )
                .mappings()
                .one_or_none()
            )
        return ClaimedJob(**row) if row else None

    def run_once(self) -> bool:
        if self.run_purge_once():
            return True
        job = self.claim(self.lease_seconds)
        if job is None:
            return False
        try:
            with LeaseHeartbeat(self, job, self.lease_seconds) as heartbeat:
                self._process(job, heartbeat)
        except LeaseLost:
            LOGGER.info("ingestion_lease_lost job_id=%s", job.job_id)
        except ProcessingDeadline as exc:
            self._retry_or_dead(job, type(exc).__name__)
        except (ParseFailure, SafeUrlError, ValueError) as exc:
            self._fail(job, type(exc).__name__, str(exc))
        except Exception as exc:
            LOGGER.error(
                "ingestion_failed job_id=%s error_class=%s", job.job_id, type(exc).__name__
            )
            self._retry_or_dead(job, type(exc).__name__)
        return True

    def claim_purge(self) -> ClaimedPurge | None:
        with self.dispatcher_sessions.begin() as session:
            row = (
                session.execute(
                    text("SELECT * FROM claim_purge_operation(:worker,:lease)"),
                    {"worker": self.worker_id, "lease": self.lease_seconds},
                )
                .mappings()
                .one_or_none()
            )
        return ClaimedPurge(**row) if row else None

    def run_purge_once(self) -> bool:
        operation = self.claim_purge()
        if operation is None:
            return False
        try:
            if operation.resource_type == "source":
                self.storage.delete_source(
                    operation.owner_id, operation.workspace_id, operation.resource_id
                )
                function = "finalize_source_purge"
            elif operation.resource_type == "memory":
                function = "finalize_memory_purge"
            else:
                raise ValueError("unsupported purge resource type")
            with self.dispatcher_sessions.begin() as session:
                completed = session.scalar(
                    text(f"SELECT {function}(:operation,:worker)"),
                    {"operation": operation.operation_id, "worker": self.worker_id},
                )
            if not completed:
                raise LeaseLost("purge lease was lost")
        except Exception as exc:
            LOGGER.error(
                "purge_failed operation_id=%s error_class=%s",
                operation.operation_id,
                type(exc).__name__,
            )
            with self.dispatcher_sessions.begin() as session:
                session.scalar(
                    text("SELECT retry_purge_operation(:operation,:worker,:error,0)"),
                    {
                        "operation": operation.operation_id,
                        "worker": self.worker_id,
                        "error": type(exc).__name__,
                    },
                )
        return True

    def run_forever(
        self,
        stop_requested: threading.Event,
        *,
        poll_seconds: float = 0.2,
    ) -> None:
        next_sweep = 0.0
        while not stop_requested.is_set():
            now = time.monotonic()
            if now >= next_sweep:
                try:
                    self.sweep_stale_stages(
                        getattr(self.settings, "stale_stage_age_seconds", 300),
                        getattr(self.settings, "stale_stage_batch_size", 100),
                    )
                except Exception as exc:
                    LOGGER.error("capture_stage_sweep_failed error_class=%s", type(exc).__name__)
                next_sweep = now + getattr(self.settings, "stale_stage_sweep_seconds", 30)
            if not self.run_once():
                stop_requested.wait(poll_seconds)

    def sweep_stale_stages(self, age_seconds: int, batch_size: int) -> int:
        with self.dispatcher_sessions.begin() as session:
            stages = tuple(
                session.execute(
                    text("SELECT * FROM list_stale_capture_stages(:age,:batch)"),
                    {"age": age_seconds, "batch": batch_size},
                ).mappings()
            )
        reconciled = 0
        for stage in stages:
            with scoped_session(self.sessions, stage["owner_id"], stage["workspace_id"]) as session:
                job = (
                    session.execute(
                        text(
                            "SELECT source_version_id FROM ingestion_jobs "
                            "WHERE id=:job AND source_id=:source AND ("
                            "state='queued' OR state IN ('failed','dead') OR ("
                            "state='processing' AND lease_expires_at<=clock_timestamp())) "
                            "FOR UPDATE"
                        ),
                        {"job": stage["job_id"], "source": stage["source_id"]},
                    )
                    .mappings()
                    .one_or_none()
                )
                if job is None:
                    continue
                writable_source = session.scalar(
                    text(
                        "SELECT id FROM sources WHERE id=:source AND deleted_at IS NULL "
                        "AND processing_state NOT IN ('purge_pending','purged') FOR UPDATE"
                    ),
                    {"source": stage["source_id"]},
                )
                if writable_source is None:
                    continue
                current_stage = (
                    session.execute(
                        text(
                            "SELECT object_key,intended_content_sha256,intended_size,state "
                            "FROM capture_stages WHERE id=:stage AND job_id=:job "
                            "AND source_id=:source AND state IN ('pending','stored') FOR UPDATE"
                        ),
                        {
                            "stage": stage["stage_id"],
                            "job": stage["job_id"],
                            "source": stage["source_id"],
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
                if current_stage is None:
                    continue

                state = self.storage.inspect(
                    current_stage["object_key"],
                    current_stage["intended_content_sha256"],
                    current_stage["intended_size"],
                )
                if state in {"missing", "mismatch"} or job["source_version_id"] is None:
                    self.storage.delete(current_stage["object_key"])
                    abandoned = session.scalar(
                        text("SELECT abandon_capture_stage(:stage,:reason)"),
                        {
                            "stage": stage["stage_id"],
                            "reason": "stale_capture_object_unavailable",
                        },
                    )
                    reconciled += int(bool(abandoned))
                    continue
                if state == "partial":
                    self.storage.promote(
                        current_stage["object_key"],
                        current_stage["intended_content_sha256"],
                        current_stage["intended_size"],
                    )
                session.execute(
                    text(
                        "UPDATE capture_stages SET state='stored',"
                        "stored_at=clock_timestamp() WHERE id=:stage AND job_id=:job "
                        "AND state='pending'"
                    ),
                    {"stage": stage["stage_id"], "job": stage["job_id"]},
                )
                finalized = session.scalar(
                    text(
                        "UPDATE capture_stages SET state='finalized',"
                        "finalized_at=clock_timestamp(),source_version_id=:version "
                        "WHERE id=:stage AND job_id=:job AND state='stored' RETURNING id"
                    ),
                    {
                        "stage": stage["stage_id"],
                        "job": stage["job_id"],
                        "version": job["source_version_id"],
                    },
                )
                reconciled += int(bool(finalized))
        return reconciled

    def heartbeat(self, job: ClaimedJob, lease_seconds: int = 30) -> bool:
        with self.dispatcher_sessions.begin() as session:
            updated = session.execute(
                text("SELECT heartbeat_ingestion_job(:job,:worker,:lease)"),
                {"job": job.job_id, "worker": self.worker_id, "lease": lease_seconds},
            ).scalar_one_or_none()
        return bool(updated)

    def _process(self, job: ClaimedJob, heartbeat: LeaseHeartbeat) -> None:
        deadline = time.monotonic() + self.settings.max_processing_seconds
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            source = (
                session.execute(
                    text(
                        "SELECT source_type,object_key,original_uri,mime_type FROM sources "
                        "WHERE id=:source"
                    ),
                    {"source": job.source_id},
                )
                .mappings()
                .one()
            )
            checkpoint = session.execute(
                text(
                    "SELECT pipeline_checkpoint,source_version_id FROM ingestion_jobs WHERE id=:job"
                ),
                {"job": job.job_id},
            ).one()
        if checkpoint.pipeline_checkpoint == "lexical_committed":
            if checkpoint.source_version_id is None:
                raise ValueError("lexical checkpoint is missing its source version")
            job = replace(job, source_version_id=checkpoint.source_version_id)
            chunks = self._load_chunks(job)
        else:
            heartbeat.assert_active()
            if source["source_type"] == "url":
                lineage = self._resume_url_object(job)
                if lineage is None:
                    fetched = fetch_safe_url(
                        source["original_uri"],
                        resolver=self.url_resolver,
                        transport=self.url_transport,
                        max_redirects=self.settings.url_max_redirects,
                        max_bytes=self.settings.max_upload_bytes,
                        timeout=self.settings.url_timeout_seconds,
                        deadline=deadline,
                    )
                    heartbeat.assert_active()
                    lineage = self._prepare_url_fetch(job, source["original_uri"], fetched)
                    content = fetched.content
                else:
                    content = b""
                self._finalize_url_object(job, lineage, content)
                job = replace(job, source_version_id=lineage.version_id)
                data = self.storage.read(lineage.object_key, lineage.sha256)
                parser_type = lineage.parser_type
            else:
                if job.source_version_id is None:
                    raise ValueError("non-URL job is missing its source version")
                content_sha256 = self._wait_for_capture_finalization(job, heartbeat, deadline)
                data = self.storage.read(source["object_key"], content_sha256)
                parser_type = source["source_type"]
            parsed = parse_document_isolated(
                data,
                parser_type,
                self.settings.max_extracted_chars,
                self._remaining(deadline),
            )
            heartbeat.assert_active()
            if job.source_version_id is None:
                raise ValueError("ingestion job did not bind a fetched content version")
            chunks = chunk_document(
                job.source_version_id, parsed, max_chunks=self.settings.max_chunks
            )
            self._commit_lexical(job, parsed.text, chunks)

        heartbeat.assert_active()
        try:
            vectors = self.provider.embed([chunk.text for chunk in chunks], deadline=deadline)
            self._validate_vectors(vectors, len(chunks))
            if time.monotonic() >= deadline:
                raise ProcessingDeadline("processing deadline exceeded")
            heartbeat.assert_active()
            self._commit_embeddings(job, chunks, vectors)
        except ProviderUnavailable as exc:
            if time.monotonic() >= deadline:
                raise ProcessingDeadline("processing deadline exceeded") from None
            heartbeat.assert_active()
            self._commit_semantic_state(job, "unavailable", type(exc).__name__)
            if not self._transition(job, "ready", "semantic_unavailable", None, None, 0):
                raise LeaseLost("ingestion lease was lost") from None
            LOGGER.info(
                "ingestion_complete job_id=%s chunks=%s semantic=unavailable",
                job.job_id,
                len(chunks),
            )
            return
        self._commit_semantic_state(job, "available", None)
        if not self._transition(job, "ready", "semantic_available", None, None, 0):
            raise LeaseLost("ingestion lease was lost")
        LOGGER.info(
            "ingestion_complete job_id=%s chunks=%s semantic=available", job.job_id, len(chunks)
        )

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessingDeadline("processing deadline exceeded")
        return remaining

    def _wait_for_capture_finalization(
        self, job: ClaimedJob, heartbeat: LeaseHeartbeat, deadline: float
    ) -> str:
        assert job.source_version_id is not None
        while True:
            heartbeat.assert_active()
            with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
                stage = (
                    session.execute(
                        text(
                            "SELECT state,intended_content_sha256,source_version_id "
                            "FROM capture_stages WHERE job_id=:job"
                        ),
                        {"job": job.job_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if stage is None:
                raise ValueError("source object has no storage lineage")
            if stage["state"] == "finalized":
                if stage["source_version_id"] != job.source_version_id:
                    raise ValueError("source object lineage does not match its ingestion job")
                return str(stage["intended_content_sha256"])
            if stage["state"] == "abandoned":
                raise ValueError("source object storage lineage was abandoned")
            time.sleep(min(0.02, self._remaining(deadline)))

    def _load_chunks(self, job: ClaimedJob) -> tuple[Chunk, ...]:
        assert job.source_version_id is not None
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            rows = session.execute(
                text(
                    "SELECT id,ordinal,chunk_text,char_start,char_end,location FROM chunks "
                    "WHERE source_version_id=:version ORDER BY ordinal"
                ),
                {"version": job.source_version_id},
            ).mappings()
            return tuple(
                Chunk(
                    row["id"],
                    row["ordinal"],
                    row["chunk_text"],
                    row["char_start"],
                    row["char_end"],
                    row["location"],
                )
                for row in rows
            )

    def _assert_owned_in_session(self, session: Session, job: ClaimedJob) -> None:
        owned = session.scalar(
            text(
                "SELECT 1 FROM ingestion_jobs WHERE id=:job AND state='processing' "
                "AND lease_owner=:worker AND lease_expires_at>clock_timestamp() FOR UPDATE"
            ),
            {"job": job.job_id, "worker": self.worker_id},
        )
        if owned is None:
            raise LeaseLost("ingestion lease was lost")

    def _commit_lexical(self, job: ClaimedJob, extracted: str, chunks: tuple[Chunk, ...]) -> None:
        assert job.source_version_id is not None
        document_id = uuid5(job.source_version_id, "document")
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            self._assert_owned_in_session(session, job)
            session.execute(
                text(
                    "INSERT INTO documents "
                    "(id,owner_id,workspace_id,source_version_id,extracted_text,character_count) "
                    "VALUES (:id,:owner,:workspace,:version,:text,:count) ON CONFLICT DO NOTHING"
                ),
                {
                    "id": document_id,
                    "owner": job.owner_id,
                    "workspace": job.workspace_id,
                    "version": job.source_version_id,
                    "text": extracted,
                    "count": len(extracted),
                },
            )
            for chunk in chunks:
                session.execute(
                    text(
                        "INSERT INTO chunks "
                        "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                        "char_start,char_end,page_number,paragraph_number,location,"
                        "chunker_version) VALUES "
                        "(:id,:owner,:workspace,:document,:version,:ordinal,:text,:start,:end,"
                        ":page,:paragraph,CAST(:location AS jsonb),'chars-v1') "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {
                        "id": chunk.id,
                        "owner": job.owner_id,
                        "workspace": job.workspace_id,
                        "document": document_id,
                        "version": job.source_version_id,
                        "ordinal": chunk.ordinal,
                        "text": chunk.text,
                        "start": chunk.char_start,
                        "end": chunk.char_end,
                        "page": chunk.location.get("page_number"),
                        "paragraph": chunk.location.get("paragraph_number"),
                        "location": json.dumps(chunk.location),
                    },
                )
            session.execute(
                text(
                    "UPDATE ingestion_jobs SET pipeline_checkpoint='lexical_committed' "
                    "WHERE id=:job"
                ),
                {"job": job.job_id},
            )
            self._assert_owned_in_session(session, job)

    def _validate_vectors(self, vectors: list[list[float]], expected: int) -> None:
        if len(vectors) != expected:
            raise ProviderUnavailable("embedding provider unavailable")
        for vector in vectors:
            if len(vector) != self.provider.dimensions or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in vector
            ):
                raise ProviderUnavailable("embedding provider unavailable")

    def _commit_embeddings(
        self, job: ClaimedJob, chunks: tuple[Chunk, ...], vectors: list[list[float]]
    ) -> None:
        if (
            self.provider.profile_version != self.settings.embedding_profile_version
            or self.provider.dimensions != self.settings.embedding_dimensions
        ):
            raise ProviderUnavailable("embedding profile configuration mismatch")
        profile_id = uuid5(
            job.workspace_id,
            f"{type(self.provider).__name__}:{self.provider.model_identifier}:"
            f"{self.provider.dimensions}:v{self.provider.profile_version}",
        )
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            self._assert_owned_in_session(session, job)
            session.execute(
                text(
                    "INSERT INTO embedding_profiles "
                    "(id,owner_id,workspace_id,provider,model_identifier,profile_version,"
                    "dimensions,answer_min_similarity) VALUES "
                    "(:id,:owner,:workspace,:provider,:model,:profile_version,:dimensions,"
                    ":answer_min_similarity) "
                    "ON CONFLICT DO NOTHING"
                ),
                {
                    "id": profile_id,
                    "owner": job.owner_id,
                    "workspace": job.workspace_id,
                    "provider": type(self.provider).__name__,
                    "model": self.provider.model_identifier,
                    "profile_version": self.provider.profile_version,
                    "dimensions": self.provider.dimensions,
                    "answer_min_similarity": self.settings.answer_min_similarity,
                },
            )
            stored_profile = (
                session.execute(
                    text(
                        "SELECT owner_id,workspace_id,provider,model_identifier,"
                        "profile_version,dimensions,answer_min_similarity "
                        "FROM embedding_profiles WHERE id=:id"
                    ),
                    {"id": profile_id},
                )
                .mappings()
                .one_or_none()
            )
            if stored_profile is None or any(
                (
                    stored_profile["owner_id"] != job.owner_id,
                    stored_profile["workspace_id"] != job.workspace_id,
                    stored_profile["provider"] != type(self.provider).__name__,
                    stored_profile["model_identifier"] != self.provider.model_identifier,
                    stored_profile["profile_version"] != self.provider.profile_version,
                    stored_profile["dimensions"] != self.provider.dimensions,
                    stored_profile["answer_min_similarity"] != self.settings.answer_min_similarity,
                )
            ):
                raise ProviderUnavailable("embedding profile configuration mismatch")
            for chunk, vector in zip(chunks, vectors, strict=True):
                session.execute(
                    text(
                        "INSERT INTO embeddings "
                        "(owner_id,workspace_id,chunk_id,profile_id,embedding) "
                        "VALUES (:owner,:workspace,:chunk,:profile,CAST(:vector AS vector)) "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {
                        "owner": job.owner_id,
                        "workspace": job.workspace_id,
                        "chunk": chunk.id,
                        "profile": profile_id,
                        "vector": "[" + ",".join(str(value) for value in vector) + "]",
                    },
                )
            self._assert_owned_in_session(session, job)

    def _commit_semantic_state(
        self, job: ClaimedJob, semantic_state: str, error_class: str | None
    ) -> None:
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            self._assert_owned_in_session(session, job)
            session.execute(
                text(
                    "UPDATE ingestion_jobs SET semantic_state=:state,semantic_error_class=:error "
                    "WHERE id=:job"
                ),
                {"state": semantic_state, "error": error_class, "job": job.job_id},
            )
            session.execute(
                text("UPDATE sources SET semantic_state=:state WHERE id=:source"),
                {"state": semantic_state, "source": job.source_id},
            )
            self._assert_owned_in_session(session, job)

    @staticmethod
    def _url_parser_type(mime_type: str) -> str:
        return {
            "text/plain": "txt",
            "text/markdown": "markdown",
            "text/html": "html",
            "application/pdf": "pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        }[mime_type]

    def _prepare_url_fetch(
        self, job: ClaimedJob, submitted_uri: str, fetched: FetchResult
    ) -> UrlObjectLineage:
        digest = hashlib.sha256(fetched.content).hexdigest()
        parser_type = self._url_parser_type(fetched.mime_type)
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            session.execute(
                text(
                    "SELECT id FROM ingestion_jobs WHERE id=:job AND state='processing' "
                    "AND lease_owner=:worker AND lease_expires_at>clock_timestamp() FOR UPDATE"
                ),
                {"job": job.job_id, "worker": self.worker_id},
            ).one()
            prior = (
                session.execute(
                    text(
                        "SELECT source_version_id,content_sha256,object_key,mime_type,final_uri,"
                        "redirect_lineage,chosen_peer,actual_peer,fetcher_version,parser_version "
                        "FROM url_fetches "
                        "WHERE job_id=:job"
                    ),
                    {"job": job.job_id},
                )
                .mappings()
                .one_or_none()
            )
            if prior is not None:
                expected_redirects = [hop.__dict__ for hop in fetched.redirects]
                if (
                    prior["content_sha256"] != digest
                    or prior["mime_type"] != fetched.mime_type
                    or prior["final_uri"] != fetched.final_uri
                    or prior["redirect_lineage"] != expected_redirects
                    or str(prior["chosen_peer"]) != fetched.chosen_address
                    or str(prior["actual_peer"]) != fetched.peer_address
                    or prior["fetcher_version"] != URL_FETCHER_VERSION
                    or prior["parser_version"] != URL_PARSER_VERSION
                ):
                    raise SafeUrlError("URL fetch provenance changed during retry")
                stage = (
                    session.execute(
                        text(
                            "SELECT id,state,intended_size FROM capture_stages "
                            "WHERE job_id=:job AND object_key=:key"
                        ),
                        {"job": job.job_id, "key": prior["object_key"]},
                    )
                    .mappings()
                    .one()
                )
                return UrlObjectLineage(
                    prior["source_version_id"],
                    stage["id"],
                    stage["state"],
                    prior["object_key"],
                    digest,
                    stage["intended_size"],
                    parser_type,
                )
            version = session.scalar(
                text(
                    "SELECT id FROM source_versions WHERE source_id=:source "
                    "AND content_sha256=:hash AND parser_name=:parser "
                    "AND parser_version=:parser_version AND fetcher_version=:fetcher_version "
                    "AND parser_mime_type=:mime"
                ),
                {
                    "source": job.source_id,
                    "hash": digest,
                    "parser": parser_type,
                    "parser_version": URL_PARSER_VERSION,
                    "fetcher_version": URL_FETCHER_VERSION,
                    "mime": fetched.mime_type,
                },
            )
            if version is None:
                version = uuid4()
                number = session.scalar(
                    text(
                        "SELECT coalesce(max(version_number),0)+1 FROM source_versions "
                        "WHERE source_id=:source"
                    ),
                    {"source": job.source_id},
                )
                session.execute(
                    text(
                        "INSERT INTO source_versions "
                        "(id,owner_id,workspace_id,source_id,version_number,parser_name,"
                        "parser_version,fetcher_version,parser_mime_type,chunker_version,"
                        "content_sha256) VALUES "
                        "(:id,:owner,:workspace,:source,:number,:parser,:parser_version,"
                        ":fetcher_version,:mime,'chars-v1',:hash)"
                    ),
                    {
                        "id": version,
                        "owner": job.owner_id,
                        "workspace": job.workspace_id,
                        "source": job.source_id,
                        "number": number,
                        "parser": parser_type,
                        "parser_version": URL_PARSER_VERSION,
                        "fetcher_version": URL_FETCHER_VERSION,
                        "mime": fetched.mime_type,
                        "hash": digest,
                    },
                )
            key = job_object_key(job.owner_id, job.workspace_id, job.source_id, job.job_id)
            existing_stage = (
                session.execute(
                    text(
                        "SELECT id,state,intended_size FROM capture_stages "
                        "WHERE job_id=:job AND object_key=:key"
                    ),
                    {"job": job.job_id, "key": key},
                )
                .mappings()
                .one_or_none()
            )
            if existing_stage is None:
                stage_id, stage_state = uuid4(), "pending"
                session.execute(
                    text(
                        "INSERT INTO capture_stages "
                        "(id,owner_id,workspace_id,object_key,kind,intended_content_sha256,"
                        "intended_size,source_id,job_id) VALUES "
                        "(:id,:owner,:workspace,:key,'url',:hash,:size,:source,:job)"
                    ),
                    {
                        "id": stage_id,
                        "owner": job.owner_id,
                        "workspace": job.workspace_id,
                        "key": key,
                        "hash": digest,
                        "size": len(fetched.content),
                        "source": job.source_id,
                        "job": job.job_id,
                    },
                )
            else:
                stage_id, stage_state = existing_stage["id"], existing_stage["state"]
            session.execute(
                text(
                    "INSERT INTO url_fetches "
                    "(owner_id,workspace_id,job_id,source_id,source_version_id,submitted_uri,"
                    "final_uri,redirect_lineage,chosen_peer,actual_peer,mime_type,byte_count,"
                    "content_sha256,object_key,fetcher_version,parser_version) VALUES "
                    "(:owner,:workspace,:job,:source,:version,:submitted,:final,"
                    "CAST(:redirects AS jsonb),CAST(:chosen AS inet),CAST(:actual AS inet),"
                    ":mime,:size,:hash,:key,:fetcher_version,:parser_version)"
                ),
                {
                    "owner": job.owner_id,
                    "workspace": job.workspace_id,
                    "job": job.job_id,
                    "source": job.source_id,
                    "version": version,
                    "submitted": submitted_uri,
                    "final": fetched.final_uri,
                    "redirects": json.dumps([hop.__dict__ for hop in fetched.redirects]),
                    "chosen": fetched.chosen_address,
                    "actual": fetched.peer_address,
                    "mime": fetched.mime_type,
                    "fetcher_version": URL_FETCHER_VERSION,
                    "parser_version": URL_PARSER_VERSION,
                    "size": len(fetched.content),
                    "hash": digest,
                    "key": key,
                },
            )
            session.execute(
                text("UPDATE ingestion_jobs SET source_version_id=:version WHERE id=:job"),
                {"version": version, "job": job.job_id},
            )
        return UrlObjectLineage(
            version, stage_id, stage_state, key, digest, len(fetched.content), parser_type
        )

    def _resume_url_object(self, job: ClaimedJob) -> UrlObjectLineage | None:
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            prior = (
                session.execute(
                    text(
                        "SELECT url_fetch.source_version_id,url_fetch.content_sha256,"
                        "url_fetch.object_key,url_fetch.mime_type,stage.id AS stage_id,"
                        "stage.state AS stage_state,stage.intended_size "
                        "FROM url_fetches AS url_fetch JOIN capture_stages AS stage "
                        "ON stage.job_id=url_fetch.job_id "
                        "AND stage.object_key=url_fetch.object_key WHERE url_fetch.job_id=:job"
                    ),
                    {"job": job.job_id},
                )
                .mappings()
                .one_or_none()
            )
        if prior is None:
            return None
        lineage = UrlObjectLineage(
            prior["source_version_id"],
            prior["stage_id"],
            prior["stage_state"],
            prior["object_key"],
            prior["content_sha256"],
            prior["intended_size"],
            self._url_parser_type(prior["mime_type"]),
        )
        state = self.storage.inspect(lineage.object_key, lineage.sha256, lineage.size)
        return lineage if state in {"partial", "final"} else None

    def _finalize_url_object(
        self, job: ClaimedJob, lineage: UrlObjectLineage, content: bytes
    ) -> None:
        with scoped_session(self.sessions, job.owner_id, job.workspace_id) as session:
            self._assert_owned_in_session(session, job)
            writable_source = session.scalar(
                text(
                    "SELECT id FROM sources WHERE id=:source AND deleted_at IS NULL "
                    "AND processing_state NOT IN ('purge_pending','purged') FOR UPDATE"
                ),
                {"source": job.source_id},
            )
            if writable_source is None:
                raise LeaseLost("ingestion lease was lost")
            stage = (
                session.execute(
                    text(
                        "SELECT state,intended_content_sha256,intended_size,source_version_id "
                        "FROM capture_stages WHERE id=:stage AND job_id=:job "
                        "AND source_id=:source AND object_key=:key FOR UPDATE"
                    ),
                    {
                        "stage": lineage.stage_id,
                        "job": job.job_id,
                        "source": job.source_id,
                        "key": lineage.object_key,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if stage is None:
                raise LeaseLost("ingestion lease was lost")
            if (
                stage["intended_content_sha256"] != lineage.sha256
                or stage["intended_size"] != lineage.size
                or (
                    stage["source_version_id"] is not None
                    and stage["source_version_id"] != lineage.version_id
                )
            ):
                raise ValueError("URL object lineage does not match its capture stage")
            if stage["state"] == "abandoned":
                raise ValueError("URL object storage lineage was abandoned")

            status = self.storage.inspect(lineage.object_key, lineage.sha256, lineage.size)
            if status in {"missing", "mismatch"}:
                self.storage.write_partial(lineage.object_key, content, lineage.sha256)
                status = "partial"
            if stage["state"] == "pending":
                session.execute(
                    text(
                        "UPDATE capture_stages SET state='stored',stored_at=clock_timestamp() "
                        "WHERE id=:stage"
                    ),
                    {"stage": lineage.stage_id},
                )
            if status == "partial":
                self.storage.promote(lineage.object_key, lineage.sha256, lineage.size)
            if stage["state"] == "finalized":
                return
            session.execute(
                text(
                    "UPDATE capture_stages SET state='finalized',finalized_at=clock_timestamp(),"
                    "source_version_id=:version WHERE id=:stage"
                ),
                {
                    "stage": lineage.stage_id,
                    "version": lineage.version_id,
                },
            )
            self._assert_owned_in_session(session, job)

    def _fail(self, job: ClaimedJob, code: str, message: str) -> None:
        safe_message = message[:200]
        updated = self._transition(job, "failed", code, code, safe_message, 0)
        if not updated:
            LOGGER.info("ingestion_lease_lost job_id=%s", job.job_id)
            return
        LOGGER.warning("ingestion_failed job_id=%s error_class=%s", job.job_id, code)

    def _retry_or_dead(self, job: ClaimedJob, error_class: str) -> None:
        exhausted = job.attempts >= 3
        job_state = "dead" if exhausted else "queued"
        error_code = "attempts_exhausted" if exhausted else "processing_retry"
        safe_message = (
            "Ingestion retry limit exhausted."
            if exhausted
            else "Ingestion will retry after a transient processing failure."
        )
        updated = self._transition(
            job,
            job_state,
            error_class,
            error_code,
            safe_message,
            min(60, 2**job.attempts),
        )
        if not updated:
            LOGGER.info("ingestion_lease_lost job_id=%s", job.job_id)
            return
        LOGGER.warning(
            "ingestion_retry job_id=%s state=%s error_class=%s",
            job.job_id,
            job_state,
            error_class,
        )

    def _transition(
        self,
        job: ClaimedJob,
        to_state: str,
        reason_class: str,
        error_code: str | None,
        safe_message: str | None,
        delay_seconds: int,
    ) -> bool:
        with self.dispatcher_sessions.begin() as session:
            updated = session.execute(
                text(
                    "SELECT transition_ingestion_job(:job,:worker,:state,:reason,:code,"
                    ":message,:delay)"
                ),
                {
                    "job": job.job_id,
                    "worker": self.worker_id,
                    "state": to_state,
                    "reason": reason_class,
                    "code": error_code,
                    "message": safe_message,
                    "delay": delay_seconds,
                },
            ).scalar_one()
        return bool(updated)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--worker-id", default=None)
    args = parser.parse_args()
    settings = get_worker_settings()
    content_engine = create_worker_content_engine(settings)
    dispatcher_engine = create_worker_dispatcher_engine(settings)
    attest_runtime_role(content_engine)
    attest_worker_role(dispatcher_engine)
    worker = IngestionWorker(
        create_session_factory(content_engine),
        FilesystemStorage(settings.storage_root, settings.max_upload_bytes),
        provider_from_settings(settings),
        settings,
        args.worker_id or f"worker-{uuid4()}",
        dispatcher_session_factory=create_session_factory(dispatcher_engine),
    )
    try:
        if args.once:
            worker.run_once()
        else:
            stop_requested = threading.Event()

            def request_stop(signum: int, frame: object) -> None:
                del signum, frame
                stop_requested.set()

            signal.signal(signal.SIGTERM, request_stop)
            signal.signal(signal.SIGINT, request_stop)
            worker.run_forever(stop_requested)
    finally:
        dispatcher_engine.dispose()
        content_engine.dispose()


if __name__ == "__main__":
    main()
