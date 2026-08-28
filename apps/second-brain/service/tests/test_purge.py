import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.db import scoped_session
from second_brain.memory import (
    MemoryEvidenceUnavailable,
    approve_memory,
    propose_memory,
    revise_memory,
)
from second_brain.providers import FakeEmbeddingProvider, UnavailableEmbeddingProvider
from second_brain.purge import PurgeNotFound, request_memory_purge, request_source_purge
from second_brain.retrieval import hybrid_search
from second_brain.storage import FilesystemStorage, object_key
from second_brain.worker import IngestionWorker


def _sessions(database_url: str) -> tuple[sessionmaker[Session], Any]:
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(bind=engine, expire_on_commit=False), engine


def _settings(database_url: str, storage_root: Path) -> Settings:
    return Settings(
        app_env="test",
        database_url=database_url,
        storage_root=storage_root,
        model_provider="fake",
    )


def _seed_workspace(admin_url: str, owner_id: UUID, workspace_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'Purge')"),
                {"id": workspace_id, "owner": owner_id},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": workspace_id, "owner": owner_id},
            )
    finally:
        engine.dispose()


def _seed_source(
    admin_url: str,
    storage: FilesystemStorage,
    owner_id: UUID,
    workspace_id: UUID,
    content: bytes,
) -> dict[str, Any]:
    source_id, version_id, document_id, chunk_id, job_id, stage_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    tag_id, profile_id = uuid4(), uuid4()
    digest = hashlib.sha256(content).hexdigest()
    key = object_key(owner_id, workspace_id, source_id)
    storage.write(key, content)
    vector = FakeEmbeddingProvider().embed([content.decode()])[0]
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,object_key,"
                    "content_sha256,normalized_dedup_sha256,mime_type,processing_state,"
                    "semantic_state) VALUES (:id,:owner,:workspace,'note','Purge evidence',"
                    ":key,:digest,:normalized,'text/plain','ready','available')"
                ),
                {
                    "id": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "key": key,
                    "digest": digest,
                    "normalized": source_id.hex * 2,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id,owner_id,workspace_id,source_id,version_number,parser_name,"
                    "parser_version,parser_mime_type,chunker_version,content_sha256) "
                    "VALUES (:id,:owner,:workspace,:source,1,'text','1','text/plain',"
                    "'chars-v1',:digest)"
                ),
                {
                    "id": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "digest": digest,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,source_version_id,state) "
                    "VALUES (:id,:owner,:workspace,:source,:version,'queued')"
                ),
                {
                    "id": job_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "version": version_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO capture_stages "
                    "(id,owner_id,workspace_id,object_key,kind,intended_content_sha256,"
                    "intended_size,state,source_id,job_id,source_version_id,stored_at,"
                    "finalized_at) VALUES (:id,:owner,:workspace,:key,'note',:digest,:size,"
                    "'finalized',:source,:job,:version,clock_timestamp(),clock_timestamp())"
                ),
                {
                    "id": stage_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "key": key,
                    "digest": digest,
                    "size": len(content),
                    "source": source_id,
                    "job": job_id,
                    "version": version_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO documents "
                    "(id,owner_id,workspace_id,source_version_id,extracted_text,character_count) "
                    "VALUES (:id,:owner,:workspace,:version,:content,:count)"
                ),
                {
                    "id": document_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "version": version_id,
                    "content": content.decode(),
                    "count": len(content.decode()),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,"
                    "chunk_text,char_start,char_end,location,chunker_version) "
                    "VALUES (:id,:owner,:workspace,:document,:version,0,:content,0,:count,"
                    "CAST(:location AS jsonb),'chars-v1')"
                ),
                {
                    "id": chunk_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "document": document_id,
                    "version": version_id,
                    "content": content.decode(),
                    "count": len(content.decode()),
                    "location": json.dumps({"section": "purge"}),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO embedding_profiles "
                    "(id,owner_id,workspace_id,provider,model_identifier,profile_version,"
                    "dimensions) VALUES (:id,:owner,:workspace,'FakeEmbeddingProvider',"
                    "'deterministic-sha256-v1',1,8)"
                ),
                {"id": profile_id, "owner": owner_id, "workspace": workspace_id},
            )
            connection.execute(
                text(
                    "INSERT INTO embeddings "
                    "(owner_id,workspace_id,chunk_id,profile_id,embedding) "
                    "VALUES (:owner,:workspace,:chunk,:profile,CAST(:vector AS vector))"
                ),
                {
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "chunk": chunk_id,
                    "profile": profile_id,
                    "vector": "[" + ",".join(str(value) for value in vector) + "]",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO tags (id,owner_id,workspace_id,name) "
                    "VALUES (:id,:owner,:workspace,'purge-tag')"
                ),
                {"id": tag_id, "owner": owner_id, "workspace": workspace_id},
            )
            connection.execute(
                text(
                    "INSERT INTO source_tags (owner_id,workspace_id,source_id,tag_id) "
                    "VALUES (:owner,:workspace,:source,:tag)"
                ),
                {
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "tag": tag_id,
                },
            )
    finally:
        engine.dispose()
    return {
        "source_id": source_id,
        "version_id": version_id,
        "document_id": document_id,
        "chunk_id": chunk_id,
        "job_id": job_id,
        "stage_id": stage_id,
        "tag_id": tag_id,
        "profile_id": profile_id,
        "digest": digest,
        "key": key,
        "size": len(content),
    }


def _worker(
    database_urls: Any,
    storage: FilesystemStorage,
    storage_root: Path,
    worker_id: str,
) -> tuple[IngestionWorker, Any]:
    sessions, engine = _sessions(database_urls.app)
    return (
        IngestionWorker(
            sessions,
            storage,
            UnavailableEmbeddingProvider(),
            _settings(database_urls.app, storage_root),
            worker_id,
            dispatcher_session_factory=database_urls.worker_sessions,
        ),
        engine,
    )


def test_source_purge_is_immediately_unsearchable_concurrent_and_physically_complete(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    storage = FilesystemStorage(tmp_path / "objects", 1024 * 1024)
    seeded = _seed_source(database_urls.admin, storage, owner, workspace, b"purge lexical evidence")
    sessions, engine = _sessions(database_urls.app)
    try:
        proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Evidence-backed memory survives source purge without its statement leak.",
            category="reference",
            evidence_chunk_ids=[seeded["chunk_id"]],
            confidence=0.8,
            evidence_quality="high",
            idempotency_key="purge-memory-proposal",
        )
        approved = approve_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=proposal["proposal_id"],
            idempotency_key="purge-memory-approve",
        )

        def request() -> dict[str, Any]:
            return request_source_purge(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                source_id=seeded["source_id"],
                reason_code="user_requested",
                idempotency_key="source-purge-once",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = tuple(pool.map(lambda _: request(), range(2)))
        assert first["operation_id"] == second["operation_id"]
        assert first["state"] == "queued"
        with scoped_session(sessions, owner, workspace) as session:
            results, _ = hybrid_search(session, "purge lexical", FakeEmbeddingProvider(), limit=10)
        assert results == []

        worker, worker_engine = _worker(
            database_urls, storage, tmp_path / "objects", "purge-worker"
        )
        try:
            assert worker.run_once() is True
        finally:
            worker_engine.dispose()

        assert storage.inspect(seeded["key"], seeded["digest"], seeded["size"]) == "missing"
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                for table, column, value in (
                    ("sources", "id", seeded["source_id"]),
                    ("source_versions", "id", seeded["version_id"]),
                    ("documents", "id", seeded["document_id"]),
                    ("chunks", "id", seeded["chunk_id"]),
                    ("ingestion_jobs", "id", seeded["job_id"]),
                    ("capture_stages", "id", seeded["stage_id"]),
                    ("source_tags", "source_id", seeded["source_id"]),
                ):
                    assert (
                        connection.scalar(
                            text(f"SELECT count(*) FROM {table} WHERE {column}=:value"),
                            {"value": value},
                        )
                        == 0
                    )
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM embeddings WHERE chunk_id=:chunk"),
                        {"chunk": seeded["chunk_id"]},
                    )
                    == 0
                )
                assert (
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM memory_evidence_tombstones "
                            "WHERE memory_id=:memory AND source_tombstone_id IS NOT NULL"
                        ),
                        {"memory": approved["memory_id"]},
                    )
                    >= 1
                )
                record = connection.execute(
                    text(
                        "SELECT original_removed,searchable_content_removed "
                        "FROM purge_records WHERE operation_id=:operation"
                    ),
                    {"operation": first["operation_id"]},
                ).one()
                assert record == (True, True)
        finally:
            admin.dispose()
    finally:
        engine.dispose()


def test_memory_approval_and_source_purge_have_deterministic_ordering(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    storage = FilesystemStorage(tmp_path / "race-objects", 1024 * 1024)
    sessions, engine = _sessions(database_urls.app)
    try:
        approval_first = _seed_source(
            database_urls.admin, storage, owner, workspace, b"approval first evidence"
        )
        first_proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Approval commits before purge.",
            category="reference",
            evidence_chunk_ids=[approval_first["chunk_id"]],
            confidence=0.8,
            evidence_quality="high",
            idempotency_key="approval-first-proposal",
        )
        approved = approve_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=first_proposal["proposal_id"],
            idempotency_key="approval-first",
        )
        request_source_purge(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            source_id=approval_first["source_id"],
            reason_code="user_requested",
            idempotency_key="approval-first-purge",
        )
        assert approved["status"] == "active"

        second_owner, second_workspace = uuid4(), uuid4()
        _seed_workspace(database_urls.admin, second_owner, second_workspace)
        purge_first = _seed_source(
            database_urls.admin,
            storage,
            second_owner,
            second_workspace,
            b"purge first evidence",
        )
        second_proposal = propose_memory(
            sessions,
            owner_id=second_owner,
            workspace_id=second_workspace,
            statement="Purge prevents later approval.",
            category="reference",
            evidence_chunk_ids=[purge_first["chunk_id"]],
            confidence=0.8,
            evidence_quality="high",
            idempotency_key="purge-first-proposal",
        )
        request_source_purge(
            sessions,
            owner_id=second_owner,
            workspace_id=second_workspace,
            source_id=purge_first["source_id"],
            reason_code="user_requested",
            idempotency_key="purge-first",
        )
        with pytest.raises(MemoryEvidenceUnavailable):
            approve_memory(
                sessions,
                owner_id=second_owner,
                workspace_id=second_workspace,
                proposal_id=second_proposal["proposal_id"],
                idempotency_key="purge-first-approval",
            )
        with scoped_session(sessions, second_owner, second_workspace) as session:
            assert (
                session.scalar(
                    text("SELECT count(*) FROM approved_memories WHERE proposal_id=:proposal"),
                    {"proposal": second_proposal["proposal_id"]},
                )
                == 0
            )
    finally:
        engine.dispose()


async def test_source_purge_route_is_tenant_scoped_and_reports_durable_worker_state(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    other_owner, other_workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _seed_workspace(database_urls.admin, other_owner, other_workspace)
    storage_root = tmp_path / "route-objects"
    storage = FilesystemStorage(storage_root, 1024 * 1024)
    seeded = _seed_source(database_urls.admin, storage, owner, workspace, b"route purge evidence")
    application = create_app(_settings(database_urls.app, storage_root))
    headers = {
        "x-second-brain-owner-id": str(owner),
        "x-second-brain-workspace-id": str(workspace),
        "Idempotency-Key": "route-source-purge",
    }
    other_headers = {
        "x-second-brain-owner-id": str(other_owner),
        "x-second-brain-workspace-id": str(other_workspace),
        "Idempotency-Key": "route-cross-tenant-purge",
    }
    async with AsyncClient(
        transport=ASGITransport(app=application, client=("127.0.0.1", 40200)),
        base_url="http://127.0.0.1",
    ) as client:
        denied = await client.post(
            f"/api/v1/sources/{seeded['source_id']}/purge",
            headers=other_headers,
            json={"reason_code": "user_requested"},
        )
        assert denied.status_code == 404
        requested = await client.post(
            f"/api/v1/sources/{seeded['source_id']}/purge",
            headers=headers,
            json={"reason_code": "user_requested"},
        )
        assert requested.status_code == 202
        operation_id = requested.json()["operation_id"]
        queued = await client.get(f"/api/v1/purges/{operation_id}", headers=headers)
        assert queued.status_code == 200 and queued.json()["state"] == "queued"
        assert (
            await client.get(f"/api/v1/sources/{seeded['source_id']}", headers=headers)
        ).status_code == 404
        assert (
            await client.get(f"/api/v1/sources/{seeded['source_id']}/content", headers=headers)
        ).status_code == 404
        assert (
            await client.get(
                f"/api/v1/sources/{seeded['source_id']}/context/{seeded['chunk_id']}",
                headers=headers,
            )
        ).status_code == 404
        assert (await client.get("/api/v1/sources", headers=headers)).json() == []
        assert (
            await client.get("/api/v1/search", headers=headers, params={"q": "route purge"})
        ).json()["results"] == []

        invalid_reason = await client.post(
            f"/api/v1/sources/{seeded['source_id']}/purge",
            headers={**headers, "Idempotency-Key": "invalid-reason"},
            json={"reason_code": "seeded-sensitive-source-string-018"},
        )
        assert invalid_reason.status_code == 422

        ordering_engine = create_engine(database_urls.admin)
        try:
            with ordering_engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE purge_operations SET available_at='2000-01-01T00:00:00Z' "
                        "WHERE id=:operation"
                    ),
                    {"operation": operation_id},
                )
        finally:
            ordering_engine.dispose()

        worker, worker_engine = _worker(database_urls, storage, storage_root, "route-purge-worker")
        try:
            assert worker.run_once() is True
        finally:
            worker_engine.dispose()

        complete = await client.get(f"/api/v1/purges/{operation_id}", headers=headers)
        assert complete.status_code == 200 and complete.json()["state"] == "complete"
        assert complete.json()["events"][-1]["to_state"] == "complete"
        assert (
            await client.get(f"/api/v1/sources/{seeded['source_id']}", headers=headers)
        ).status_code == 404
        assert (await client.get("/api/v1/sources", headers=headers)).json() == []
    assert storage.inspect(seeded["key"], seeded["digest"], seeded["size"]) == "missing"


async def test_memory_purge_route_locks_only_mutable_memory_row(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    foreign_owner, foreign_workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _seed_workspace(database_urls.admin, foreign_owner, foreign_workspace)
    storage_root = tmp_path / "memory-route-objects"
    storage = FilesystemStorage(storage_root, 1024 * 1024)
    seeded = _seed_source(database_urls.admin, storage, owner, workspace, b"revision two purge")
    sessions, engine = _sessions(database_urls.app)
    try:
        proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="The first durable memory meaning.",
            category="other",
            evidence_chunk_ids=[seeded["chunk_id"]],
            confidence=0.7,
            evidence_quality="medium",
            idempotency_key="memory-route-proposal",
        )
        approved = approve_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=proposal["proposal_id"],
            idempotency_key="memory-route-approval",
        )
        revised = revise_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=approved["memory_id"],
            statement="The second durable memory meaning.",
            category="other",
            evidence_chunk_ids=[seeded["chunk_id"]],
            confidence=0.8,
            evidence_quality="high",
            idempotency_key="memory-route-revision",
        )
        assert revised["revision_number"] == 2 and revised["status"] == "active"

        application = create_app(_settings(database_urls.app, storage_root))
        owner_headers = {
            "x-second-brain-owner-id": str(owner),
            "x-second-brain-workspace-id": str(workspace),
            "Idempotency-Key": "memory-route-purge",
        }
        foreign_headers = {
            "x-second-brain-owner-id": str(foreign_owner),
            "x-second-brain-workspace-id": str(foreign_workspace),
            "Idempotency-Key": "foreign-memory-route-purge",
        }
        async with AsyncClient(
            transport=ASGITransport(app=application, client=("127.0.0.1", 40201)),
            base_url="http://127.0.0.1",
        ) as client:
            denied = await client.post(
                f"/api/v1/memories/{approved['memory_id']}/purge",
                headers=foreign_headers,
                json={"reason_code": "user_requested"},
            )
            requested = await client.post(
                f"/api/v1/memories/{approved['memory_id']}/purge",
                headers=owner_headers,
                json={"reason_code": "user_requested"},
            )

        assert denied.status_code == 404
        assert requested.status_code == 202 and requested.json()["state"] == "queued"
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                status = connection.scalar(
                    text("SELECT status FROM approved_memories WHERE id=:memory"),
                    {"memory": approved["memory_id"]},
                )
                operations = connection.scalar(
                    text(
                        "SELECT count(*) FROM purge_operations WHERE resource_type='memory' "
                        "AND resource_id=:memory AND owner_id=:owner AND workspace_id=:workspace"
                    ),
                    {
                        "memory": approved["memory_id"],
                        "owner": owner,
                        "workspace": workspace,
                    },
                )
                foreign_operations = connection.scalar(
                    text(
                        "SELECT count(*) FROM purge_operations WHERE resource_type='memory' "
                        "AND resource_id=:memory AND owner_id=:owner AND workspace_id=:workspace"
                    ),
                    {
                        "memory": approved["memory_id"],
                        "owner": foreign_owner,
                        "workspace": foreign_workspace,
                    },
                )
        finally:
            admin.dispose()
        assert status == "purge_pending"
        assert operations == 1 and foreign_operations == 0
    finally:
        engine.dispose()


class CrashAfterDeleteStorage(FilesystemStorage):
    def __init__(self, root: Path, max_bytes: int) -> None:
        super().__init__(root, max_bytes)
        self.crashed = False

    def delete_source(self, owner_id: UUID, workspace_id: UUID, source_id: UUID) -> None:
        super().delete_source(owner_id, workspace_id, source_id)
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated crash after object deletion")


def test_purge_restarts_after_object_delete_without_duplicate_or_loss(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    storage = CrashAfterDeleteStorage(tmp_path / "objects", 1024 * 1024)
    seeded = _seed_source(database_urls.admin, storage, owner, workspace, b"restart purge")
    sessions, engine = _sessions(database_urls.app)
    try:
        operation = request_source_purge(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            source_id=seeded["source_id"],
            reason_code="user_requested",
            idempotency_key="restart-purge",
        )
        ordering_engine = create_engine(database_urls.admin)
        try:
            with ordering_engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE purge_operations SET available_at='2000-01-01T00:00:00Z' "
                        "WHERE id=:operation"
                    ),
                    {"operation": operation["operation_id"]},
                )
        finally:
            ordering_engine.dispose()
        first_worker, first_engine = _worker(
            database_urls, storage, tmp_path / "objects", "crashing-purge-worker"
        )
        try:
            assert first_worker.run_once() is True
        finally:
            first_engine.dispose()

        ordering_engine = create_engine(database_urls.admin)
        try:
            with ordering_engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE purge_operations SET available_at='2100-01-01T00:00:00Z' "
                        "WHERE state='queued' AND id<>:operation"
                    ),
                    {"operation": operation["operation_id"]},
                )
                connection.execute(
                    text(
                        "UPDATE purge_operations SET available_at='2000-01-01T00:00:00Z' "
                        "WHERE id=:operation"
                    ),
                    {"operation": operation["operation_id"]},
                )
        finally:
            ordering_engine.dispose()

        recovered_storage = FilesystemStorage(tmp_path / "objects", 1024 * 1024)
        second_worker, second_engine = _worker(
            database_urls, recovered_storage, tmp_path / "objects", "recovery-purge-worker"
        )
        try:
            assert second_worker.run_once() is True
        finally:
            second_engine.dispose()

        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                assert (
                    connection.scalar(
                        text("SELECT state FROM purge_operations WHERE id=:id"),
                        {"id": operation["operation_id"]},
                    )
                    == "complete"
                )
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM purge_records WHERE operation_id=:id"),
                        {"id": operation["operation_id"]},
                    )
                    == 1
                )
        finally:
            admin.dispose()
    finally:
        engine.dispose()


def test_cross_scope_source_purge_fails_and_memory_purge_removes_meaning(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    foreign_owner, foreign_workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _seed_workspace(database_urls.admin, foreign_owner, foreign_workspace)
    storage = FilesystemStorage(tmp_path / "objects", 1024 * 1024)
    seeded = _seed_source(database_urls.admin, storage, owner, workspace, b"memory purge")
    owner_sessions, owner_engine = _sessions(database_urls.app)
    foreign_sessions, foreign_engine = _sessions(database_urls.app)
    try:
        with pytest.raises(PurgeNotFound):
            request_source_purge(
                foreign_sessions,
                owner_id=foreign_owner,
                workspace_id=foreign_workspace,
                source_id=seeded["source_id"],
                reason_code="user_requested",
                idempotency_key="foreign-purge",
            )
        proposal = propose_memory(
            owner_sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="This statement must be physically purged.",
            category="other",
            evidence_chunk_ids=[seeded["chunk_id"]],
            confidence=0.6,
            evidence_quality="medium",
            idempotency_key="memory-to-purge",
        )
        memory = approve_memory(
            owner_sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=proposal["proposal_id"],
            idempotency_key="approve-memory-to-purge",
        )
        operation = request_memory_purge(
            owner_sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=memory["memory_id"],
            reason_code="user_requested",
            idempotency_key="memory-purge",
        )
        worker, worker_engine = _worker(
            database_urls, storage, tmp_path / "objects", "memory-purge-worker"
        )
        try:
            assert worker.run_once() is True
        finally:
            worker_engine.dispose()
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM approved_memories WHERE id=:memory"),
                        {"memory": memory["memory_id"]},
                    )
                    == 0
                )
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM memory_revisions WHERE memory_id=:memory"),
                        {"memory": memory["memory_id"]},
                    )
                    == 0
                )
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM memory_proposals WHERE id=:proposal"),
                        {"proposal": proposal["proposal_id"]},
                    )
                    == 0
                )
                audit = connection.execute(
                    text(
                        "SELECT resource_type,resource_id FROM purge_records "
                        "WHERE operation_id=:operation"
                    ),
                    {"operation": operation["operation_id"]},
                ).one()
                assert audit == ("memory", memory["memory_id"])
        finally:
            admin.dispose()
    finally:
        foreign_engine.dispose()
        owner_engine.dispose()
