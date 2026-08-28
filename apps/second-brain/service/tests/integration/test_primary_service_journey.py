from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.db import create_database_engine, create_session_factory
from second_brain.providers import FakeEmbeddingProvider, FakeGenerationProvider
from second_brain.storage import FilesystemStorage
from second_brain.worker import IngestionWorker


def _seed_workspace(admin_url: str, owner_id: UUID, workspace_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text(
                    "INSERT INTO workspaces (id,owner_id,name) "
                    "VALUES (:id,:owner,'Integration workspace')"
                ),
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


def _headers(
    owner_id: UUID, workspace_id: UUID, idempotency_key: str | None = None
) -> dict[str, str]:
    headers = {
        "x-second-brain-owner-id": str(owner_id),
        "x-second-brain-workspace-id": str(workspace_id),
    }
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    return headers


async def test_real_service_vertical_slice_preserves_lineage_and_purges_all_content(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = uuid4(), uuid4()
    foreign_owner_id, foreign_workspace_id = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner_id, workspace_id)
    _seed_workspace(database_urls.admin, foreign_owner_id, foreign_workspace_id)

    storage_root = tmp_path / "objects"
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        storage_root=storage_root,
        model_provider="fake",
    )
    storage = FilesystemStorage(storage_root, settings.max_upload_bytes)
    application = create_app(
        settings,
        embedding_provider=FakeEmbeddingProvider(),
        generation_provider=FakeGenerationProvider(),
    )
    owner_headers = _headers(owner_id, workspace_id)
    foreign_headers = _headers(foreign_owner_id, foreign_workspace_id)
    source_text = (
        "The Atlas project preserves orbital archive evidence with deterministic provenance."
    )

    engine = create_database_engine(settings)
    worker = IngestionWorker(
        create_session_factory(engine),
        storage,
        FakeEmbeddingProvider(),
        settings,
        "integration-worker",
        dispatcher_session_factory=database_urls.worker_sessions,
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=application, client=("127.0.0.1", 40500)),
            base_url="http://127.0.0.1",
        ) as client:
            capture = await client.post(
                "/api/v1/captures/text",
                headers=_headers(owner_id, workspace_id, "integration-capture"),
                json={"title": "Atlas research", "content": source_text},
            )
            assert capture.status_code == 202
            source_id = UUID(capture.json()["source_id"])
            job_id = UUID(capture.json()["job_id"])
            assert capture.json()["state"] == "queued"

            assert worker.run_once() is True
            assert worker.run_once() is False

            job = await client.get(f"/api/v1/jobs/{job_id}", headers=owner_headers)
            assert job.status_code == 200 and job.json()["state"] == "ready"

            search = await client.get(
                "/api/v1/search",
                headers=owner_headers,
                params={"q": "orbital archive deterministic provenance"},
            )
            assert search.status_code == 200 and search.json()["semantic_status"] == "available"
            assert len(search.json()["results"]) == 1
            match = search.json()["results"][0]
            chunk_id = UUID(match["chunk_id"])
            assert match["source_id"] == str(source_id)
            assert match["lexical_rank"] == 1
            assert match["semantic_rank"] == 1
            assert "semantic_status" not in match

            assert (
                await client.get(
                    "/api/v1/search",
                    headers=foreign_headers,
                    params={"q": "orbital archive deterministic provenance"},
                )
            ).json()["results"] == []
            assert (
                await client.get(
                    f"/api/v1/sources/{source_id}/context/{chunk_id}",
                    headers=foreign_headers,
                )
            ).status_code == 404

            answer = await client.post(
                "/api/v1/answers",
                headers=_headers(owner_id, workspace_id, "integration-answer"),
                json={"query": "What does the Atlas project preserve?"},
            )
            assert answer.status_code == 200 and answer.json()["status"] == "grounded"
            statement = answer.json()["evidence_supported_statements"][0]
            citation = statement["citations"][0]
            assert citation["source_id"] == str(source_id)
            assert citation["chunk_id"] == str(chunk_id)
            assert citation["citation_id"]
            assert citation["source_version_id"]
            assert citation["char_start"] == 0
            assert citation["char_end"] == len(source_text)
            proposal = answer.json()["proposed_memory"]
            assert proposal["status"] == "proposed"
            assert proposal["evidence"][0]["chunk_id"] == str(chunk_id)

            context = await client.get(
                f"/api/v1/sources/{source_id}/context/{chunk_id}", headers=owner_headers
            )
            assert context.status_code == 200
            assert source_text in context.json()["context_text"]
            assert (await client.get("/api/v1/memories", headers=owner_headers)).json() == []

            proposal_id = proposal["proposal_id"]
            approved = await client.post(
                f"/api/v1/memory-proposals/{proposal_id}/approve",
                headers=_headers(owner_id, workspace_id, "integration-approve"),
                json={},
            )
            assert approved.status_code == 200 and approved.json()["status"] == "active"
            memory_id = approved.json()["memory_id"]
            assert approved.json()["revision_number"] == 1

            revised = await client.post(
                f"/api/v1/memories/{memory_id}/revise",
                headers=_headers(owner_id, workspace_id, "integration-revise"),
                json={
                    "statement": "The Atlas project deliberately preserves its orbital archive.",
                    "category": "project_fact",
                    "confidence": 0.95,
                    "evidence_quality": "high",
                    "source_chunk_ids": [str(chunk_id)],
                },
            )
            assert revised.status_code == 200 and revised.json()["revision_number"] == 2
            memory = await client.get(f"/api/v1/memories/{memory_id}", headers=owner_headers)
            assert memory.status_code == 200
            assert [item["revision_number"] for item in memory.json()["revisions"]] == [1, 2]
            assert all(
                item["source_chunk_ids"] == [str(chunk_id)] for item in memory.json()["revisions"]
            )

            admin = create_engine(database_urls.admin)
            try:
                with admin.connect() as connection:
                    original = connection.execute(
                        text("SELECT object_key,content_sha256 FROM sources WHERE id=:source"),
                        {"source": source_id},
                    ).one()
            finally:
                admin.dispose()
            assert (
                storage.inspect(original.object_key, original.content_sha256, len(source_text))
                == "final"
            )

            denied_purge = await client.post(
                f"/api/v1/sources/{source_id}/purge",
                headers=_headers(foreign_owner_id, foreign_workspace_id, "foreign-purge"),
                json={"reason_code": "user_requested"},
            )
            assert denied_purge.status_code == 404
            purge = await client.post(
                f"/api/v1/sources/{source_id}/purge",
                headers=_headers(owner_id, workspace_id, "integration-purge"),
                json={"reason_code": "user_requested"},
            )
            assert purge.status_code == 202 and purge.json()["state"] == "queued"
            operation_id = purge.json()["operation_id"]

            assert worker.run_once() is True
            purge_status = await client.get(f"/api/v1/purges/{operation_id}", headers=owner_headers)
            assert purge_status.status_code == 200
            assert purge_status.json()["state"] == "complete"
            assert (
                await client.get(
                    "/api/v1/search",
                    headers=owner_headers,
                    params={"q": "orbital archive deterministic provenance"},
                )
            ).json()["results"] == []
            assert (
                await client.get(
                    f"/api/v1/sources/{source_id}/context/{chunk_id}", headers=owner_headers
                )
            ).status_code == 404
            assert (
                await client.get(f"/api/v1/sources/{source_id}/content", headers=owner_headers)
            ).status_code == 404

        assert (
            storage.inspect(original.object_key, original.content_sha256, len(source_text))
            == "missing"
        )
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM embeddings WHERE chunk_id=:chunk"),
                        {"chunk": chunk_id},
                    )
                    == 0
                )
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM chunks WHERE id=:chunk"),
                        {"chunk": chunk_id},
                    )
                    == 0
                )
                assert (
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM memory_evidence_tombstones "
                            "WHERE memory_id=:memory AND source_tombstone_id IS NOT NULL"
                        ),
                        {"memory": memory_id},
                    )
                    >= 1
                )
        finally:
            admin.dispose()
    finally:
        engine.dispose()
