import asyncio
import hashlib
import io
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from docx import Document as DocxDocument
from httpx import ASGITransport, AsyncClient
from pytest import LogCaptureFixture, MonkeyPatch, mark, raises
from sqlalchemy import create_engine, text

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.db import create_database_engine, create_session_factory
from second_brain.parsers import ParseFailure
from second_brain.providers import FakeEmbeddingProvider, UnavailableEmbeddingProvider
from second_brain.storage import StoredObject
from second_brain.url_ingest import BoundResponse, fetch_safe_url
from second_brain.worker import IngestionWorker, LeaseLost


def seed_workspace(admin_url: str) -> tuple[UUID, UUID]:
    owner_id, workspace_id = uuid4(), uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text(
                    "INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'Test workspace')"
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
    return owner_id, workspace_id


def principal_headers(owner_id: UUID, workspace_id: UUID) -> dict[str, str]:
    return {
        "x-second-brain-owner-id": str(owner_id),
        "x-second-brain-workspace-id": str(workspace_id),
    }


def make_settings(
    database_url: str,
    storage_root: Path,
    *,
    answer_min_similarity: float | None = None,
    embedding_profile_version: int = 1,
) -> Settings:
    return Settings(
        app_env="test",
        database_url=database_url,
        storage_root=storage_root,
        model_provider="fake",
        answer_min_similarity=answer_min_similarity,
        embedding_profile_version=embedding_profile_version,
    )


def minimal_pdf(value: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({value}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, item in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode() + item + b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(result)


class PublicResolver:
    def resolve(  # type: ignore[no-untyped-def]
        self, hostname: str, port: int, deadline: float
    ):
        del port, deadline
        return (ip_address("93.184.216.34"),)


class HtmlTransport:
    def get(  # type: ignore[no-untyped-def]
        self, url: str, host: str, address, timeout: float, max_bytes: int
    ):
        return BoundResponse(
            200,
            {"content-type": "text/html"},
            b"<html><style>secret-css</style><body>URL provenance evidence</body></html>",
            address,
        )


class MutableTextTransport:
    def __init__(self, content: bytes, mime_type: str = "text/plain") -> None:
        self.content, self.mime_type = content, mime_type

    def get(  # type: ignore[no-untyped-def]
        self, url: str, host: str, address, timeout: float, max_bytes: int
    ):
        del url, host, timeout, max_bytes
        return BoundResponse(200, {"content-type": self.mime_type}, self.content, address)


async def test_note_capture_is_durable_deduplicated_lexically_searchable_and_openable(
    database_urls: Any, tmp_path: Path, caplog: LogCaptureFixture
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    headers = principal_headers(owner_id, workspace_id)
    marker = "PRIVATE-NOTE-MARKER-8fe2"

    logging.getLogger("second_brain.api").disabled = False
    logging.getLogger("second_brain.worker").disabled = False
    with caplog.at_level(logging.INFO):
        transport = ASGITransport(app=app, client=("127.0.0.1", 39001))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            first = await client.post(
                "/api/v1/captures/text",
                headers=headers,
                json={
                    "title": "Research note",
                    "content": f"Provenance  research uses deterministic evidence. {marker}",
                    "idempotency_key": "note-001",
                },
            )
            duplicate = await client.post(
                "/api/v1/captures/text",
                headers=headers,
                json={
                    "title": "Duplicate title",
                    "content": f"Provenance  research uses deterministic evidence. {marker}",
                },
            )

            assert first.status_code == 202
            assert first.json()["state"] == "queued"
            assert duplicate.status_code == 202
            assert duplicate.json()["duplicate"] is True
            assert duplicate.json()["source_id"] == first.json()["source_id"]

            engine = create_database_engine(settings)
            try:
                worker = IngestionWorker(
                    create_session_factory(engine),
                    app.state.storage,
                    UnavailableEmbeddingProvider(),
                    settings,
                    "test-worker",
                    dispatcher_session_factory=database_urls.worker_sessions,
                )
                assert worker.run_once() is True
                assert worker.run_once() is False
            finally:
                engine.dispose()

            job = await client.get(f"/api/v1/jobs/{first.json()['job_id']}", headers=headers)
            opened = await client.get(
                f"/api/v1/sources/{first.json()['source_id']}/content", headers=headers
            )
            found = await client.get(
                "/api/v1/search", params={"q": "deterministic evidence"}, headers=headers
            )

    assert job.status_code == 200
    assert job.json()["state"] == "ready"
    assert opened.status_code == 200
    assert marker in opened.json()["extracted_text"]
    assert found.status_code == 200
    assert [row["source_id"] for row in found.json()["results"]] == [first.json()["source_id"]]
    assert marker not in caplog.text

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM sources WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM source_versions WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_jobs WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_job_events WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM documents WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM chunks WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM embeddings WHERE owner_id=:owner)"
                ),
                {"owner": owner_id},
            ).one()
            hashes = connection.execute(
                text(
                    "SELECT content_sha256,normalized_dedup_sha256 FROM sources "
                    "WHERE owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one()
    finally:
        admin.dispose()
    assert counts == (1, 1, 1, 3, 1, 1, 0)
    # Text hashing and parsing share the same versioned canonical normalizer.
    assert hashes[0] == hashes[1]


@mark.parametrize("same_content", [False, True])
async def test_worker_does_not_fail_parallel_capture_before_storage_finalizes(
    database_urls: Any,
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    same_content: bool,
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "parallel-capture-objects")
    app = create_app(settings)
    headers = principal_headers(owner_id, workspace_id)
    entered_write = threading.Event()
    release_write = threading.Event()
    original_write_partial = cast(
        Callable[[str, bytes, str], StoredObject], app.state.storage.write_partial
    )

    def gated_write_partial(key: str, data: bytes, expected_sha256: str) -> StoredObject:
        entered_write.set()
        if not release_write.wait(5):
            raise TimeoutError("parallel capture storage gate timed out")
        return original_write_partial(key, data, expected_sha256)

    monkeypatch.setattr(app.state.storage, "write_partial", gated_write_partial)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39029))
    engine = create_database_engine(settings)
    worker = IngestionWorker(
        create_session_factory(engine),
        app.state.storage,
        UnavailableEmbeddingProvider(),
        settings,
        "parallel-capture-worker",
        dispatcher_session_factory=database_urls.worker_sessions,
    )
    worker_task: asyncio.Task[bool] | None = None
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            first_content = "parallel desktop evidence"
            second_content = first_content if same_content else "parallel mobile evidence"
            requests = [
                asyncio.create_task(
                    client.post(
                        "/api/v1/captures/text",
                        headers=headers,
                        json={
                            "title": "Desktop parallel capture",
                            "content": first_content,
                            "idempotency_key": "parallel-desktop-capture",
                        },
                    )
                ),
                asyncio.create_task(
                    client.post(
                        "/api/v1/captures/text",
                        headers=headers,
                        json={
                            "title": "Mobile parallel capture",
                            "content": second_content,
                            "idempotency_key": "parallel-mobile-capture",
                        },
                    )
                ),
            ]
            assert await asyncio.to_thread(entered_write.wait, 5)
            worker_task = asyncio.create_task(asyncio.to_thread(worker.run_once))
            await asyncio.sleep(0.1)
            assert not worker_task.done()
            release_write.set()
            responses = await asyncio.gather(*requests)
            assert await worker_task is True
            if same_content:
                assert await asyncio.to_thread(worker.run_once) is False
            else:
                assert await asyncio.to_thread(worker.run_once) is True
    finally:
        release_write.set()
        if worker_task is not None and not worker_task.done():
            await worker_task
        engine.dispose()
    assert all(response.status_code == 202 for response in responses)
    payloads = [response.json() for response in responses]
    expected_count = 1 if same_content else 2
    assert len({payload["source_id"] for payload in payloads}) == expected_count
    assert sorted(payload["duplicate"] for payload in payloads) == (
        [False, True] if same_content else [False, False]
    )
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT count(DISTINCT source.id),count(DISTINCT job.id),"
                    "count(DISTINCT stage.id),min(job.attempts),max(job.attempts),"
                    "count(*) FILTER (WHERE job.state='ready'),"
                    "count(*) FILTER (WHERE event.reason_class='claimed') "
                    "FROM sources AS source "
                    "JOIN ingestion_jobs AS job ON job.source_id=source.id "
                    "JOIN capture_stages AS stage ON stage.job_id=job.id "
                    "JOIN ingestion_job_events AS event ON event.job_id=job.id "
                    "WHERE source.owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one() == (
                expected_count,
                expected_count,
                expected_count,
                1,
                1,
                expected_count * 3,
                expected_count,
            )
    finally:
        admin.dispose()


async def test_idempotency_header_replays_same_request_and_rejects_conflicting_input(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    headers = {
        **principal_headers(owner_id, workspace_id),
        "idempotency-key": "header-attempt-001",
    }
    transport = ASGITransport(app=app, client=("127.0.0.1", 39007))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        first = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Stable request", "content": "same evidence"},
        )
        replay = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Stable request", "content": "same evidence"},
        )
        conflict = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Changed request", "content": "different evidence"},
        )

        engine = create_database_engine(settings)
        try:
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "idempotency-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            assert worker.run_once() is True
        finally:
            engine.dispose()

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["duplicate"] is True
    assert replay.json()["source_id"] == first.json()["source_id"]
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "idempotency_conflict"


async def test_fake_embedding_worker_persists_vectors_and_whitespace_search_is_rejected(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(
        database_urls.app,
        tmp_path / "objects",
        answer_min_similarity=0.42,
        embedding_profile_version=7,
    )
    app = create_app(settings)
    headers = principal_headers(owner_id, workspace_id)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39008))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Embedded note", "content": "vector-ready evidence"},
        )
        assert captured.status_code == 202
        engine = create_database_engine(settings)
        try:
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                FakeEmbeddingProvider(settings.embedding_dimensions, profile_version=7),
                settings,
                "embedding-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            assert worker.run_once() is True
        finally:
            engine.dispose()
        whitespace = await client.get("/api/v1/search", params={"q": "   \t"}, headers=headers)

    assert whitespace.status_code == 422
    assert whitespace.json()["code"] == "validation_error"
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT count(chunk.id),count(embedding.id),"
                    "min(vector_dims(embedding.embedding)) "
                    "FROM chunks AS chunk JOIN embeddings AS embedding "
                    "ON embedding.chunk_id=chunk.id WHERE chunk.owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one()
            profile = connection.execute(
                text(
                    "SELECT provider,model_identifier,profile_version,dimensions,"
                    "answer_min_similarity "
                    "FROM embedding_profiles WHERE owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one()
    finally:
        admin.dispose()
    assert counts == (1, 1, settings.embedding_dimensions)
    assert profile == (
        "FakeEmbeddingProvider",
        "deterministic-sha256-v1",
        7,
        settings.embedding_dimensions,
        0.42,
    )


async def test_worker_fails_closed_on_calibration_drift_and_reuses_bumped_profile(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    storage_root = tmp_path / "objects"
    initial_settings = make_settings(
        database_urls.app,
        storage_root,
        answer_min_similarity=0.2,
        embedding_profile_version=7,
    )
    app = create_app(initial_settings)
    headers = principal_headers(owner_id, workspace_id)

    def process_once(worker_settings: Settings) -> None:
        engine = create_database_engine(worker_settings)
        try:
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                FakeEmbeddingProvider(
                    worker_settings.embedding_dimensions,
                    profile_version=worker_settings.embedding_profile_version,
                ),
                worker_settings,
                f"profile-worker-v{worker_settings.embedding_profile_version}",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            assert worker.run_once() is True
        finally:
            engine.dispose()

    async with AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 39018)),
        base_url="http://127.0.0.1",
    ) as client:
        initial = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Initial profile", "content": "initial profile evidence"},
        )
        assert initial.status_code == 202
        process_once(initial_settings)

        drift_settings = make_settings(
            database_urls.app,
            storage_root,
            answer_min_similarity=0.9,
            embedding_profile_version=7,
        )
        drift = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Drift profile", "content": "drift profile evidence"},
        )
        assert drift.status_code == 202
        process_once(drift_settings)

        bumped_settings = make_settings(
            database_urls.app,
            storage_root,
            answer_min_similarity=0.9,
            embedding_profile_version=8,
        )
        bumped_source_ids: list[str] = []
        for ordinal in (1, 2):
            bumped = await client.post(
                "/api/v1/captures/text",
                headers=headers,
                json={
                    "title": f"Bumped profile {ordinal}",
                    "content": f"bumped profile evidence {ordinal}",
                },
            )
            assert bumped.status_code == 202
            bumped_source_ids.append(bumped.json()["source_id"])
            process_once(bumped_settings)

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            drift_state = connection.execute(
                text(
                    "SELECT source.semantic_state,job.semantic_state,job.semantic_error_class "
                    "FROM sources AS source JOIN ingestion_jobs AS job "
                    "ON job.source_id=source.id WHERE source.id=:source"
                ),
                {"source": drift.json()["source_id"]},
            ).one()
            bumped_states = (
                connection.execute(
                    text(
                        "SELECT semantic_state FROM sources "
                        "WHERE id=ANY(CAST(:sources AS uuid[])) ORDER BY id"
                    ),
                    {"sources": bumped_source_ids},
                )
                .scalars()
                .all()
            )
            profiles = connection.execute(
                text(
                    "SELECT profile.profile_version,profile.answer_min_similarity,"
                    "count(embedding.id) FROM embedding_profiles AS profile "
                    "LEFT JOIN embeddings AS embedding ON embedding.profile_id=profile.id "
                    "WHERE profile.owner_id=:owner GROUP BY profile.id ORDER BY profile_version"
                ),
                {"owner": owner_id},
            ).all()
        assert drift_state == ("unavailable", "unavailable", "ProviderUnavailable")
        assert bumped_states == ["available", "available"]
        assert [tuple(row) for row in profiles] == [(7, 0.2, 1), (8, 0.9, 2)]
    finally:
        admin.dispose()


async def test_expired_worker_lease_is_reclaimed_without_duplicate_stage_rows(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39002))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post(
            "/api/v1/captures/upload",
            headers=principal_headers(owner_id, workspace_id),
            data={"title": "Restart-safe text"},
            files={"file": ("restart.txt", b"durable worker restart evidence", "text/plain")},
        )
    assert response.status_code == 202

    first_engine = create_database_engine(settings)
    try:
        first_worker = IngestionWorker(
            create_session_factory(first_engine),
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "crashed-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        claimed = first_worker.claim(lease_seconds=30)
        assert claimed is not None
    finally:
        first_engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            assert (
                connection.scalar(
                    text("SELECT processing_state FROM sources WHERE id=:id"),
                    {"id": claimed.source_id},
                )
                == "processing"
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET "
                    "lease_expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE id=:id"
                ),
                {"id": claimed.job_id},
            )
    finally:
        admin.dispose()

    second_engine = create_database_engine(settings)
    try:
        restarted = IngestionWorker(
            create_session_factory(second_engine),
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "restarted-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert restarted.run_once() is True
        assert restarted.run_once() is False
    finally:
        second_engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            result = connection.execute(
                text(
                    "SELECT job.state,job.attempts,"
                    "(SELECT count(*) FROM documents "
                    "WHERE source_version_id=job.source_version_id),"
                    "(SELECT count(*) FROM chunks WHERE source_version_id=job.source_version_id) "
                    "FROM ingestion_jobs AS job WHERE job.id=:id"
                ),
                {"id": claimed.job_id},
            ).one()
    finally:
        admin.dispose()
    assert result == ("ready", 2, 1, 1)

    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "VALUES (:owner,:workspace,:job,3,'ready','processing','test_exhaustion')"
                ),
                {
                    "owner": claimed.owner_id,
                    "workspace": claimed.workspace_id,
                    "job": claimed.job_id,
                },
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='processing',attempts=3,"
                    "lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=:id"
                ),
                {"id": claimed.job_id},
            )
            connection.execute(
                text("UPDATE sources SET processing_state='processing' WHERE id=:id"),
                {"id": claimed.source_id},
            )
    finally:
        admin.dispose()
    exhausted_engine = create_database_engine(settings)
    try:
        exhausted_workers = [
            IngestionWorker(
                create_session_factory(exhausted_engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                f"exhaustion-worker-{index}",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            for index in range(2)
        ]
        with ThreadPoolExecutor(max_workers=2) as executor:
            assert list(executor.map(lambda worker: worker.claim(), exhausted_workers)) == [
                None,
                None,
            ]
    finally:
        exhausted_engine.dispose()
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            exhausted_state = connection.execute(
                text(
                    "SELECT job.state,source.processing_state,"
                    "(SELECT count(*) FROM ingestion_job_events AS event "
                    "WHERE event.job_id=job.id AND event.reason_class='attempts_exhausted') "
                    "FROM ingestion_jobs AS job JOIN sources AS source "
                    "ON source.id=job.source_id WHERE job.id=:id"
                ),
                {"id": claimed.job_id},
            ).one()
    finally:
        admin.dispose()
    assert exhausted_state == ("dead", "failed", 1)


async def test_stale_worker_cannot_fail_job_after_another_worker_reclaims_lease(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39009))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Lease ownership", "content": "lease-bound evidence"},
        )
    assert response.status_code == 202

    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    try:
        sessions = create_session_factory(engine)
        stale = IngestionWorker(
            sessions,
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "stale-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        current = IngestionWorker(
            sessions,
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "current-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        stale_job = stale.claim(lease_seconds=30)
        assert stale_job is not None
        with admin.begin() as connection:
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET "
                    "lease_expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE id=:id"
                ),
                {"id": stale_job.job_id},
            )
        current_job = current.claim(lease_seconds=30)
        assert current_job is not None
        stale._fail(stale_job, "ParseFailure", "stale worker must not win")
        with admin.connect() as connection:
            state = connection.execute(
                text(
                    "SELECT job.state,job.lease_owner,source.processing_state "
                    "FROM ingestion_jobs AS job JOIN sources AS source ON source.id=job.source_id "
                    "WHERE job.id=:id"
                ),
                {"id": stale_job.job_id},
            ).one()
    finally:
        engine.dispose()
        admin.dispose()
    assert state == ("processing", "current-worker", "processing")


async def test_parser_failure_is_visible_safe_and_tenant_scoped(
    database_urls: Any, tmp_path: Path, caplog: LogCaptureFixture, monkeypatch: MonkeyPatch
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    other_owner_id, other_workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    marker = "SEEDED-PRIVATE-PARSER-CONTENT-5b91"
    transport = ASGITransport(app=app, client=("127.0.0.1", 39003))

    logging.getLogger("second_brain.worker").disabled = False
    with caplog.at_level(logging.INFO):
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            captured = await client.post(
                "/api/v1/captures/upload",
                headers=principal_headers(owner_id, workspace_id),
                data={"title": "Invalid PDF"},
                files={
                    "file": (
                        "invalid.pdf",
                        minimal_pdf(marker),
                        "application/pdf",
                    )
                },
            )
            assert captured.status_code == 202

            def fail_parser(*args: object, **kwargs: object) -> object:
                del args, kwargs
                raise ParseFailure("seeded parser failure")

            monkeypatch.setattr("second_brain.worker.parse_document_isolated", fail_parser)

            engine = create_database_engine(settings)
            try:
                worker = IngestionWorker(
                    create_session_factory(engine),
                    app.state.storage,
                    UnavailableEmbeddingProvider(),
                    settings,
                    "failure-worker",
                    dispatcher_session_factory=database_urls.worker_sessions,
                )
                assert worker.run_once() is True
            finally:
                engine.dispose()

            job = await client.get(
                f"/api/v1/jobs/{captured.json()['job_id']}",
                headers=principal_headers(owner_id, workspace_id),
            )
            foreign_job = await client.get(
                f"/api/v1/jobs/{captured.json()['job_id']}",
                headers=principal_headers(other_owner_id, other_workspace_id),
            )
            foreign_source = await client.get(
                f"/api/v1/sources/{captured.json()['source_id']}",
                headers=principal_headers(other_owner_id, other_workspace_id),
            )

    assert job.status_code == 200
    assert job.json()["state"] == "failed"
    assert job.json()["error_code"] == "ParseFailure"
    assert marker not in job.text
    assert foreign_job.status_code == 404
    assert foreign_source.status_code == 404
    assert marker not in caplog.text
    assert marker[:5] not in caplog.text


async def test_safe_url_capture_is_processed_with_bound_offline_transport(
    database_urls: Any, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("request-time capture attempted DNS")
        ),
    )
    resolver, bound_transport = PublicResolver(), HtmlTransport()
    app.state.url_resolver = resolver
    transport = ASGITransport(app=app, client=("127.0.0.1", 39004))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/url",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Public evidence", "url": "https://public.test/evidence"},
        )
        assert captured.status_code == 202
        assert captured.json()["source_version_id"] is None

        engine = create_database_engine(settings)
        try:
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "url-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
                url_resolver=resolver,
                url_transport=bound_transport,
            )
            assert worker.run_once() is True
        finally:
            engine.dispose()

        opened = await client.get(
            f"/api/v1/sources/{captured.json()['source_id']}/content",
            headers=principal_headers(owner_id, workspace_id),
        )
    assert opened.status_code == 200
    assert opened.json()["extracted_text"] == "URL provenance evidence"
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            provenance = connection.execute(
                text(
                    "SELECT source.content_sha256,source.object_key,job.source_version_id,"
                    "version.content_sha256,stage.state,fetched.byte_count,"
                    "fetched.content_sha256,fetched.object_key FROM sources AS source "
                    "JOIN ingestion_jobs AS job ON job.source_id=source.id "
                    "JOIN source_versions AS version ON version.id=job.source_version_id "
                    "JOIN capture_stages AS stage ON stage.source_version_id=version.id "
                    "JOIN url_fetches AS fetched ON fetched.job_id=job.id "
                    "WHERE source.owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one()
    finally:
        admin.dispose()
    expected_hash = hashlib.sha256(
        b"<html><style>secret-css</style><body>URL provenance evidence</body></html>"
    ).hexdigest()
    assert provenance[:2] == (None, None)
    assert provenance[2] is not None
    assert provenance[3:7] == (expected_hash, "finalized", 74, expected_hash)
    assert app.state.storage.read(provenance[7], expected_hash).startswith(b"<html>")


async def test_url_refetch_versions_changed_bytes_and_reuses_identical_bytes(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    resolver = PublicResolver()
    app.state.url_resolver = resolver
    fetched = MutableTextTransport(b"first fetched bytes")
    headers = principal_headers(owner_id, workspace_id)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39014))
    engine = create_database_engine(settings)
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            version_ids: list[str] = []
            for content in (
                b"first fetched bytes",
                b"changed fetched bytes",
                b"changed fetched bytes",
            ):
                fetched.content = content
                captured = await client.post(
                    "/api/v1/captures/url",
                    headers=headers,
                    json={
                        "title": "Versioned public source",
                        "url": "https://public.test/versioned",
                    },
                )
                assert captured.status_code == 202
                worker = IngestionWorker(
                    create_session_factory(engine),
                    app.state.storage,
                    UnavailableEmbeddingProvider(),
                    settings,
                    f"url-refetch-{len(version_ids)}",
                    dispatcher_session_factory=database_urls.worker_sessions,
                    url_resolver=resolver,
                    url_transport=fetched,
                )
                assert worker.run_once() is True
                job = await client.get(f"/api/v1/jobs/{captured.json()['job_id']}", headers=headers)
                assert job.json()["state"] == "ready"
                admin = create_engine(database_urls.admin)
                try:
                    with admin.connect() as connection:
                        version_ids.append(
                            str(
                                connection.scalar(
                                    text(
                                        "SELECT source_version_id FROM ingestion_jobs WHERE id=:job"
                                    ),
                                    {"job": captured.json()["job_id"]},
                                )
                            )
                        )
                finally:
                    admin.dispose()
    finally:
        engine.dispose()
    assert version_ids[0] != version_ids[1]
    assert version_ids[1] == version_ids[2]
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM sources WHERE owner_id=:owner"), {"owner": owner_id}
                )
                == 1
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM source_versions WHERE owner_id=:owner"),
                    {"owner": owner_id},
                )
                == 2
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM url_fetches WHERE owner_id=:owner"),
                    {"owner": owner_id},
                )
                == 3
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM capture_stages WHERE owner_id=:owner"),
                    {"owner": owner_id},
                )
                == 3
            )
            assert not connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM capture_stages AS stage "
                    "JOIN url_fetches AS fetched ON fetched.job_id=stage.job_id "
                    "WHERE stage.owner_id=:owner AND ("
                    "stage.source_id<>fetched.source_id "
                    "OR stage.source_version_id<>fetched.source_version_id "
                    "OR stage.object_key<>fetched.object_key))"
                ),
                {"owner": owner_id},
            )
    finally:
        admin.dispose()


async def test_url_partial_stage_is_reconciled_after_worker_restart(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    resolver = PublicResolver()
    app.state.url_resolver = resolver
    fetched_transport = MutableTextTransport(b"restart-safe fetched bytes")
    headers = principal_headers(owner_id, workspace_id)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39015))
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            captured = await client.post(
                "/api/v1/captures/url",
                headers=headers,
                json={"title": "Restart URL", "url": "https://public.test/restart"},
            )
            first = IngestionWorker(
                sessions,
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "url-crashed-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
                url_resolver=resolver,
                url_transport=fetched_transport,
            )
            claimed = first.claim(1)
            assert claimed is not None
            fetched = fetch_safe_url(
                "https://public.test/restart",
                resolver=resolver,
                transport=fetched_transport,
                timeout=1,
            )
            lineage = first._prepare_url_fetch(claimed, "https://public.test/restart", fetched)
            app.state.storage.write_partial(lineage.object_key, fetched.content, lineage.sha256)

            admin = create_engine(database_urls.admin)
            try:
                with admin.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE ingestion_jobs SET "
                            "lease_expires_at=clock_timestamp()-interval '1s' "
                            "WHERE id=:job"
                        ),
                        {"job": claimed.job_id},
                    )
            finally:
                admin.dispose()
            second = IngestionWorker(
                sessions,
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "url-recovery-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
                url_resolver=resolver,
                url_transport=fetched_transport,
            )
            assert second.run_once() is True
            job = await client.get(f"/api/v1/jobs/{captured.json()['job_id']}", headers=headers)
            assert job.json()["state"] == "ready"
    finally:
        engine.dispose()
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT stage.state,count(fetched.id),count(version.id) "
                    "FROM capture_stages AS stage "
                    "JOIN url_fetches AS fetched "
                    "ON fetched.job_id=stage.job_id "
                    "JOIN source_versions AS version ON version.id=stage.source_version_id "
                    "WHERE stage.owner_id=:owner GROUP BY stage.state"
                ),
                {"owner": owner_id},
            ).one() == ("finalized", 1, 1)
    finally:
        admin.dispose()
    assert len(list(settings.storage_root.rglob(claimed.job_id.hex))) == 1
    assert not list(settings.storage_root.rglob("*.partial"))


async def test_stale_url_finalizer_cannot_resurrect_content_after_completed_purge(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "purged-url-objects")
    app = create_app(settings)
    resolver = PublicResolver()
    fetched_transport = MutableTextTransport(b"private URL bytes that must stay purged")
    app.state.url_resolver = resolver
    headers = principal_headers(owner_id, workspace_id)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39018))
    engine = create_database_engine(settings)
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            captured = await client.post(
                "/api/v1/captures/url",
                headers=headers,
                json={"title": "Purged URL", "url": "https://public.test/purged"},
            )
            assert captured.status_code == 202
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "stale-url-finalizer",
                dispatcher_session_factory=database_urls.worker_sessions,
                url_resolver=resolver,
                url_transport=fetched_transport,
            )
            claimed = worker.claim(30)
            assert claimed is not None
            fetched = fetch_safe_url(
                "https://public.test/purged",
                resolver=resolver,
                transport=fetched_transport,
                timeout=1,
            )
            lineage = worker._prepare_url_fetch(claimed, "https://public.test/purged", fetched)

            purge = await client.post(
                f"/api/v1/sources/{claimed.source_id}/purge",
                headers={**headers, "Idempotency-Key": "purge-before-url-finalize"},
                json={"reason_code": "user_requested"},
            )
            assert purge.status_code == 202
            assert worker.run_purge_once() is True

            with raises(LeaseLost, match="ingestion lease was lost"):
                worker._finalize_url_object(claimed, lineage, fetched.content)
    finally:
        engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM sources WHERE id=:source),"
                    "(SELECT count(*) FROM ingestion_jobs WHERE id=:job),"
                    "(SELECT count(*) FROM source_versions WHERE id=:version),"
                    "(SELECT count(*) FROM capture_stages WHERE id=:stage),"
                    "(SELECT count(*) FROM url_fetches WHERE job_id=:job)"
                ),
                {
                    "source": claimed.source_id,
                    "job": claimed.job_id,
                    "version": lineage.version_id,
                    "stage": lineage.stage_id,
                },
            ).one()
    finally:
        admin.dispose()
    assert counts == (0, 0, 0, 0, 0)
    assert not list(settings.storage_root.rglob("*.partial"))
    assert not list(settings.storage_root.rglob(claimed.job_id.hex))


async def test_stale_stage_sweeper_cannot_dead_letter_a_source_pending_purge(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "purge-sweep-objects")
    app = create_app(settings)
    resolver = PublicResolver()
    fetched_transport = MutableTextTransport(b"purge must win over stale reconciliation")
    app.state.url_resolver = resolver
    headers = principal_headers(owner_id, workspace_id)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39019))
    engine = create_database_engine(settings)
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            captured = await client.post(
                "/api/v1/captures/url",
                headers=headers,
                json={"title": "Purge versus sweep", "url": "https://public.test/sweep"},
            )
            assert captured.status_code == 202
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                "purge-sweep-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
                url_resolver=resolver,
                url_transport=fetched_transport,
            )
            claimed = worker.claim(30)
            assert claimed is not None
            fetched = fetch_safe_url(
                "https://public.test/sweep",
                resolver=resolver,
                transport=fetched_transport,
                timeout=1,
            )
            lineage = worker._prepare_url_fetch(claimed, "https://public.test/sweep", fetched)

            admin = create_engine(database_urls.admin)
            try:
                with admin.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE ingestion_jobs SET "
                            "lease_expires_at=clock_timestamp()-interval '1 second' "
                            "WHERE id=:job"
                        ),
                        {"job": claimed.job_id},
                    )
            finally:
                admin.dispose()

            time.sleep(1.1)

            purge = await client.post(
                f"/api/v1/sources/{claimed.source_id}/purge",
                headers={**headers, "Idempotency-Key": "purge-before-stale-sweep"},
                json={"reason_code": "user_requested"},
            )
            assert purge.status_code == 202
            worker.sweep_stale_stages(1, 1000)

            admin = create_engine(database_urls.admin)
            try:
                with admin.connect() as connection:
                    target_state = connection.execute(
                        text(
                            "SELECT source.processing_state,job.state,stage.state "
                            "FROM sources AS source JOIN ingestion_jobs AS job "
                            "ON job.source_id=source.id JOIN capture_stages AS stage "
                            "ON stage.job_id=job.id WHERE source.id=:source"
                        ),
                        {"source": claimed.source_id},
                    ).one()
            finally:
                admin.dispose()
            assert target_state == ("purge_pending", "processing", "pending")

            assert worker.run_purge_once() is True
    finally:
        engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM sources WHERE id=:source),"
                    "(SELECT count(*) FROM ingestion_jobs WHERE id=:job),"
                    "(SELECT count(*) FROM source_versions WHERE id=:version),"
                    "(SELECT count(*) FROM capture_stages WHERE id=:stage),"
                    "(SELECT count(*) FROM url_fetches WHERE job_id=:job)"
                ),
                {
                    "source": claimed.source_id,
                    "job": claimed.job_id,
                    "version": lineage.version_id,
                    "stage": lineage.stage_id,
                },
            ).one()
    finally:
        admin.dispose()
    assert counts == (0, 0, 0, 0, 0)
    assert not list(settings.storage_root.rglob("*.partial"))
    assert not list(settings.storage_root.rglob(claimed.job_id.hex))


async def test_actual_sigkill_during_api_partial_write_recovers_exactly_once(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    storage_root = tmp_path / "api-kill-objects"
    content = "torn-write-evidence-" * 20_000
    content_path = tmp_path / "api-kill-content.txt"
    content_path.write_text(content, encoding="utf-8")
    child = r"""
import asyncio, os, signal, sys
from pathlib import Path
from httpx import ASGITransport, AsyncClient
from second_brain.app import create_app
from second_brain.config import Settings
real_write = os.write
def torn_write(fd, data):
    try:
        path = os.readlink(f'/proc/self/fd/{fd}')
    except OSError:
        path = ''
    if path.endswith('.partial') and len(data) > 4096:
        real_write(fd, data[:4096])
        os.kill(os.getpid(), signal.SIGKILL)
    return real_write(fd, data)
os.write = torn_write
async def main():
    settings = Settings(
        app_env='test', database_url=sys.argv[1], storage_root=Path(sys.argv[2])
    )
    app = create_app(settings)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url='http://127.0.0.1'
    ) as client:
        content = Path(sys.argv[5]).read_text(encoding='utf-8')
        await client.post('/api/v1/captures/text', headers={
            'x-second-brain-owner-id': sys.argv[3],
            'x-second-brain-workspace-id': sys.argv[4],
        }, json={'title':'Killed API capture','content':content,'idempotency_key':'kill-api-1'})
asyncio.run(main())
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child,
            database_urls.app,
            str(storage_root),
            str(owner_id),
            str(workspace_id),
            str(content_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert process.wait(timeout=15) == -signal.SIGKILL
    assert len(list(storage_root.rglob("*.partial"))) == 1

    app = create_app(
        Settings(app_env="test", database_url=database_urls.app, storage_root=storage_root)
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        response = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={
                "title": "Killed API capture",
                "content": content,
                "idempotency_key": "kill-api-1",
            },
        )
    assert response.status_code == 202
    assert response.json()["duplicate"] is True
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT count(DISTINCT source.id),count(DISTINCT version.id),"
                    "count(DISTINCT job.id),count(DISTINCT stage.id) FROM sources AS source "
                    "JOIN source_versions AS version ON version.source_id=source.id "
                    "JOIN ingestion_jobs AS job ON job.source_id=source.id "
                    "JOIN capture_stages AS stage ON stage.source_id=source.id "
                    "WHERE source.owner_id=:owner"
                ),
                {"owner": owner_id},
            ).one() == (1, 1, 1, 1)
    finally:
        admin.dispose()
    assert len(list(storage_root.rglob("original"))) == 1
    assert not list(storage_root.rglob("*.partial"))
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "SELECT owner_id,workspace_id,id,attempts,'queued','failed','test_cleanup' "
                    "FROM ingestion_jobs WHERE id=:job"
                ),
                {"job": response.json()["job_id"]},
            )
            connection.execute(
                text("UPDATE ingestion_jobs SET state='failed' WHERE id=:job"),
                {"job": response.json()["job_id"]},
            )
    finally:
        admin.dispose()


async def test_actual_sigkill_during_url_partial_write_refetches_matching_provenance_once(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    storage_root = tmp_path / "url-kill-objects"
    content = b"url-torn-write-evidence-" * 20_000
    content_path = tmp_path / "url-kill-content.bin"
    content_path.write_bytes(content)
    app = create_app(
        Settings(app_env="test", database_url=database_urls.app, storage_root=storage_root)
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/url",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Killed URL capture", "url": "https://public.test/killed?proof=1"},
        )
    assert captured.status_code == 202
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text("UPDATE ingestion_jobs SET available_at='1970-01-01' WHERE id=:job"),
                {"job": captured.json()["job_id"]},
            )
    finally:
        admin.dispose()
    child = r"""
import os, signal, sys
from ipaddress import ip_address
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from second_brain.config import Settings
from second_brain.db import create_database_engine, create_session_factory
from second_brain.providers import UnavailableEmbeddingProvider
from second_brain.storage import FilesystemStorage
from second_brain.url_ingest import BoundResponse
from second_brain.worker import IngestionWorker
class Resolver:
    def resolve(self, hostname, port, deadline):
        return (ip_address('93.184.216.34'),)
class Transport:
    def get(self, url, host, address, timeout, max_bytes):
        return BoundResponse(
            200, {'content-type':'text/plain'}, Path(sys.argv[3]).read_bytes(), address
        )
real_write = os.write
def torn_write(fd, data):
    try:
        path = os.readlink(f'/proc/self/fd/{fd}')
    except OSError:
        path = ''
    if path.endswith('.partial') and len(data) > 4096:
        real_write(fd, data[:4096])
        os.kill(os.getpid(), signal.SIGKILL)
    return real_write(fd, data)
os.write = torn_write
s = Settings(app_env='test', database_url=sys.argv[1], storage_root=Path(sys.argv[2]))
content_engine = create_database_engine(s)
dispatcher_engine = create_engine(sys.argv[4])
w = IngestionWorker(
    create_session_factory(content_engine),
    FilesystemStorage(s.storage_root, s.max_upload_bytes),
    UnavailableEmbeddingProvider(),
    s,
    'url-killed-writer',
    dispatcher_session_factory=sessionmaker(bind=dispatcher_engine, expire_on_commit=False),
    url_resolver=Resolver(),
    url_transport=Transport(),
    lease_seconds=1,
)
w.run_once()
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child,
            database_urls.app,
            str(storage_root),
            str(content_path),
            database_urls.worker,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert process.wait(timeout=15) == -signal.SIGKILL
    assert len(list(storage_root.rglob("*.partial"))) == 1
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET lease_expires_at=clock_timestamp()-interval '1s' "
                    "WHERE id=:job"
                ),
                {"job": captured.json()["job_id"]},
            )
    finally:
        admin.dispose()
    engine = create_database_engine(
        Settings(app_env="test", database_url=database_urls.app, storage_root=storage_root)
    )
    try:
        replacement = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            UnavailableEmbeddingProvider(),
            app.state.settings,
            "url-replacement-writer",
            dispatcher_session_factory=database_urls.worker_sessions,
            url_resolver=PublicResolver(),
            url_transport=MutableTextTransport(content),
        )
        assert replacement.run_once() is True
    finally:
        engine.dispose()
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT job.state,count(DISTINCT version.id),count(DISTINCT stage.id),"
                    "count(DISTINCT fetched.id) FROM ingestion_jobs AS job "
                    "JOIN source_versions AS version ON version.id=job.source_version_id "
                    "JOIN capture_stages AS stage ON stage.job_id=job.id "
                    "JOIN url_fetches AS fetched ON fetched.job_id=job.id "
                    "WHERE job.id=:job GROUP BY job.state"
                ),
                {"job": captured.json()["job_id"]},
            ).one() == ("ready", 1, 1, 1)
    finally:
        admin.dispose()
    assert len(list(storage_root.rglob("*.partial"))) == 0
    assert len([path for path in storage_root.rglob("*") if path.is_file()]) == 1


async def test_url_retry_rejects_same_bytes_with_different_parser_mime(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "mime-provenance")
    app = create_app(settings)
    resolver = PublicResolver()
    content = b"same fetched bytes"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/url",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "MIME provenance", "url": "https://public.test/mime?version=1"},
        )
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text("UPDATE ingestion_jobs SET available_at='1970-01-01' WHERE id=:job"),
                {"job": captured.json()["job_id"]},
            )
    finally:
        admin.dispose()
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    try:
        first_transport = MutableTextTransport(content, "text/plain")
        first = IngestionWorker(
            sessions,
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "mime-first",
            dispatcher_session_factory=database_urls.worker_sessions,
            url_resolver=resolver,
            url_transport=first_transport,
            lease_seconds=1,
        )
        claimed = first.claim(1)
        assert claimed is not None
        fetched = fetch_safe_url(
            "https://public.test/mime?version=1",
            resolver=resolver,
            transport=first_transport,
            timeout=1,
        )
        first._prepare_url_fetch(claimed, "https://public.test/mime?version=1", fetched)
        admin = create_engine(database_urls.admin)
        try:
            with admin.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE ingestion_jobs SET lease_expires_at="
                        "clock_timestamp()-interval '1s' "
                        "WHERE id=:job"
                    ),
                    {"job": claimed.job_id},
                )
        finally:
            admin.dispose()
        replacement = IngestionWorker(
            sessions,
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "mime-retry",
            dispatcher_session_factory=database_urls.worker_sessions,
            url_resolver=resolver,
            url_transport=MutableTextTransport(content, "text/html"),
        )
        assert replacement.run_once() is True
    finally:
        engine.dispose()
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT job.state,job.error_code,count(version.id),count(fetched.id) "
                    "FROM ingestion_jobs AS job JOIN source_versions AS version "
                    "ON version.source_id=job.source_id JOIN url_fetches AS fetched "
                    "ON fetched.job_id=job.id WHERE job.id=:job "
                    "GROUP BY job.state,job.error_code"
                ),
                {"job": captured.json()["job_id"]},
            ).one() == ("failed", "SafeUrlError", 1, 1)
    finally:
        admin.dispose()
    assert not list(settings.storage_root.rglob("*.*partial"))


@mark.parametrize(
    ("filename", "mime_type", "content", "expected", "location_column"),
    [
        (
            "evidence.pdf",
            "application/pdf",
            minimal_pdf("PDF end to end evidence"),
            "PDF end to end evidence",
            "page_number",
        ),
        (
            "evidence.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            None,
            "DOCX end to end evidence",
            "paragraph_number",
        ),
    ],
)
async def test_supported_documents_complete_the_persisted_path(
    database_urls: Any,
    tmp_path: Path,
    filename: str,
    mime_type: str,
    content: bytes | None,
    expected: str,
    location_column: str,
) -> None:
    if content is None:
        output = io.BytesIO()
        document = DocxDocument()
        document.add_paragraph(expected)
        document.save(output)
        content = output.getvalue()
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39005))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/upload",
            headers=principal_headers(owner_id, workspace_id),
            data={"title": filename},
            files={"file": (filename, content, mime_type)},
        )
        assert captured.status_code == 202
        engine = create_database_engine(settings)
        try:
            worker = IngestionWorker(
                create_session_factory(engine),
                app.state.storage,
                UnavailableEmbeddingProvider(),
                settings,
                f"{filename}-worker",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            assert worker.run_once() is True
        finally:
            engine.dispose()
        opened = await client.get(
            f"/api/v1/sources/{captured.json()['source_id']}/content",
            headers=principal_headers(owner_id, workspace_id),
        )
    assert opened.status_code == 200
    assert opened.json()["extracted_text"] == expected

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            location = connection.scalar(
                text(f"SELECT {location_column} FROM chunks WHERE owner_id=:owner"),
                {"owner": owner_id},
            )
    finally:
        admin.dispose()
    assert location == 1


async def test_hostile_pdf_graph_is_accepted_cheaply_then_fails_in_isolated_parser(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "hostile-pdf")
    app = create_app(settings)
    hostile = (
        b"%PDF-1.7\n1 0 obj << /Type /Pages /Kids [1 0 R] /Count 1 >> endobj\nstartxref\n0\n%%EOF\n"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/upload",
            headers=principal_headers(owner_id, workspace_id),
            data={"title": "Hostile PDF graph"},
            files={"file": ("hostile.pdf", hostile, "application/pdf")},
        )
    assert captured.status_code == 202
    engine = create_database_engine(settings)
    try:
        worker = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "hostile-pdf-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert worker.run_once() is True
    finally:
        engine.dispose()
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            state = connection.execute(
                text("SELECT state,error_code FROM ingestion_jobs WHERE id=:job"),
                {"job": captured.json()["job_id"]},
            ).one()
    finally:
        admin.dispose()
    assert state[0] == "failed"
    assert state[1] in {"ParseFailure", "ParserIsolationFailure"}


async def test_transient_worker_failure_backs_off_and_eventually_dead_letters(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39006))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Missing object", "content": "retry-safe private content"},
        )
    assert captured.status_code == 202
    source_id = UUID(captured.json()["source_id"])
    app.state.storage.delete(f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}/original")

    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    try:
        worker = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            UnavailableEmbeddingProvider(),
            settings,
            "retry-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        for attempt in range(1, 4):
            assert worker.run_once() is True
            with admin.connect() as connection:
                state = connection.execute(
                    text(
                        "SELECT state,attempts,available_at>clock_timestamp() "
                        "FROM ingestion_jobs WHERE id=:id"
                    ),
                    {"id": UUID(captured.json()["job_id"])},
                ).one()
            if attempt < 3:
                assert state == ("queued", attempt, True)
                with admin.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE ingestion_jobs SET available_at=clock_timestamp() WHERE id=:id"
                        ),
                        {"id": UUID(captured.json()["job_id"])},
                    )
            else:
                assert state[0:2] == ("dead", 3)
    finally:
        engine.dispose()
        admin.dispose()


async def test_malformed_embeddings_leave_one_lexical_document_ready(
    database_urls: Any, tmp_path: Path
) -> None:
    class MalformedProvider:
        dimensions = 3
        status = "available"
        model_identifier = "malformed-test"
        profile_version = 1

        def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
            del deadline
            return [[True, 0.2, 0.3] for _ in texts]

    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39016))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Lexical fallback", "content": "lexical evidence survives"},
        )
    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    try:
        worker = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            MalformedProvider(),
            settings,
            "malformed-provider-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert worker.run_once() is True
        assert worker.run_once() is False
        with admin.connect() as connection:
            job = connection.execute(
                text(
                    "SELECT state,pipeline_checkpoint,semantic_state FROM ingestion_jobs "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            ).one()
            source = connection.execute(
                text("SELECT processing_state,semantic_state FROM sources WHERE id=:source"),
                {"source": UUID(captured.json()["source_id"])},
            ).one()
            counts = connection.execute(
                text(
                    "SELECT (SELECT count(*) FROM documents WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM chunks WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM embeddings WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_job_events "
                    " WHERE job_id=:job AND reason_class='semantic_unavailable')"
                ),
                {"owner": owner_id, "job": UUID(captured.json()["job_id"])},
            ).one()
    finally:
        engine.dispose()
        admin.dispose()
    assert job == ("ready", "lexical_committed", "unavailable")
    assert source == ("ready", "unavailable")
    assert counts == (1, 1, 0, 1)


async def test_restart_from_lexical_checkpoint_skips_parser_and_deduplicates(
    database_urls: Any, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    class CrashAfterLexicalProvider:
        dimensions = 8
        status = "available"
        model_identifier = "crash-after-lexical"
        profile_version = 1

        def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
            del texts, deadline
            raise KeyboardInterrupt

    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39017))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Restart checkpoint", "content": "restart checkpoint evidence"},
        )
    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    sessions = create_session_factory(engine)
    try:
        crashed = IngestionWorker(
            sessions,
            app.state.storage,
            CrashAfterLexicalProvider(),
            settings,
            "checkpoint-crashed-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        try:
            crashed.run_once()
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("crash provider did not interrupt the worker")
        with admin.begin() as connection:
            checkpoint = connection.execute(
                text("SELECT state,pipeline_checkpoint FROM ingestion_jobs WHERE id=:job"),
                {"job": UUID(captured.json()["job_id"])},
            ).one()
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET lease_expires_at=clock_timestamp()-interval '1s' "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            )
        assert checkpoint == ("processing", "lexical_committed")

        def parser_must_not_run(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise AssertionError("lexical checkpoint was reparsed")

        monkeypatch.setattr("second_brain.worker.parse_document_isolated", parser_must_not_run)
        replacement = IngestionWorker(
            sessions,
            app.state.storage,
            FakeEmbeddingProvider(8),
            settings,
            "checkpoint-replacement-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert replacement.run_once() is True
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT (SELECT count(*) FROM documents WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM chunks WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM embeddings WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_job_events "
                    " WHERE job_id=:job AND to_state='ready')"
                ),
                {"owner": owner_id, "job": UUID(captured.json()["job_id"])},
            ).one()
            final = connection.execute(
                text(
                    "SELECT state,pipeline_checkpoint,semantic_state FROM ingestion_jobs "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            ).one()
    finally:
        engine.dispose()
        admin.dispose()
    assert counts == (1, 1, 1, 1)
    assert final == ("ready", "lexical_committed", "available")


async def test_independent_heartbeat_prevents_reclaim_during_slow_provider(
    database_urls: Any, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    provider_started = threading.Event()

    class SlowProvider(FakeEmbeddingProvider):
        def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
            provider_started.set()
            time.sleep(1.2)
            return super().embed(texts, deadline=deadline)

    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects").model_copy(
        update={"max_processing_seconds": 5}
    )
    app = create_app(settings)
    from second_brain.parser_subprocess import parse_document_isolated as real_parser

    def slow_parser(*args: Any, **kwargs: Any) -> Any:
        time.sleep(1.1)
        return real_parser(*args, **kwargs)

    monkeypatch.setattr("second_brain.worker.parse_document_isolated", slow_parser)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39018))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Heartbeat", "content": "heartbeat evidence"},
        )
    engine = create_database_engine(settings)
    try:
        worker = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            SlowProvider(8),
            settings,
            "slow-heartbeat-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
            lease_seconds=1,
        )
        thread = threading.Thread(target=worker.run_once)
        thread.start()
        assert provider_started.wait(2)
        time.sleep(1.05)
        competitor = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            FakeEmbeddingProvider(8),
            settings,
            "heartbeat-competitor",
            dispatcher_session_factory=database_urls.worker_sessions,
            lease_seconds=1,
        )
        assert competitor.claim(1) is None
        thread.join(3)
        assert not thread.is_alive()
    finally:
        engine.dispose()


async def test_heartbeat_loss_prevents_stale_semantic_commit(
    database_urls: Any, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    lose_heartbeat = threading.Event()

    class LoseLeaseProvider(FakeEmbeddingProvider):
        def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
            lose_heartbeat.set()
            time.sleep(0.05)
            return super().embed(texts, deadline=deadline)

    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39019))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Lost lease", "content": "lost lease evidence"},
        )
    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    sessions = create_session_factory(engine)
    try:
        worker = IngestionWorker(
            sessions,
            app.state.storage,
            LoseLeaseProvider(8),
            settings,
            "lease-loss-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
            lease_seconds=1,
        )
        real_heartbeat = worker.heartbeat

        def heartbeat(job: Any, lease_seconds: int = 30) -> bool:
            return False if lose_heartbeat.is_set() else real_heartbeat(job, lease_seconds)

        monkeypatch.setattr(worker, "heartbeat", heartbeat)
        assert worker.run_once() is True
        with admin.begin() as connection:
            state = connection.execute(
                text(
                    "SELECT state,pipeline_checkpoint,semantic_state FROM ingestion_jobs "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            ).one()
            counts = connection.execute(
                text(
                    "SELECT (SELECT count(*) FROM documents WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM chunks WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM embeddings WHERE owner_id=:owner)"
                ),
                {"owner": owner_id},
            ).one()
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET lease_expires_at=clock_timestamp()-interval '1s' "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            )
        assert state == ("processing", "lexical_committed", "pending")
        assert counts == (1, 1, 0)
        replacement = IngestionWorker(
            sessions,
            app.state.storage,
            FakeEmbeddingProvider(8),
            settings,
            "lease-loss-replacement",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert replacement.run_once() is True
    finally:
        engine.dispose()
        admin.dispose()


async def test_total_deadline_overrun_cannot_become_ready(
    database_urls: Any, tmp_path: Path
) -> None:
    class DeadlineIgnoringProvider(FakeEmbeddingProvider):
        def embed(self, texts: list[str], *, deadline: float | None = None) -> list[list[float]]:
            del deadline
            time.sleep(1.1)
            return super().embed(texts)

    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects").model_copy(
        update={"max_processing_seconds": 1}
    )
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39020))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Deadline", "content": "deadline evidence"},
        )
    engine = create_database_engine(settings)
    admin = create_engine(database_urls.admin)
    try:
        worker = IngestionWorker(
            create_session_factory(engine),
            app.state.storage,
            DeadlineIgnoringProvider(8),
            settings,
            "deadline-worker",
            dispatcher_session_factory=database_urls.worker_sessions,
            lease_seconds=1,
        )
        assert worker.run_once() is True
        with admin.connect() as connection:
            state = connection.execute(
                text(
                    "SELECT state,pipeline_checkpoint,semantic_state FROM ingestion_jobs "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            ).one()
    finally:
        engine.dispose()
        admin.dispose()
    assert state == ("queued", "lexical_committed", "pending")


async def test_killed_claim_process_is_reclaimed_once_without_duplicates(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39021))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Killed worker", "content": "killed worker evidence"},
        )
    environment = os.environ.copy()
    environment.update(
        {
            "SECOND_BRAIN_WORKER_CONTENT_DATABASE_URL": database_urls.app,
            "SECOND_BRAIN_WORKER_DISPATCHER_DATABASE_URL": database_urls.worker,
            "SECOND_BRAIN_WORKER_STORAGE_ROOT": str(tmp_path / "objects"),
            "SECOND_BRAIN_WORKER_MODEL_PROVIDER": "fake",
        }
    )
    claim_program = """
import time
from second_brain.config import get_worker_settings
from second_brain.db import (create_session_factory, create_worker_content_engine,
    create_worker_dispatcher_engine)
from second_brain.storage import FilesystemStorage
from second_brain.worker import IngestionWorker, provider_from_settings
s=get_worker_settings()
content=create_worker_content_engine(s)
dispatcher=create_worker_dispatcher_engine(s)
w=IngestionWorker(create_session_factory(content),FilesystemStorage(s.storage_root,s.max_upload_bytes),provider_from_settings(s),s,'killed-claim-worker',dispatcher_session_factory=create_session_factory(dispatcher),lease_seconds=1)
assert w.claim(1) is not None; print('claimed',flush=True); time.sleep(60)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", claim_program],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "claimed"
        process.kill()
        process.wait(timeout=3)
        time.sleep(1.1)
        completed = subprocess.run(
            [sys.executable, "-m", "second_brain.worker", "--once", "--worker-id", "replacement"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        assert completed.returncode == 0, completed.stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            counts = connection.execute(
                text(
                    "SELECT (SELECT count(*) FROM documents WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM chunks WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM embeddings WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_job_events WHERE job_id=:job "
                    " AND reason_class='lease_reclaimed'),"
                    "(SELECT count(*) FROM ingestion_job_events WHERE job_id=:job "
                    " AND to_state='ready')"
                ),
                {"owner": owner_id, "job": UUID(captured.json()["job_id"])},
            ).one()
    finally:
        admin.dispose()
    assert counts == (1, 1, 1, 1, 1)


async def test_long_running_worker_survives_empty_queue_and_consumes_delayed_job(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = make_settings(database_urls.app, tmp_path / "objects")
    app = create_app(settings)
    engine = create_database_engine(settings)
    worker = IngestionWorker(
        create_session_factory(engine),
        app.state.storage,
        FakeEmbeddingProvider(8),
        settings,
        "long-running-worker",
        dispatcher_session_factory=database_urls.worker_sessions,
    )
    stop_requested = threading.Event()
    thread = threading.Thread(
        target=worker.run_forever,
        args=(stop_requested,),
        kwargs={"poll_seconds": 0.05},
    )
    thread.start()
    time.sleep(0.15)
    transport = ASGITransport(app=app, client=("127.0.0.1", 39022))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        captured = await client.post(
            "/api/v1/captures/text",
            headers=principal_headers(owner_id, workspace_id),
            json={"title": "Delayed queue", "content": "delayed queue evidence"},
        )
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET available_at=clock_timestamp()+interval '300ms' "
                    "WHERE id=:job"
                ),
                {"job": UUID(captured.json()["job_id"])},
            )
        deadline = time.monotonic() + 5
        state = "queued"
        while time.monotonic() < deadline and state != "ready":
            with admin.connect() as connection:
                state = connection.scalar(
                    text("SELECT state FROM ingestion_jobs WHERE id=:job"),
                    {"job": UUID(captured.json()["job_id"])},
                )
            time.sleep(0.05)
        assert state == "ready"
    finally:
        stop_requested.set()
        thread.join(3)
        engine.dispose()
        admin.dispose()
    assert not thread.is_alive()


def test_long_running_worker_process_stops_cleanly_on_sigterm(
    database_urls: Any, tmp_path: Path
) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "SECOND_BRAIN_WORKER_CONTENT_DATABASE_URL": database_urls.app,
            "SECOND_BRAIN_WORKER_DISPATCHER_DATABASE_URL": database_urls.worker,
            "SECOND_BRAIN_WORKER_STORAGE_ROOT": str(tmp_path / "objects"),
            "SECOND_BRAIN_WORKER_MODEL_PROVIDER": "fake",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "second_brain.worker", "--worker-id", "sigterm-worker"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        time.sleep(0.4)
        process.terminate()
        _, error = process.communicate(timeout=5)
        assert process.returncode == 0, error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
