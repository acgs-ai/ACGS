import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.db import create_database_engine, create_session_factory
from second_brain.memory import propose_memory
from second_brain.policy import PolicyContext, PolicyDecision
from second_brain.providers import UnavailableEmbeddingProvider
from second_brain.safe_logging import safe_log, safe_metadata
from second_brain.worker import IngestionWorker

SENSITIVE = "seeded-sensitive-source-string-018"


def test_safe_logging_emits_only_allowlisted_metadata(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("second_brain.privacy_test")
    logger.disabled = False
    with caplog.at_level(logging.INFO, logger=logger.name):
        safe_log(
            logger,
            logging.INFO,
            "source_processed",
            source_id=uuid4(),
            state="ready",
            count=3,
            latency_ms=12.5,
            reason_code="ingestion.ready",
        )

    assert "source_processed" in caplog.text
    assert "ready" in caplog.text
    assert SENSITIVE not in caplog.text


def test_safe_logging_rejects_content_and_never_logs_it(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("second_brain.privacy_test")
    logger.disabled = False

    with caplog.at_level(logging.INFO, logger=logger.name), pytest.raises(ValueError):
        safe_log(logger, logging.INFO, "unsafe", content=SENSITIVE)

    assert SENSITIVE not in caplog.text


def test_exception_metadata_is_reduced_to_class_name() -> None:
    metadata = safe_metadata(error=RuntimeError(SENSITIVE), job_id=uuid4())

    assert metadata["error_class"] == "RuntimeError"
    assert SENSITIVE not in str(metadata)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("state", SENSITIVE),
        ("reason_code", SENSITIVE),
        ("count", -1),
        ("latency_ms", float("inf")),
        ("policy_id", "x" * 129),
    ],
)
def test_allowlisted_values_are_bounded(key: str, value: object) -> None:
    with pytest.raises(ValueError):
        safe_metadata(**cast(Any, {key: value}))


class PassingPolicy:
    def __init__(self) -> None:
        self.contexts: list[PolicyContext] = []

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        self.contexts.append(context)
        return PolicyDecision(
            decision="pass",
            reason_code="policy.logging_test",
            policy_id="local-test-policy",
            policy_version="1",
            audit_id=f"audit-{len(self.contexts)}",
            evaluated_at=datetime.now(UTC),
            obligations=("record_audit",),
        )


def _seed_workspace(admin_url: str, owner: UUID, workspace: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner, "email": f"{owner}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'privacy')"),
                {"id": workspace, "owner": owner},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": workspace, "owner": owner},
            )
    finally:
        engine.dispose()


async def test_seeded_private_marker_never_leaks_across_complete_lifecycle_logs(
    database_urls: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        storage_root=tmp_path / "objects",
        policy_enabled=True,
    )
    policy = PassingPolicy()
    application = create_app(settings, policy_port=policy)
    headers = {
        "x-second-brain-owner-id": str(owner),
        "x-second-brain-workspace-id": str(workspace),
    }
    logging.getLogger("second_brain.api").disabled = False
    logging.getLogger("second_brain.worker").disabled = False

    with caplog.at_level(logging.INFO):
        async with AsyncClient(
            transport=ASGITransport(app=application, client=("127.0.0.1", 40400)),
            base_url="http://127.0.0.1",
        ) as client:
            captured = await client.post(
                "/api/v1/captures/text",
                headers=headers,
                json={"title": "Private", "content": f"durable evidence {SENSITIVE}"},
            )
            assert captured.status_code == 202
            source_id = captured.json()["source_id"]
            job_id = captured.json()["job_id"]
            ordering_engine = create_engine(database_urls.admin)
            try:
                with ordering_engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE ingestion_jobs SET available_at='2000-01-01T00:00:00Z' "
                            "WHERE id=:job"
                        ),
                        {"job": job_id},
                    )
            finally:
                ordering_engine.dispose()

            content_engine = create_database_engine(settings)
            try:
                worker = IngestionWorker(
                    create_session_factory(content_engine),
                    application.state.storage,
                    UnavailableEmbeddingProvider(),
                    settings,
                    "privacy-ingestion-worker",
                    dispatcher_session_factory=database_urls.worker_sessions,
                )
                for _ in range(20):
                    assert worker.run_once() is True
                    probe = create_engine(database_urls.admin)
                    try:
                        with probe.connect() as connection:
                            if (
                                connection.scalar(
                                    text("SELECT processing_state FROM sources WHERE id=:source"),
                                    {"source": source_id},
                                )
                                == "ready"
                            ):
                                break
                    finally:
                        probe.dispose()
                else:
                    pytest.fail("privacy ingestion job was not processed")
            finally:
                content_engine.dispose()

            admin = create_engine(database_urls.admin)
            try:
                with admin.connect() as connection:
                    chunk_id = connection.scalar(
                        text(
                            "SELECT chunk.id FROM chunks AS chunk "
                            "JOIN source_versions AS version "
                            "ON version.id=chunk.source_version_id "
                            "WHERE version.source_id=:source"
                        ),
                        {"source": source_id},
                    )
            finally:
                admin.dispose()
            assert chunk_id is not None

            memory_engine = create_database_engine(settings)
            try:
                proposal = propose_memory(
                    create_session_factory(memory_engine),
                    owner_id=owner,
                    workspace_id=workspace,
                    statement=f"A durable memory derived from {SENSITIVE}",
                    category="reference",
                    evidence_chunk_ids=[chunk_id],
                    confidence=0.8,
                    evidence_quality="high",
                    idempotency_key="privacy-proposal",
                )
            finally:
                memory_engine.dispose()

            approved = await client.post(
                f"/api/v1/memory-proposals/{proposal['proposal_id']}/approve",
                headers={**headers, "Idempotency-Key": "privacy-approve"},
                json={},
            )
            assert approved.status_code == 200
            today = await client.get("/api/v1/today", headers=headers)
            assert today.status_code == 200
            purge = await client.post(
                f"/api/v1/sources/{source_id}/purge",
                headers={**headers, "Idempotency-Key": "privacy-purge"},
                json={"reason_code": "user_requested"},
            )
            assert purge.status_code == 202
            rejected_reason = await client.post(
                f"/api/v1/sources/{source_id}/purge",
                headers={**headers, "Idempotency-Key": "privacy-invalid-reason"},
                json={"reason_code": SENSITIVE},
            )
            assert rejected_reason.status_code == 422

            purge_engine = create_database_engine(settings)
            try:
                purge_worker = IngestionWorker(
                    create_session_factory(purge_engine),
                    application.state.storage,
                    UnavailableEmbeddingProvider(),
                    settings,
                    "privacy-purge-worker",
                    dispatcher_session_factory=database_urls.worker_sessions,
                )
                for _ in range(20):
                    assert purge_worker.run_once() is True
                    probe = create_engine(database_urls.admin)
                    try:
                        with probe.connect() as connection:
                            if (
                                connection.scalar(
                                    text("SELECT state FROM purge_operations WHERE id=:operation"),
                                    {"operation": purge.json()["operation_id"]},
                                )
                                == "complete"
                            ):
                                break
                    finally:
                        probe.dispose()
                else:
                    pytest.fail("privacy purge operation was not processed")
            finally:
                purge_engine.dispose()
            status = await client.get(
                f"/api/v1/purges/{purge.json()['operation_id']}", headers=headers
            )
            assert status.status_code == 200 and status.json()["state"] == "complete"

        safe_log(
            logging.getLogger("second_brain.worker"),
            logging.ERROR,
            "privacy_error_probe",
            error=RuntimeError(SENSITIVE),
            job_id=UUID(job_id),
        )

    assert SENSITIVE not in caplog.text
    assert source_id in caplog.text and job_id in caplog.text
    assert "state=queued" in caplog.text and "state=active" in caplog.text
    assert "action=capture_source" in caplog.text and "action=purge_source" in caplog.text
    assert "error_class=RuntimeError" in caplog.text
    assert [item.action for item in policy.contexts] == [
        "capture_source",
        "approve_memory",
        "purge_source",
    ]
    audit_engine = create_engine(database_urls.admin)
    try:
        with audit_engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM purge_operations WHERE reason_code=:marker"),
                    {"marker": SENSITIVE},
                )
                == 0
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM purge_operation_events WHERE reason_class=:marker"),
                    {"marker": SENSITIVE},
                )
                == 0
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM purge_records WHERE reason_code=:marker"),
                    {"marker": SENSITIVE},
                )
                == 0
            )
    finally:
        audit_engine.dispose()
