import logging
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from second_brain.app import create_app
from second_brain.config import Settings


def seed_source(
    admin_url: str, owner_id: UUID, workspace_id: UUID, source_id: UUID, marker: str
) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id, email) VALUES (:id, :email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id, owner_id, name) VALUES (:id, :owner, :name)"),
                {"id": workspace_id, "owner": owner_id, "name": marker},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id, user_id, role) "
                    "VALUES (:workspace, :owner, 'owner')"
                ),
                {"owner": owner_id, "workspace": workspace_id},
            )
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id, owner_id, workspace_id, source_type, display_title, content_sha256, "
                    "normalized_dedup_sha256, mime_type, processing_state) "
                    "VALUES (:id, :owner, :workspace, 'note', :title, :content_hash, "
                    ":dedup_hash, 'text/plain', 'ready')"
                ),
                {
                    "id": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "title": marker,
                    "content_hash": marker.encode().hex().ljust(64, "0")[:64],
                    "dedup_hash": marker.encode().hex().rjust(64, "0")[-64:],
                },
            )
    finally:
        engine.dispose()


def test_direct_sql_requires_set_local_and_isolates_owner_and_workspace(
    database_urls: Any,
) -> None:
    owner_a, workspace_a, source_a = uuid4(), uuid4(), uuid4()
    owner_b, workspace_b, source_b = uuid4(), uuid4(), uuid4()
    seed_source(database_urls.admin, owner_a, workspace_a, source_a, "source-a")
    seed_source(database_urls.admin, owner_b, workspace_b, source_b, "source-b")

    engine = create_engine(database_urls.app)
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT count(*) FROM sources")) == 0
            connection.execute(
                text("SELECT set_config('app.owner_id', :value, true)"), {"value": str(owner_a)}
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id', :value, true)"),
                {"value": str(workspace_a)},
            )
            assert connection.scalars(text("SELECT id FROM sources")).all() == [source_a]

        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id', :value, true)"), {"value": str(owner_a)}
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id', :value, true)"),
                {"value": str(workspace_b)},
            )
            assert connection.scalar(text("SELECT count(*) FROM sources")) == 0
    finally:
        engine.dispose()


async def test_api_cannot_open_another_principals_source_or_spoof_from_network(
    database_urls: Any,
) -> None:
    owner_a, workspace_a, source_a = uuid4(), uuid4(), uuid4()
    owner_b, workspace_b, source_b = uuid4(), uuid4(), uuid4()
    seed_source(database_urls.admin, owner_a, workspace_a, source_a, "api-source-a")
    seed_source(database_urls.admin, owner_b, workspace_b, source_b, "api-source-b")
    settings = Settings(app_env="test", database_url=database_urls.app)

    transport = ASGITransport(app=create_app(settings), client=("127.0.0.1", 50000))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get(
            f"/api/v1/sources/{source_a}",
            headers={
                "x-second-brain-owner-id": str(owner_a),
                "x-second-brain-workspace-id": str(workspace_a),
            },
        )
        denied = await client.get(
            f"/api/v1/sources/{source_b}",
            headers={
                "x-second-brain-owner-id": str(owner_a),
                "x-second-brain-workspace-id": str(workspace_a),
            },
        )

    assert response.status_code == 200
    assert response.json()["source_id"] == str(source_a)
    assert denied.status_code == 404

    external_transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    async with AsyncClient(
        transport=external_transport, base_url="http://203.0.113.10"
    ) as external:
        spoofed = await external.get(
            f"/api/v1/sources/{source_a}",
            headers={
                "x-second-brain-owner-id": str(owner_a),
                "x-second-brain-workspace-id": str(workspace_a),
            },
        )
    assert spoofed.status_code == 403
    assert spoofed.json()["code"] == "development_principal_forbidden"


async def test_production_rejects_browser_principal_headers(database_urls: Any) -> None:
    owner_id, workspace_id, source_id = uuid4(), uuid4(), uuid4()
    seed_source(database_urls.admin, owner_id, workspace_id, source_id, "signed-source")
    settings = Settings(
        app_env="production",
        auth_mode="trusted_proxy",
        bind_host="0.0.0.0",
        trusted_proxy_secret="test-verifier-secret-material-at-least-32-bytes",
        trusted_proxy_network="203.0.113.0/24",
        trusted_assertion_issuer="test",
        trusted_assertion_audience="second-brain",
        public_origin="https://brain.example.test",
        database_url=database_urls.app,
    )
    headers = {
        "x-second-brain-owner-id": str(owner_id),
        "x-second-brain-workspace-id": str(workspace_id),
    }

    transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        rejected = await client.get(f"/api/v1/sources/{source_id}", headers=headers)

    assert rejected.status_code == 400
    assert rejected.json()["code"] == "browser_principal_headers_forbidden"


async def test_access_logs_do_not_contain_private_source_content(
    caplog: pytest.LogCaptureFixture,
    database_urls: Any,
) -> None:
    owner_id, workspace_id, source_id = uuid4(), uuid4(), uuid4()
    private_marker = "SEEDED-PRIVATE-SOURCE-CONTENT-7f18"
    seed_source(database_urls.admin, owner_id, workspace_id, source_id, private_marker)
    settings = Settings(app_env="test", database_url=database_urls.app)

    with caplog.at_level(logging.INFO, logger="second_brain.api"):
        transport = ASGITransport(app=create_app(settings), client=("127.0.0.1", 50000))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            response = await client.get(
                f"/api/v1/sources/{source_id}",
                headers={
                    "x-second-brain-owner-id": str(owner_id),
                    "x-second-brain-workspace-id": str(workspace_id),
                },
            )

    assert response.status_code == 200
    assert private_marker not in caplog.text


def test_lineage_constraint_rejects_cross_workspace_source_version(database_urls: Any) -> None:
    owner_a, workspace_a, source_a = uuid4(), uuid4(), uuid4()
    owner_b, workspace_b, _ = uuid4(), uuid4(), uuid4()
    seed_source(database_urls.admin, owner_a, workspace_a, source_a, "constraint-source-a")
    seed_source(database_urls.admin, owner_b, workspace_b, uuid4(), "constraint-source-b")

    engine = create_engine(database_urls.admin)
    try:
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(owner_id, workspace_id, source_id, version_number, parser_name, "
                    "parser_version, chunker_version, content_sha256) "
                    "VALUES (:owner, :workspace, :source, 1, 'text', '1', 'v1', :hash)"
                ),
                {
                    "owner": owner_b,
                    "workspace": workspace_b,
                    "source": source_a,
                    "hash": "a" * 64,
                },
            )
    finally:
        engine.dispose()


def test_source_version_and_original_provenance_are_immutable(database_urls: Any) -> None:
    owner_id, workspace_id, source_id = uuid4(), uuid4(), uuid4()
    seed_source(database_urls.admin, owner_id, workspace_id, source_id, "immutable-source")
    version_id = uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id, owner_id, workspace_id, source_id, version_number, parser_name, "
                    "parser_version, chunker_version, content_sha256) "
                    "VALUES (:id, :owner, :workspace, :source, 1, 'text', '1', 'v1', :hash)"
                ),
                {
                    "id": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "hash": "b" * 64,
                },
            )

        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(
                text("UPDATE source_versions SET parser_version='2' WHERE id=:id"),
                {"id": version_id},
            )

        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(
                text("UPDATE sources SET content_sha256=:hash WHERE id=:id"),
                {"id": source_id, "hash": "c" * 64},
            )

        with engine.begin() as connection:
            connection.execute(
                text("UPDATE sources SET processing_state='processing' WHERE id=:id"),
                {"id": source_id},
            )
    finally:
        engine.dispose()
