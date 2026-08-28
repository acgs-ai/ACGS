import logging
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr, ValidationError
from pytest import LogCaptureFixture, MonkeyPatch, raises
from sqlalchemy import create_engine

from second_brain.app import create_app, normalize_request_id
from second_brain.config import Settings, WorkerSettings
from second_brain.db import (
    RuntimeRoleAttestationError,
    attest_runtime_role,
    attest_worker_role,
    create_database_engine,
)
from second_brain.providers import (
    UnavailableEmbeddingProvider,
    UnavailableGenerationProvider,
)
from second_brain.worker import provider_from_settings


async def test_health_has_stable_safe_shape() -> None:
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )

    transport = ASGITransport(app=create_app(settings))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"service": "second-brain", "status": "ok"}


async def test_unknown_route_uses_safe_error_contract() -> None:
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )

    transport = ASGITransport(app=create_app(settings))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        trace_id = str(uuid4())
        response = await client.get("/api/v1/not-present", headers={"x-request-id": trace_id})

    assert response.status_code == 404
    assert response.json() == {
        "code": "not_found",
        "title": "Not found",
        "detail": "The requested resource is unavailable.",
        "retryable": False,
        "trace_id": trace_id,
    }


async def test_status_reports_real_database_and_local_provider_state(database_urls: Any) -> None:
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        max_upload_bytes=123456,
        max_extracted_chars=234567,
        max_chunks=321,
        max_processing_seconds=17,
    )

    transport = ASGITransport(app=create_app(settings))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get("/api/v1/status")

    assert response.status_code == 200
    assert response.json() == {
        "service": "second-brain",
        "status": "ready",
        "database": "available",
        "storage": "filesystem",
        "model_provider": "fake",
        "embedding_provider_status": "available",
        "generation_provider_status": "available",
        "provider_status_scope": "local_adapter_state_not_remote_health",
        "max_upload_bytes": 123456,
        "max_extracted_chars": 234567,
        "max_chunks": 321,
        "max_processing_seconds": 17,
    }


async def test_status_reports_safe_config_without_loading_worker_secret(database_urls: Any) -> None:
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        model_provider="openai_compatible",
    )

    transport = ASGITransport(
        app=create_app(
            settings,
            embedding_provider=UnavailableEmbeddingProvider(),
            generation_provider=UnavailableGenerationProvider(),
        )
    )
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get("/api/v1/status")

    assert response.status_code == 200
    assert response.json() == {
        "service": "second-brain",
        "status": "ready",
        "database": "available",
        "storage": "filesystem",
        "model_provider": "openai_compatible",
        "embedding_provider_status": "unavailable",
        "generation_provider_status": "unavailable",
        "provider_status_scope": "local_adapter_state_not_remote_health",
        "max_upload_bytes": 10_000_000,
        "max_extracted_chars": 2_000_000,
        "max_chunks": 5000,
        "max_processing_seconds": 30,
    }
    assert "url" not in response.text.lower()
    assert "secret" not in response.text.lower()
    assert not hasattr(settings, "model_api_key")


def test_development_principal_refuses_production_startup() -> None:
    with raises(ValidationError, match="development_headers auth_mode is forbidden in production"):
        Settings(
            app_env="production",
            auth_mode="development_headers",
            database_url="postgresql+psycopg://second_brain_app@unused/test",
        )


def test_production_refuses_startup_without_trusted_verifier() -> None:
    for invalid_secret in (None, "   "):
        with raises(ValidationError, match="trusted principal verifier is required in production"):
            Settings(
                app_env="production",
                auth_mode="trusted_proxy",
                trusted_proxy_secret=invalid_secret,
                database_url="postgresql+psycopg://second_brain_app@unused/test",
            )


def test_development_headers_require_loopback_bind() -> None:
    with raises(ValidationError, match="loopback bind_host"):
        Settings(
            app_env="test",
            auth_mode="development_headers",
            bind_host="0.0.0.0",
            database_url="postgresql+psycopg://second_brain_app@unused/test",
        )


def test_production_rejects_weak_hmac_and_unsafe_proxy_networks() -> None:
    base = {
        "app_env": "production",
        "auth_mode": "trusted_proxy",
        "bind_host": "0.0.0.0",
        "database_url": "postgresql+psycopg://second_brain_app@unused/test",
        "trusted_proxy_secret": "x" * 32,
        "trusted_proxy_network": "127.0.0.1/32",
        "trusted_assertion_issuer": "issuer",
        "trusted_assertion_audience": "audience",
        "public_origin": "https://brain.example.test",
    }
    with raises(ValidationError, match="at least 32 bytes"):
        Settings(**{**base, "trusted_proxy_secret": "short"})
    for network in ("0.0.0.0/0", "10.0.0.0/8", "255.255.255.255/32", "8.8.8.8/32"):
        with raises(ValidationError, match="bounded non-global"):
            Settings(**{**base, "trusted_proxy_network": network})


def test_runtime_settings_reject_owner_credentials_and_do_not_serialize_them(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    canonical = tmp_path / ".env"
    canonical.write_text(
        "SECOND_BRAIN_APP_ENV=development\n"
        "SECOND_BRAIN_AUTH_MODE=development_headers\n"
        "SECOND_BRAIN_DATABASE_URL=postgresql+psycopg://second_brain_app@unused/test\n"
        "SECOND_BRAIN_STORAGE_BACKEND=filesystem\n"
        "SECOND_BRAIN_MODEL_PROVIDER=fake\n"
        "SECOND_BRAIN_EMBEDDING_PROFILE_VERSION=7\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=canonical)

    assert settings.app_env == "development"
    assert settings.embedding_profile_version == 7
    assert create_app(settings).state.embedding_provider.profile_version == 7
    assert set(settings.model_dump()) == {
        "app_env",
        "auth_mode",
        "bind_host",
        "bind_port",
        "database_url",
        "storage_backend",
        "model_provider",
        "policy_enabled",
        "trusted_proxy_secret",
        "trusted_proxy_network",
        "trusted_assertion_issuer",
        "trusted_assertion_audience",
        "public_origin",
        "session_idle_seconds",
        "session_absolute_seconds",
        "exchange_rate_limit",
        "exchange_rate_window_seconds",
        "storage_root",
        "max_request_envelope_bytes",
        "request_body_timeout_seconds",
        "max_upload_bytes",
        "max_extracted_chars",
        "max_chunks",
        "max_processing_seconds",
        "url_max_redirects",
        "url_timeout_seconds",
        "model_base_url",
        "embedding_model",
        "embedding_dimensions",
        "embedding_profile_version",
        "answer_min_similarity",
    }
    assert "owner" not in repr(settings).lower()
    assert "admin" not in repr(settings).lower()

    canonical.write_text(
        canonical.read_text(encoding="utf-8") + "SECOND_BRAIN_DB_OWNER_PASSWORD=owner-secret\n",
        encoding="utf-8",
    )
    with raises(ValidationError, match="extra_forbidden"):
        Settings(_env_file=canonical)


def test_api_settings_never_load_worker_model_secret(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("SECOND_BRAIN_MODEL_API_KEY", "must-not-enter-api-process")
    with raises(ValueError, match="unknown Second Brain environment keys"):
        Settings()
    monkeypatch.delenv("SECOND_BRAIN_MODEL_API_KEY")
    monkeypatch.setenv("SECOND_BRAIN_WORKER_MODEL_API_KEY", "worker-only-secret")
    settings = Settings()
    assert not hasattr(settings, "model_api_key")

    monkeypatch.setenv("SECOND_BRAIN_DB_OWNER_PASSWORD", "owner-secret")
    with raises(ValueError, match="unknown Second Brain environment keys"):
        Settings(_env_file=None)


def test_runtime_settings_reject_database_owner_dsn() -> None:
    with raises(ValidationError, match="second_brain_app"):
        Settings(
            app_env="test",
            database_url=(
                "postgresql+psycopg://second_brain_owner:second_brain_owner_dev@"
                "127.0.0.1:55439/second_brain"
            ),
        )


def test_api_settings_do_not_load_worker_dispatcher_secret(
    monkeypatch: MonkeyPatch,
) -> None:
    marker = "WORKER-ONLY-PASSWORD-MARKER"
    monkeypatch.setenv(
        "SECOND_BRAIN_WORKER_DISPATCHER_DATABASE_URL",
        f"postgresql+psycopg://second_brain_worker:{marker}@unused/test",
    )
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )
    assert marker not in repr(settings)
    assert not any(key.startswith("worker_") for key in settings.model_dump())


async def test_runtime_role_attestation_accepts_restricted_app_role(database_urls: Any) -> None:
    settings = Settings(app_env="test", database_url=database_urls.app)
    engine = create_database_engine(settings)
    try:
        attest_runtime_role(engine)
    finally:
        engine.dispose()

    application = create_app(settings)
    async with application.router.lifespan_context(application):
        pass


def test_runtime_role_attestation_rejects_owner_role(database_urls: Any) -> None:
    engine = create_engine(database_urls.admin)
    try:
        with raises(RuntimeRoleAttestationError, match="second_brain_app"):
            attest_runtime_role(engine)
    finally:
        engine.dispose()


def test_worker_settings_and_role_attestation_fail_closed(
    database_urls: Any, monkeypatch: MonkeyPatch
) -> None:
    with raises(ValidationError, match="second_brain_worker"):
        WorkerSettings(dispatcher_database_url=database_urls.app)
    with raises(ValidationError, match="second_brain_app"):
        WorkerSettings(content_database_url=database_urls.worker)

    monkeypatch.setenv("SECOND_BRAIN_WORKER_EMBEDDING_PROFILE_VERSION", "9")
    worker_settings = WorkerSettings()
    assert worker_settings.embedding_profile_version == 9
    assert provider_from_settings(worker_settings).profile_version == 9
    remote_worker_settings = WorkerSettings(
        model_provider="openai_compatible",
        model_api_key=SecretStr("server-only-test-key"),
        embedding_profile_version=10,
    )
    assert provider_from_settings(remote_worker_settings).profile_version == 10

    worker_engine = create_engine(database_urls.worker)
    try:
        attest_worker_role(worker_engine)
    finally:
        worker_engine.dispose()

    owner_engine = create_engine(database_urls.admin)
    try:
        with raises(RuntimeRoleAttestationError, match="second_brain_worker"):
            attest_worker_role(owner_engine)
    finally:
        owner_engine.dispose()


def test_request_id_accepts_only_uuid_values() -> None:
    valid = str(uuid4())
    assert normalize_request_id(valid) == valid
    for invalid in ("trace-test", "bad\r\nprivate-marker", "SEEDED-SENSITIVE-HEADER"):
        generated = normalize_request_id(invalid)
        assert generated != invalid
        UUID(generated)


async def test_sensitive_request_header_is_not_logged(caplog: LogCaptureFixture) -> None:
    marker = "SEEDED-SENSITIVE-HEADER-f8ce"
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )
    logging.getLogger("second_brain.api").disabled = False
    with caplog.at_level(logging.INFO, logger="second_brain.api"):
        transport = ASGITransport(app=create_app(settings))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            response = await client.get(
                "/api/v1/health",
                headers={"x-request-id": marker, "x-private-marker": marker},
            )

    UUID(response.headers["x-request-id"])
    assert marker not in caplog.text


async def test_unmatched_attacker_path_and_query_are_not_logged(
    caplog: LogCaptureFixture,
) -> None:
    marker = "SEEDED-ATTACKER-PATH-SOURCE-CONTENT-a19f"
    settings = Settings(
        app_env="test", database_url="postgresql+psycopg://second_brain_app@unused/test"
    )
    logging.getLogger("second_brain.api").disabled = False
    with caplog.at_level(logging.INFO, logger="second_brain.api"):
        transport = ASGITransport(app=create_app(settings))
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            response = await client.get(f"/api/v1/{marker}?query={marker}")
    assert response.status_code == 404
    assert marker not in caplog.text
    assert "route=<unmatched>" in caplog.text


async def test_early_security_denials_are_finalized_and_safely_logged(
    database_urls: Any, caplog: LogCaptureFixture
) -> None:
    marker = "EARLY-DENIAL-PRIVATE-MARKER-70ce"
    settings = Settings(
        app_env="production",
        auth_mode="trusted_proxy",
        bind_host="0.0.0.0",
        database_url=database_urls.app,
        trusted_proxy_secret="test-proxy-secret-material-32-bytes-minimum",
        trusted_proxy_network="203.0.113.0/24",
        trusted_assertion_issuer="test-issuer",
        trusted_assertion_audience="second-brain",
        public_origin="https://brain.example.test",
    )
    logging.getLogger("second_brain.api").disabled = False
    with caplog.at_level(logging.INFO, logger="second_brain.api"):
        transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
        async with AsyncClient(
            transport=transport, base_url="https://brain.example.test"
        ) as client:
            origin_denial = await client.post(
                f"/api/v1/session/check?private={marker}",
                headers={"host": marker, "x-request-id": f"bad\r\n{marker}"},
            )
            session_denial = await client.post(
                "/api/v1/session/check",
                headers={"origin": "https://brain.example.test"},
            )
    assert origin_denial.status_code == 403
    assert origin_denial.json()["code"] == "origin_forbidden"
    assert session_denial.status_code == 401
    assert session_denial.json()["code"] == "session_required"
    for response in (origin_denial, session_denial):
        assert response.headers["x-request-id"] == response.json()["trace_id"]
        UUID(response.headers["x-request-id"])
    assert marker not in caplog.text
    assert "route=<security-middleware>" in caplog.text
    assert "status=403" in caplog.text
    assert "denial_code=origin_forbidden" in caplog.text
    assert "status=401" in caplog.text
    assert "denial_code=session_required" in caplog.text
