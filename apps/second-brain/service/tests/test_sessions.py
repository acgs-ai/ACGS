import asyncio
import hashlib
import hmac
import logging
import time
from typing import Any
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from pytest import LogCaptureFixture, MonkeyPatch
from sqlalchemy import create_engine, text

from second_brain import auth as auth_module
from second_brain.app import create_app
from second_brain.auth import assertion_signing_payload
from second_brain.config import Settings

TEST_PROXY_SECRET = "test-proxy-secret-material-32-bytes-minimum"


def production_settings(database_url: str, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_env": "production",
        "auth_mode": "trusted_proxy",
        "bind_host": "0.0.0.0",
        "database_url": database_url,
        "trusted_proxy_secret": TEST_PROXY_SECRET,
        "trusted_proxy_network": "203.0.113.0/24",
        "trusted_assertion_issuer": "test-issuer",
        "trusted_assertion_audience": "second-brain",
        "public_origin": "https://brain.example.test",
    }
    values.update(overrides)
    return Settings(**values)


def seed_membership(admin_url: str) -> tuple[str, str]:
    owner, workspace = uuid4(), uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner, "email": f"{owner}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'session')"),
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
    return str(owner), str(workspace)


def signed_assertion(
    owner: str,
    workspace: str,
    secret: str = TEST_PROXY_SECRET,
    **overrides: Any,
) -> dict[str, Any]:
    now = int(time.time())
    assertion: dict[str, Any] = {
        "issuer": "test-issuer",
        "audience": "second-brain",
        "issued_at": now,
        "expires_at": now + 60,
        "nonce": str(uuid4()),
        "owner_id": owner,
        "workspace_id": workspace,
    }
    assertion.update(overrides)
    supplied_signature = assertion.pop("signature", None)
    assertion["signature"] = (
        supplied_signature
        or hmac.new(
            secret.encode(), assertion_signing_payload(assertion), hashlib.sha256
        ).hexdigest()
    )
    return assertion


async def test_trusted_exchange_issues_hardened_server_session(database_urls: Any) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        response = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )

    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "second_brain_session=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Max-Age=86400" in cookie
    assert "expires=" in cookie.lower()
    payload = response.json()
    assert payload["status"] == "authenticated"
    assert len(payload["csrf_token"]) >= 32
    token = response.cookies["second_brain_session"]
    engine = create_engine(database_urls.admin)
    try:
        with engine.connect() as connection:
            stored = connection.execute(
                text(
                    "SELECT token_hash,csrf_token_hash FROM sessions WHERE token_hash=:token_hash"
                ),
                {"token_hash": hashlib.sha256(token.encode()).hexdigest()},
            ).one()
        assert stored.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert stored.csrf_token_hash == hashlib.sha256(payload["csrf_token"].encode()).hexdigest()
        assert token not in {stored.token_hash, stored.csrf_token_hash}
    finally:
        engine.dispose()


async def test_exchange_rejects_proxy_claim_and_assertion_failures(database_urls: Any) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    untrusted = ASGITransport(app=create_app(settings), client=("198.51.100.4", 50000))
    async with AsyncClient(transport=untrusted, base_url="https://brain.example.test") as client:
        response = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )
    assert response.status_code == 403
    assert response.json()["code"] == "trusted_proxy_required"

    trusted = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    now = int(time.time())
    invalid_assertions = (
        signed_assertion(owner, workspace, issuer="wrong"),
        signed_assertion(owner, workspace, audience="wrong"),
        signed_assertion(owner, workspace, issued_at=now - 121, expires_at=now + 1),
        signed_assertion(owner, workspace, issued_at=now, expires_at=now - 1),
        signed_assertion(owner, workspace, signature="0" * 64),
    )
    async with AsyncClient(transport=trusted, base_url="https://brain.example.test") as client:
        for assertion in invalid_assertions:
            response = await client.post("/api/v1/auth/exchange", json=assertion)
            assert response.status_code == 401


async def test_exchange_rejects_replay_and_missing_membership(database_urls: Any) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    assertion = signed_assertion(owner, workspace)
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        first = await client.post("/api/v1/auth/exchange", json=assertion)
        replay = await client.post("/api/v1/auth/exchange", json=assertion)
        missing = await client.post(
            "/api/v1/auth/exchange",
            json=signed_assertion(str(uuid4()), str(uuid4())),
        )
    assert first.status_code == 200
    assert replay.status_code == 409
    assert replay.json()["code"] == "assertion_replayed"
    assert missing.status_code == 403
    assert missing.json()["code"] == "workspace_membership_required"


async def test_production_uses_cookie_only_and_enforces_origin_and_csrf(
    database_urls: Any, caplog: LogCaptureFixture
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    logging.getLogger("second_brain.api").disabled = False
    caplog.set_level(logging.INFO, logger="second_brain.api")
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        exchange = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )
        csrf = exchange.json()["csrf_token"]
        read = await client.get("/api/v1/session/check")
        spoofed = await client.get(
            "/api/v1/session/check",
            headers={
                "x-second-brain-owner-id": owner,
                "x-second-brain-workspace-id": workspace,
                "x-second-brain-principal-signature": "0" * 64,
            },
        )
        no_origin = await client.post("/api/v1/session/check", headers={"x-csrf-token": csrf})
        no_csrf = await client.post(
            "/api/v1/session/check", headers={"origin": "https://brain.example.test"}
        )
        accepted = await client.post(
            "/api/v1/session/check",
            headers={"origin": "https://brain.example.test", "x-csrf-token": csrf},
        )
    assert read.status_code == 200
    assert spoofed.status_code == 400
    assert spoofed.json()["code"] == "browser_principal_headers_forbidden"
    assert no_origin.status_code == 403
    assert no_origin.json()["code"] == "origin_forbidden"
    assert no_csrf.status_code == 403
    assert no_csrf.json()["code"] == "csrf_invalid"
    for denial in (no_origin, no_csrf):
        assert denial.headers["x-request-id"] == denial.json()["trace_id"]
    assert "route=<security-middleware>" in caplog.text
    assert "denial_code=origin_forbidden" in caplog.text
    assert "denial_code=csrf_invalid" in caplog.text
    assert accepted.status_code == 200


async def test_session_rotation_and_server_expiry_invalidate_old_cookies(
    database_urls: Any,
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    application = create_app(settings)
    transport = ASGITransport(app=application, client=("203.0.113.10", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        first = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        old_token = first.cookies["second_brain_session"]
        second = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        new_token = second.cookies["second_brain_session"]
        assert new_token != old_token
        assert (await client.get("/api/v1/session/check")).status_code == 200

    old_transport = ASGITransport(app=application, client=("203.0.113.10", 50000))
    async with AsyncClient(transport=old_transport, base_url="https://brain.example.test") as old:
        old.cookies.set("second_brain_session", old_token, domain="brain.example.test", path="/")
        assert (await old.get("/api/v1/session/check")).status_code == 401

    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE sessions SET idle_expires_at=now()-interval '1 second' "
                    "WHERE token_hash=:token"
                ),
                {"token": hashlib.sha256(new_token.encode()).hexdigest()},
            )
    finally:
        engine.dispose()
    expired_transport = ASGITransport(app=application, client=("203.0.113.10", 50000))
    async with AsyncClient(
        transport=expired_transport, base_url="https://brain.example.test"
    ) as expired:
        expired.cookies.set(
            "second_brain_session", new_token, domain="brain.example.test", path="/"
        )
        response = await expired.get("/api/v1/session/check")
    assert response.status_code == 401
    assert response.json()["code"] == "session_invalid"


async def test_assertion_and_session_secrets_are_not_logged(
    database_urls: Any, caplog: LogCaptureFixture
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app)
    assertion = signed_assertion(owner, workspace)
    sensitive_signature = assertion["signature"]
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.10", 50000))
    with caplog.at_level(logging.INFO, logger="second_brain.api"):
        async with AsyncClient(
            transport=transport, base_url="https://brain.example.test"
        ) as client:
            response = await client.post("/api/v1/auth/exchange", json=assertion)
            session_token = response.cookies["second_brain_session"]
            csrf_token = response.json()["csrf_token"]
    assert response.status_code == 200
    assert sensitive_signature not in caplog.text
    assert session_token not in caplog.text
    assert csrf_token not in caplog.text


async def test_exchange_rate_limit_is_database_backed_and_fail_closed(database_urls: Any) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(
        database_urls.app,
        trusted_proxy_network="203.0.113.77/32",
        exchange_rate_limit=2,
        exchange_rate_window_seconds=300,
    )
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.77", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        first = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        second = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        limited = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )
    assert first.status_code == 200
    assert second.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["code"] == "exchange_rate_limited"


async def test_invalid_assertions_do_not_consume_authenticated_identity_budget(
    database_urls: Any,
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(
        database_urls.app,
        trusted_proxy_network="203.0.113.78/32",
        exchange_rate_limit=1,
        exchange_rate_window_seconds=300,
    )
    transport = ASGITransport(app=create_app(settings), client=("203.0.113.78", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        invalid = await client.post(
            "/api/v1/auth/exchange",
            json=signed_assertion(owner, workspace, signature="0" * 64),
        )
        valid = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        limited = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )
    assert invalid.status_code == 401
    assert valid.status_code == 200
    assert limited.status_code == 429


async def test_exchange_limit_is_atomic_and_partitioned_by_validated_identity(
    database_urls: Any,
) -> None:
    owner_a, workspace_a = seed_membership(database_urls.admin)
    owner_b, workspace_b = seed_membership(database_urls.admin)
    settings = production_settings(
        database_urls.app,
        trusted_proxy_network="203.0.113.79/32",
        exchange_rate_limit=1,
        exchange_rate_window_seconds=300,
    )
    application = create_app(settings)
    transport = ASGITransport(app=application, client=("203.0.113.79", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        first_a, second_a = await asyncio.gather(
            client.post("/api/v1/auth/exchange", json=signed_assertion(owner_a, workspace_a)),
            client.post("/api/v1/auth/exchange", json=signed_assertion(owner_a, workspace_a)),
        )
        identity_b = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner_b, workspace_b)
        )
    assert sorted((first_a.status_code, second_a.status_code)) == [200, 429]
    assert identity_b.status_code == 200


async def test_non_nonce_integrity_collision_is_not_misclassified_as_replay(
    database_urls: Any, monkeypatch: MonkeyPatch
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(database_urls.app, trusted_proxy_network="203.0.113.88/32")
    generated = iter(("same-session-token", "csrf-one", "same-session-token", "csrf-two"))
    monkeypatch.setattr(auth_module, "new_opaque_secret", lambda: next(generated))
    application = create_app(settings)
    transport = ASGITransport(
        app=application, client=("203.0.113.88", 50000), raise_app_exceptions=False
    )
    second_assertion = signed_assertion(owner, workspace)
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        first = await client.post("/api/v1/auth/exchange", json=signed_assertion(owner, workspace))
        collision = await client.post("/api/v1/auth/exchange", json=second_assertion)
    assert first.status_code == 200
    assert collision.status_code == 500
    assert collision.json()["code"] == "internal_error"
    assert collision.json()["code"] != "assertion_replayed"
    engine = create_engine(database_urls.admin)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM used_assertion_nonces WHERE nonce=:nonce"),
                    {"nonce": second_assertion["nonce"]},
                )
                == 0
            )
    finally:
        engine.dispose()


async def test_sliding_idle_session_remains_active_beyond_initial_idle_interval(
    database_urls: Any,
) -> None:
    owner, workspace = seed_membership(database_urls.admin)
    settings = production_settings(
        database_urls.app,
        trusted_proxy_network="203.0.113.99/32",
        session_idle_seconds=60,
        session_absolute_seconds=300,
    )
    application = create_app(settings)
    transport = ASGITransport(app=application, client=("203.0.113.99", 50000))
    async with AsyncClient(transport=transport, base_url="https://brain.example.test") as client:
        exchange = await client.post(
            "/api/v1/auth/exchange", json=signed_assertion(owner, workspace)
        )
        token = exchange.cookies["second_brain_session"]
        assert "Max-Age=300" in exchange.headers["set-cookie"]
        engine = create_engine(database_urls.admin)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE sessions SET issued_at=now()-interval '120 seconds', "
                        "last_seen_at=now()-interval '30 seconds', "
                        "idle_expires_at=now()+interval '30 seconds' WHERE token_hash=:token"
                    ),
                    {"token": hashlib.sha256(token.encode()).hexdigest()},
                )
            response = await client.get("/api/v1/session/check")
            with engine.connect() as connection:
                remaining = connection.scalar(
                    text(
                        "SELECT extract(epoch FROM (idle_expires_at-now())) FROM sessions "
                        "WHERE token_hash=:token"
                    ),
                    {"token": hashlib.sha256(token.encode()).hexdigest()},
                )
        finally:
            engine.dispose()
    assert response.status_code == 200
    assert remaining is not None and remaining > 50
