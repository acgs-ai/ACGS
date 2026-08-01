"""Real-router security and stability tests for public v1 collection cursors."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

import acgs_control_plane.pagination as pagination
from acgs_control_plane.models import (
    AgentRecord,
    ComplianceExport,
    Organization,
    PolicyBundle,
    ReceiptRow,
    User,
)
from acgs_control_plane.pagination import (
    CursorKeyring,
    issue_collection_cursor,
    issue_receipt_cursor,
    receipt_filter_digest,
)

RESOURCE_CASES = (
    ("users", User, "user_id"),
    ("agents", AgentRecord, "agent_id"),
    ("policies", PolicyBundle, "bundle_id"),
    ("exports", ComplianceExport, "export_id"),
)


def _app(client: TestClient) -> FastAPI:
    return client.app  # type: ignore[return-value]


def _row(resource: str, org_id: str, index: int) -> Any:
    common = {"id": f"{resource}-{index:02d}", "org_id": org_id}
    if resource == "users":
        return User(
            **common,
            name=f"User {index}",
            email=f"cursor-{index}@example.com",
            role="viewer",
            api_key_hash=None,
        )
    if resource == "agents":
        return AgentRecord(
            **common,
            name=f"Agent {index}",
            description="",
            trust_tier="untrusted",
            allowed_tools=[],
            status="active",
        )
    if resource == "policies":
        return PolicyBundle(
            **common,
            policy_id=f"policy-{index}",
            version=f"version-{index}",
            bundle={"rules": []},
            status="published",
        )
    return ComplianceExport(
        **common,
        created_by="test",
        receipt_count=0,
        bundle_hash=f"hash-{index}",
        bundle={},
    )


def _seed_tied_rows(client: TestClient, org_id: str, resource: str, model: Any) -> list[str]:
    base = datetime(2026, 7, 31, 12, 0, 0, 654_321, tzinfo=UTC)
    with _app(client).state.session_factory() as session:
        if resource == "users":
            admin = session.execute(select(User).where(User.org_id == org_id)).scalar_one()
            admin.created_at = base - timedelta(seconds=10)
        for index in range(6):
            row = _row(resource, org_id, index)
            row.created_at = base + timedelta(seconds=index // 2)
            session.add(row)
        session.commit()
        return [
            row.id
            for row in session.execute(
                select(model)
                .where(model.org_id == org_id)
                .order_by(model.created_at.desc(), model.id.desc())
            ).scalars()
        ]


@pytest.mark.parametrize(("resource", "model", "id_field"), RESOURCE_CASES)
def test_collection_pages_cover_tied_order_exactly_once_with_limit_changes(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    resource: str,
    model: Any,
    id_field: str,
) -> None:
    expected = _seed_tied_rows(client, org["org_id"], resource, model)
    collected: list[str] = []
    cursor: str | None = None
    for limit in (2, 1, 3, 2):
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        response = client.get(
            f"/v1/orgs/{org['org_id']}/{resource}", params=params, headers=admin_headers
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "private, no-store"
        body = response.json()
        assert body["limit"] == limit
        collected.extend(item[id_field] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert collected == expected
    assert len(collected) == len(set(collected))


def test_collection_cursor_is_stable_across_newer_insert_and_boundary_delete(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    org_id = org["org_id"]
    expected = _seed_tied_rows(client, org_id, "agents", AgentRecord)
    first = client.get(
        f"/v1/orgs/{org_id}/agents", params={"limit": 2}, headers=admin_headers
    ).json()
    assert [item["agent_id"] for item in first["items"]] == expected[:2]
    with _app(client).state.session_factory() as session:
        session.add(
            AgentRecord(
                id="newer-agent",
                org_id=org_id,
                name="Newer agent",
                description="",
                trust_tier="untrusted",
                allowed_tools=[],
                status="active",
                created_at=datetime(2027, 1, 1, tzinfo=UTC),
            )
        )
        session.execute(delete(AgentRecord).where(AgentRecord.id == expected[1]))
        session.commit()
    resumed = client.get(
        f"/v1/orgs/{org_id}/agents",
        params={"limit": 500, "cursor": first["next_cursor"]},
        headers=admin_headers,
    )
    assert resumed.status_code == 200, resumed.text
    assert [item["agent_id"] for item in resumed.json()["items"]] == expected[2:]


def _aad(kid: str, org_id: str, resource: str) -> bytes:
    return json.dumps(
        {"kid": kid, "resource": resource, "scope_org_id": org_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _decode_payload(
    token: str, keyring: CursorKeyring, org_id: str, resource: str
) -> dict[str, Any]:
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    return json.loads(
        AESGCM(keyring.active_key).decrypt(
            raw[:12], raw[12:], _aad(keyring.active_key_id, org_id, resource)
        )
    )


def _encode_payload(
    payload: dict[str, Any], keyring: CursorKeyring, org_id: str, resource: str
) -> str:
    nonce = b"collection12"
    plaintext = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    raw = nonce + AESGCM(keyring.active_key).encrypt(
        nonce, plaintext, _aad(keyring.active_key_id, org_id, resource)
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _snapshot(client: TestClient, audit_dir: Path, org_id: str) -> tuple[int, int, bytes]:
    with _app(client).state.session_factory() as session:
        receipt_count = session.scalar(
            select(func.count()).select_from(ReceiptRow).where(ReceiptRow.org_id == org_id)
        )
        org = session.get(Organization, org_id)
        assert org is not None
        audit = b"".join(
            path.read_bytes() for path in sorted(audit_dir.glob("**/*")) if path.is_file()
        )
        return int(receipt_count or 0), org.audit_anchor_count, audit


def _assert_generic_invalid(response: Any) -> None:
    assert response.status_code == 400
    assert response.headers["cache-control"] == "private, no-store"
    body = response.json()
    assert set(body) == {"code", "status", "request_id"}
    assert body["code"] == "invalid_cursor"
    assert body["status"] == "error"
    assert not any(word in response.text for word in ("decrypt", "expired", "scope", "resource"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.__setitem__("order", "id_desc"),
        lambda payload: payload.__setitem__("filter_digest", "0" * 64),
        lambda payload: payload.__setitem__("v", 2),
        lambda payload: payload.__setitem__("extra", True),
        lambda payload: payload.pop("boundary_id"),
        lambda payload: payload.__setitem__("boundary_id", 7),
    ],
)
def test_collection_cursor_payload_failures_are_generic_and_side_effect_free(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    audit_dir: Path,
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    org_id = org["org_id"]
    _seed_tied_rows(client, org_id, "agents", AgentRecord)
    first = client.get(
        f"/v1/orgs/{org_id}/agents", params={"limit": 1}, headers=admin_headers
    ).json()
    keyring = _app(client).state.settings.cursor_keyring
    payload = _decode_payload(first["next_cursor"], keyring, org_id, "agents")
    mutate(payload)
    token = _encode_payload(payload, keyring, org_id, "agents")
    before = _snapshot(client, audit_dir, org_id)
    response = client.get(
        f"/v1/orgs/{org_id}/agents", params={"cursor": token}, headers=admin_headers
    )
    _assert_generic_invalid(response)
    assert _snapshot(client, audit_dir, org_id) == before


def test_collection_cursor_crypto_scope_and_cross_resource_failures_are_generic(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    org_id = org["org_id"]
    keyring = _app(client).state.settings.cursor_keyring
    now = datetime.now(UTC)
    tokens = [
        "bad",
        "A" * 4097,
        issue_collection_cursor(
            keyring=CursorKeyring(active_key_id="wrong", active_key=b"x" * 32),
            org_id=org_id,
            resource="agents",
            boundary_created_at=now,
            boundary_id="id",
        ),
        issue_collection_cursor(
            keyring=keyring,
            org_id="other-org",
            resource="agents",
            boundary_created_at=now,
            boundary_id="id",
        ),
        issue_collection_cursor(
            keyring=keyring,
            org_id=org_id,
            resource="users",
            boundary_created_at=now,
            boundary_id="id",
        ),
        issue_collection_cursor(
            keyring=keyring,
            org_id=org_id,
            resource="agents",
            boundary_created_at=now,
            boundary_id="id",
            now=now - timedelta(seconds=keyring.ttl_seconds + 1),
        ),
    ]
    for token in tokens:
        response = client.get(
            f"/v1/orgs/{org_id}/agents", params={"cursor": token}, headers=admin_headers
        )
        _assert_generic_invalid(response)


@pytest.mark.parametrize("failure_source", ["entropy", "aead"])
def test_collection_cursor_issuance_does_not_downgrade_internal_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure_source: str,
) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("internal cursor failure")

    if failure_source == "entropy":
        monkeypatch.setattr(pagination.secrets, "token_bytes", _boom)
    else:
        monkeypatch.setattr(pagination.AESGCM, "encrypt", _boom)
    with pytest.raises(RuntimeError, match="internal cursor failure"):
        issue_collection_cursor(
            keyring=CursorKeyring(active_key_id="test", active_key=b"k" * 32),
            org_id="org",
            resource="agents",
            boundary_created_at=datetime.now(UTC),
            boundary_id="agent",
        )


def test_receipt_and_collection_cursor_protocols_reject_each_other(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    org_id = org["org_id"]
    keyring = _app(client).state.settings.cursor_keyring
    now = datetime.now(UTC)
    receipt_token = issue_receipt_cursor(
        keyring=keyring,
        org_id=org_id,
        filter_digest=receipt_filter_digest(
            decision=None, tool=None, actor=None, since=None, until=None
        ),
        boundary_created_at=now,
        boundary_receipt_id="receipt",
    )
    collection_token = issue_collection_cursor(
        keyring=keyring,
        org_id=org_id,
        resource="agents",
        boundary_created_at=now,
        boundary_id="agent",
    )
    _assert_generic_invalid(
        client.get(
            f"/v1/orgs/{org_id}/agents",
            params={"cursor": receipt_token},
            headers=admin_headers,
        )
    )
    _assert_generic_invalid(
        client.get(
            f"/orgs/{org_id}/receipts",
            params={"cursor": collection_token},
            headers=admin_headers,
        )
    )


@pytest.mark.parametrize(
    "query",
    [
        "cursor=",
        "limit=",
        "limit=0",
        "limit=501",
        f"limit={'9' * 5000}",
        "limit=01",
        "limit=+1",
        "limit=%31",
        "limit=1&limit=2",
        "cursor=a&cursor=b",
        "unknown=1",
        "limit=1&",
    ],
)
def test_collection_query_admission_is_strict_and_generic(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    query: str,
) -> None:
    response = client.get(f"/v1/orgs/{org['org_id']}/agents?{query}", headers=admin_headers)
    _assert_generic_invalid(response)


def test_collection_query_admission_runs_after_auth_tenant_and_rbac(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    make_user: Callable[[str], dict[str, str]],
) -> None:
    other = client.post(
        "/orgs",
        json={
            "name": "Other cursor org",
            "admin_name": "Other",
            "admin_email": "other-cursor@example.com",
        },
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
    ).json()
    viewer = make_user("viewer")
    malformed = "?unknown=1&cursor="
    assert client.get(f"/v1/orgs/{org['org_id']}/agents{malformed}").status_code == 401
    assert (
        client.get(
            f"/v1/orgs/{other['org_id']}/agents{malformed}", headers=admin_headers
        ).status_code
        == 404
    )
    assert (
        client.get(f"/v1/orgs/{org['org_id']}/exports{malformed}", headers=viewer).status_code
        == 403
    )


@pytest.mark.parametrize("resource", ["users", "agents", "policies", "exports"])
@pytest.mark.parametrize("trailing", ["/", "///", "%2F%2F"])
def test_collection_trailing_slash_is_internally_canonicalized_without_redirect(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    resource: str,
    trailing: str,
) -> None:
    secret = "trailing-query-secret"
    response = client.get(
        f"/v1/orgs/{org['org_id']}/{resource}{trailing}?cursor={secret}",
        headers=admin_headers,
        follow_redirects=False,
    )
    _assert_generic_invalid(response)
    assert "location" not in response.headers
    assert secret not in response.text
    assert f"/v1/orgs/{{org_id}}/{resource}/" not in _app(client).openapi()["paths"]


@pytest.mark.parametrize("trailing", ["/", "///", "%2F%2F"])
def test_collection_trailing_slash_preserves_security_precedence_without_reflection(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    make_user: Callable[[str], dict[str, str]],
    trailing: str,
) -> None:
    other = client.post(
        "/orgs",
        json={
            "name": "Trailing other org",
            "admin_name": "Other",
            "admin_email": "trailing-other@example.com",
        },
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
    ).json()
    viewer = make_user("viewer")
    secret = "trailing-precedence-secret"
    query = f"?unknown={secret}&cursor="
    responses = (
        (
            client.get(
                f"/v1/orgs/{org['org_id']}/agents{trailing}{query}",
                follow_redirects=False,
            ),
            401,
            "unauthorized",
        ),
        (
            client.get(
                f"/v1/orgs/{other['org_id']}/agents{trailing}{query}",
                headers=admin_headers,
                follow_redirects=False,
            ),
            404,
            "not_found",
        ),
        (
            client.get(
                f"/v1/orgs/{org['org_id']}/exports{trailing}{query}",
                headers=viewer,
                follow_redirects=False,
            ),
            403,
            "forbidden",
        ),
        (
            client.get(
                f"/v1/orgs/{org['org_id']}/agents{trailing}{query}",
                headers=admin_headers,
                follow_redirects=False,
            ),
            400,
            "invalid_cursor",
        ),
    )
    for response, status, code in responses:
        assert response.status_code == status
        assert response.json()["code"] == code
        assert response.headers["cache-control"] == "private, no-store"
        assert "location" not in response.headers
        assert secret not in response.text


def test_collection_query_has_a_raw_aggregate_byte_bound_before_parsing(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    sent: list[dict[str, Any]] = []
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    path = f"/v1/orgs/{org['org_id']}/agents"
    secret = b"Q" * 5000
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"cursor=" + secret,
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (b"x-api-key", admin_headers["X-API-Key"].encode("ascii")),
        ],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "state": {},
    }
    asyncio.run(_app(client)(scope, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    headers = {name.lower(): value for name, value in start["headers"]}
    assert start["status"] == 400
    assert json.loads(body)["code"] == "invalid_cursor"
    assert headers[b"cache-control"] == b"private, no-store"
    assert secret not in body
