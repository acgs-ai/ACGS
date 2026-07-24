"""Request admission and redacted error contract tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from itertools import count
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from acgs_control_plane.api_contract import REQUEST_ID_RE, append_bounded_body_chunk
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.models import ComplianceExport, Organization, PolicyBundle, ReceiptRow

_BOOTSTRAP_COUNTER = count()


def _small_client(tmp_path: Path, audit_dir: Path, limit: int = 512) -> TestClient:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'acp-small.sqlite3'}",
        audit_dir=audit_dir,
        bootstrap_token="test-bootstrap-token",
        create_tables=True,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        max_request_body_bytes=limit,
    )
    return TestClient(create_app(settings), raise_server_exceptions=False)


def _bootstrap(client: TestClient) -> dict[str, Any]:
    response = client.post(
        "/orgs",
        json={
            "name": f"Contract Org {next(_BOOTSTRAP_COUNTER)}",
            "admin_name": "Root Admin",
            "admin_email": "root@contract.example.com",
        },
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _audit_bytes(audit_dir: Path) -> bytes:
    if not audit_dir.exists():
        return b""
    payload = bytearray()
    for path in sorted(p for p in audit_dir.rglob("*") if p.is_file()):
        payload.extend(path.relative_to(audit_dir).as_posix().encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(path.read_bytes())
    return bytes(payload)


def _snapshot(client: TestClient, audit_dir: Path, org_id: str) -> dict[str, Any]:
    session = client.app.state.session_factory()
    try:
        org = session.get(Organization, org_id)
        assert org is not None
        export_count = session.execute(select(ComplianceExport)).scalars().all()
        receipts = session.execute(select(ReceiptRow)).scalars().all()
        policies = (
            session.execute(select(PolicyBundle).where(PolicyBundle.org_id == org_id))
            .scalars()
            .all()
        )
        return {
            "exports": len(export_count),
            "receipts": len(receipts),
            "policies": sorted((policy.policy_id, policy.status) for policy in policies),
            "anchor_count": org.audit_anchor_count,
            "anchor_hash": org.audit_anchor_hash,
            "audit_bytes": _audit_bytes(audit_dir),
        }
    finally:
        session.close()


def _assert_server_request_id(response: Any) -> None:
    request_id = response.headers["x-request-id"]
    assert REQUEST_ID_RE.fullmatch(request_id)
    assert response.json()["request_id"] == request_id


def test_authenticated_declared_oversized_export_is_rejected_before_state_change(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir)
    org = _bootstrap(client)
    headers = {"X-API-Key": org["admin_api_key"], "X-Request-ID": "attacker-controlled"}
    before = _snapshot(client, audit_dir, org["org_id"])

    response = client.post(
        f"/orgs/{org['org_id']}/exports",
        json={"note": "x" * 1000},
        headers=headers,
    )

    assert response.status_code == 413
    assert response.json()["code"] == "request_body_too_large"
    assert "attacker-controlled" not in response.text
    _assert_server_request_id(response)
    assert _snapshot(client, audit_dir, org["org_id"]) == before


def test_streamed_no_content_length_oversized_export_is_rejected_before_state_change(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    org = _bootstrap(client)
    before = _snapshot(client, audit_dir, org["org_id"])

    result = _run_asgi_request(
        client.app,
        "POST",
        f"/orgs/{org['org_id']}/exports",
        headers=[
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"x-api-key", org["admin_api_key"].encode("ascii")),
            (b"x-request-id", b"attacker-controlled"),
        ],
        chunks=[b'{"note":"', b"x" * 600, b'"}'],
    )

    assert result["status"] == 413
    assert result["json"]["code"] == "request_body_too_large"
    assert result["headers"][b"x-request-id"].decode("ascii") == result["json"]["request_id"]
    assert REQUEST_ID_RE.fullmatch(result["json"]["request_id"])
    assert b"attacker-controlled" not in result["body"]
    assert _snapshot(client, audit_dir, org["org_id"]) == before


def test_malformed_json_is_redacted_and_leaves_state_unchanged(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir)
    org = _bootstrap(client)
    before = _snapshot(client, audit_dir, org["org_id"])
    sentinel = "sk_live_SENTINEL_SECRET"

    response = client.post(
        f"/orgs/{org['org_id']}/exports",
        content=f'{{"note": "{sentinel}",'.encode(),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": org["admin_api_key"],
            "X-Request-ID": "attacker-controlled",
        },
    )

    assert response.status_code == 400
    assert response.json()["code"] == "malformed_json"
    assert sentinel not in response.text
    assert "attacker-controlled" not in response.text
    _assert_server_request_id(response)
    assert _snapshot(client, audit_dir, org["org_id"]) == before


def test_unauthenticated_rejected_requests_expose_no_tenant_or_governance_evidence(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir)
    org = _bootstrap(client)
    before = _snapshot(client, audit_dir, org["org_id"])

    oversized = client.post(
        f"/orgs/{org['org_id']}/exports",
        json={"note": "x" * 1000},
        headers={"X-Request-ID": "attacker-controlled"},
    )
    malformed = client.post(
        f"/orgs/{org['org_id']}/exports",
        content=b'{"note": "sk_live_SENTINEL_SECRET",',
        headers={"Content-Type": "application/json", "X-Request-ID": "attacker-controlled"},
    )

    assert oversized.status_code == 413
    assert malformed.status_code == 400
    for response in (oversized, malformed):
        body = response.text
        assert org["org_id"] not in body
        assert "receipt" not in body
        assert "organization" not in body
        assert "attacker-controlled" not in body
        _assert_server_request_id(response)
    assert _snapshot(client, audit_dir, org["org_id"]) == before


def test_invalid_content_length_is_rejected_without_reading_body(tmp_path: Path) -> None:
    client = _small_client(tmp_path, tmp_path / "audit")
    result, receive_calls = _run_asgi_request_with_receive_count(
        client.app,
        "POST",
        "/orgs",
        headers=[
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
            (b"content-length", b"3"),
        ],
        chunks=[b"{}"],
    )

    assert receive_calls == 0
    assert result["status"] == 400
    assert result["json"]["code"] == "invalid_content_length"
    assert REQUEST_ID_RE.fullmatch(result["json"]["request_id"])


def test_policy_activation_bodyless_route_is_not_invoked_until_stream_admitted(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    org, second_bundle_id = _seed_policy_activation_target(client)
    org_id = org["org_id"]
    before = _snapshot(client, audit_dir, org_id)

    result = _run_asgi_request(
        client.app,
        "POST",
        f"/orgs/{org_id}/policies/{second_bundle_id}/activate",
        headers=[
            (b"host", b"testserver"),
            (b"x-api-key", org["admin_api_key"].encode("ascii")),
            (b"x-request-id", b"attacker-controlled"),
        ],
        chunks=[b"x" * 600],
    )

    assert result["status"] == 413
    assert result["json"]["code"] == "request_body_too_large"
    assert b"attacker-controlled" not in result["body"]
    assert _snapshot(client, audit_dir, org_id) == before


def test_policy_activation_rejects_first_event_disconnect_without_state_change(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    org, second_bundle_id = _seed_policy_activation_target(client)
    org_id = org["org_id"]
    before = _snapshot(client, audit_dir, org_id)

    result = _run_asgi_messages(
        client.app,
        "POST",
        f"/orgs/{org_id}/policies/{second_bundle_id}/activate",
        headers=[
            (b"host", b"testserver"),
            (b"x-api-key", org["admin_api_key"].encode("ascii")),
        ],
        messages=[{"type": "http.disconnect"}],
        expect_response=False,
    )

    assert result["sent"] == []
    assert _snapshot(client, audit_dir, org_id) == before


def test_policy_activation_rejects_unexpected_receive_event_without_state_change(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    org, second_bundle_id = _seed_policy_activation_target(client)
    org_id = org["org_id"]
    before = _snapshot(client, audit_dir, org_id)

    result = _run_asgi_messages(
        client.app,
        "POST",
        f"/orgs/{org_id}/policies/{second_bundle_id}/activate",
        headers=[
            (b"host", b"testserver"),
            (b"x-api-key", org["admin_api_key"].encode("ascii")),
        ],
        messages=[{"type": "websocket.receive"}],
    )

    assert result["status"] == 400
    assert result["json"]["code"] == "invalid_request_stream"
    assert _snapshot(client, audit_dir, org_id) == before


def test_policy_activation_zero_byte_chunk_flood_then_overflow_is_rejected(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    org, second_bundle_id = _seed_policy_activation_target(client)
    org_id = org["org_id"]
    before = _snapshot(client, audit_dir, org_id)
    messages = [{"type": "http.request", "body": b"", "more_body": True} for _ in range(1000)]
    messages.append({"type": "http.request", "body": b"x" * 600, "more_body": False})

    result = _run_asgi_messages(
        client.app,
        "POST",
        f"/orgs/{org_id}/policies/{second_bundle_id}/activate",
        headers=[
            (b"host", b"testserver"),
            (b"x-api-key", org["admin_api_key"].encode("ascii")),
        ],
        messages=messages,
    )

    assert result["status"] == 413
    assert result["json"]["code"] == "request_body_too_large"
    assert _snapshot(client, audit_dir, org_id) == before


def test_policy_activation_rejects_declared_length_mismatch_without_state_change(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _small_client(tmp_path, audit_dir, limit=512)
    for declared, chunks in ((b"1", [b"abc"]), (b"20", [b"abc"])):
        org, second_bundle_id = _seed_policy_activation_target(client)
        org_id = org["org_id"]
        before = _snapshot(client, audit_dir, org_id)

        result = _run_asgi_request(
            client.app,
            "POST",
            f"/orgs/{org_id}/policies/{second_bundle_id}/activate",
            headers=[
                (b"host", b"testserver"),
                (b"x-api-key", org["admin_api_key"].encode("ascii")),
                (b"content-length", declared),
            ],
            chunks=chunks,
        )

        assert result["status"] == 400
        assert result["json"]["code"] == "invalid_content_length"
        assert _snapshot(client, audit_dir, org_id) == before


def test_hostile_content_length_values_fail_closed_without_read_or_route(
    tmp_path: Path,
) -> None:
    client = _small_client(tmp_path, tmp_path / "audit")
    cases = [
        (b"\xff", 400, "invalid_content_length"),
        (b"9" * 5000, 413, "request_body_too_large"),
    ]
    for raw_length, status, code in cases:
        result, receive_calls = _run_asgi_request_with_receive_count(
            client.app,
            "POST",
            "/orgs",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"application/json"),
                (b"content-length", raw_length),
            ],
            chunks=[b"{}"],
        )
        assert receive_calls == 0
        assert result["status"] == status
        assert result["json"]["code"] == code
        assert REQUEST_ID_RE.fullmatch(result["json"]["request_id"])


def test_bounded_append_rejects_oversized_chunk_before_copy() -> None:
    class TrackingBytearray(bytearray):
        extend_calls = 0

        def extend(self, item: object) -> None:
            type(self).extend_calls += 1
            super().extend(item)

    class HugeChunk:
        copied = False

        def __len__(self) -> int:
            return 5 * 1024 * 1024

        def __iter__(self):
            type(self).copied = True
            return iter(())

    body = TrackingBytearray(b"abc")
    result = append_bounded_body_chunk(body, HugeChunk(), max_request_body_bytes=512)  # type: ignore[arg-type]

    assert result == "invalid"
    assert body == b"abc"
    assert HugeChunk.copied is False
    assert TrackingBytearray.extend_calls == 0

    huge_bytes = b"x" * (2 * 1024 * 1024)
    result = append_bounded_body_chunk(body, huge_bytes, max_request_body_bytes=512)
    assert result == "too_large"
    assert body == b"abc"
    assert TrackingBytearray.extend_calls == 0


def test_direct_settings_and_middleware_reject_unsafe_limits(
    monkeypatch: Any,
) -> None:
    from acgs_control_plane.api_contract import RequestAdmissionMiddleware
    from acgs_control_plane.config import RequestBodyLimitConfigurationError

    def app(_scope: Any, _receive: Any, _send: Any) -> None:
        raise AssertionError("constructor should reject before app use")

    for value in (0, True, 16 * 1024 * 1024 + 1):
        try:
            Settings(max_request_body_bytes=value)  # type: ignore[arg-type]
        except RequestBodyLimitConfigurationError:
            pass
        else:
            raise AssertionError(f"unsafe Settings limit accepted: {value!r}")

        try:
            RequestAdmissionMiddleware(app, max_request_body_bytes=value)  # type: ignore[arg-type]
        except RequestBodyLimitConfigurationError:
            pass
        else:
            raise AssertionError(f"unsafe middleware limit accepted: {value!r}")

    sentinel = "9" * 5000
    monkeypatch.setenv("ACP_MAX_REQUEST_BODY_BYTES", sentinel)
    try:
        Settings.from_env()
    except RequestBodyLimitConfigurationError as exc:
        assert sentinel not in str(exc)
    else:
        raise AssertionError("huge env limit was accepted")


def _run_asgi_request_with_receive_count(
    app: Callable[..., Any],
    method: str,
    path: str,
    *,
    headers: list[tuple[bytes, bytes]],
    chunks: list[bytes],
) -> tuple[dict[str, Any], int]:
    receive_calls = 0
    messages = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    return (
        _run_asgi_request(app, method, path, headers=headers, chunks=chunks, receive=receive),
        receive_calls,
    )


def _seed_policy_activation_target(client: TestClient) -> tuple[dict[str, Any], str]:
    org = _bootstrap(client)
    org_id = org["org_id"]
    headers = {"X-API-Key": org["admin_api_key"]}
    first = client.post(
        f"/orgs/{org_id}/policies",
        json={
            "policy_id": f"first-{org_id}",
            "rules": [{"id": "r1", "effect": "deny", "tools": ["x"]}],
        },
        headers=headers,
    )
    assert first.status_code == 201, first.text
    active = client.post(
        f"/orgs/{org_id}/policies/{first.json()['bundle_id']}/activate",
        headers=headers,
    )
    assert active.status_code == 200, active.text
    second = client.post(
        f"/orgs/{org_id}/policies",
        json={
            "policy_id": f"second-{org_id}",
            "rules": [{"id": "r2", "effect": "deny", "tools": ["y"]}],
        },
        headers=headers,
    )
    assert second.status_code == 201, second.text
    return org, str(second.json()["bundle_id"])


def test_settings_request_body_limit_env_is_bounded_and_redacted(
    monkeypatch: Any,
) -> None:
    from acgs_control_plane.config import (
        DEFAULT_MAX_REQUEST_BODY_BYTES,
        MAX_MAX_REQUEST_BODY_BYTES,
        RequestBodyLimitConfigurationError,
        Settings,
    )

    monkeypatch.delenv("ACP_MAX_REQUEST_BODY_BYTES", raising=False)
    assert Settings.from_env().max_request_body_bytes == DEFAULT_MAX_REQUEST_BODY_BYTES

    monkeypatch.setenv("ACP_MAX_REQUEST_BODY_BYTES", "4096")
    assert Settings.from_env().max_request_body_bytes == 4096

    sentinel = "999999999999999999999999999999999999999999"
    monkeypatch.setenv("ACP_MAX_REQUEST_BODY_BYTES", sentinel)
    try:
        Settings.from_env()
    except RequestBodyLimitConfigurationError as exc:
        assert "ACP_MAX_REQUEST_BODY_BYTES" in str(exc)
        assert sentinel not in str(exc)
        assert str(MAX_MAX_REQUEST_BODY_BYTES) in str(exc)
    else:
        raise AssertionError("unsafe body limit was accepted")


def _run_asgi_request(
    app: Callable[..., Any],
    method: str,
    path: str,
    *,
    headers: list[tuple[bytes, bytes]],
    chunks: list[bytes],
    receive: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    return _run_asgi_messages(
        app,
        method,
        path,
        headers=headers,
        messages=[
            {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
            for index, chunk in enumerate(chunks)
        ],
        receive=receive,
    )


def _run_asgi_messages(
    app: Callable[..., Any],
    method: str,
    path: str,
    *,
    headers: list[tuple[bytes, bytes]],
    messages: list[dict[str, Any]],
    receive: Callable[[], Any] | None = None,
    expect_response: bool = True,
) -> dict[str, Any]:
    pending = list(messages)
    sent: list[dict[str, Any]] = []

    async def default_receive() -> dict[str, Any]:
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    import anyio

    anyio.run(
        app,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers,
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "state": {},
        },
        receive or default_receive,
        send,
    )
    body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    if not expect_response:
        return {"sent": sent, "body": body}
    return {
        "status": next(
            message["status"] for message in sent if message["type"] == "http.response.start"
        ),
        "headers": dict(
            next(message["headers"] for message in sent if message["type"] == "http.response.start")
        ),
        "body": body,
        "json": json.loads(body),
    }
