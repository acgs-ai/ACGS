"""P0 executable production-posture and future managed-contract gates."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from starlette.responses import PlainTextResponse
from starlette.routing import Host, Route

import acgs_control_plane.app as app_module
import acgs_control_plane.governance as governance_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import (
    RuntimePosture,
    RuntimePostureConfigurationError,
    Settings,
)
from acgs_control_plane.db import Base
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    AuthenticatedRuntimeContext,
    ExecutionClass,
    ProductionPostureBlocked,
    _canonical_json_subset,
    _issue_authenticated_runtime_context,
    _issue_server_managed_bundle,
    existing_org_audit_store,
    managed_contract_stub,
    org_audit_store,
)


def _settings(tmp_path: Path, posture: RuntimePosture | None) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'must-not-exist.sqlite3'}",
        audit_dir=tmp_path / "audit",
        create_tables=True,
        runtime_posture=posture,
    )


def test_production_rejects_legacy_unsigned_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = create_app(_settings(tmp_path, RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED))
    actual = {
        (method, route.path)
        for route in local.routes
        if isinstance(route, APIRoute)
        for method in route.methods or ()
    }
    expected = {(record.method, record.path) for record in ROUTE_CONTRACTS}
    assert actual == expected
    assert len(expected) == len(ROUTE_CONTRACTS)
    legacy = [
        r for r in ROUTE_CONTRACTS if r.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    assert len(legacy) == 7
    assert TestClient(local).get("/healthz").status_code == 200
    ready = TestClient(local).get("/readyz")
    assert ready.status_code == 503
    assert ready.json() == {
        "code": "PRODUCTION_POSTURE_BLOCKED",
        "stage": "pre-persistence",
        "status": "not-production-ready",
        "blockers": [blocker.to_dict() for blocker in local.state.readiness_blockers],
    }
    local.state.engine.dispose()
    (tmp_path / "must-not-exist.sqlite3").unlink()

    calls = {"engine": 0}

    def forbidden_engine(_url: str) -> Any:
        calls["engine"] += 1
        raise AssertionError("persistence constructed before posture refusal")

    monkeypatch.setattr("acgs_control_plane.app.make_engine", forbidden_engine)
    with pytest.raises(ProductionPostureBlocked) as missing:
        create_app(_settings(tmp_path, None))
    assert missing.value.stage == "pre-persistence"
    assert calls == {"engine": 0}
    unknown_settings = _settings(tmp_path, None)
    object.__setattr__(unknown_settings, "runtime_posture", "mystery")
    with pytest.raises(ProductionPostureBlocked) as unknown:
        create_app(unknown_settings)
    assert unknown.value.blockers[0].code == "RUNTIME_POSTURE_UNKNOWN"

    providers: tuple[Any, ...] = ()
    with pytest.raises(ProductionPostureBlocked) as blocked:
        create_app(_settings(tmp_path, RuntimePosture.PRODUCTION), production_providers=providers)
    assert calls == {"engine": 0}
    assert len([b for b in blocked.value.blockers if b.code == "LEGACY_UNSIGNED_WRITE"]) == 7
    assert not (tmp_path / "must-not-exist.sqlite3").exists()
    assert not (tmp_path / "audit").exists()

    original_register = app_module._register_routes

    def register_with_drift(app: Any) -> None:
        original_register(app)

        @app.get("/synthetic-later-route")
        def synthetic() -> dict[str, bool]:
            return {"unexpected": True}

        @app.post("/synthetic-later-write")
        def synthetic_write() -> dict[str, bool]:
            return {"unexpected": True}

        async def raw_route(_request: Any) -> PlainTextResponse:
            return PlainTextResponse("unexpected")

        app.router.routes.append(Route("/synthetic-raw-route", raw_route, methods=["GET"]))
        nested = FastAPI()

        @nested.post("/write")
        def nested_write() -> dict[str, bool]:
            return {"unexpected": True}

        app.mount("/nested", nested)

        @app.websocket("/synthetic-websocket")
        async def synthetic_websocket(_socket: Any) -> None:
            return None

        app.router.routes.append(Host("synthetic.example", app=nested))

    monkeypatch.setattr(app_module, "_register_routes", register_with_drift)
    with pytest.raises(ProductionPostureBlocked) as drifted:
        create_app(_settings(tmp_path, RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED))
    routes = {b.route for b in drifted.value.blockers}
    assert "GET /synthetic-later-route" in routes
    assert "POST /synthetic-later-write" in routes
    assert "GET /synthetic-raw-route" in routes
    assert any(route and route.startswith("Mount ") for route in routes)
    assert any(route and "WebSocketRoute " in route for route in routes)
    assert any(route and route.startswith("Host ") for route in routes)
    assert calls == {"engine": 0}


def _server_bundle() -> Any:
    context = _issue_authenticated_runtime_context(
        actor="invitee:1",
        tenant="tenant:prospective",
        project="project:default",
        environment="environment:default",
        authentication_method="oidc",
        authority_domain="platform",
        validated_at="2026-07-11T00:00:00Z",
    )
    return _issue_server_managed_bundle(
        context=context,
        authority="platform.provisioner/v1",
        validator="platform.bootstrap-policy/v1",
        policy_id="bootstrap",
        policy_version="1",
        policy_hash="a" * 64,
        issued_at="2026-07-11T00:00:00Z",
        expires_at="2026-07-11T00:01:00Z",
        key_id="key-1",
        audit_anchor="b" * 64,
        idempotency_key="op-1",
    )


def test_tenant_bootstrap_and_register_contract_stub_no_mutation() -> None:
    bundle = _server_bundle()
    expected = {
        "DENY": "MANAGED_DECISION_DENIED",
        "ESCALATE": "MANAGED_DECISION_ESCALATED",
        "ALLOW": "CANONICAL_PATH_NOT_ENABLED",
    }
    for decision, code in expected.items():
        for contract, body in (
            ("tenant.bootstrap/v1", {"display_name": "Acme"}),
            ("agent.register/v1", {"name": "dispatcher", "configuration": {"mode": "strict"}}),
        ):
            with pytest.raises(ProductionPostureBlocked) as stopped:
                managed_contract_stub(contract, body, bundle, decision=decision)
            assert stopped.value.blockers[0].code == code
            assert not hasattr(stopped.value, "contract")
            assert "dispatcher" not in str(stopped.value)

    aliases = (
        "actor",
        "tenant",
        "org_id",
        "project",
        "environment",
        "authority",
        "validator",
        "policy",
        "policy_id",
        "policy_version",
        "policy_hash",
        "receipt",
        "receipt_id",
        "boundary",
        "execution_boundary",
        "issued_at",
        "expires_at",
        "key_id",
        "audit_anchor",
        "idempotency",
        "idempotency_key",
    )
    for alias in aliases:
        with pytest.raises(ValueError, match="caller-controlled or unknown"):
            managed_contract_stub(
                "agent.register/v1", {"name": "x", alias: "attacker"}, bundle, decision="ALLOW"
            )
    with pytest.raises(TypeError, match="closed server bundle"):
        managed_contract_stub("agent.register/v1", {"name": "x"}, {}, decision="ALLOW")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="keys must be strings"):
        managed_contract_stub(
            "agent.register/v1", {"configuration": {1: "x"}}, bundle, decision="ALLOW"
        )
    for ambiguous in (float("nan"), float("inf"), 1.5):
        with pytest.raises(ValueError, match="rejects floats"):
            managed_contract_stub(
                "agent.register/v1", {"configuration": ambiguous}, bundle, decision="ALLOW"
            )


def _fs_snapshot(root: Path) -> dict[str, tuple[int, int, bytes]]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): (
            path.stat().st_size,
            path.stat().st_mtime_ns,
            path.read_bytes(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def test_all_read_operations_and_simulation_are_filesystem_pure(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    audit_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org["org_id"]
    agent = client.post(f"/orgs/{org_id}/agents", json={"name": "reader"}, headers=admin_headers)
    export = client.post(f"/orgs/{org_id}/exports", json={"note": ""}, headers=admin_headers)
    receipt_id = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["items"][0][
        "receipt_id"
    ]
    before = _fs_snapshot(audit_dir)
    with client.app.state.session_factory() as session:
        db_before = {
            table.name: session.execute(select(func.count()).select_from(table)).scalar_one()
            for table in Base.metadata.sorted_tables
        }

    def forbidden_membrane(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("read/simulation constructed governance membrane")

    monkeypatch.setattr(app_module, "_membrane", forbidden_membrane)
    urls = (
        f"/orgs/{org_id}",
        f"/orgs/{org_id}/users",
        f"/orgs/{org_id}/agents",
        f"/orgs/{org_id}/agents/{agent.json()['agent_id']}",
        f"/orgs/{org_id}/policies",
        f"/orgs/{org_id}/receipts",
        f"/orgs/{org_id}/receipts/{receipt_id}",
        f"/orgs/{org_id}/dashboard",
        f"/orgs/{org_id}/exports",
        f"/orgs/{org_id}/exports/{export.json()['export_id']}",
    )
    for url in urls:
        assert client.get(url, headers=admin_headers).status_code == 200, url
    simulate = {"tool": "agent.register", "args": {}, "actor": "test"}
    assert (
        client.post(
            f"/orgs/{org_id}/policies/simulate", json=simulate, headers=admin_headers
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/orgs/{org_id}/receipts/{receipt_id}/verify", headers=admin_headers
        ).status_code
        == 200
    )
    assert _fs_snapshot(audit_dir) == before
    with client.app.state.session_factory() as session:
        db_after = {
            table.name: session.execute(select(func.count()).select_from(table)).scalar_one()
            for table in Base.metadata.sorted_tables
        }
    assert db_after == db_before

    shutil.rmtree(audit_dir)
    assert (
        client.post(
            f"/orgs/{org_id}/policies/simulate", json=simulate, headers=admin_headers
        ).status_code
        == 200
    )
    assert client.get(f"/orgs/{org_id}/dashboard", headers=admin_headers).status_code == 200
    assert (
        client.post(
            f"/orgs/{org_id}/receipts/{receipt_id}/verify", headers=admin_headers
        ).status_code
        == 200
    )
    assert not audit_dir.exists()


def test_audit_symlinks_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    root_link = tmp_path / "audit"
    root_link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="root symlinks"):
        org_audit_store(root_link, "org")
    root_link.unlink()
    root_link.mkdir()
    file_link = root_link / "org.audit.jsonl"
    outside_file = target / "outside.jsonl"
    outside_file.write_text("secret")
    file_link.symlink_to(outside_file)
    with pytest.raises(ValueError, match="non-symlink"):
        existing_org_audit_store(root_link, "org")
    with pytest.raises(ValueError, match="organization identifier"):
        existing_org_audit_store(root_link, "../outside")


def test_raw_context_bundle_and_environment_posture_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACP_RUNTIME_POSTURE", "typo-production")
    with pytest.raises(RuntimePostureConfigurationError) as posture:
        Settings.from_env()
    payload = posture.value.args[0]
    assert '"code": "PRODUCTION_POSTURE_BLOCKED"' in payload
    assert '"stage": "pre-persistence"' in payload

    raw_context = {
        "actor": "a",
        "tenant": "t",
        "project": "p",
        "environment": "e",
        "authentication_method": "oidc",
        "authority_domain": "platform",
        "validated_at": "2026-07-11T00:00:00Z",
    }
    with pytest.raises(TypeError, match="capability"):
        AuthenticatedRuntimeContext(object(), **raw_context)
    context = _issue_authenticated_runtime_context(**raw_context)
    valid = {
        "context": context,
        "authority": "authority",
        "validator": "validator",
        "policy_id": "policy",
        "policy_version": "1",
        "policy_hash": "a" * 64,
        "issued_at": "2026-07-11T00:00:00Z",
        "expires_at": "2026-07-11T00:01:00Z",
        "key_id": "key-1",
        "audit_anchor": "b" * 64,
        "idempotency_key": "op-1",
    }
    missing = dict(valid)
    missing.pop("key_id")
    with pytest.raises(ValueError, match="complete nonempty"):
        _issue_server_managed_bundle(**missing)
    extra = dict(valid, unexpected="x")
    with pytest.raises(ValueError, match="complete nonempty"):
        _issue_server_managed_bundle(**extra)
    same_party = dict(valid, validator="authority")
    with pytest.raises(ValueError, match="distinct"):
        _issue_server_managed_bundle(**same_party)
    too_long = dict(valid, expires_at="2026-07-11T00:06:00Z")
    with pytest.raises(ValueError, match="bounded"):
        _issue_server_managed_bundle(**too_long)


def test_inert_stub_has_no_provider_executor_or_persistence_callback_surface() -> None:
    counters = {name: 0 for name in ("provider", "executor", "consumption", "outbox", "external")}

    def callback(name: str) -> None:
        counters[name] += 1

    with pytest.raises(TypeError, match="unexpected keyword"):
        managed_contract_stub(
            "agent.register/v1",
            {"name": "x"},
            _server_bundle(),
            decision="ALLOW",
            providers=lambda: callback("provider"),  # type: ignore[call-arg]
            executor=lambda: callback("executor"),
            consumption=lambda: callback("consumption"),
            outbox=lambda: callback("outbox"),
            external=lambda: callback("external"),
        )
    assert counters == {name: 0 for name in counters}


def test_jcs_compatible_constrained_canonical_json_golden_vectors() -> None:
    # RFC 8785 orders property names by UTF-16 code units, not Unicode scalar value.
    assert _canonical_json_subset({"\ue000": 1, "\U00010000": 2}) == (
        '{"\U00010000":2,"\ue000":1}'.encode()
    )
    assert _canonical_json_subset({"s": '\b\t\n\f\r"\\\x00'}) == (
        b'{"s":"\\b\\t\\n\\f\\r\\"\\\\\\u0000"}'
    )
    assert _canonical_json_subset({"n": 9_007_199_254_740_991}) == (b'{"n":9007199254740991}')
    for unsafe in (9_007_199_254_740_992, -9_007_199_254_740_992):
        with pytest.raises(ValueError, match="safe domain"):
            _canonical_json_subset({"n": unsafe})
    for unsupported in (0.0, -0.0, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="rejects floats"):
            _canonical_json_subset({"n": unsupported})

    class SneakyDict(dict[str, Any]):
        pass

    class SneakyList(list[Any]):
        pass

    with pytest.raises(ValueError, match="subclasses"):
        _canonical_json_subset(SneakyDict(name="x"))
    with pytest.raises(ValueError, match="subclasses"):
        _canonical_json_subset({"configuration": SneakyList([1])})


def test_managed_contract_hashes_the_exact_canonical_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {"name": "agent", "configuration": {"\ue000": 1, "\U00010000": 2}}
    expected = _canonical_json_subset(body)
    captured: list[bytes] = []
    original_sha256 = governance_module.hashlib.sha256

    def capture(data: bytes = b"") -> Any:
        captured.append(data)
        return original_sha256(data)

    monkeypatch.setattr(governance_module.hashlib, "sha256", capture)
    with pytest.raises(ProductionPostureBlocked):
        managed_contract_stub("agent.register/v1", body, _server_bundle(), decision="ALLOW")
    assert captured == [expected]


def test_read_audit_snapshot_survives_path_replacement_without_reading_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "audit"
    root.mkdir()
    path = root / "org.audit.jsonl"
    safe = b'{"safe":true}\n'
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b'{"outside_secret":true}\n')
    path.write_bytes(safe)
    original_read = governance_module.os.read
    replaced = {"done": False}

    def replace_then_read(fd: int, size: int) -> bytes:
        if not replaced["done"]:
            replaced["done"] = True
            path.rename(root / "opened-original.jsonl")
            path.symlink_to(outside)
        return original_read(fd, size)

    monkeypatch.setattr(governance_module.os, "read", replace_then_read)
    snapshot = existing_org_audit_store(root, "org")
    assert snapshot is not None
    assert snapshot.raw == safe
    assert b"outside_secret" not in snapshot.raw
