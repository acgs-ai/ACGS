"""Shared fixtures: SQLite-backed app, bootstrapped org, role helpers.

Production runs PostgreSQL; tests run the identical ORM/queries on SQLite.
Nothing here mocks the governance membrane — every test exercises the real
gove-zone kernel, policy evaluation, and audit chain on disk.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from gove_zone.signing import Ed25519Signer

from acgs_control_plane.app import NativeAgentTransactionProviders, create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.native_receipts import (
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    TenantPrivacyProvider,
)

BOOTSTRAP_TOKEN = "test-bootstrap-token"
_ISSUER_PRIVATE = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
_ATTESTOR_PRIVATE = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)


@pytest.fixture()
def bootstrap_headers() -> dict[str, str]:
    return {"X-Bootstrap-Token": BOOTSTRAP_TOKEN}


@pytest.fixture()
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit"


@pytest.fixture()
def native_agent_transaction_providers() -> NativeAgentTransactionProviders:
    issuer = Ed25519Signer.from_private_bytes(_ISSUER_PRIVATE, key_id="test-native-issuer")
    attestor = Ed25519Signer.from_private_bytes(
        _ATTESTOR_PRIVATE,
        key_id="test-native-attestor",
    )
    return NativeAgentTransactionProviders(
        receipt_trust=ManagedNativeReceiptTrust(
            signer=issuer,
            verifiers={issuer.key_id: issuer},
        ),
        consumption_trust=ManagedConsumptionAttestationTrust(
            signer=attestor,
            verifiers={attestor.key_id: attestor},
        ),
        privacy=TenantPrivacyProvider(b"shared-test-native-privacy-key-32b"),
    )


@pytest.fixture()
def client(
    tmp_path: Path,
    audit_dir: Path,
    native_agent_transaction_providers: NativeAgentTransactionProviders,
) -> TestClient:
    database_url = f"sqlite:///{tmp_path / 'acp.sqlite3'}"
    upgrade_database(database_url)
    settings = Settings(
        database_url=database_url,
        audit_dir=audit_dir,
        bootstrap_token=BOOTSTRAP_TOKEN,
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
    )
    app = create_app(settings, native_agent_transaction=native_agent_transaction_providers)
    # raise_server_exceptions=False: policy DENY/ESCALATE map to HTTP via
    # exception handlers; tests assert status codes, not tracebacks.
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def org(client: TestClient) -> dict[str, Any]:
    """A bootstrapped org: {org_id, name, admin_user_id, admin_api_key}."""
    resp = client.post(
        "/orgs",
        json={
            "name": "Acme AI",
            "admin_name": "Root Admin",
            "admin_email": "root@acme.example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.fixture()
def admin_headers(org: dict[str, Any]) -> dict[str, str]:
    return {"X-API-Key": org["admin_api_key"]}


@pytest.fixture()
def make_user(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> Callable[[str], dict[str, str]]:
    """Create a user with the given role; returns auth headers for that user."""

    counter = {"n": 0}

    def _make(role: str) -> dict[str, str]:
        counter["n"] += 1
        resp = client.post(
            f"/orgs/{org['org_id']}/users",
            json={
                "name": f"{role} user",
                "email": f"{role}{counter['n']}@acme.example.com",
                "role": role,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 201, resp.text
        return {"X-API-Key": resp.json()["api_key"]}

    return _make


@pytest.fixture()
def publish_and_activate(client: TestClient) -> Callable[..., dict[str, Any]]:
    def _run(
        org_id: str,
        headers: dict[str, str],
        rules: list[dict[str, Any]],
        policy_id: str = "org-governance",
    ) -> dict[str, Any]:
        resp = client.post(
            f"/orgs/{org_id}/policies",
            json={"policy_id": policy_id, "rules": rules},
            headers=headers,
        )
        assert resp.status_code == 201, resp.text
        bundle = resp.json()
        resp = client.post(
            f"/orgs/{org_id}/policies/{bundle['bundle_id']}/activate", headers=headers
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    return _run
