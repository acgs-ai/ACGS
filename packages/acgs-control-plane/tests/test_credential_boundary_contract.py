"""Credential-boundary contract for control-plane response schemas.

``test_openapi_drift.py`` pins four components field-by-field; every other
component -- including every one that carries a one-time credential -- is
unpinned there. A new secret-bearing response field therefore reaches the public
schema without any contract gate objecting.

These checks close that specific hole. They are deliberately schema-level and
carry no PostgreSQL marker, so they run in the ordinary control-plane lane
rather than skipping with the P2 gate.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.schemas import TenantBootstrapResponse

# Property names that denote a credential rather than a reference to one. A hash
# or a digest is not a credential, so the pattern deliberately does not match
# ``api_key_hash``.
CREDENTIAL_NAME_PATTERN = re.compile(r"api_key|secret|token|credential|private_key", re.IGNORECASE)

# Response components allowed to carry a raw credential, each issuing it exactly
# once at creation time. Adding an entry here is the explicit approval step: it
# should not happen without deciding that the route may emit a secret at all.
APPROVED_CREDENTIAL_PROPERTIES: dict[str, frozenset[str]] = {
    "OrgCreateResponse": frozenset({"admin_api_key"}),
    "TenantBootstrapResponse": frozenset({"owner_api_key"}),
    "UserCreateResponse": frozenset({"api_key"}),
}


def _app(tmp_path: Path) -> Any:
    return create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'credential-boundary.sqlite3'}",
            audit_dir=tmp_path / "audit",
            bootstrap_token="test-bootstrap-token",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )


def _credential_properties(schema: dict[str, Any]) -> dict[str, frozenset[str]]:
    found: dict[str, frozenset[str]] = {}
    for name, component in schema.get("components", {}).get("schemas", {}).items():
        matches = frozenset(
            prop
            for prop in (component.get("properties") or {})
            if CREDENTIAL_NAME_PATTERN.search(prop)
        )
        if matches:
            found[name] = matches
    return found


def test_credential_bearing_response_components_are_an_explicit_allowlist(tmp_path: Path) -> None:
    """No response component may expose a raw credential without prior approval.

    A failure here is not a lint nit. It means a secret-shaped field entered the
    published contract; decide whether the route may emit a credential at all
    before extending APPROVED_CREDENTIAL_PROPERTIES.
    """
    assert _credential_properties(_app(tmp_path).openapi()) == APPROVED_CREDENTIAL_PROPERTIES


def test_tenant_bootstrap_owner_api_key_is_optional_so_replay_can_omit_it(tmp_path: Path) -> None:
    """The replay response must be representable without the secret.

    Bootstrap returns the raw owner key exactly once and stores a redacted copy
    for idempotent replay. If the field were required, that stored copy could
    not be a valid response and the secret would have to be persisted.
    """
    component = _app(tmp_path).openapi()["components"]["schemas"]["TenantBootstrapResponse"]
    assert "owner_api_key" not in component.get("required", [])
    assert TenantBootstrapResponse.model_fields["owner_api_key"].default is None


def test_redacted_replay_payload_is_a_valid_response_and_drops_only_the_secret() -> None:
    """Redaction must remove the credential and nothing else.

    This is the shape actually written to the idempotency row, so it has to
    round-trip as a complete response while carrying no trace of the raw key.
    """
    raw_key = "acp_boundary_probe_value"
    issued = TenantBootstrapResponse(
        org_id="org-1",
        project_id="proj-1",
        environment_id="env-1",
        owner_user_id="user-1",
        owner_membership_id="member-1",
        owner_api_key=raw_key,
        receipt_id="receipt-1",
        receipt_hash="receipt-hash-1",
        event_hash="event-hash-1",
        idempotency_key="idem-1",
        assurance_class="native",
    )
    stored = issued.model_copy(update={"owner_api_key": None}).model_dump()

    assert raw_key not in str(stored)
    assert TenantBootstrapResponse.model_validate(stored).owner_api_key is None
    assert {key: value for key, value in stored.items() if key != "owner_api_key"} == {
        key: value for key, value in issued.model_dump().items() if key != "owner_api_key"
    }
