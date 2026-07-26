"""Compliance export: hash manifest, recomputation, tamper evidence."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json
from gove_zone.receipt import DecisionReceipt

from acgs_control_plane.exports import verify_export_bundle
from acgs_control_plane.native_receipts import (
    ManagedNativeReceiptTrust,
    NativeReceiptContext,
)


def test_export_bundle_is_verifiable_and_complete(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    client.post(f"/orgs/{org_id}/agents", json={"name": "bot-a"}, headers=admin_headers)
    client.post(
        f"/orgs/{org_id}/policies",
        json={"policy_id": "p1", "rules": [{"id": "r1", "effect": "deny", "tools": ["x"]}]},
        headers=admin_headers,
    )

    created = client.post(
        f"/orgs/{org_id}/exports", json={"note": "annual audit"}, headers=admin_headers
    )
    assert created.status_code == 201, created.text
    summary = created.json()
    assert summary["receipt_id"]  # the export itself was a governed action
    assert summary["receipt_count"] == 3  # org.create + policy.publish + native agent create

    detail = client.get(
        f"/orgs/{org_id}/exports/{summary['export_id']}", headers=admin_headers
    ).json()
    bundle = detail["bundle"]
    assert bundle["schema"] == "acgs-control-plane/export/v1"
    assert bundle["note"] == "annual audit"
    sections = bundle["sections"]
    assert len(sections["receipts"]) == 2
    assert len(sections["native_receipts"]) == 1
    assert sections["native_receipts"][0]["assurance_class"] == "native"
    assert sections["native_receipts"][0]["source_system"] == "gove-zone"
    assert sections["native_receipts"][0]["tool"] == "database.agent.create"
    assert len(sections["native_governance_chain"]["events"]) == 1
    assert len(sections["native_consumptions"]) == 1
    assert len(sections["agents"]) == 1
    assert len(sections["policies"]) == 1
    assert sections["audit_chain"]["event_count"] == len(sections["audit_chain"]["events"])

    # Manifest recomputes cleanly with gove-zone's canonical hashing.
    check = verify_export_bundle(bundle)
    assert check == {"valid": True, "section_mismatches": [], "bundle_hash_ok": True}


def test_export_native_evidence_is_sufficient_for_offline_verification(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    native_agent_transaction_providers: Any,
) -> None:
    org_id = org["org_id"]
    created_agent = client.post(
        f"/orgs/{org_id}/agents", json={"name": "offline-native-bot"}, headers=admin_headers
    )
    assert created_agent.status_code == 201, created_agent.text

    created_export = client.post(
        f"/orgs/{org_id}/exports", json={"note": "native offline"}, headers=admin_headers
    )
    assert created_export.status_code == 201, created_export.text
    bundle = client.get(
        f"/orgs/{org_id}/exports/{created_export.json()['export_id']}",
        headers=admin_headers,
    ).json()["bundle"]

    sections = bundle["sections"]
    native_receipts = sections["native_receipts"]
    chain = sections["native_governance_chain"]
    consumptions = sections["native_consumptions"]
    assert len(native_receipts) == 1
    assert len(chain["events"]) == 1
    assert len(consumptions) == 1

    event = chain["events"][0]
    head = chain["head"]
    assert head["last_sequence"] == 1
    assert head["last_event_hash"] == event["event_hash"]
    payload = dict(event["payload"])
    claimed_hash = payload.pop("event_hash")
    assert claimed_hash == event["event_hash"]
    assert event["previous_hash"] == GENESIS_HASH
    assert payload["previous_hash"] == GENESIS_HASH
    assert sha256_json(payload) == event["event_hash"]

    native = native_receipts[0]
    assert native["assurance_class"] == "native"
    assert native["source_system"] == "gove-zone"
    assert native["audit_event_hash"] == event["event_hash"]
    assert "args" not in native["projection"]
    assert "args" not in native["receipt_artifact"]
    receipt = DecisionReceipt.from_dict(native["receipt_artifact"])
    context = NativeReceiptContext(
        org_id=org_id,
        execution_boundary=native["projection"]["execution_boundary"],
        actor=native["projection"]["actor"],
        action=native["projection"]["proposed_action"],
        policy_bundle_id=native["projection"]["policy_bundle_id"],
        policy_hash=native["projection"]["policy_hash"],
        audit_hash=native["audit_event_hash"],
        args=None,
        validator_role=native["projection"]["validator_role"],
        authority=native["projection"]["authority"],
    )
    trust = native_agent_transaction_providers.receipt_trust
    assert isinstance(trust, ManagedNativeReceiptTrust)
    trust.verify_historical(receipt, context)

    consumption = consumptions[0]
    assert consumption["native_receipt_id"] == native["native_receipt_row_id"]
    assert consumption["receipt_hash"] == native["receipt_hash"]
    assert consumption["audit_event_hash"] == native["audit_event_hash"]
    native_agent_transaction_providers.consumption_trust.verify(
        consumption["attestation_artifact"],
        artifact_hash=consumption["attestation_artifact_hash"],
        algorithm=consumption["attestation_signature_algorithm"],
        key_id=consumption["attestation_signing_key_id"],
        signature=consumption["attestation_signature"],
    )
    assert consumption["attestation_artifact"]["receipt_id"] == native["receipt_id"]
    assert consumption["attestation_artifact"]["audit_event_hash"] == native["audit_event_hash"]


def test_export_tamper_is_detected(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    summary = client.post(
        f"/orgs/{org_id}/exports", json={"note": ""}, headers=admin_headers
    ).json()
    bundle = client.get(
        f"/orgs/{org_id}/exports/{summary['export_id']}", headers=admin_headers
    ).json()["bundle"]

    bundle["sections"]["receipts"][0]["decision"] = "allow-forged"
    check = verify_export_bundle(bundle)
    assert check["valid"] is False
    assert "receipts" in check["section_mismatches"]


def test_export_receipt_recorded_after_bundle(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    """The export's own receipt postdates the bundle, so it appears in the
    NEXT export — evidence chains forward, never self-references."""
    org_id = org["org_id"]
    first = client.post(
        f"/orgs/{org_id}/exports", json={"note": "first"}, headers=admin_headers
    ).json()
    second = client.post(
        f"/orgs/{org_id}/exports", json={"note": "second"}, headers=admin_headers
    ).json()
    bundle = client.get(
        f"/orgs/{org_id}/exports/{second['export_id']}", headers=admin_headers
    ).json()["bundle"]
    receipt_ids = {r["event_id"] for r in bundle["sections"]["receipts"]}
    assert first["receipt_id"] in receipt_ids
