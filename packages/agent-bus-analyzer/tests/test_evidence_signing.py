"""Evidence packet signing contract tests.

The analyzer's downloadable receipt proof must distinguish local canonical
digests from deployment-managed signatures. Deployment mode uses stdlib HMAC so
the contract is testable without adding cryptography dependencies.
"""

from __future__ import annotations

import pytest

from agent_bus_analyzer.errors import IntegrityStoreUnavailable
from agent_bus_analyzer.signing import sign_evidence_packet, verify_evidence_packet


def _packet() -> dict[str, object]:
    return {
        "kind": "receipt-proof-export",
        "receipt_id": "rcpt-1",
        "receipt_hash": "a" * 64,
        "event_hashes": ["b" * 64],
    }


def test_evidence_packet_uses_deployment_managed_hmac_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_KEY_ID", "bus-signer-v1")
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_SECRET", "deploy-secret-material")

    signed = sign_evidence_packet(_packet())

    signature = signed["export_signature"]
    assert signature["status"] == "signed"
    assert signature["algorithm"] == "HMAC-SHA256-CANONICAL-JSON"
    assert signature["key_id"] == "bus-signer-v1"
    assert isinstance(signature["signature"], str)
    assert verify_evidence_packet(signed, secret="deploy-secret-material") is True


def test_verification_rejects_tampered_payload_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_KEY_ID", "bus-signer-v1")
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_SECRET", "deploy-secret-material")

    signed = sign_evidence_packet(_packet())
    signature = signed["export_signature"]
    assert isinstance(signature, dict)
    signature["payload_digest"] = "0" * 64

    assert verify_evidence_packet(signed, secret="deploy-secret-material") is False


def test_unsigned_local_digest_is_explicit_when_signing_material_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_KEY_ID", raising=False)
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_REQUIRED", raising=False)

    signed = sign_evidence_packet(_packet())

    signature = signed["export_signature"]
    assert signature == {
        "status": "unsigned-local-digest",
        "algorithm": "SHA256-CANONICAL-JSON",
        "digest": signature["digest"],
        "reason": "ACGS_EVIDENCE_SIGNING_SECRET unset",
    }


def test_required_signing_fails_closed_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_REQUIRED", "true")
    monkeypatch.setenv("ACGS_EVIDENCE_SIGNING_KEY_ID", "bus-signer-v1")
    monkeypatch.delenv("ACGS_EVIDENCE_SIGNING_SECRET", raising=False)

    with pytest.raises(IntegrityStoreUnavailable, match="signing material"):
        sign_evidence_packet(_packet())
