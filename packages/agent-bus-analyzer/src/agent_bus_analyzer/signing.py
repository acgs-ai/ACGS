"""Evidence-packet signing helpers.

The analyzer cannot depend on deployment-specific KMS clients, but the packet
format must be ready for managed signing material. This module uses stdlib HMAC
with environment-supplied key material as the portable local/deployment
contract:

- ``ACGS_EVIDENCE_SIGNING_KEY_ID``: non-secret key/version identifier.
- ``ACGS_EVIDENCE_SIGNING_SECRET``: secret signing material.
- ``ACGS_EVIDENCE_SIGNING_REQUIRED``: when truthy, missing/partial material
  fails closed instead of emitting an unsigned local digest.

Unsigned mode is explicit and suitable only for local/dev evidence. It must not
be described as a production signature.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from agent_bus_analyzer.errors import IntegrityStoreUnavailable
from agent_bus_analyzer.hashing import canonical_json

_TRUTHY = {"1", "true", "yes", "on", "required"}


def _signing_required() -> bool:
    return os.getenv("ACGS_EVIDENCE_SIGNING_REQUIRED", "").strip().lower() in _TRUTHY


def _payload_without_signature(packet: dict[str, Any]) -> dict[str, Any]:
    payload = dict(packet)
    payload.pop("export_signature", None)
    return payload


def _payload_bytes(packet: dict[str, Any]) -> bytes:
    return canonical_json(_payload_without_signature(packet)).encode("utf-8")


def sign_evidence_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *packet* with an explicit ``export_signature`` block.

    If both key id and secret are set, the signature is an HMAC-SHA256 over the
    canonical JSON packet excluding ``export_signature`` itself. If neither is
    set and signing is not required, a local digest is attached instead.

    Partial signing configuration or required-signing-without-material fails
    closed so deploys cannot silently downgrade from signed evidence to digest
    evidence.
    """
    out = _payload_without_signature(packet)
    key_id = os.getenv("ACGS_EVIDENCE_SIGNING_KEY_ID")
    secret = os.getenv("ACGS_EVIDENCE_SIGNING_SECRET")
    body = _payload_bytes(out)
    digest = hashlib.sha256(body).hexdigest()

    if key_id and secret:
        out["export_signature"] = {
            "status": "signed",
            "algorithm": "HMAC-SHA256-CANONICAL-JSON",
            "key_id": key_id,
            "payload_digest": digest,
            "signature": hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest(),
        }
        return out

    if key_id or secret or _signing_required():
        raise IntegrityStoreUnavailable(
            "evidence signing material is incomplete; set both "
            "ACGS_EVIDENCE_SIGNING_KEY_ID and ACGS_EVIDENCE_SIGNING_SECRET"
        )

    out["export_signature"] = {
        "status": "unsigned-local-digest",
        "algorithm": "SHA256-CANONICAL-JSON",
        "digest": digest,
        "reason": "ACGS_EVIDENCE_SIGNING_SECRET unset",
    }
    return out


def verify_evidence_packet(packet: dict[str, Any], *, secret: str) -> bool:
    """Verify a signed packet against *secret*.

    Returns ``False`` for unsigned packets or malformed signature blocks.
    """
    signature = packet.get("export_signature")
    if not isinstance(signature, dict):
        return False
    if signature.get("status") != "signed":
        return False
    if signature.get("algorithm") != "HMAC-SHA256-CANONICAL-JSON":
        return False
    claimed_digest = signature.get("payload_digest")
    if not isinstance(claimed_digest, str):
        return False
    body = _payload_bytes(packet)
    if not hmac.compare_digest(claimed_digest, hashlib.sha256(body).hexdigest()):
        return False
    claimed = signature.get("signature")
    if not isinstance(claimed, str):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(claimed, expected)
