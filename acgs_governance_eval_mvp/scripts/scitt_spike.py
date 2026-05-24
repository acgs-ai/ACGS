"""SCITT receipt-format feasibility spike (1-day).

Wraps a realistic ACGS ``ChainHashAuditStore`` audit event in a
COSE_Sign1 envelope (RFC 8152) signed with Ed25519 (alg=-8), decodes
it, verifies the signature, and asserts payload round-trip equality.

Hand-rolled on cbor2 + cryptography because ``pycose`` is not
installed and Python 3.14.4 in this venv has known pydantic-v1
incompatibilities that block fresh installs. The COSE_Sign1
serialization here follows RFC 8152 sec. 4.2 strictly enough for a
round-trip; production use would still want a vetted library.

Run: ``python scripts/scitt_spike.py``
"""

from __future__ import annotations

import json
import sys
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# COSE algorithm + header constants (RFC 8152 / IANA COSE registry).
COSE_ALG_EDDSA = -8
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_SIGN1_TAG = 18


def build_sample_event() -> dict[str, Any]:
    """Hand-built event mirroring ChainHashAuditStore on-disk shape.

    Includes nonce_consumed + authorization_trace with one signed hop,
    so the round-trip exercises every nested-dict shape ACGS emits.
    All scalar leaves are str/int/bool/None -- matching what sha256_json
    actually produces today.
    """
    return {
        "decision_id": "01J3X8K7N9V2QH7B5D6Z4Y0M8R",
        "timestamp": "2026-05-24T12:34:56+00:00",
        "tenant": "default",
        "actor_id": "codex:gpt-5",
        "action_type": "governance.receipt.verify",
        "resource": "wf:nightly-eval",
        "allow": True,
        "reason": "policy-allow",
        "nonce_consumed": {
            "trace_id": "trace-7f3e",
            "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        },
        "authorization_trace": {
            "version": "hop-sig/v1",
            "trace_id": "trace-7f3e",
            "trace_hash": "sha256:abc123def456",
            "principal_chain": ["codex:gpt-5", "tool:eval-runner"],
            "hops": [
                {
                    "principal_id": "tool:eval-runner",
                    "role": "implementation-agent",
                    "tenant": "default",
                    "delegator_id": "codex:gpt-5",
                    "delegated_at": "2026-05-24T12:34:50+00:00",
                    "not_after": "2026-05-24T13:34:50+00:00",
                    "delegation_evidence_hash": "sha256:delegation-evidence",
                    "signature": "MEUCIQDxxx...padding",
                    "public_key_kid": "kid-eval-runner-1",
                },
            ],
        },
        "previous_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "event_hash": "sha256:9b1d4f0e2c8a47b56e3f1d2c9a8b7e6d5c4b3a2918f0e1d2c3b4a59687d6c5b4",
    }


def cose_sign1_encode(
    payload: dict[str, Any],
    priv: Ed25519PrivateKey,
    kid: bytes,
) -> bytes:
    """Encode a payload dict as a tagged COSE_Sign1 message.

    Structure (RFC 8152 sec. 4.2):
        Sig_structure = ["Signature1", protected, external_aad, payload]
        COSE_Sign1    = [protected, unprotected, payload, signature]
        Tagged with CBOR tag 18.
    """
    protected_map = {COSE_HEADER_ALG: COSE_ALG_EDDSA}
    protected = cbor2.dumps(protected_map)
    unprotected = {COSE_HEADER_KID: kid}
    payload_bytes = cbor2.dumps(payload)
    external_aad = b""

    sig_structure = ["Signature1", protected, external_aad, payload_bytes]
    to_be_signed = cbor2.dumps(sig_structure)
    signature = priv.sign(to_be_signed)

    sign1 = [protected, unprotected, payload_bytes, signature]
    return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, sign1))


def cose_sign1_decode_and_verify(
    envelope: bytes,
    pub: Ed25519PublicKey,
) -> dict[str, Any]:
    """Decode + verify a COSE_Sign1 envelope; return the payload dict."""
    tagged = cbor2.loads(envelope)
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != COSE_SIGN1_TAG:
        raise ValueError(f"expected CBOR tag {COSE_SIGN1_TAG}, got {tagged!r}")
    protected, unprotected, payload_bytes, signature = tagged.value

    protected_map = cbor2.loads(protected) if protected else {}
    alg = protected_map.get(COSE_HEADER_ALG)
    if alg != COSE_ALG_EDDSA:
        raise ValueError(f"expected alg=EdDSA ({COSE_ALG_EDDSA}), got {alg!r}")

    sig_structure = ["Signature1", protected, b"", payload_bytes]
    to_be_signed = cbor2.dumps(sig_structure)
    pub.verify(signature, to_be_signed)  # raises InvalidSignature on failure
    _ = unprotected  # kid available; not used for verification in this spike

    return cbor2.loads(payload_bytes)


def main() -> int:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = b"scitt-spike-key-1"

    original = build_sample_event()

    try:
        envelope = cose_sign1_encode(original, priv, kid)
    except Exception as exc:  # noqa: BLE001
        print(f"SCITT spike: round-trip FAIL -- encode raised {exc!r}")
        return 1

    try:
        decoded = cose_sign1_decode_and_verify(envelope, pub)
    except InvalidSignature:
        print("SCITT spike: round-trip FAIL -- signature did not verify")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"SCITT spike: round-trip FAIL -- decode raised {exc!r}")
        return 1

    # Compare via JSON serialization to mirror sha256_json semantics.
    orig_json = json.dumps(original, sort_keys=True, default=str)
    decoded_json = json.dumps(decoded, sort_keys=True, default=str)

    print(f"envelope size: {len(envelope)} bytes")
    print(f"payload keys : {sorted(original.keys())}")
    print(f"alg          : EdDSA (-8), kid={kid.decode()}")

    if orig_json == decoded_json:
        print(
            "SCITT spike: round-trip PASS -- "
            "ACGS event survives COSE_Sign1 (EdDSA/Ed25519) cleanly"
        )
        return 0

    # Find the first drifting field for a useful PARTIAL message.
    drift_field = "<unknown>"
    for key in sorted(original.keys()):
        if json.dumps(original.get(key), sort_keys=True, default=str) != json.dumps(
            decoded.get(key), sort_keys=True, default=str
        ):
            drift_field = key
            break
    print(
        "SCITT spike: round-trip PARTIAL -- "
        f"payload drift detected at field '{drift_field}'"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
