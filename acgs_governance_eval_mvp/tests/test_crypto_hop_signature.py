"""Phase 2 hop-signature primitives.

See `docs/design/phase2-trace-crypto.md` §algorithm and ADR-0007 §1.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _imports():
    from governance.crypto.hop_signature import (
        DOMAIN_TAG_HOP,
        HopSignatureError,
        sign_hop,
        verify_hop,
    )

    return DOMAIN_TAG_HOP, sign_hop, verify_hop, HopSignatureError


def _payload(**overrides):
    base = {
        "alg": "Ed25519",
        "key_version": 1,
        "schema_version": "phase2-hop-v2",
        "trace_id": "trace-1",
        "parent_workflow_id": None,
        "workflow_id": "workflow-1",
        "evaluation_policy": "access-time",
        "hop_index": 0,
        "delegator_id": "orchestrator-root",
        "delegatee_id": "codex:gpt-5",
        "role": "implementation-agent",
        "tenant": "default",
        "delegated_at": "2026-05-23T00:00:00+00:00",
        "not_after": "2026-05-24T00:00:00+00:00",
        "delegation_evidence_hash": "sha256:root",
        "action_binding": {
            "action_type": "gov.invoke",
            "tenant": "default",
            "actor_id": "codex:gpt-5",
            "resource": "workflow-1",
            "inputs_hash": "sha256:in",
            "workflow_id": "workflow-1",
            "policy_version": "policy-test/v1",
            "role_version": "roles-test/v1",
            "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        },
    }
    base.update(overrides)
    return base


def test_domain_tag_is_versioned_v2():
    DOMAIN_TAG_HOP, *_ = _imports()
    assert DOMAIN_TAG_HOP == b"ACGS.AuthorizationTrace.Hop.v2\x00"


def test_sign_then_verify_round_trip():
    _, sign_hop, verify_hop, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    payload = _payload()
    sig = sign_hop(sk, payload)
    # round-trip must succeed (no raise)
    verify_hop(sk.public_key(), payload, sig)


def test_verify_rejects_wrong_key():
    _, sign_hop, verify_hop, HopSignatureError = _imports()
    sk = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate().public_key()
    sig = sign_hop(sk, _payload())
    with pytest.raises(HopSignatureError):
        verify_hop(other, _payload(), sig)


def test_verify_rejects_tampered_payload():
    _, sign_hop, verify_hop, HopSignatureError = _imports()
    sk = Ed25519PrivateKey.generate()
    sig = sign_hop(sk, _payload(delegatee_id="codex:gpt-5"))
    tampered = _payload(delegatee_id="attacker:agent")
    with pytest.raises(HopSignatureError):
        verify_hop(sk.public_key(), tampered, sig)


def test_verify_rejects_wrong_domain_tag():
    """A signature produced over the canonical payload WITHOUT the v2
    tag must not verify under the v2 tag. Closes cross-protocol
    signature reuse."""
    _, _, verify_hop, HopSignatureError = _imports()
    sk = Ed25519PrivateKey.generate()
    from governance.crypto.canonical import canonical_bytes

    bare_bytes = canonical_bytes(_payload())
    bare_sig = sk.sign(bare_bytes)  # no domain tag
    with pytest.raises(HopSignatureError):
        verify_hop(sk.public_key(), _payload(), bare_sig)


def test_signatures_are_deterministic():
    """Ed25519 is deterministic; canonicalizer is deterministic;
    therefore signatures are byte-stable across calls."""
    _, sign_hop, _, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    a = sign_hop(sk, _payload())
    b = sign_hop(sk, _payload())
    assert a == b


def test_sign_hop_rejects_uncanonicalizable_payload():
    """If the payload contains a float, signing must fail before
    producing bytes that could be reused under a stricter verifier."""
    _, sign_hop, _, _ = _imports()
    from governance.crypto.canonical import CanonicalizationError

    sk = Ed25519PrivateKey.generate()
    with pytest.raises(CanonicalizationError):
        sign_hop(sk, _payload(key_version=1.0))  # float instead of int
