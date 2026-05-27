"""Hop verification that binds a signed payload to a KeyEntry.

Covers design-doc tests #1-#9 and #19 (TTL bound).
See `docs/design/phase2-trace-crypto.md` §verification path
and ADR-0007 §5, §6.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _imports():
    from governance.crypto.hop_signature import sign_hop
    from governance.crypto.hop_verify import (
        MAX_TRACE_TTL_DEFAULT,
        HopVerificationError,
        verify_hop_against_entry,
    )
    from governance.crypto.principal_keys import KeyEntry

    return (
        sign_hop,
        verify_hop_against_entry,
        HopVerificationError,
        KeyEntry,
        MAX_TRACE_TTL_DEFAULT,
    )


def _now():
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def _payload(
    *,
    delegator_id="orchestrator-root",
    tenant="default",
    delegated_at=None,
    not_after=None,
):
    delegated_at = delegated_at or _now() - timedelta(minutes=1)
    not_after = not_after or _now() + timedelta(hours=1)
    return {
        "alg": "Ed25519",
        "key_version": 1,
        "schema_version": "phase2-hop-v2",
        "trace_id": "trace-1",
        "parent_workflow_id": None,
        "workflow_id": "workflow-1",
        "evaluation_policy": "access-time",
        "hop_index": 0,
        "delegator_id": delegator_id,
        "delegatee_id": "codex:gpt-5",
        "role": "implementation-agent",
        "tenant": tenant,
        "delegated_at": delegated_at.isoformat(),
        "not_after": not_after.isoformat(),
        "delegation_evidence_hash": "sha256:root",
        "action_binding": {
            "action_type": "gov.invoke",
            "tenant": tenant,
            "actor_id": "codex:gpt-5",
            "resource": "workflow-1",
            "inputs_hash": "sha256:in",
            "workflow_id": "workflow-1",
            "policy_version": "policy-test/v1",
            "role_version": "roles-test/v1",
            "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        },
    }


def _key_entry(
    KeyEntry,
    public_key,
    *,
    principal_id="orchestrator-root",
    tenant="default",
    purposes=frozenset({"trace-delegation"}),
    valid_from=None,
    valid_to=None,
    revoked_at=None,
):
    return KeyEntry(
        key_id="key-1",
        public_key=public_key,
        principal_id=principal_id,
        tenant=tenant,
        issuer="acgs-root-ca",
        valid_from=valid_from or (_now() - timedelta(days=1)),
        valid_to=valid_to or (_now() + timedelta(days=30)),
        purposes=purposes,
        revoked_at=revoked_at,
    )


def test_valid_hop_with_matching_entry_passes():
    sign_hop, verify, _, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    payload = _payload()
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key())
    verify(payload, sig, entry)


def test_signature_required_raises_on_bad_bytes():
    _, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    entry = _key_entry(KeyEntry, sk.public_key())
    with pytest.raises(HopVerificationError):
        verify(_payload(), b"not-a-valid-signature", entry)


def test_key_principal_id_must_match_delegator():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    payload = _payload(delegator_id="orchestrator-root")
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key(), principal_id="someone-else")
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_cross_tenant_key_rejected():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    payload = _payload(tenant="tenant-a")
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key(), tenant="tenant-b")
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_purpose_must_include_trace_delegation():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    payload = _payload()
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key(), purposes=frozenset({"policy-sign"}))
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_key_validity_window_enforced():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    # delegated 2 days before key validity window starts
    delegated_at = _now() - timedelta(days=2)
    payload = _payload(
        delegated_at=delegated_at,
        not_after=delegated_at + timedelta(hours=1),
    )
    sig = sign_hop(sk, payload)
    entry = _key_entry(
        KeyEntry,
        sk.public_key(),
        valid_from=_now() - timedelta(hours=1),
        valid_to=_now() + timedelta(days=30),
    )
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_key_revocation_enforced():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    # key was revoked 30 minutes ago; hop delegated 1 minute ago
    payload = _payload()
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key(), revoked_at=_now() - timedelta(minutes=30))
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_hop_expired_not_after_in_past_raises():
    sign_hop, verify, HopVerificationError, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    # not_after 2 minutes in the past (well beyond default 60s skew tolerance)
    delegated_at = _now() - timedelta(minutes=5)
    payload = _payload(delegated_at=delegated_at, not_after=_now() - timedelta(minutes=2))
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key())
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_ttl_bound_enforced():
    """`not_after - delegated_at` must be <= MAX_TRACE_TTL.
    Default MAX_TRACE_TTL is 24h; 48h hop window must raise."""
    sign_hop, verify, HopVerificationError, KeyEntry, MAX_TRACE_TTL_DEFAULT = _imports()
    assert MAX_TRACE_TTL_DEFAULT == timedelta(hours=24)
    sk = Ed25519PrivateKey.generate()
    delegated_at = _now() - timedelta(minutes=1)
    payload = _payload(
        delegated_at=delegated_at,
        not_after=delegated_at + timedelta(hours=48),
    )
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key())
    with pytest.raises(HopVerificationError):
        verify(payload, sig, entry)


def test_clock_skew_tolerance_accepts_slightly_expired_hop():
    """A hop whose not_after is within CLOCK_SKEW_TOLERANCE of now
    is accepted (the clock might be a little ahead)."""
    sign_hop, verify, _, KeyEntry, _ = _imports()
    sk = Ed25519PrivateKey.generate()
    delegated_at = _now() - timedelta(minutes=2)
    # not_after only 30s in the past — within default 60s tolerance
    payload = _payload(delegated_at=delegated_at, not_after=_now() - timedelta(seconds=30))
    sig = sign_hop(sk, payload)
    entry = _key_entry(KeyEntry, sk.public_key())
    verify(payload, sig, entry)
