"""Design tests #23, #24, and custom-kwarg for clock_skew_tolerance.

Tests verify that ``verify_hop_against_entry`` correctly applies the
60-second default clock-skew window and respects a caller-supplied
override via the ``clock_skew_tolerance`` kwarg.

See ``governance/crypto/hop_verify.py`` §check 7 and ADR-0007 §10.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from governance.crypto.hop_signature import sign_hop  # noqa: E402
from governance.crypto.hop_verify import (  # noqa: E402
    CLOCK_SKEW_TOLERANCE,
    HopVerificationError,
    verify_hop_against_entry,
)
from governance.crypto.principal_keys import KeyEntry  # noqa: E402


def _now() -> datetime:
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def _make_key_entry(public_key, *, principal_id: str = "orchestrator-root", tenant: str = "default") -> KeyEntry:
    now = _now()
    return KeyEntry(
        key_id="key-1",
        public_key=public_key,
        principal_id=principal_id,
        tenant=tenant,
        issuer="acgs-root-ca",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=30),
        purposes=frozenset({"trace-delegation"}),
        revoked_at=None,
    )


def _make_payload(
    *,
    delegated_at: datetime | None = None,
    not_after: datetime,
    delegator_id: str = "orchestrator-root",
    tenant: str = "default",
) -> dict:
    now = _now()
    da = delegated_at or (now - timedelta(minutes=5))
    return {
        "alg": "Ed25519",
        "key_version": 1,
        "schema_version": "phase2-hop-v2",
        "trace_id": "trace-skew-test",
        "parent_workflow_id": None,
        "workflow_id": "workflow-skew-test",
        "evaluation_policy": "access-time",
        "hop_index": 0,
        "delegator_id": delegator_id,
        "delegatee_id": "codex:gpt-5",
        "role": "implementation-agent",
        "tenant": tenant,
        "delegated_at": da.isoformat(),
        "not_after": not_after.isoformat(),
        "delegation_evidence_hash": "sha256:skew-test",
        "action_binding": {
            "action_type": "gov.invoke",
            "tenant": tenant,
            "actor_id": "codex:gpt-5",
            "resource": "workflow-skew-test",
            "inputs_hash": "sha256:in",
            "workflow_id": "workflow-skew-test",
            "policy_version": "policy-test/v1",
            "role_version": "roles-test/v1",
            "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        },
    }


def test_hop_within_skew_tolerance_accepted() -> None:
    """Design test #23: hop expired 30 s ago is within the 60 s default tolerance."""
    assert CLOCK_SKEW_TOLERANCE == timedelta(seconds=60)
    sk = Ed25519PrivateKey.generate()
    now = _now()
    # not_after = 30 s in the past — within 60 s tolerance
    not_after = now - timedelta(seconds=30)
    payload = _make_payload(not_after=not_after)
    sig = sign_hop(sk, payload)
    entry = _make_key_entry(sk.public_key())
    # Must not raise
    verify_hop_against_entry(payload, sig, entry, now=now)


def test_hop_beyond_skew_tolerance_rejected() -> None:
    """Design test #24: hop expired 120 s ago is beyond the 60 s default tolerance."""
    assert CLOCK_SKEW_TOLERANCE == timedelta(seconds=60)
    sk = Ed25519PrivateKey.generate()
    now = _now()
    # not_after = 120 s in the past — beyond 60 s tolerance
    not_after = now - timedelta(seconds=120)
    payload = _make_payload(not_after=not_after)
    sig = sign_hop(sk, payload)
    entry = _make_key_entry(sk.public_key())
    with pytest.raises(HopVerificationError, match="hop expired"):
        verify_hop_against_entry(payload, sig, entry, now=now)


def test_custom_skew_tolerance_kwarg_respected() -> None:
    """A 5 s custom tolerance rejects a hop expired by 30 s, even though
    the 60 s default would accept it."""
    sk = Ed25519PrivateKey.generate()
    now = _now()
    # 30 s expired — would pass at 60 s default, must fail at 5 s
    not_after = now - timedelta(seconds=30)
    payload = _make_payload(not_after=not_after)
    sig = sign_hop(sk, payload)
    entry = _make_key_entry(sk.public_key())
    with pytest.raises(HopVerificationError, match="hop expired"):
        verify_hop_against_entry(payload, sig, entry, now=now, clock_skew_tolerance=timedelta(seconds=5))
