"""Phase 2 signed-trace verification suite.

Covers the AuthorizationTrace.from_dict key-store-enabled verification
path (per docs/design/phase2-trace-crypto.md §verification path).

Maps to design test plan:
- #10  test_chain_continuity_broken
- #11  test_chain_root_reserved_at_index_0
- #12  test_action_binding_each_field_mismatch (parametrized over 8 fields)
- #18  test_full_round_trip_signed
- #1   test_action_binding_required_on_wire (Phase 2 field presence)
- (chain-shape invariants — duplicate hop_index, duplicate principal_id)
- (key-store coverage — unknown signing_key_id)

The hop-level signature/identity/tenant/purpose/validity/revocation/
TTL checks are already covered at the primitive layer in
test_crypto_hop_verify.py (design tests #2-#9, #19).
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from _phase2_helpers import HopSpec, mint_signed_trace  # noqa: E402
from governance.models import (  # noqa: E402
    AuthorizationTrace,
    AuthorizationTraceIntegrityError,
    LegacyUnsignedTraceError,
)


def _two_hop(tmp_path):
    return mint_signed_trace(
        tmp_path,
        hops=[
            HopSpec(principal_id="codex:gpt-5", role="implementation-agent"),
            HopSpec(principal_id="codex:gpt-5-worker", role="receipt-verifier"),
        ],
    )


# ----- Phase 2 field presence on the wire -----


def test_action_binding_required_on_wire(tmp_path):
    """Wire payload missing action_binding must raise (it is the
    Phase 2 wire-format requirement; trace_hash check would also catch
    this but the field-presence check fires first)."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()
    del payload["workflow_scope"]["action_binding"]

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_legacy_flat_shape_raises_value_error(tmp_path):
    """Phase-1-style flat shape (no nested workflow_scope/receipt)
    raises ValueError before any Phase 2 logic runs."""
    minted = _two_hop(tmp_path)
    trace = minted.trace
    flat = {
        "trace_id": trace.trace_id,
        "workflow_id": trace.workflow_id,
        "parent_workflow_id": None,
        "principal_chain": list(trace.principal_chain),
        "evaluation_policy": "access-time",
        "schema_version": "v1",
        "trace_hash": trace.trace_hash(),
    }
    with pytest.raises(ValueError):
        AuthorizationTrace.from_dict(flat)


def test_legacy_unsigned_payload_raises_legacy_error(tmp_path):
    """Phase-1-shape with workflow_scope but missing signatures +
    action_binding raises LegacyUnsignedTraceError specifically."""
    payload = {
        "workflow_scope": {
            "workflow_id": "wf-1",
            "parent_workflow_id": None,
            "principal_chain": [
                {
                    "principal_id": "codex:gpt-5",
                    "role": "implementation-agent",
                    "tenant": "default",
                    "delegated_at": "2026-05-22T00:00:00+00:00",
                    "delegation_evidence_hash": "sha256:x",
                }
            ],
        },
        "evaluation_policy": "access-time",
        "receipt": {
            "trace_hash": "0" * 64,
            "audit_event_hash": "0" * 64,
            "trace_id": "trace-x",
            "schema_version": "v1",
        },
    }
    with pytest.raises(LegacyUnsignedTraceError):
        AuthorizationTrace.from_dict(payload)


# ----- Action-binding tamper (design test #12) -----


@pytest.mark.parametrize(
    "field_name",
    [
        "action_type",
        "tenant",
        "actor_id",
        "resource",
        "inputs_hash",
        "workflow_id",
        "policy_version",
        "role_version",
    ],
)
def test_action_binding_each_field_mismatch_breaks_verification(tmp_path, field_name):
    """Tampering any one of the 8 non-nonce action_binding fields
    invalidates the trace_hash (the trace_hash covers action_binding)
    AND breaks per-hop signature verification (the signed hop_payload
    inlines action_binding)."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()
    payload["workflow_scope"]["action_binding"][field_name] = "tampered-value"

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload, key_store=minted.key_store)


def test_action_binding_session_nonce_tamper_breaks_verification(tmp_path):
    """The 9th binding field (session_nonce) is also covered."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()
    payload["workflow_scope"]["action_binding"]["session_nonce"] = "ZZZZZZZZZZZZZZZZZZZZZZ"
    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload, key_store=minted.key_store)


# ----- Chain continuity (design tests #10, #11) -----


def test_chain_continuity_broken_raises(tmp_path):
    """hop[1].delegator_id must equal hop[0].principal_id."""
    minted = _two_hop(tmp_path)
    chain = [dict(h) for h in minted.trace.principal_chain]
    chain[1]["delegator_id"] = "some-other-principal"
    tampered = AuthorizationTrace(
        trace_id=minted.trace.trace_id,
        workflow_id=minted.trace.workflow_id,
        parent_workflow_id=minted.trace.parent_workflow_id,
        principal_chain=tuple(chain),
        evaluation_policy=minted.trace.evaluation_policy,
        action_binding=dict(minted.trace.action_binding),
    )
    payload = tampered.to_dict()

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_chain_root_reserved_at_index_0_raises(tmp_path):
    """index 0's delegator_id must be 'orchestrator-root'."""
    minted = mint_signed_trace(
        tmp_path,
        hops=[HopSpec(principal_id="codex:gpt-5", delegator_id="not-the-root")],
    )
    payload = minted.trace.to_dict()
    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_chain_duplicate_hop_index_raises(tmp_path):
    """No two hops may share the same index. Because principal_chain
    is a list ordered by hop_index, we model duplicate index as
    duplicate principal_id (which the same check catches)."""
    minted = _two_hop(tmp_path)
    chain = [dict(h) for h in minted.trace.principal_chain]
    chain[1]["principal_id"] = chain[0]["principal_id"]
    chain[1]["delegator_id"] = chain[0]["principal_id"]
    tampered = AuthorizationTrace(
        trace_id=minted.trace.trace_id,
        workflow_id=minted.trace.workflow_id,
        parent_workflow_id=minted.trace.parent_workflow_id,
        principal_chain=tuple(chain),
        evaluation_policy=minted.trace.evaluation_policy,
        action_binding=dict(minted.trace.action_binding),
    )
    payload = tampered.to_dict()
    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_chain_duplicate_principal_raises(tmp_path):
    """Two hops sharing the same principal_id with chain-consistent
    delegator wiring is still rejected (duplicate principal in chain)."""
    minted = mint_signed_trace(
        tmp_path,
        hops=[
            HopSpec(principal_id="codex:gpt-5"),
            HopSpec(principal_id="codex:gpt-5"),  # duplicate
        ],
    )
    payload = minted.trace.to_dict()
    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


# ----- Full round trip (design test #18) -----


def test_full_round_trip_signed(tmp_path):
    """Mint -> to_dict -> from_dict (with key_store) -> equal."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()
    rehydrated = AuthorizationTrace.from_dict(payload, key_store=minted.key_store)
    assert rehydrated == minted.trace


def test_round_trip_without_key_store_passes(tmp_path):
    """Same round-trip without a key_store: structural checks +
    trace_hash only; signatures pass through unverified."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()
    rehydrated = AuthorizationTrace.from_dict(payload)
    assert rehydrated == minted.trace


# ----- Key-store error paths -----


def test_unknown_signing_key_id_raises(tmp_path):
    """If a hop references a signing_key_id not in the store, the
    underlying UnknownSigningKeyError is wrapped in
    AuthorizationTraceIntegrityError."""
    minted = _two_hop(tmp_path)
    payload = copy.deepcopy(minted.trace.to_dict())
    # tamper the on-wire signing_key_id to an unknown id; this also
    # invalidates the trace_hash, so we re-mint the receipt hash to
    # ensure the key-store-lookup path is what raises.
    payload["workflow_scope"]["principal_chain"][0]["signing_key_id"] = "key-does-not-exist"
    # Recompute trace_hash so the test isolates the unknown-key error.
    rebuilt = AuthorizationTrace(
        trace_id=minted.trace.trace_id,
        workflow_id=minted.trace.workflow_id,
        parent_workflow_id=minted.trace.parent_workflow_id,
        principal_chain=tuple(payload["workflow_scope"]["principal_chain"]),
        evaluation_policy=minted.trace.evaluation_policy,
        action_binding=dict(minted.trace.action_binding),
    )
    payload = rebuilt.to_dict()

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload, key_store=minted.key_store)


def test_tampered_signature_breaks_verification(tmp_path):
    """Bit-flip the signature bytes; key_store verification raises."""
    minted = _two_hop(tmp_path)
    chain = [dict(h) for h in minted.trace.principal_chain]
    # flip first character of base64url signature
    sig = chain[0]["signature"]
    chain[0]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = AuthorizationTrace(
        trace_id=minted.trace.trace_id,
        workflow_id=minted.trace.workflow_id,
        parent_workflow_id=minted.trace.parent_workflow_id,
        principal_chain=tuple(chain),
        evaluation_policy=minted.trace.evaluation_policy,
        action_binding=dict(minted.trace.action_binding),
    )
    payload = tampered.to_dict()

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload, key_store=minted.key_store)


def test_now_kwarg_threads_through_to_expiry_check(tmp_path):
    """The now= kwarg is what makes expiry deterministic under test."""
    minted = _two_hop(tmp_path)
    payload = minted.trace.to_dict()

    # Advance now past every hop's not_after window -> expiry check fails.
    future = datetime.now(tz=timezone.utc) + timedelta(days=7)
    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload, key_store=minted.key_store, now=future)

    # Real now still passes.
    AuthorizationTrace.from_dict(payload, key_store=minted.key_store)
