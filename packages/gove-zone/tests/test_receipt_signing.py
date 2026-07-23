"""Ed25519 receipt signing — proving the recomputed-receipt residual is closed.

The receipt schema binds everything into ``receipt_hash``, but a hash is
recomputable: a process that can rebuild the canonical dict can mint a "valid"
``receipt_hash`` (the prior ``signature = "unsigned_local"`` residual). Asymmetric
signing closes it: the issuer signs ``receipt_hash`` with a PRIVATE key, the gate
verifies with the PUBLIC key. These tests prove rejection THROUGH THE GATE
(``execute_with_receipt``), not via ``verify()`` in isolation, and assert the
guarded side effect never runs on a forged receipt.

The residual-closure GATE proof is
``test_forged_recomputed_receipt_rejected_without_private_key``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from gove_zone.executor import adapter_artifact_digest

cryptography = pytest.importorskip("cryptography")

from gove_zone import (  # noqa: E402  (after importorskip by design)
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Ed25519Signer,
    GovernedExecutor,
    ReceiptValidationError,
    ReceiptVerifier,
    Validator,
    execute_with_receipt,
)
from gove_zone._strict_dispatch_fixture import StrictReceiptGateFixture  # noqa: E402
from gove_zone.decision import sha256_json  # noqa: E402

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}


class SideEffect:
    """A guarded side effect that records whether it actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.args = kwargs
        return "SIDE EFFECT EXECUTED"


def _issue(
    strict_gate: StrictReceiptGateFixture,
    signer: Ed25519Signer | None,
    *,
    actor: str = "agent-1",
    validator_id: str = "constitutional-council",
    args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    """Mint an ALLOW receipt, optionally signed by *signer*."""
    effective_args = args if args is not None else ARGS
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_abc",
        actor=actor,
    )
    event = strict_gate.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=str(event["event_hash"]),
        previous_audit_hash=str(event["previous_hash"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator(validator_id),
        authority="tenant-A/write-grant",
        signer=signer,
    )


def _run_gate(
    strict_gate: StrictReceiptGateFixture,
    receipt: DecisionReceipt,
    side_effect: SideEffect,
    *,
    verifier: Any,
    args: dict[str, Any] | None = None,
    expected_actor: str = "agent-1",
) -> Any:
    return execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(side_effect.run),
        tool_fn=side_effect.run,
        args=args if args is not None else ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=expected_actor,
        consumption_store=strict_gate.consumption_store,
        rejection_audit=strict_gate.audit,
        verifier=verifier,
        lifecycle_signer=strict_gate.lifecycle_signer,
        lifecycle_authority_id="fixture-lifecycle-validator",
        require_signature=True,
    )


def test_signed_receipt_verifies_and_executes(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """A receipt signed by the private key passes the matching public-key gate."""
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    receipt = _issue(strict_receipt_gate, signer)
    assert receipt.signature_algorithm == "ed25519"
    assert receipt.signing_key_id == signer.key_id
    assert receipt.signature != "unsigned_local"

    side_effect = SideEffect()
    result = _run_gate(strict_receipt_gate, receipt, side_effect, verifier=verifier)
    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.ran is True


def test_forged_recomputed_receipt_rejected_without_private_key(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """RESIDUAL-CLOSURE GATE PROOF.

    An attacker tampers a field AND recomputes a CONSISTENT receipt_hash
    (simulating the pre-signing forgery that the hash alone could not stop).
    Because they lack the private key, they cannot produce a valid signature
    over the new hash — the stale signature no longer attests it. The gate
    rejects with "invalid signature" and the side effect never runs.
    """
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    receipt = _issue(strict_receipt_gate, signer, actor="agent-1")

    # Tamper the actor, then recompute a consistent hash (forge the hash chain).
    # Keep approval_chain_summary.proposer consistent so check 2d is not what
    # trips — we want the SIGNATURE check to be the thing that rejects.
    summary = dict(receipt.approval_chain_summary)
    summary["proposer"] = "attacker"
    forged = dataclasses.replace(receipt, actor="attacker", approval_chain_summary=summary)
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())
    # The recomputed hash is internally consistent (passes check 2), but the
    # signature still signs the ORIGINAL hash, so it cannot match the new hash.

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="invalid signature"):
        _run_gate(strict_receipt_gate, forged, side_effect, verifier=verifier)
    assert side_effect.ran is False


def test_attacker_mints_with_own_keypair_unknown_key_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """An attacker mints a brand-new, validly-self-signed receipt with THEIR OWN
    keypair (different key_id). The gate trusts a Mapping of known keys that does
    NOT contain the attacker's key_id → "unknown signing key", rejected.
    """
    trusted = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    # Verifier registry trusts only the legitimate key.
    registry = {trusted.key_id: Ed25519Signer.from_public_bytes(trusted.public_bytes())}

    forged = _issue(
        strict_receipt_gate,
        attacker,
    )  # internally valid, signed by the attacker's key
    assert forged.signing_key_id == attacker.key_id
    assert forged.signing_key_id not in registry

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="unknown signing key"):
        _run_gate(strict_receipt_gate, forged, side_effect, verifier=registry)
    assert side_effect.ran is False


def test_signed_receipt_via_known_key_mapping_executes(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """The Mapping path resolves a trusted key_id and executes."""
    signer = Ed25519Signer.generate()
    registry = {signer.key_id: Ed25519Signer.from_public_bytes(signer.public_bytes())}
    receipt = _issue(strict_receipt_gate, signer)

    side_effect = SideEffect()
    _run_gate(strict_receipt_gate, receipt, side_effect, verifier=registry)
    assert side_effect.ran is True


def test_algorithm_downgrade_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """Downgrade a signed receipt to algorithm 'none' (recomputing the hash so it
    stays internally consistent). With require_signature the gate rejects it as
    an unsigned receipt — the attacker cannot strip signing to dodge the key.
    """
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    receipt = _issue(strict_receipt_gate, signer)

    downgraded = dataclasses.replace(
        receipt, signature_algorithm="none", signing_key_id="", signature="unsigned_local"
    )
    downgraded = dataclasses.replace(downgraded, receipt_hash=downgraded.compute_hash())

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="unsigned receipt rejected"):
        _run_gate(strict_receipt_gate, downgraded, side_effect, verifier=verifier)
    assert side_effect.ran is False


def test_wrong_public_key_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """Verifying with an unrelated public key fails the signature check."""
    signer = Ed25519Signer.generate()
    wrong = Ed25519Signer.generate()  # unrelated keypair
    wrong_verifier = Ed25519Signer.from_public_bytes(wrong.public_bytes())
    receipt = _issue(strict_receipt_gate, signer)

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="invalid signature"):
        _run_gate(strict_receipt_gate, receipt, side_effect, verifier=wrong_verifier)
    assert side_effect.ran is False


def test_unsigned_receipt_fails_closed_at_strict_gate(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """The strict side-effect boundary never executes an unsigned receipt."""
    receipt = _issue(strict_receipt_gate, None)
    assert receipt.signature_algorithm == "none"
    assert receipt.signature == "unsigned_local"

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="unsigned receipt rejected"):
        _run_gate(
            strict_receipt_gate,
            receipt,
            side_effect,
            verifier=strict_receipt_gate.signer,
        )
    assert side_effect.ran is False


def test_unsigned_rejected_when_required(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """An unsigned receipt is rejected when a configured production gate requires a
    signature. A verifier is supplied (so the production-no-verifier loud guard does
    not pre-empt this); the receipt itself is unsigned, so require_signature rejects it.
    """
    verifier = Ed25519Signer.generate()
    receipt = _issue(strict_receipt_gate, None)
    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="unsigned receipt rejected"):
        _run_gate(strict_receipt_gate, receipt, side_effect, verifier=verifier)
    assert side_effect.ran is False


def test_production_default_no_verifier_fails_loud(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """DEFAULT-FLIP PROOF: production posture (require_signature=True) with NO verifier
    configured fails closed LOUD, naming the dev opt-out, before any receipt content is
    trusted. This is the no-key-configured exit, distinct from "unsigned receipt rejected"
    (which needs a verifier present).
    """
    from gove_zone import ProductionProfileError

    receipt = _issue(strict_receipt_gate, None)
    side_effect = SideEffect()
    with pytest.raises(ProductionProfileError, match="requires a signer/verifier"):
        _run_gate(strict_receipt_gate, receipt, side_effect, verifier=None)
    assert side_effect.ran is False


def test_signing_fields_bound_into_receipt_hash(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """Tampering signature_algorithm or signing_key_id WITHOUT recomputing the
    hash is caught by the receipt_hash check (anti-downgrade binding), before
    the signature check is even reached.
    """
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    receipt = _issue(strict_receipt_gate, signer)

    # Flip signing_key_id but leave receipt_hash stale.
    tampered = dataclasses.replace(receipt, signing_key_id="someone-elses-key")
    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        _run_gate(strict_receipt_gate, tampered, side_effect, verifier=verifier)
    assert side_effect.ran is False

    # Same for signature_algorithm.
    tampered2 = dataclasses.replace(receipt, signature_algorithm="rsa")
    side_effect2 = SideEffect()
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        _run_gate(strict_receipt_gate, tampered2, side_effect2, verifier=verifier)
    assert side_effect2.ran is False


def test_signature_algorithm_mismatch_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """A verifier whose algorithm differs from the receipt's is rejected before
    any verify() call (defends against a confused-deputy verifier).
    """
    signer = Ed25519Signer.generate()
    receipt = _issue(strict_receipt_gate, signer)

    class NoneAlgVerifier:
        algorithm = "none"
        key_id = ""

        def sign(self, payload: bytes) -> str:  # pragma: no cover - not called
            return "unsigned_local"

        def verify(self, payload: bytes, signature: str) -> bool:  # pragma: no cover
            return True

    side_effect = SideEffect()
    with pytest.raises(ReceiptValidationError, match="signature algorithm mismatch"):
        _run_gate(strict_receipt_gate, receipt, side_effect, verifier=NoneAlgVerifier())
    assert side_effect.ran is False


def test_signed_receipt_without_verifier_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """A receipt that CLAIMS a signature must be cryptographically verified even
    when require_signature=False. Presenting a signed receipt with verifier=None
    was the footgun (signature silently skipped); it now raises unconditionally.

    This test is the closed-footgun proof — it must REJECT (was the fail-open hole).
    """
    signer = Ed25519Signer.generate()
    signed = _issue(strict_receipt_gate, signer)
    assert signed.signature_algorithm == "ed25519"

    side_effect = SideEffect()
    from gove_zone import ProductionProfileError

    with pytest.raises(ProductionProfileError, match="requires a signer/verifier"):
        _run_gate(strict_receipt_gate, signed, side_effect, verifier=None)
    assert side_effect.ran is False


def test_governed_executor_enforces_require_signature(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """The enforcement params are wired through GovernedExecutor.execute, not
    only execute_with_receipt. Constructor defaults + per-call override both
    route to the gate.
    """
    # A configured production executor: require_signature=True WITH a verifier, so
    # the production-no-verifier loud guard does not pre-empt the require_signature path.
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    side_effect = SideEffect()
    executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        verifier=verifier,
        lifecycle_signer=strict_receipt_gate.lifecycle_signer,
        lifecycle_authority_id="fixture-lifecycle-validator",
        consumption_store=strict_receipt_gate.consumption_store,
        rejection_audit=strict_receipt_gate.audit,
    )
    executor.register(ACTION, side_effect.run)

    unsigned = _issue(strict_receipt_gate, None)
    with pytest.raises(ReceiptValidationError, match="unsigned receipt rejected"):
        executor.execute(ACTION, ARGS, unsigned)
    assert side_effect.ran is False

    # A signed receipt matching the configured verifier executes.
    signed = _issue(strict_receipt_gate, signer)
    result = executor.execute(ACTION, ARGS, signed)
    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.ran is True


def test_receipt_verifier_threads_signature_params(
    strict_receipt_gate: StrictReceiptGateFixture,
) -> None:
    """ReceiptVerifier.verify / is_valid pass verifier + require_signature through
    to DecisionReceipt.verify (the single gate).
    """
    signer = Ed25519Signer.generate()
    verifier_key = Ed25519Signer.from_public_bytes(signer.public_bytes())

    rv = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        verifier=verifier_key,
        require_signature=True,
    )

    signed = _issue(strict_receipt_gate, signer)
    assert rv.is_valid(signed, expected_action=ACTION, expected_args=ARGS) is True

    unsigned = _issue(strict_receipt_gate, None)
    assert rv.is_valid(unsigned, expected_action=ACTION, expected_args=ARGS) is False
    with pytest.raises(ReceiptValidationError, match="unsigned receipt rejected"):
        rv.verify(unsigned, expected_action=ACTION, expected_args=ARGS)
