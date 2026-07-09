"""Adversary class: RECEIPT FORGERY under the unsigned (dev) posture.

``receipt_hash`` is a keyless SHA-256 (receipt.py compute_hash). In unsigned mode any
party who can construct a DecisionReceipt can mint a valid-looking ALLOW — there is no
cryptographic root of trust. This is closed ONLY when signing is engaged
(``require_signature=True`` + a trusted Ed25519 verifier). See threat-model-v2.md §1/§6.

This file makes the unsigned-mode residual a live tripwire (asserted, not just prose),
proves signing closes it, and pins the ReceiptVerifier default-posture inconsistency:
``execute_with_receipt`` defaults ``require_signature=True`` while ``ReceiptVerifier``
defaults ``require_signature=False``.
"""

from __future__ import annotations

import dataclasses

import pytest

from gove_zone import (
    Ed25519Signer,
    ProductionProfileError,
    ReceiptValidationError,
    ReceiptVerifier,
    execute_with_receipt,
)

# Must match tests/adversary/conftest.py.
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS = {"path": "safe.txt"}


def test_unsigned_recomputed_forgery_executes_KNOWN_LIMITATION(
    side_effect, issue, run_gate
) -> None:
    """An attacker with no private key mints a valid ALLOW via the public schema and it
    executes in unsigned mode — the forged authorization succeeds today."""
    forged = issue(actor="attacker", validator_id="attacker-cabal")

    result = run_gate(forged, side_effect, expected_actor="attacker")

    assert result == "SIDE EFFECT EXECUTED"
    assert side_effect.run_count == 1, (
        "unsigned mode has no cryptographic root of trust: a self-minted ALLOW verifies. "
        "If this fails, unsigned forgery may have been closed (update the manifest)."
    )


def test_signed_mode_rejects_recomputed_field_tamper(side_effect, issue, run_gate) -> None:
    """The DEFENDED expectation: with signing engaged, tampering a field and recomputing
    the keyless hash cannot re-produce a valid signature (no private key), so the gate
    rejects it and the side effect never runs."""
    signer = Ed25519Signer.generate()
    legit = issue(signer=signer, actor="agent-1")

    # Attacker edits the actor and recomputes the keyless receipt_hash, but the existing
    # signature was made over the ORIGINAL hash and cannot be re-forged.
    tampered = dataclasses.replace(legit, actor="attacker")
    tampered = dataclasses.replace(tampered, receipt_hash=tampered.compute_hash())

    with pytest.raises(ReceiptValidationError):
        run_gate(
            tampered,
            side_effect,
            expected_actor="attacker",
            verifier=signer,
            require_signature=True,
        )
    assert side_effect.run_count == 0


def test_execute_with_receipt_default_demands_a_verifier_HELD(side_effect, issue) -> None:
    """execute_with_receipt is secure-by-default: require_signature=True with no verifier
    fails closed with ProductionProfileError (it never auto-generates a key)."""
    forged = issue(actor="attacker", validator_id="attacker-cabal")
    with pytest.raises(ProductionProfileError):
        execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=forged,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="attacker",
        )  # require_signature defaults to True
    assert side_effect.run_count == 0


def test_receipt_verifier_default_accepts_unsigned_forgery_KNOWN_GAP(
    side_effect, issue
) -> None:
    """Inconsistent default posture across gate surfaces: ReceiptVerifier defaults
    require_signature=False, so the SAME unsigned forgery execute_with_receipt would
    guard against is accepted silently through ReceiptVerifier with no production signal."""
    forged = issue(actor="attacker", validator_id="attacker-cabal")
    verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_actor="attacker",
    )  # require_signature defaults to False

    # No exception -> the unsigned forgery is accepted by the default ReceiptVerifier.
    verifier.verify(forged, expected_action=ACTION, expected_args=ARGS)
    assert verifier.is_valid(forged, expected_action=ACTION, expected_args=ARGS), (
        "ReceiptVerifier defaults require_signature=False (contracts.py) while "
        "execute_with_receipt defaults True (executor.py) — same trust decision, opposite "
        "default. If this fails, the defaults were aligned (good — update the manifest)."
    )
