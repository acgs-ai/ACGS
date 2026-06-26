"""Runtime signing-key revocation (B2) — proven THROUGH THE GATE.

The discriminating property: a receipt signed by a revoked ``signing_key_id``
is rejected **even when its signature is cryptographically valid and the key is
still present in the verifier map**. That is the thing the pre-B2 path could not
do — the only prior remedy was removing the key from the map and redeploying.

Loader tests (no crypto) prove :class:`RevocationList` is fail-closed. Gate tests
(crypto) drive the real gates — :meth:`ReceiptVerifier.verify` and
:meth:`GovernedExecutor.execute` — never ``receipt.verify`` in isolation for the
wiring proofs, and assert the guarded side effect never runs on a revoked key.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from gove_zone.revocation import RevocationList, RevocationListError

# --- loader / value-object units (stdlib only, no crypto) -------------------


def test_is_revoked_exact_match() -> None:
    rl = RevocationList(["k-compromised", "k-old"])
    assert rl.is_revoked("k-compromised") is True
    assert rl.is_revoked("k-old") is True
    assert rl.is_revoked("k-good") is False


def test_empty_list_revokes_nothing() -> None:
    rl = RevocationList([])
    assert rl.is_revoked("anything") is False


def test_rejects_empty_key_id_at_construction() -> None:
    # The empty string is the unsigned sentinel; revoking it would aim at every
    # unsigned receipt. Fail-closed at construction.
    with pytest.raises(RevocationListError, match="empty key_id"):
        RevocationList(["k1", ""])


def test_from_json_loads_array(tmp_path) -> None:
    p = tmp_path / "revoked.json"
    p.write_text(json.dumps(["k1", "k2"]), encoding="utf-8")
    rl = RevocationList.from_json(p)
    assert rl.is_revoked("k1") is True
    assert rl.is_revoked("k3") is False


def test_from_json_rejects_non_list(tmp_path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"k1": True}), encoding="utf-8")
    with pytest.raises(RevocationListError, match="array of strings"):
        RevocationList.from_json(p)


def test_from_json_rejects_non_string_element(tmp_path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(["k1", 7]), encoding="utf-8")
    with pytest.raises(RevocationListError, match="array of strings"):
        RevocationList.from_json(p)


def test_from_json_rejects_empty_string_element(tmp_path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(["k1", ""]), encoding="utf-8")
    with pytest.raises(RevocationListError, match="empty key_id"):
        RevocationList.from_json(p)


def test_from_json_rejects_unreadable_path(tmp_path) -> None:
    with pytest.raises(RevocationListError, match="cannot load"):
        RevocationList.from_json(tmp_path / "does-not-exist.json")


def test_from_json_rejects_malformed_json(tmp_path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(RevocationListError, match="cannot load"):
        RevocationList.from_json(p)


# --- gate wiring (crypto) ---------------------------------------------------

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
)
from gove_zone.decision import sha256_json  # noqa: E402
from gove_zone.errors import ReceiptRejectionReason  # noqa: E402

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}


class SideEffect:
    """A guarded side effect that records whether it actually ran."""

    def __init__(self) -> None:
        self.ran = False

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        return "SIDE EFFECT EXECUTED"


def _issue(signer: Ed25519Signer | None, *, actor: str = "agent-1") -> DecisionReceipt:
    """Mint an ALLOW receipt, optionally signed by *signer*."""
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="v1",
        event_id="ev_abc",
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        signer=signer,
    )


def _verifier(
    *,
    verifier: Any,
    require_signature: bool,
    revoked_keys: RevocationList | None,
) -> ReceiptVerifier:
    return ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        verifier=verifier,
        require_signature=require_signature,
        revoked_keys=revoked_keys,
    )


def test_revoked_key_rejected_through_receipt_verifier() -> None:
    """THE discriminating proof: the revoked key is STILL in the verifier map and
    the signature is valid, yet the gate rejects on SIGNING_KEY_REVOKED."""
    signer = Ed25519Signer.generate(key_id="k-compromised")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k-compromised")
    receipt = _issue(signer)

    gate = _verifier(
        verifier={"k-compromised": pub},  # key is PRESENT and valid
        require_signature=True,
        revoked_keys=RevocationList(["k-compromised"]),
    )
    with pytest.raises(ReceiptValidationError, match="signing key revoked") as ei:
        gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)
    assert ei.value.reason_code == ReceiptRejectionReason.SIGNING_KEY_REVOKED


def test_non_revoked_key_allowed() -> None:
    signer = Ed25519Signer.generate(key_id="k-good")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k-good")
    receipt = _issue(signer)

    gate = _verifier(
        verifier={"k-good": pub},
        require_signature=True,
        revoked_keys=RevocationList(["k-other"]),
    )
    gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)  # no raise


def test_default_none_revocation_unchanged() -> None:
    """revoked_keys defaults to None — behavior identical to today."""
    signer = Ed25519Signer.generate(key_id="k1")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k1")
    receipt = _issue(signer)

    gate = _verifier(verifier={"k1": pub}, require_signature=True, revoked_keys=None)
    gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)  # no raise


def test_empty_revocation_list_allows() -> None:
    signer = Ed25519Signer.generate(key_id="k1")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k1")
    receipt = _issue(signer)

    gate = _verifier(
        verifier={"k1": pub}, require_signature=True, revoked_keys=RevocationList([])
    )
    gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)  # no raise


@pytest.mark.parametrize("require_signature", [True, False])
def test_unsigned_receipt_unaffected_by_revocation(require_signature: bool) -> None:
    """An unsigned receipt (signing_key_id == "") never enters the signed branch,
    so a non-empty revocation set cannot reject it by empty-string match. With
    require_signature=True it is still rejected — but for UNSIGNED_REJECTED, not
    SIGNING_KEY_REVOKED."""
    receipt = _issue(None)  # unsigned: signature_algorithm == "none"
    assert receipt.signing_key_id == ""

    # A verifier is supplied so require_signature=True reaches receipt.verify's
    # unsigned check (rather than the production-misconfig guard). The unsigned
    # receipt never uses it.
    pub = Ed25519Signer.generate(key_id="kv")
    gate = _verifier(
        verifier=pub,
        require_signature=require_signature,
        revoked_keys=RevocationList(["k-compromised"]),
    )
    if require_signature:
        with pytest.raises(ReceiptValidationError) as ei:
            gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)
        # rejected for being unsigned, NOT for revocation
        assert ei.value.reason_code == ReceiptRejectionReason.UNSIGNED_REJECTED
    else:
        gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)  # dev mode: allowed


def test_revoked_key_rejected_in_dev_mode() -> None:
    """A signed receipt with a revoked key is rejected even with
    require_signature=False — revocation fires inside the signed branch
    regardless of the unsigned-acceptance flag."""
    signer = Ed25519Signer.generate(key_id="k-compromised")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k-compromised")
    receipt = _issue(signer)

    gate = _verifier(
        verifier={"k-compromised": pub},
        require_signature=False,
        revoked_keys=RevocationList(["k-compromised"]),
    )
    with pytest.raises(ReceiptValidationError, match="signing key revoked"):
        gate.verify(receipt, expected_action=ACTION, expected_args=ARGS)


def test_revoked_key_rejected_through_executor_side_effect_never_runs() -> None:
    """Gate wiring through GovernedExecutor.execute: a revoked key rejects and the
    registered tool never runs."""
    signer = Ed25519Signer.generate(key_id="k-compromised")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k-compromised")
    receipt = _issue(signer)
    side_effect = SideEffect()

    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        verifier={"k-compromised": pub},
        require_signature=True,
        revoked_keys=RevocationList(["k-compromised"]),
    )
    ex.register(ACTION, side_effect.run)
    with pytest.raises(ReceiptValidationError, match="signing key revoked"):
        ex.execute(ACTION, ARGS, receipt)
    assert side_effect.ran is False


def test_revoked_key_rejected_through_low_level_primitive() -> None:
    """The bare receipt.verify primitive also honors revoked_keys (defense in
    depth; the gates above are the wiring proofs)."""
    signer = Ed25519Signer.generate(key_id="k-compromised")
    pub = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k-compromised")
    receipt = _issue(signer)

    with pytest.raises(ReceiptValidationError, match="signing key revoked"):
        receipt.verify(
            verifier={"k-compromised": pub},
            require_signature=True,
            revoked_keys=RevocationList(["k-compromised"]),
        )
