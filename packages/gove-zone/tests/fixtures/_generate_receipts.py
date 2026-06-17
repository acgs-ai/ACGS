"""Deterministic generator for the receipt golden-fixture corpus.

First slice (baselines + Layer A) of the verifier fixture corpus. See
``.omc/research/verifier-fixture-acceptance-spec.md`` for the full design.

Every fixture is **minted from the real issuance path** (``DecisionReceipt.from_record``)
then mutated by exactly one documented edit — never hand-authored (spec §3.1). Determinism
is mandatory (spec §3.3): a fixed Ed25519 seed (Ed25519 signatures are deterministic per
RFC 8032) and a pinned ``timestamp_iso`` make ``receipt_hash`` and ``signature`` byte-stable,
so the committed corpus is regenerable and a CI guard can assert it has not drifted.

Run from the repo root::

    uv run --package gove-zone --extra crypto python \
        packages/gove-zone/tests/fixtures/_generate_receipts.py

Layer A fixtures all hand-edit a field that is **bound into ``receipt_hash``** and therefore
all reject with the SAME reason (``RECEIPT_HASH_MISMATCH``, check 2). That is the point: it
proves the binding surface. Semantic (Layer B) fixtures — where the reason actually varies —
land with the B4-V0 reason-code enum (spec §2/§9).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Ed25519Signer,
    Validator,
)
from gove_zone.decision import sha256_json
from gove_zone.errors import ReceiptRejectionReason as R

# --- Fixed, deterministic test material (NOT production keys) ----------------
SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
EVIL_SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: attacker").digest()
SIGNER = Ed25519Signer.from_private_bytes(SEED, key_id="fixture-key-1")
EVIL_SIGNER = Ed25519Signer.from_private_bytes(EVIL_SEED, key_id="fixture-key-evil")

TS = "2026-01-01T00:00:00+00:00"
EXP_FAR = "2030-01-01T00:00:00+00:00"
EXP_PAST = "2025-06-01T00:00:00+00:00"  # < TS, so verify(now_iso=TS) sees it expired

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
VALIDATOR = "constitutional-council"
ARGS: dict[str, Any] = {"path": "safe.txt"}

CORPUS_DIR = Path(__file__).parent / "receipts"


def mint(
    *,
    decision: Decision = Decision.ALLOW,
    actor: str = ACTOR,
    validator_id: str = VALIDATOR,
    args: dict[str, Any] | None = None,
    signer: Ed25519Signer | None = SIGNER,
    expires_at: str = "",
    transformed_args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    """Mint a genuinely-valid receipt through the real issuance path."""
    effective_args = ARGS if args is None else args
    record = DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_abc",
        actor=actor,
        timestamp_iso=TS,
        transformed_args=transformed_args,
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
        validator=Validator(validator_id),
        authority="tenant-A/write-grant",
        expires_at=expires_at,
        signer=signer,
    )


# Verify kwargs shared by the happy-path baselines (exercises checks 5/6/7/2b/10b).
_FULL_EXPECTED: dict[str, Any] = {
    "expected_tenant_id": TENANT,
    "expected_execution_boundary": BOUNDARY,
    "expected_action": ACTION,
    "expected_actor": ACTOR,
    "expected_args": ARGS,
}
# Layer A only needs to reach check 2 — keep kwargs minimal so nothing else interferes.
_LAYER_A_KW: dict[str, Any] = {"require_signature": True}
_HASH_MISMATCH = "RECEIPT_HASH_MISMATCH"


def _bound_field_tamper(receipt: DecisionReceipt, field: str, value: Any) -> DecisionReceipt:
    """Hand-edit one hash-bound field WITHOUT recomputing the hash (Layer A)."""
    return dataclasses.replace(receipt, **{field: value})


def build_fixtures() -> list[dict[str, Any]]:
    """Return the corpus: each entry is {name, receipt, meta}."""
    fixtures: list[dict[str, Any]] = []

    def add(name: str, receipt: DecisionReceipt, meta: dict[str, Any]) -> None:
        fixtures.append({"name": name, "receipt": receipt, "meta": {"name": name, **meta}})

    # --- Baselines (must ACCEPT) ------------------------------------------
    add(
        "valid-allow-signed",
        mint(),
        {
            "expected": "accept",
            "reason_code": None,
            "layer": "baseline",
            "entry": "verify",
            "verifier": "trusted-single",
            "verify_kwargs": {**_FULL_EXPECTED, "require_signature": True},
            "notes": "canonical demo subject: signed, fresh, correct context",
        },
    )
    add(
        "valid-allow-unsigned-dev",
        mint(signer=None),
        {
            "expected": "accept",
            "reason_code": None,
            "layer": "baseline",
            "entry": "verify",
            "verifier": "none",
            "verify_kwargs": {**_FULL_EXPECTED, "require_signature": False},
            "notes": "dev profile only; documents the unsigned posture",
        },
    )

    # --- Layer A (hand-edit bound field -> RECEIPT_HASH_MISMATCH, check 2) --
    def layer_a(name: str, receipt: DecisionReceipt, note: str) -> None:
        add(
            name,
            receipt,
            {
                "expected": "reject",
                "reason_code": _HASH_MISMATCH,
                "layer": "A",
                "entry": "verify",
                "verifier": "trusted-single",
                "verify_kwargs": dict(_LAYER_A_KW),
                "notes": note,
            },
        )

    base = mint()
    layer_a("tamper-actor", _bound_field_tamper(base, "actor", "attacker"), "actor field flipped")
    layer_a(
        "tamper-argument-hash",
        _bound_field_tamper(base, "argument_hash", "0" * 64),
        "argument_hash flipped (binding defeats arg substitution)",
    )
    layer_a(
        "tamper-policy-hash",
        _bound_field_tamper(base, "policy_hash", "tampered-policy-hash"),
        "policy_hash flipped",
    )
    layer_a(
        "tamper-decision-deny-to-allow",
        _bound_field_tamper(mint(decision=Decision.DENY), "decision", "allow"),
        "DENY relabeled ALLOW; caught at hash check before the deny check (4)",
    )
    layer_a(
        "tamper-expires-extend",
        _bound_field_tamper(mint(expires_at=EXP_FAR), "expires_at", "2099-01-01T00:00:00+00:00"),
        "expiry pushed forward; rejects as HASH_MISMATCH not EXPIRED (the F2 trap, pinned)",
    )
    layer_a(
        "tamper-sig-downgrade",
        _bound_field_tamper(base, "signature_algorithm", "none"),
        "anti-downgrade: algorithm is bound into the hash",
    )
    layer_a(
        "tamper-key-swap",
        _bound_field_tamper(base, "signing_key_id", "fixture-key-evil"),
        "key id is bound; cannot reach the unknown-key check",
    )

    # --- Layer B (semantic: each rejects for its OWN distinct reason) -------
    # These reach a real check via a genuinely-wrong-but-consistent receipt OR a
    # valid receipt + mismatched verify() context. The credibility set: "rejected
    # for the right reason" across distinct failure modes. reason_code is the enum
    # member (StrEnum -> serialises to its plain-string value in meta.json).
    def layer_b(
        name: str,
        receipt: DecisionReceipt,
        reason: R,
        *,
        verifier: str = "trusted-single",
        kwargs: dict[str, Any] | None = None,
        note: str = "",
    ) -> None:
        vk: dict[str, Any] = {"require_signature": True}
        vk.update(kwargs or {})
        add(
            name,
            receipt,
            {
                "expected": "reject",
                "reason_code": reason,
                "layer": "B",
                "entry": "verify",
                "verifier": verifier,
                "verify_kwargs": vk,
                "notes": note,
            },
        )

    # Context-mismatch: receipt is valid; the mismatch is in expected_* at the gate.
    layer_b(
        "wrong-tenant",
        mint(),
        R.TENANT_MISMATCH,
        kwargs={"expected_tenant_id": "tenant-Z"},
        note="receipt not issued for this tenant",
    )
    layer_b(
        "wrong-boundary",
        mint(),
        R.EXECUTION_BOUNDARY_MISMATCH,
        kwargs={"expected_execution_boundary": "prod-cluster"},
        note="wrong execution boundary",
    )
    layer_b(
        "wrong-action",
        mint(),
        R.ACTION_MISMATCH,
        kwargs={"expected_action": "runtime.file.delete"},
        note="receipt authorizes a different action",
    )
    layer_b(
        "wrong-audit-hash",
        mint(),
        R.AUDIT_HASH_MISMATCH,
        kwargs={"expected_audit_hash": "different-audit-hash"},
        note="not anchored to this audit event",
    )
    layer_b(
        "wrong-policy-hash",
        mint(),
        R.POLICY_HASH_MISMATCH,
        kwargs={"expected_policy_hash": "different-policy-hash"},
        note="policy hash mismatch",
    )
    layer_b(
        "wrong-bundle",
        mint(),
        R.POLICY_BUNDLE_MISMATCH,
        kwargs={"expected_policy_bundle_id": "different-bundle"},
        note="policy bundle mismatch",
    )
    layer_b(
        "actor-mismatch",
        mint(),
        R.ACTOR_MISMATCH,
        kwargs={"expected_actor": "intruder"},
        note="receipt not issued for this caller",
    )
    layer_b(
        "wrong-args-substitution",
        mint(),
        R.ARGUMENT_MISMATCH,
        kwargs={"expected_args": {"path": "/etc/shadow"}},
        note="ALLOW receipt for safe.txt cannot authorize /etc/shadow (arg binding)",
    )

    # Re-minted intrinsic-wrong: the receipt itself carries the rejecting property.
    layer_b(
        "denied-cannot-execute",
        mint(decision=Decision.DENY),
        R.DENIED_RECEIPT,
        note="a DENY receipt is not executable",
    )
    layer_b(
        "escalated-cannot-execute",
        mint(decision=Decision.ESCALATE),
        R.ESCALATED_RECEIPT,
        note="an ESCALATE receipt is not executable",
    )
    layer_b(
        "expired",
        mint(expires_at=EXP_PAST),
        R.RECEIPT_EXPIRED,
        kwargs={"now_iso": TS},
        note="genuinely-issued receipt used past its lifetime",
    )
    layer_b(
        "missing-field-authority",
        _bound_field_tamper(mint(), "authority", ""),
        R.MISSING_REQUIRED_FIELD,
        note="empty required field caught at check 1 (before hash)",
    )
    layer_b(
        "transform-mismatch",
        mint(decision=Decision.TRANSFORM, transformed_args={"path": "redacted.txt"}),
        R.TRANSFORM_MISMATCH,
        kwargs={"expected_args": {"path": "other.txt"}},
        note="executed args do not match the approved transform",
    )

    # Signature failures (signed receipts).
    layer_b(
        "unsigned-rejected",
        mint(signer=None),
        R.UNSIGNED_REJECTED,
        verifier="none",
        note="require_signature=True but the receipt is unsigned",
    )
    layer_b(
        "sig-invalid",
        dataclasses.replace(mint(), signature=SIGNER.sign(b"a-different-message")),
        R.SIGNATURE_INVALID,
        note="well-formed signature that does not attest this hash",
    )
    layer_b(
        "sig-unknown-key",
        mint(signer=EVIL_SIGNER),
        R.SIGNING_KEY_UNKNOWN,
        verifier="trusted-registry",
        note="signed by a key absent from the trust registry",
    )
    layer_b(
        "sig-missing-verifier",
        mint(),
        R.SIGNED_RECEIPT_NO_VERIFIER,
        verifier="none",
        note="a receipt claiming a signature cannot skip verification",
    )

    return fixtures


def write_corpus(target: Path = CORPUS_DIR) -> int:
    fixtures = build_fixtures()
    for entry in fixtures:
        d = target / entry["name"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "receipt.json").write_text(entry["receipt"].to_json() + "\n", encoding="utf-8")
        meta = {**entry["meta"], "produced_by": "tests/fixtures/_generate_receipts.py"}
        (d / "meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return len(fixtures)


if __name__ == "__main__":
    n = write_corpus()
    print(f"wrote {n} fixtures to {CORPUS_DIR}")
