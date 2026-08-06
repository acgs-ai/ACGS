"""A scoped-trust Decision Receipt v2 is rejected explicitly, never mis-verified.

This vendored receipt parser carries no scoped-trust fields. Without an
explicit guard, ``DecisionReceipt.from_dict`` would silently DROP
``receipt_schema_version`` / ``project_id`` / ``environment_id`` /
``trust_epoch``, recompute ``receipt_hash`` over the wrong payload, and report
``RECEIPT_HASH_MISMATCH``: a false tamper verdict for an intact artifact, the
same failure class as the generator-footer false alarm this package exists to
prevent. gove-zone refuses to package a v2 receipt at generation time
(scoped-trust verification needs an expected tenant/project/environment scope
and a trust registry, which no proof-pack verification path accepts), so a v2
receipt inside an acgs/proof-pack/v1 or v1.1 bundle is unsupported input, not
tampering; the rejection must say so.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from acgs_proofpack_verifier import verify_pack
from acgs_proofpack_verifier.proofpack import PackGenerationError, generate_proof_pack
from acgs_proofpack_verifier.receipt import DecisionReceipt

_FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = _FIXTURES / "golden"
NOW_ISO = "2026-01-01T00:00:00+00:00"

RECEIPT_HASH_MISMATCH = "RECEIPT_HASH_MISMATCH"

_SCOPED_TRUST_FIELDS = {
    "receipt_schema_version": "gove-zone/decision-receipt/v2",
    "project_id": "proj-1",
    "environment_id": "env-1",
    "trust_epoch": 1,
}


def _golden_receipt_doc() -> dict[str, Any]:
    return json.loads((GOLDEN / "decision-receipt.json").read_text(encoding="utf-8"))


def _v2_receipt_doc() -> dict[str, Any]:
    doc = _golden_receipt_doc()
    doc.update(_SCOPED_TRUST_FIELDS)
    return doc


def test_from_dict_rejects_scoped_trust_receipt_by_name() -> None:
    with pytest.raises(ValueError, match="scoped-trust"):
        DecisionReceipt.from_dict(_v2_receipt_doc())


@pytest.mark.parametrize("field", sorted(_SCOPED_TRUST_FIELDS))
def test_from_dict_rejects_each_scoped_trust_field_alone(field: str) -> None:
    """The guard fires field-by-field: a half-v2 receipt cannot slip through
    and have its remaining scoped-trust fields silently dropped."""
    doc = _golden_receipt_doc()
    doc[field] = _SCOPED_TRUST_FIELDS[field]
    with pytest.raises(ValueError, match=field):
        DecisionReceipt.from_dict(doc)


def test_generate_refuses_scoped_trust_v2_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt-v2.json"
    receipt.write_text(json.dumps(_v2_receipt_doc(), sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(PackGenerationError, match="scoped-trust"):
        generate_proof_pack(
            tmp_path / "pack",
            receipt_path=receipt,
            audit_path=tmp_path / "audit.jsonl",
        )


def test_pack_with_v2_receipt_fails_closed_without_false_tamper_verdict(
    tmp_path: Path,
) -> None:
    """A hand-minted pack carrying a receipt v2 must fail verification, and the
    failure must be the parser's explicit refusal, never a fabricated
    RECEIPT_HASH_MISMATCH. Modeled as the strongest editor, who recomputes the
    unauthenticated evidence.json digest so tier 1 passes."""
    pack = tmp_path / "pack"
    shutil.copytree(GOLDEN, pack)
    receipt_path = pack / "decision-receipt.json"
    receipt_path.write_text(json.dumps(_v2_receipt_doc(), sort_keys=True) + "\n", encoding="utf-8")
    raw = receipt_path.read_bytes()
    evidence_path = pack / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["artifacts"]["decision-receipt.json"] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    result = verify_pack(pack, now_iso=NOW_ISO)
    assert not result.valid
    assert result.reasons, "a v2-receipt pack must carry an explicit rejection reason"
    assert RECEIPT_HASH_MISMATCH not in [str(r) for r in result.reasons], (
        "an intact scoped-trust receipt must not be reported as hash tampering: "
        f"{[str(r) for r in result.reasons]}"
    )
