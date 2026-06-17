"""Runner for the receipt golden-fixture corpus (spec §5/§6).

For every fixture under ``fixtures/receipts/<name>/`` this asserts the verifier returns the
DECLARED verdict AND, on rejection, the DECLARED ``reason_code`` — not merely "rejected".
That is what enforces the F2 trap (spec §2): a fixture mislabelled "expired" that actually
yields ``RECEIPT_HASH_MISMATCH`` fails the run.

``reason_code`` is read through ``_observed_reason_code``, which returns the library's stable
``exc.reason_code`` (B4-V0). The earlier bootstrap message-substring classifier is gone — the
suite asserts on the machine-readable contract, not free-text.

First slice: baselines + Layer A (all reject as ``RECEIPT_HASH_MISMATCH``). Layer B (semantic
rows, distinct reason codes) and ``entry == "gate"`` fixtures land next.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

cryptography = pytest.importorskip("cryptography")  # signed fixtures need verification

from gove_zone import DecisionReceipt, Ed25519Signer  # noqa: E402
from gove_zone.errors import GoveZoneError, ReceiptRejectionReason  # noqa: E402

CORPUS = Path(__file__).parent / "fixtures" / "receipts"
_GENERATOR = Path(__file__).parent / "fixtures" / "_generate_receipts.py"

# Rebuild the trusted verifier from the same fixed seed the generator signs with. Kept in
# sync by test_trusted_key_matches_signed_fixture (asserts key_id against the committed receipt).
_SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
_TRUSTED = Ed25519Signer.from_public_bytes(
    Ed25519Signer.from_private_bytes(_SEED, key_id="fixture-key-1").public_bytes(),
    key_id="fixture-key-1",
)
VERIFIERS: dict[str, Any] = {
    "trusted-single": _TRUSTED,
    "trusted-registry": {"fixture-key-1": _TRUSTED},
    "none": None,
}


def _observed_reason_code(exc: BaseException) -> str:
    """Read the stable machine-readable reason_code the library carries (B4-V0).

    This replaced a bootstrap message-substring classifier: every ``verify()`` rejection and
    every ``ReceiptValidationError`` subclass now populates ``exc.reason_code``, so the suite
    asserts on the contract — not on free-text the message layer is free to reword. A missing
    code is a B4-V0 regression, not an "unclassified" soft pass.
    """
    code = getattr(exc, "reason_code", None)
    assert code is not None, f"exception carries no reason_code (B4-V0 regression): {exc!r}"
    return str(code)


def _load(name: str) -> tuple[DecisionReceipt, dict[str, Any]]:
    d = CORPUS / name
    receipt = DecisionReceipt.from_json((d / "receipt.json").read_text())
    meta = json.loads((d / "meta.json").read_text())
    return receipt, meta


def _case_names() -> list[str]:
    return sorted(p.name for p in CORPUS.iterdir() if p.is_dir())


@pytest.mark.parametrize("name", _case_names())
def test_fixture_verdict_and_reason(name: str) -> None:
    receipt, meta = _load(name)
    if meta["entry"] != "verify":
        pytest.skip("gate-entry fixtures land with Layer B")

    kwargs = dict(meta["verify_kwargs"])
    kwargs["verifier"] = VERIFIERS[meta["verifier"]]

    if meta["expected"] == "accept":
        receipt.verify(**kwargs)  # must not raise — a raise here fails the test
        assert meta["reason_code"] is None
    else:
        with pytest.raises(GoveZoneError) as excinfo:
            receipt.verify(**kwargs)
        observed = _observed_reason_code(excinfo.value)
        assert observed == meta["reason_code"], (
            f"{name}: rejected for the WRONG reason — "
            f"declared {meta['reason_code']!r}, observed {observed!r} ({excinfo.value})"
        )


def test_corpus_is_nonempty_and_covers_both_outcomes() -> None:
    metas = [_load(n)[1] for n in _case_names()]
    outcomes = {m["expected"] for m in metas}
    assert outcomes == {"accept", "reject"}, outcomes
    assert len(metas) >= 9


def test_trusted_key_matches_signed_fixture() -> None:
    """Guard against verifier/generator key drift."""
    receipt, _ = _load("valid-allow-signed")
    assert receipt.signing_key_id == _TRUSTED.key_id == "fixture-key-1"


def test_reject_fixture_carries_enum_reason_code() -> None:
    """B4-V0: a reject fixture's exception carries a real ``ReceiptRejectionReason`` member —
    proving the runner asserts on the library contract, not a message classifier.
    """
    receipt, meta = _load("tamper-actor")
    with pytest.raises(GoveZoneError) as excinfo:
        receipt.verify(verifier=VERIFIERS["trusted-single"], require_signature=True)
    assert isinstance(excinfo.value.reason_code, ReceiptRejectionReason)
    assert excinfo.value.reason_code == ReceiptRejectionReason.RECEIPT_HASH_MISMATCH
    assert meta["reason_code"] == "RECEIPT_HASH_MISMATCH"


def test_tamper_is_caught_only_by_verification() -> None:
    """Non-bypassability (spec §6): a tampered receipt is structurally indistinguishable from a
    valid one — it parses and round-trips — and ONLY verify()'s hash binding rejects it. This
    proves the corpus tests a load-bearing check, not a tautology a no-op verifier would pass.
    """
    receipt, _ = _load("tamper-actor")
    # Parses and round-trips like any receipt: nothing structural objects.
    assert receipt.actor == "attacker"
    assert DecisionReceipt.from_json(receipt.to_json()).receipt_hash == receipt.receipt_hash
    # The ONLY thing that catches it is the hash binding inside verify():
    assert receipt.compute_hash() != receipt.receipt_hash  # a bypass would miss this
    with pytest.raises(GoveZoneError, match="receipt_hash mismatch"):
        receipt.verify(verifier=VERIFIERS["trusted-single"], require_signature=True)


def test_corpus_matches_fresh_generation(tmp_path: Path) -> None:
    """Determinism + no-drift for the WHOLE corpus — both ``receipt.json`` AND ``meta.json``.

    ``meta.json`` carries the runtime contract (`expected`, `reason_code`, `verifier`,
    `verify_kwargs`) that `test_fixture_verdict_and_reason` trusts, so the guard must catch
    metadata drift too — not just receipt bytes. A fresh generation into a temp dir must
    reproduce the committed corpus byte-for-byte (fixed seed + pinned timestamp make
    receipt_hash and Ed25519 signatures reproducible) AND have the identical file set.
    """
    spec = importlib.util.spec_from_file_location("_fixture_gen", _GENERATOR)
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    fresh = tmp_path / "receipts"
    n = gen.write_corpus(fresh)
    assert n == len(_case_names())

    def _rel_files(root: Path) -> list[str]:
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())

    committed_files = _rel_files(CORPUS)
    assert committed_files == _rel_files(fresh), "fixture file set drifted (files added/removed)"
    for rel in committed_files:
        assert (CORPUS / rel).read_bytes() == (fresh / rel).read_bytes(), f"drift in {rel}"
