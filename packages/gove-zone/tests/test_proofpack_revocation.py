"""Revocation applied to the OFFLINE proof-pack verifier (B4-c, the named B2 fast-follow).

PR #166 added :class:`~gove_zone.revocation.RevocationList` and
``DecisionReceipt.verify(revoked_keys=...)``, but left the *offline* surface —
``verify_proof_pack`` and the ``verify-proofpack`` CLI — unable to apply a revocation
list. That gap is documented in ``revocation.py`` / ``signing.py`` as a deferred
fast-follow. These tests pin it closed:

* a signed pack whose signing key is revoked is rejected **offline**
  (``SIGNING_KEY_REVOKED``), so a key compromised *after* the pack was minted cannot
  be verified as valid by a relying party;
* omitting ``revoked_keys`` preserves the prior verdict **exactly** (additive,
  off-by-default);
* revoking an **unrelated** key changes nothing (no over-broad kill).

No fixture regeneration: the committed ``valid-allow`` pack is signed by
``fixture-key-1``; the verdict, not the bytes, is the contract.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

pytest.importorskip("cryptography")  # signed pack needs signature verification

from gove_zone import Ed25519Signer  # noqa: E402
from gove_zone.revocation import RevocationList  # noqa: E402
from gove_zone.verifier import ProofPackVerificationResult, verify_proof_pack  # noqa: E402

CORPUS = Path(__file__).parent / "fixtures" / "proofpacks"
_NOW = "2026-01-01T00:00:00+00:00"
_FIXTURE_KEY_ID = "fixture-key-1"

# Rebuild the public-key verifier from the same fixed seed the generator signs with
# (mirrors test_proofpack_corpus.py). The key is reconstructed out-of-band, never read
# from the pack (that would be the trust-anchor circularity of docs/PROOF_PATH.md).
_SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
_TRUSTED = Ed25519Signer.from_public_bytes(
    Ed25519Signer.from_private_bytes(_SEED, key_id=_FIXTURE_KEY_ID).public_bytes(),
    key_id=_FIXTURE_KEY_ID,
)


def _verify(revoked_keys: RevocationList | None) -> ProofPackVerificationResult:
    # ``valid-allow`` ships a SIGNED, declared-accept receipt signed by fixture-key-1.
    return verify_proof_pack(
        CORPUS / "valid-allow",
        verifier={_FIXTURE_KEY_ID: _TRUSTED},
        now_iso=_NOW,
        revoked_keys=revoked_keys,
    )


def test_baseline_valid_when_no_revocation_applied() -> None:
    """Off-by-default: omitting ``revoked_keys`` preserves the prior valid=True verdict."""
    result = _verify(None)
    assert result.valid is True
    assert result.reasons == []
    assert result.signature_verified is True


def test_revoking_the_signing_key_rejects_offline() -> None:
    """A signed pack whose signing key is on the revocation list is rejected offline."""
    result = _verify(RevocationList([_FIXTURE_KEY_ID]))
    observed = {str(r) for r in result.reasons}
    assert result.valid is False
    assert "SIGNING_KEY_REVOKED" in observed, observed
    # The per-receipt signature tri-state must read False (a revoked key is a signature
    # failure), not be silently aggregated as a passing True.
    assert result.signature_verified is False


def test_revoking_an_unrelated_key_is_inert() -> None:
    """Revoking a DIFFERENT key_id leaves the verdict unchanged (no over-broad kill)."""
    result = _verify(RevocationList(["some-other-key"]))
    assert result.valid is True
    assert result.reasons == []
    assert result.signature_verified is True


def test_empty_revocation_list_matches_no_list() -> None:
    """An empty revocation list is a no-op equivalent to ``None`` (additive contract)."""
    result = _verify(RevocationList([]))
    assert result.valid is True
    assert result.reasons == []
