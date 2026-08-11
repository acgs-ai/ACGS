"""Unit guards for ``gove_zone.signing`` — the signer API itself.

``test_receipt_signing.py`` covers signing through the gate: signed receipts
execute, forged ones do not. What it does not pin is the signer's own contract,
and two of those properties are load-bearing on their own:

* a **verify-only** signer (constructed from a public key) must refuse to sign
  rather than produce something a relying party would treat as a signature;
* :class:`NullSigner.verify` must return ``False`` — an explicitly unsigned
  receipt is never "signature-valid". Acceptance of unsigned receipts is a gate
  policy (``require_signature=False``), never a signer verdict. Flipping this to
  ``True`` would make every unsigned receipt verify everywhere.

The malformed-input paths matter because signature material arrives from
whoever produced the receipt.
"""

from __future__ import annotations

import pytest

cryptography = pytest.importorskip("cryptography")

from gove_zone.signing import (  # noqa: E402
    Ed25519Signer,
    NullSigner,
    SigningError,
    make_signer,
)

PAYLOAD = b"canonical receipt payload"


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #
def test_a_signer_needs_at_least_one_key():
    with pytest.raises(SigningError, match="requires a private or public key"):
        Ed25519Signer()


def test_key_id_defaults_to_a_digest_of_the_public_key():
    signer = Ed25519Signer.generate()

    assert len(signer.key_id) == 16
    assert Ed25519Signer.from_public_bytes(signer.public_bytes()).key_id == signer.key_id


def test_an_explicit_key_id_is_preserved():
    assert Ed25519Signer.generate(key_id="ops-key-1").key_id == "ops-key-1"


def test_the_public_key_is_derived_from_the_private_key():
    signer = Ed25519Signer.generate()

    roundtripped = Ed25519Signer.from_public_bytes(signer.public_bytes())

    assert roundtripped.verify(PAYLOAD, signer.sign(PAYLOAD)) is True


def test_public_bytes_is_the_raw_32_byte_key():
    assert len(Ed25519Signer.generate().public_bytes()) == 32


def test_a_round_trip_through_private_bytes_preserves_the_identity():
    original = Ed25519Signer.generate(key_id="k")
    restored = Ed25519Signer.from_private_bytes(_private_bytes(original), key_id="k")

    assert restored.public_bytes() == original.public_bytes()
    assert restored.verify(PAYLOAD, original.sign(PAYLOAD)) is True


def _private_bytes(signer: Ed25519Signer) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return signer._private_key.private_bytes(  # noqa: SLF001 - no public accessor by design
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.mark.parametrize("raw", [b"", b"too-short", b"x" * 33])
def test_invalid_private_key_bytes_raise_a_signing_error(raw: bytes):
    with pytest.raises(SigningError, match="invalid Ed25519 private key bytes"):
        Ed25519Signer.from_private_bytes(raw)


@pytest.mark.parametrize("raw", [b"", b"too-short", b"x" * 33])
def test_invalid_public_key_bytes_raise_a_signing_error(raw: bytes):
    with pytest.raises(SigningError, match="invalid Ed25519 public key bytes"):
        Ed25519Signer.from_public_bytes(raw)


# --------------------------------------------------------------------------- #
# Signing and verifying
# --------------------------------------------------------------------------- #
def test_a_verify_only_signer_refuses_to_sign():
    """Constructed from a public key alone — it must fail loudly rather than
    emit anything a relying party could mistake for a signature."""
    verify_only = Ed25519Signer.from_public_bytes(Ed25519Signer.generate().public_bytes())

    with pytest.raises(SigningError, match="verify-only"):
        verify_only.sign(PAYLOAD)


def test_a_signature_over_a_different_payload_does_not_verify():
    signer = Ed25519Signer.generate()

    assert signer.verify(b"a different payload", signer.sign(PAYLOAD)) is False


def test_a_signature_from_a_different_key_does_not_verify():
    assert Ed25519Signer.generate().verify(PAYLOAD, Ed25519Signer.generate().sign(PAYLOAD)) is False


@pytest.mark.parametrize(
    "signature",
    ["not-hex", "zz", "abc", "", "unsigned_local"],
)
def test_a_signature_that_is_not_hex_is_rejected_without_raising(signature: str):
    """Signature material is attacker-controlled; a decode error must be a
    ``False`` verdict, not an exception escaping into the caller."""
    assert Ed25519Signer.generate().verify(PAYLOAD, signature) is False


def test_a_well_formed_hex_signature_of_the_wrong_length_is_rejected():
    assert Ed25519Signer.generate().verify(PAYLOAD, "ab" * 64) is False


def test_signatures_are_hex_encoded():
    signature = Ed25519Signer.generate().sign(PAYLOAD)

    assert len(signature) == 128
    bytes.fromhex(signature)  # raises if not hex


# --------------------------------------------------------------------------- #
# NullSigner — the explicit unsigned signer
# --------------------------------------------------------------------------- #
def test_null_signer_stamps_the_explicit_unsigned_marker():
    assert NullSigner().sign(PAYLOAD) == "unsigned_local"
    assert NullSigner().algorithm == "none"
    assert NullSigner().key_id == ""


def test_null_signer_never_reports_a_valid_signature():
    """An explicitly-unsigned receipt is never signature-valid — including
    against its own marker. Accepting unsigned receipts is a gate policy."""
    null = NullSigner()

    assert null.verify(PAYLOAD, "unsigned_local") is False
    assert null.verify(PAYLOAD, null.sign(PAYLOAD)) is False
    assert null.verify(b"", "") is False


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def test_make_signer_builds_an_ed25519_signer_and_forwards_kwargs():
    source = Ed25519Signer.generate()

    signer = make_signer("ed25519", public_key=_public_key(source), key_id="x")

    assert isinstance(signer, Ed25519Signer)
    assert signer.key_id == "x"


def _public_key(signer: Ed25519Signer):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PublicKey.from_public_bytes(signer.public_bytes())


def test_make_signer_builds_a_null_signer():
    assert isinstance(make_signer("none"), NullSigner)


@pytest.mark.parametrize("algorithm", ["", "rsa", "ED25519", "hmac-sha256"])
def test_make_signer_refuses_an_unknown_algorithm(algorithm: str):
    """Unknown algorithm must fail closed, not silently fall back to unsigned."""
    with pytest.raises(SigningError, match="unknown signing algorithm"):
        make_signer(algorithm)
