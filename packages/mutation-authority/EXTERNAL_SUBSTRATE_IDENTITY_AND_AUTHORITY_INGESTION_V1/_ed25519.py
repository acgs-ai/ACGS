"""Optional Ed25519 backend for ASYMMETRIC_VALIDATOR_KEYS_V1.

Uses the `cryptography` package when importable; this package's baseline
remains stdlib-only and every Ed25519 code path fails CLOSED when the backend
is absent: verification returns False (nothing routes on an unverifiable
signature) and signing raises. No hand-rolled cryptography.

Raw 32-byte keys, hex-encoded at rest. Public keys live IN the validator
registry events (they are public), so Ed25519 attestations are verifiable
without any keystore access — the third-party-verifiability gap of the HMAC
mode (threat model R2) closes for records signed in this mode.
"""

from __future__ import annotations

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    AVAILABLE = True
except ImportError:  # backend absent: sign raises, verify fails closed
    AVAILABLE = False


class Ed25519Unavailable(RuntimeError):
    """The optional Ed25519 backend is not installed."""


def generate() -> tuple[bytes, bytes]:
    """(private_bytes, public_bytes), both raw 32 bytes."""
    if not AVAILABLE:
        raise Ed25519Unavailable("cryptography package not installed")
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    return (
        priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def sign(private_bytes: bytes, message: str) -> str:
    if not AVAILABLE:
        raise Ed25519Unavailable("cryptography package not installed")
    return Ed25519PrivateKey.from_private_bytes(private_bytes).sign(message.encode("utf-8")).hex()


def verify(public_bytes: bytes, message: str, signature_hex: str) -> bool:
    """False on any failure — bad signature, malformed key, absent backend."""
    if not AVAILABLE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            bytes.fromhex(signature_hex), message.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
