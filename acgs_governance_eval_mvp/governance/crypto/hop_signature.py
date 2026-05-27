"""Phase 2 hop-signature primitives.

Per-delegation-hop Ed25519 signatures with domain separation.
See `docs/design/phase2-trace-crypto.md` §algorithm and ADR-0007 §1.

The signed bytes are always

.. code-block:: python

    DOMAIN_TAG_HOP + canonical_bytes(hop_payload)

so a signature minted with a different protocol's tag (or no tag at
all) does not verify here. The version suffix (``v2``) is bumped on
any ABI change to the hop payload shape.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes

DOMAIN_TAG_HOP: bytes = b"ACGS.AuthorizationTrace.Hop.v2\x00"


class HopSignatureError(ValueError):
    """Raised when a hop signature fails to verify."""


def _signed_bytes(payload: dict[str, Any]) -> bytes:
    return DOMAIN_TAG_HOP + canonical_bytes(payload)


def sign_hop(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> bytes:
    """Produce the Ed25519 signature for a hop payload.

    The payload is canonicalized via :func:`canonical_bytes`, then
    prepended with the domain tag before signing. Raises
    :class:`CanonicalizationError` if the payload contains
    uncanonicalizable types (rejected before any signing happens).
    """
    return private_key.sign(_signed_bytes(payload))


def verify_hop(
    public_key: Ed25519PublicKey,
    payload: dict[str, Any],
    signature: bytes,
) -> None:
    """Verify ``signature`` covers ``payload`` under ``public_key``.

    Raises :class:`HopSignatureError` on any failure: bad signature
    bytes, wrong key, tampered payload, or signature minted without
    the v2 domain tag.
    """
    try:
        public_key.verify(signature, _signed_bytes(payload))
    except InvalidSignature as exc:
        raise HopSignatureError("hop signature did not verify") from exc


__all__ = [
    "DOMAIN_TAG_HOP",
    "HopSignatureError",
    "sign_hop",
    "verify_hop",
]
