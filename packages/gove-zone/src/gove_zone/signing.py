"""Asymmetric receipt signing — the production-profile closure of the recomputed-receipt residual.

The receipt schema binds goal/action/authority/validator/args/policy/boundary
into ``receipt_hash``. But a hash is recomputable: any process that can rebuild
the canonical dict can mint a "valid" ``receipt_hash``. Ed25519 asymmetric signing
closes that residual **when engaged**: the signer signs ``receipt_hash`` with a
PRIVATE key; the gate verifies with the PUBLIC key. Only the private-key holder
can sign, so a recomputed-hash forgery is cryptographically infeasible.

**Precondition for closure.** The residual is closed only when:
  (a) receipts are issued with a private-key signer (``from_record(signer=…)``), AND
  (b) the gate is configured with a matching public-key verifier AND
      ``require_signature=True``.
This is the **default** posture: the production profile
(``GovernanceProfile.production`` / unset ``GOVE_ZONE_PROFILE``) makes the gates
default to ``require_signature=True``, and a production gate with no verifier fails
closed loud. The unsigned path is the explicit dev-mode opt-out
(``GovernanceProfile.dev`` / ``require_signature=False``).

**Residuals this mechanism does NOT address:**
  - Private-key **custody**: if the signing key is compromised, an attacker can
    issue valid-looking receipts. Key custody is the operator's responsibility.
  - Key **distribution / trust establishment**: the verifier mapping is static;
    there is no PKI, no certificate chain, and no trust-store bootstrapping.
  - **Revocation**: a compromised key cannot be revoked; the verifier mapping must
    be updated and redeployed by the operator.

``cryptography`` is an optional dependency behind the ``crypto`` extra and is
lazy-imported. The core library stays stdlib-only: importing this module never
imports ``cryptography`` until a signer is actually constructed.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from gove_zone.errors import SigningError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

_MISSING_DEP_MSG = "Ed25519 signing requires the 'crypto' extra: pip install gove-zone[crypto]"


@runtime_checkable
class ReceiptSigner(Protocol):
    """Pluggable signer/verifier for receipt hashes.

    A signer binds an ``algorithm`` and a ``key_id`` (both bound into
    ``receipt_hash`` at issuance, giving anti-downgrade) and can ``sign`` a
    payload (``receipt_hash`` bytes) and ``verify`` a signature against one. A
    verify-only signer's ``sign`` raises :class:`SigningError`.
    """

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class Ed25519Signer:
    """Ed25519 signer/verifier. Construct with a private key (sign+verify) or a
    public key only (verify-only).

    ``cryptography`` is lazy-imported in every method that touches it; if it is
    not installed a :class:`SigningError` is raised pointing at the ``crypto``
    extra.
    """

    algorithm = "ed25519"

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
        key_id: str | None = None,
    ) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise SigningError(_MISSING_DEP_MSG) from exc

        if private_key is None and public_key is None:
            raise SigningError("Ed25519Signer requires a private or public key")

        self._private_key = private_key
        if public_key is not None:
            self._public_key = public_key
        else:
            # private_key is non-None here (guarded above); derive its public key.
            assert private_key is not None
            self._public_key = private_key.public_key()

        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = key_id if key_id else hashlib.sha256(pub_bytes).hexdigest()[:16]

    @property
    def key_id(self) -> str:
        return self._key_id

    @classmethod
    def generate(cls, key_id: str | None = None) -> Ed25519Signer:
        """Generate a fresh keypair (test/dev convenience)."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise SigningError(_MISSING_DEP_MSG) from exc
        return cls(private_key=ed25519.Ed25519PrivateKey.generate(), key_id=key_id)

    @classmethod
    def from_private_bytes(cls, raw: bytes, key_id: str | None = None) -> Ed25519Signer:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise SigningError(_MISSING_DEP_MSG) from exc
        try:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise SigningError(f"invalid Ed25519 private key bytes: {exc}") from exc
        return cls(private_key=private_key, key_id=key_id)

    @classmethod
    def from_public_bytes(cls, raw: bytes, key_id: str | None = None) -> Ed25519Signer:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise SigningError(_MISSING_DEP_MSG) from exc
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise SigningError(f"invalid Ed25519 public key bytes: {exc}") from exc
        return cls(public_key=public_key, key_id=key_id)

    def public_bytes(self) -> bytes:
        """Raw 32-byte public key (for handing a verifier to the gate)."""
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> str:
        if self._private_key is None:
            raise SigningError("this Ed25519Signer is verify-only (no private key)")
        return self._private_key.sign(payload).hex()

    def verify(self, payload: bytes, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            sig_bytes = bytes.fromhex(signature)
        except (ValueError, TypeError):
            return False
        try:
            self._public_key.verify(sig_bytes, payload)
            return True
        except InvalidSignature:
            return False


class NullSigner:
    """The explicit unsigned signer. ``sign`` stamps ``"unsigned_local"``;
    ``verify`` always returns False.

    An explicitly-unsigned receipt is never "signature-valid". Acceptance of
    unsigned receipts is controlled by ``require_signature=False`` at the gate,
    NOT by ``NullSigner.verify`` returning True.
    """

    algorithm = "none"
    key_id = ""

    def sign(self, payload: bytes) -> str:
        return "unsigned_local"

    def verify(self, payload: bytes, signature: str) -> bool:
        return False


def make_signer(algorithm: str, **kwargs: object) -> ReceiptSigner:
    """Factory: map an algorithm string to a signer (lazy construction).

    ``"ed25519"`` → :class:`Ed25519Signer` (kwargs forwarded);
    ``"none"`` → :class:`NullSigner`.
    """
    if algorithm == "ed25519":
        return Ed25519Signer(**kwargs)  # type: ignore[arg-type]
    if algorithm == "none":
        return NullSigner()
    raise SigningError(f"unknown signing algorithm: {algorithm!r}")
