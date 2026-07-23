"""Asymmetric receipt signing — opt-in closure of the recomputed-receipt residual.

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
Default deployments are unsigned; operators must engage signing explicitly.

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
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from gove_zone.errors import SigningError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Priv,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

_MISSING_DEP_MSG = "Ed25519 signing requires the 'crypto' extra: pip install gove-zone[crypto]"
_LIFECYCLE_DOMAIN = b"gove-zone:lifecycle-authorization:v1\x00"
_ED25519_PUBLIC_KEY_SIZE = 32
# The only algorithm with a public-key export/load primitive in this module. A
# lifecycle trust root must be reconstructible from exported bytes, so an
# authority whose verifier cannot be re-derived is refused rather than retained.
_LIFECYCLE_VERIFIER_ALGORITHM = "ed25519"


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


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


@dataclass(frozen=True, slots=True)
class LifecycleAttestation:
    """Independent authorization proof for one exact lifecycle record."""

    authority_id: str
    key_id: str
    algorithm: str
    payload_hash: str
    signature: str

    def __post_init__(self) -> None:
        for name in ("authority_id", "key_id", "algorithm", "signature"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"lifecycle attestation {name} is required")
        if (
            type(self.payload_hash) is not str
            or len(self.payload_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.payload_hash)
        ):
            raise ValueError("lifecycle attestation payload_hash must be SHA-256")
        if self.algorithm == "none":
            raise ValueError("unsigned lifecycle attestations are not trusted")

    @classmethod
    def issue(
        cls,
        payload: Mapping[str, Any],
        *,
        signer: ReceiptSigner,
        authority_id: str,
    ) -> LifecycleAttestation:
        if not isinstance(signer, ReceiptSigner):
            raise TypeError("lifecycle signer must implement ReceiptSigner")
        signing_payload = lifecycle_signing_payload(payload)
        return cls(
            authority_id=authority_id,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            payload_hash=hashlib.sha256(signing_payload).hexdigest(),
            signature=signer.sign(signing_payload),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LifecycleAttestation:
        if set(payload) != {
            "authority_id",
            "key_id",
            "algorithm",
            "payload_hash",
            "signature",
        }:
            raise ValueError("lifecycle attestation schema is invalid")
        return cls(
            authority_id=payload["authority_id"],
            key_id=payload["key_id"],
            algorithm=payload["algorithm"],
            payload_hash=payload["payload_hash"],
            signature=payload["signature"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
        }


def lifecycle_signing_payload(payload: Mapping[str, Any]) -> bytes:
    """Return domain-separated bytes for a record without its attestation."""

    if "lifecycle_attestation" in payload:
        raise ValueError("lifecycle signing payload must exclude its attestation")
    return _LIFECYCLE_DOMAIN + _canonical_payload(payload)


@dataclass(frozen=True, slots=True)
class _LifecycleTrustRoot:
    """Immutable verification material for one lifecycle authority.

    Holds only value types copied out of the caller's verifier at registry
    construction: no signer handle, no key object, no private key. Rebuilding a
    verifier from ``public_bytes`` is what makes the trust root independent of
    later mutation of the object it was snapshotted from.
    """

    authority_id: str
    key_id: str
    algorithm: str
    public_bytes: bytes

    def verifier(self) -> Ed25519Signer:
        return Ed25519Signer.from_public_bytes(self.public_bytes, key_id=self.key_id)


def _snapshot_verification_material(verifier: object) -> tuple[str, str, bytes]:
    """Copy immutable verification material out of a caller-owned verifier.

    Fails closed on anything that cannot be reduced to a fixed identity plus raw
    Ed25519 public bytes — including exports that hand back a mutable buffer,
    which the caller could rewrite after the registry was built.
    """

    key_id = getattr(verifier, "key_id", None)
    algorithm = getattr(verifier, "algorithm", None)
    if type(key_id) is not str or not key_id.strip():
        raise ValueError("lifecycle verifier identity is invalid")
    if type(algorithm) is not str or algorithm == "none" or not algorithm.strip():
        raise ValueError("lifecycle verifier identity is invalid")
    if algorithm != _LIFECYCLE_VERIFIER_ALGORITHM:
        raise ValueError("lifecycle verifier algorithm is unsupported")

    export = getattr(verifier, "public_bytes", None)
    if not callable(export):
        raise TypeError("lifecycle verifier must export raw public key bytes")
    try:
        raw = export()
    except Exception as exc:
        raise ValueError(f"lifecycle verifier public key export failed: {exc}") from exc
    # `type(...) is bytes` rejects bytearray/memoryview and bytes subclasses: a
    # caller-retained mutable buffer must never become a trust root.
    if type(raw) is not bytes:
        raise ValueError("lifecycle verifier public key export must be immutable bytes")
    if len(raw) != _ED25519_PUBLIC_KEY_SIZE:
        raise ValueError("lifecycle verifier public key must be 32 raw Ed25519 bytes")
    return key_id, algorithm, bytes(raw)


class LifecycleVerifierRegistry:
    """Frozen lifecycle-authority trust snapshot.

    The registry captures **verification material**, not verifier objects. Each
    authority is reduced at construction to ``(key_id, algorithm, public_bytes)``
    and every :meth:`verify` rebuilds a fresh verify-only signer from those
    bytes. Consequently, mutating the signer that was passed in — its public key,
    its ``key_id`` — or the mapping it came from cannot change what this registry
    trusts. Only material that survives snapshot + reload is ever trusted.

    Instances are immutable after construction: the trust roots are frozen
    values behind a read-only mapping, and attribute rebinding is refused.
    """

    __slots__ = ("_roots",)

    _roots: Mapping[str, _LifecycleTrustRoot]

    def __init__(
        self,
        entries: Mapping[str, ReceiptSigner] | Iterable[tuple[str, ReceiptSigner]],
    ) -> None:
        items = list(entries.items()) if isinstance(entries, Mapping) else list(entries)
        roots: dict[str, _LifecycleTrustRoot] = {}
        key_ids: dict[str, bytes] = {}
        for authority_id, verifier in items:
            if type(authority_id) is not str or not authority_id.strip():
                raise ValueError("lifecycle authority id is required")
            if authority_id in roots:
                raise ValueError("duplicate lifecycle authority id")
            if not isinstance(verifier, ReceiptSigner):
                raise TypeError("lifecycle verifier must implement ReceiptSigner")
            key_id, algorithm, public_bytes = _snapshot_verification_material(verifier)
            if key_id in key_ids:
                raise ValueError("duplicate lifecycle verifier key id")
            root = _LifecycleTrustRoot(
                authority_id=authority_id,
                key_id=key_id,
                algorithm=algorithm,
                public_bytes=public_bytes,
            )
            # Prove the snapshot is loadable now, so a malformed key fails at
            # construction rather than silently at verification time.
            root.verifier()
            roots[authority_id] = root
            key_ids[key_id] = public_bytes
        if not roots:
            raise ValueError("lifecycle verifier registry must not be empty")
        object.__setattr__(self, "_roots", MappingProxyType(roots))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("lifecycle verifier registry is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("lifecycle verifier registry is immutable")

    def verify(
        self,
        attestation: LifecycleAttestation,
        payload: Mapping[str, Any],
        *,
        forbidden_key_ids: Iterable[str] = (),
        forbidden_authority_ids: Iterable[str] = (),
    ) -> bool:
        if type(attestation) is not LifecycleAttestation:
            return False
        if attestation.key_id in frozenset(forbidden_key_ids):
            return False
        if attestation.authority_id in frozenset(forbidden_authority_ids):
            return False
        root = self._roots.get(attestation.authority_id)
        if root is None:
            return False
        if root.key_id != attestation.key_id or root.algorithm != attestation.algorithm:
            return False
        signing_payload = lifecycle_signing_payload(payload)
        if hashlib.sha256(signing_payload).hexdigest() != attestation.payload_hash:
            return False
        try:
            return root.verifier().verify(signing_payload, attestation.signature) is True
        except Exception:
            return False


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
        private_key: _Priv | None = None,
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
