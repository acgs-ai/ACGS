"""Signing adapter: reuses gove-zone Ed25519 with canary-specific binding.

Reuse decision (design: "reuse the repository's Ed25519 implementation and
key-policy enforcement where possible"): the primitive is
``gove_zone.signing.Ed25519Signer``; this module adds only what the canary
protocol requires on top of it —

- **domain-bound payloads**: every signature covers a length-prefixed
  tuple (domain, ledger_id, protocol hash, role, purpose, payload) so a
  signature can never be replayed across ledgers, roles, protocol
  versions, or purposes;
- **key policy**: production T1 completion requires the organizational
  key, which R0 does not possess. Ephemeral keys must be explicitly
  declared as such and are refused for production issuance.
"""

from __future__ import annotations

from dataclasses import dataclass

from gove_zone.signing import Ed25519Signer

from .canonical import length_prefixed
from .errors import KeyPolicyError, SignatureError

SIG_DOMAIN = b"acgs-canary/v1/sig"

ROLE_ISSUER = "issuer"
ROLE_LICENSEE = "licensee"
_ROLES = frozenset({ROLE_ISSUER, ROLE_LICENSEE})

PURPOSE_ISSUE = "variant-issue"
PURPOSE_COUNTERSIGN = "variant-countersign"
_PURPOSES = frozenset({PURPOSE_ISSUE, PURPOSE_COUNTERSIGN})

KEY_CLASS_EPHEMERAL_TEST = "ephemeral-test"
KEY_CLASS_ORGANIZATION = "organization"
_KEY_CLASSES = frozenset({KEY_CLASS_EPHEMERAL_TEST, KEY_CLASS_ORGANIZATION})


@dataclass(frozen=True)
class BoundKey:
    """An Ed25519 signer plus its declared key class."""

    signer: Ed25519Signer
    key_class: str

    def __post_init__(self) -> None:
        if self.key_class not in _KEY_CLASSES:
            raise KeyPolicyError(f"unknown key class: {self.key_class!r}")

    def __repr__(self) -> str:  # never print key material
        return f"BoundKey(key_id={self.signer.key_id!r}, key_class={self.key_class!r})"

    __str__ = __repr__


def ephemeral_test_key(key_id: str | None = None) -> BoundKey:
    """Generate a clearly-marked ephemeral test key."""
    return BoundKey(
        signer=Ed25519Signer.generate(key_id=key_id), key_class=KEY_CLASS_EPHEMERAL_TEST
    )


def organization_key_available() -> bool:
    """R0 truth: the organizational signing key is not configured."""
    return False


def enforce_production_policy(key: BoundKey, *, production: bool) -> None:
    """Refuse non-organizational keys for production issuance. Fail closed.

    ``key_class`` is caller-supplied metadata, not an authenticated key
    identity, so the declared class alone is never sufficient: production
    additionally requires the provisioned organizational key, which R0
    does not possess. A generated key labeled "organization" is refused.
    """
    if not production:
        return
    if key.key_class != KEY_CLASS_ORGANIZATION:
        raise KeyPolicyError(
            "production T1 issuance requires the organizational signing key; "
            "it is not configured in R0 and ephemeral keys are refused"
        )
    if not organization_key_available():
        raise KeyPolicyError(
            "key declares the organization class but no organizational signing "
            "key is provisioned (R0); the declaration cannot be authenticated, "
            "so production issuance is refused"
        )


def signing_payload(
    *,
    ledger_id: str,
    protocol_sha256: str,
    role: str,
    purpose: str,
    payload: bytes,
) -> bytes:
    """The exact bytes a role signs. Unambiguous by length prefixing."""
    if role not in _ROLES:
        raise SignatureError(f"unknown signing role: {role!r}")
    if purpose not in _PURPOSES:
        raise SignatureError(f"unknown signing purpose: {purpose!r}")
    if not isinstance(payload, bytes) or not payload:
        raise SignatureError("payload must be non-empty bytes")
    return length_prefixed(
        SIG_DOMAIN,
        ledger_id.encode("utf-8"),
        protocol_sha256.encode("ascii"),
        role.encode("ascii"),
        purpose.encode("ascii"),
        payload,
    )


def sign(
    key: BoundKey,
    *,
    ledger_id: str,
    protocol_sha256: str,
    role: str,
    purpose: str,
    payload: bytes,
) -> dict[str, str]:
    """Produce signature metadata for a ledger entry."""
    data = signing_payload(
        ledger_id=ledger_id,
        protocol_sha256=protocol_sha256,
        role=role,
        purpose=purpose,
        payload=payload,
    )
    return {
        "algorithm": key.signer.algorithm,
        "key_id": key.signer.key_id,
        "key_class": key.key_class,
        "public_key_hex": key.signer.public_bytes().hex(),
        "role": role,
        "purpose": purpose,
        "signature_hex": key.signer.sign(data),
    }


def verify(
    sig_meta: dict[str, str],
    *,
    ledger_id: str,
    protocol_sha256: str,
    role: str,
    purpose: str,
    payload: bytes,
) -> bool:
    """Verify signature metadata against the expected binding. Fail closed.

    The caller's expected role/purpose must equal the recorded ones — a
    signature recorded for one role cannot verify as another even if the
    key matches (role-confusion rejection).
    """
    required = {
        "algorithm",
        "key_id",
        "key_class",
        "public_key_hex",
        "role",
        "purpose",
        "signature_hex",
    }
    if set(sig_meta) != required:
        raise SignatureError("malformed signature metadata")
    if sig_meta["algorithm"] != "ed25519":
        raise SignatureError(f"unsupported algorithm: {sig_meta['algorithm']!r}")
    if sig_meta["role"] != role or sig_meta["purpose"] != purpose:
        return False
    try:
        pub = bytes.fromhex(sig_meta["public_key_hex"])
    except ValueError as exc:
        raise SignatureError("malformed public key hex") from exc
    verifier = Ed25519Signer.from_public_bytes(pub, key_id=sig_meta["key_id"])
    data = signing_payload(
        ledger_id=ledger_id,
        protocol_sha256=protocol_sha256,
        role=role,
        purpose=purpose,
        payload=payload,
    )
    return verifier.verify(data, sig_meta["signature_hex"])
