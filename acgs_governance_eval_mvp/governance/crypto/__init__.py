"""Phase 2 cryptographic core for authorization trace verification.

See `docs/design/phase2-trace-crypto.md` and ADR-0007.
"""

from .canonical import CanonicalizationError, canonical_bytes
from .hop_signature import DOMAIN_TAG_HOP, HopSignatureError, sign_hop, verify_hop
from .principal_keys import (
    FilePrincipalKeyStore,
    KeyEntry,
    PrincipalKeyStore,
    UnknownSigningKeyError,
)

__all__ = [
    "CanonicalizationError",
    "DOMAIN_TAG_HOP",
    "FilePrincipalKeyStore",
    "HopSignatureError",
    "KeyEntry",
    "PrincipalKeyStore",
    "UnknownSigningKeyError",
    "canonical_bytes",
    "sign_hop",
    "verify_hop",
]
