"""Phase 2 cryptographic core for authorization trace verification.

See `docs/design/phase2-trace-crypto.md` and ADR-0007.
"""

from .canonical import CanonicalizationError, canonical_bytes
from .hop_signature import DOMAIN_TAG_HOP, HopSignatureError, sign_hop, verify_hop
from .hop_verify import (
    CLOCK_SKEW_TOLERANCE,
    HopVerificationError,
    MAX_TRACE_TTL_DEFAULT,
    verify_hop_against_entry,
)
from .principal_keys import (
    FilePrincipalKeyStore,
    KeyEntry,
    PrincipalKeyStore,
    UnknownSigningKeyError,
)

__all__ = [
    "CLOCK_SKEW_TOLERANCE",
    "CanonicalizationError",
    "DOMAIN_TAG_HOP",
    "FilePrincipalKeyStore",
    "HopSignatureError",
    "HopVerificationError",
    "KeyEntry",
    "MAX_TRACE_TTL_DEFAULT",
    "PrincipalKeyStore",
    "UnknownSigningKeyError",
    "canonical_bytes",
    "sign_hop",
    "verify_hop",
    "verify_hop_against_entry",
]
