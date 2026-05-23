"""Phase 2 cryptographic core for authorization trace verification.

See `docs/design/phase2-trace-crypto.md` and ADR-0007.
"""

from .canonical import CanonicalizationError, canonical_bytes
from .principal_keys import (
    FilePrincipalKeyStore,
    KeyEntry,
    PrincipalKeyStore,
    UnknownSigningKeyError,
)

__all__ = [
    "CanonicalizationError",
    "FilePrincipalKeyStore",
    "KeyEntry",
    "PrincipalKeyStore",
    "UnknownSigningKeyError",
    "canonical_bytes",
]
