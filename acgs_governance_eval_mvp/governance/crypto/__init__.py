"""Phase 2 cryptographic core for authorization trace verification.

See `docs/design/phase2-trace-crypto.md` and ADR-0007.
"""

from .canonical import CanonicalizationError, canonical_bytes

__all__ = ["CanonicalizationError", "canonical_bytes"]
