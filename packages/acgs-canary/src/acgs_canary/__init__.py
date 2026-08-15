"""acgs-canary — R0 tooling for licensee-keyed canary variants.

Private infrastructure only: restricted canary store, pool management,
variant-manifest and Merkle commitments, the acceptance ledger, external
anchoring interfaces, and the frozen protocol identity.

R0 does not rebuild the public dataset, publish anything, disclose canary
existence publicly, or complete a commercial issuance. See
docs/IMPLEMENTATION.md for the threat model and evidentiary limits.
"""

from .protocol import protocol_hash

__all__ = ["protocol_hash"]
__version__ = "0.1.0"
