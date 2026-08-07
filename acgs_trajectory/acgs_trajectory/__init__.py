"""ACGS governed ingestion foundation (Phase 1).

Turns a Claude Code session JSONL into an immutable, provenance-stamped,
replayable ``governance_trajectory/v2`` object. Phase 1 is ingestion only:
no evaluation, scoring, labels, or packaging. See docs/adr/0001, docs/adr/0002.
"""

from .canonical import canonical_bytes, sha256_hex
from .errors import IngestError, QuarantineError

SCHEMA_VERSION = "governance_trajectory/v2"

__all__ = [
    "SCHEMA_VERSION",
    "canonical_bytes",
    "sha256_hex",
    "IngestError",
    "QuarantineError",
]
