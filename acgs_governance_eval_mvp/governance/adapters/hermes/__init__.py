"""Hermes host adapter — folded in from the retired ``hermes_acgs_bundle/``.

Runtime constitutional governance hooks for a Hermes-style tool lifecycle
(pre-tool / post-tool / final-answer), backed by the bundle's chain-hashed
evidence writer. Behavior is fail-closed: evaluation errors DENY (or
SOFT_BLOCK for final checks) unless the integrator explicitly opts out.

``CONSTITUTION_MIN_PATH`` points at the shipped minimal reference
constitution (YAML-compatible JSON, loadable without PyYAML).
"""

from __future__ import annotations

from pathlib import Path

from governance.adapters.hermes.evidence_writer import (
    ChainEvidenceWriter,
    GovernEvent,
    merkle_root,
)
from governance.adapters.hermes.middleware import (
    ALLOW,
    DENY,
    REDACT,
    REQUIRE_HUMAN,
    REWRITE,
    SOFT_BLOCK_WITH_EXPLANATION,
    DEFAULT_CONSTITUTION,
    GovernanceDecision,
    HermesACGSMiddleware,
)

CONSTITUTION_MIN_PATH = Path(__file__).resolve().parent / "constitution.min.yaml"

__all__ = [
    "ALLOW",
    "DENY",
    "REDACT",
    "REQUIRE_HUMAN",
    "REWRITE",
    "SOFT_BLOCK_WITH_EXPLANATION",
    "CONSTITUTION_MIN_PATH",
    "ChainEvidenceWriter",
    "DEFAULT_CONSTITUTION",
    "GovernEvent",
    "GovernanceDecision",
    "HermesACGSMiddleware",
    "merkle_root",
]
