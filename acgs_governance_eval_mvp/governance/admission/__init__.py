"""ACGS Admission Gate v0.1.

Pre-execution legitimacy layer for deterministic workflows. Exposes the
canonical :func:`decide` entry point plus :func:`verify_decision` for replay.
"""

from governance.admission.gate import decide
from governance.admission.policy import (
    PolicyBundle,
    load_policy_bundle,
    policy_bundle_hash,
)
from governance.admission.replay import (
    ReplayError,
    verify_decision,
    verify_decision_with_execution,
)

SCHEMA_VERSION = "admission_gate/0.1"

# Note: ``governance.admission.gate.make_receipt`` exists for advanced callers
# that need to mint a receipt outside of ``decide()``, but it is intentionally
# NOT in the public surface — it raises ValueError if you hand it a decision
# body that already has a receipt, which makes it a footgun in normal use.
__all__ = [
    "SCHEMA_VERSION",
    "PolicyBundle",
    "ReplayError",
    "decide",
    "load_policy_bundle",
    "policy_bundle_hash",
    "verify_decision",
    "verify_decision_with_execution",
]
