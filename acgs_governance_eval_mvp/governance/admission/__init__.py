"""ACGS Admission Gate v0.1.

Pre-execution legitimacy layer for deterministic workflows. Exposes the
canonical :func:`decide` entry point plus :func:`verify_decision` for replay.
"""

from governance.admission.gate import decide, make_receipt
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

__all__ = [
    "SCHEMA_VERSION",
    "PolicyBundle",
    "ReplayError",
    "decide",
    "load_policy_bundle",
    "make_receipt",
    "policy_bundle_hash",
    "verify_decision",
    "verify_decision_with_execution",
]
