"""mutation-authority — Mutation Authority Governance Layer.

No Valid Mutation Decision Receipt, No Repository State Change.
"""

from .canonical import ABSENT
from .effect import ACCEPTED, REJECTED, CommitResult, EffectBinder
from .engine import ALLOW, DENY, Decision, DecisionEngine
from .intent import MutationIntent, SignedIntent
from .ledger import AuditLedger, LedgerIntegrityError
from .receipt import MutationDecisionReceipt
from .root import GovernanceRoot, RootIntegrityError
from .state import repository_violations

__all__ = [
    "ABSENT",
    "ACCEPTED",
    "ALLOW",
    "DENY",
    "REJECTED",
    "AuditLedger",
    "CommitResult",
    "Decision",
    "DecisionEngine",
    "EffectBinder",
    "GovernanceRoot",
    "LedgerIntegrityError",
    "MutationDecisionReceipt",
    "MutationIntent",
    "RootIntegrityError",
    "SignedIntent",
    "repository_violations",
]
