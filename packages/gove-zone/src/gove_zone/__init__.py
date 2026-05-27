"""gove-zone: minimal governed agent runtime.

A small library that wraps AI agent tool calls with policy checks,
fail-closed decisions, replayable receipts, and a tamper-evident audit chain.
"""

from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from gove_zone.decision import (
    Decision,
    DecisionRecord,
    canonical_json,
    sha256_json,
)
from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    GoveZoneError,
    PolicyError,
    UnknownToolError,
)
from gove_zone.frontend_contract import (
    receipt_to_governed_action,
    record_to_governed_action,
)
from gove_zone.kernel import Kernel
from gove_zone.policy import (
    AllowAllPolicy,
    BoundaryPolicy,
    CompositePolicy,
    DenyAllPolicy,
    Policy,
    new_event_id,
)
from gove_zone.receipt import Receipt, safe_result_hash
from gove_zone.replay import (
    ReplayResult,
    find_event,
    replay_call,
    replay_event,
)
from gove_zone.tool import ToolCall, ToolRegistry

__version__ = "0.1.0.dev0"

__all__ = [
    "GENESIS_HASH",
    "AllowAllPolicy",
    "AuditError",
    "BoundaryPolicy",
    "ChainHashAuditStore",
    "CompositePolicy",
    "Decision",
    "DecisionRecord",
    "DeniedError",
    "DenyAllPolicy",
    "EscalateError",
    "GoveZoneError",
    "Kernel",
    "Policy",
    "PolicyError",
    "Receipt",
    "ReplayResult",
    "ToolCall",
    "ToolRegistry",
    "UnknownToolError",
    "__version__",
    "canonical_json",
    "find_event",
    "new_event_id",
    "receipt_to_governed_action",
    "record_to_governed_action",
    "replay_call",
    "replay_event",
    "safe_result_hash",
    "sha256_json",
]
