"""gove-zone: minimal governed agent runtime.

A small library that wraps AI agent tool calls with policy checks,
fail-closed decisions, replayable receipts, and a tamper-evident audit chain.
"""

from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from gove_zone.benchmark_adapters import (
    agentdojo_scenarios_from_fixture,
    injecagent_scenarios_from_fixture,
    load_benchmark_suite,
)
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
from gove_zone.evaluation import (
    EvaluationReport,
    EvaluationResult,
    EvaluationScenario,
    evaluate_policy_scenarios,
    load_evaluation_scenarios,
    load_evaluation_suite,
)
from gove_zone.frontend_contract import (
    receipt_to_governed_action,
    record_to_governed_action,
)
from gove_zone.integration import (
    GateMode,
    GateModeError,
    emit_receipt_for_hook,
    emit_receipts_for_hook,
    tool_call_from_hook_payload,
    tool_calls_from_hook_payload,
)
from gove_zone.kernel import Kernel
from gove_zone.policy import (
    AllowAllPolicy,
    BoundaryPolicy,
    CompositePolicy,
    DenyAllPolicy,
    PathBoundaryPolicy,
    Policy,
    PolicyRule,
    RuleSetPolicy,
    new_event_id,
)
from gove_zone.receipt import Receipt, safe_result_hash
from gove_zone.replay import (
    ReplayResult,
    find_event,
    replay_call,
    replay_event,
)
from gove_zone.tool import ToolCall, ToolRegistry, normalize_path_context

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
    "EvaluationReport",
    "EvaluationResult",
    "EvaluationScenario",
    "DenyAllPolicy",
    "EscalateError",
    "GateMode",
    "GateModeError",
    "GoveZoneError",
    "Kernel",
    "PathBoundaryPolicy",
    "Policy",
    "PolicyRule",
    "PolicyError",
    "Receipt",
    "ReplayResult",
    "RuleSetPolicy",
    "ToolCall",
    "ToolRegistry",
    "UnknownToolError",
    "__version__",
    "agentdojo_scenarios_from_fixture",
    "emit_receipt_for_hook",
    "emit_receipts_for_hook",
    "evaluate_policy_scenarios",
    "injecagent_scenarios_from_fixture",
    "load_benchmark_suite",
    "load_evaluation_scenarios",
    "load_evaluation_suite",
    "canonical_json",
    "find_event",
    "new_event_id",
    "normalize_path_context",
    "receipt_to_governed_action",
    "record_to_governed_action",
    "replay_call",
    "replay_event",
    "safe_result_hash",
    "sha256_json",
    "tool_call_from_hook_payload",
    "tool_calls_from_hook_payload",
]
