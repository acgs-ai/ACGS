"""gove-zone: minimal governed agent runtime.

A small library that wraps AI agent tool calls with policy checks,
fail-closed decisions, replayable receipts, and a tamper-evident audit chain.
"""

from gove_zone.audit import GENESIS_HASH, AuditChainError, ChainHashAuditStore
from gove_zone.benchmark_adapters import (
    agentdojo_scenarios_from_fixture,
    injecagent_scenarios_from_fixture,
    load_benchmark_suite,
)
from gove_zone.contracts import (
    AuditEvent,
    ExecutionBoundary,
    GovernanceRequest,
    PolicyBundleRef,
    ProposedAction,
    ReceiptVerifier,
    TenantPolicyBinding,
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
    ReceiptValidationError,
    SigningError,
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
from gove_zone.executor import (
    GovernedExecutor,
    execute_with_receipt,
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
from gove_zone.plan import WorkflowAuthorization
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
from gove_zone.receipt import DecisionReceipt, Receipt, Validator, safe_result_hash
from gove_zone.replay import (
    ReplayResult,
    find_event,
    replay_call,
    replay_event,
)
from gove_zone.signing import (
    Ed25519Signer,
    NullSigner,
    ReceiptSigner,
    make_signer,
)
from gove_zone.smoke import run_smoke
from gove_zone.tenant import (
    TenantPolicyStore,
    TransformPolicy,
    evaluate_tenant_action,
)
from gove_zone.tool import ToolCall, ToolRegistry, normalize_path_context
from gove_zone.workflow import (
    WorkflowDAG,
    WorkflowExecutor,
    WorkflowStep,
    WorkflowStepReceipt,
    verify_workflow_replay,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "GENESIS_HASH",
    "AllowAllPolicy",
    "AuditChainError",
    "AuditError",
    "AuditEvent",
    "BoundaryPolicy",
    "ChainHashAuditStore",
    "CompositePolicy",
    "Decision",
    "DecisionRecord",
    "DecisionReceipt",
    "DeniedError",
    "EvaluationReport",
    "EvaluationResult",
    "EvaluationScenario",
    "DenyAllPolicy",
    "Ed25519Signer",
    "EscalateError",
    "ExecutionBoundary",
    "GateMode",
    "GateModeError",
    "GovernanceRequest",
    "GovernedExecutor",
    "GoveZoneError",
    "Kernel",
    "NullSigner",
    "PathBoundaryPolicy",
    "Policy",
    "PolicyBundleRef",
    "PolicyRule",
    "PolicyError",
    "ProposedAction",
    "Receipt",
    "ReceiptSigner",
    "ReceiptValidationError",
    "ReceiptVerifier",
    "ReplayResult",
    "RuleSetPolicy",
    "SigningError",
    "TenantPolicyBinding",
    "TenantPolicyStore",
    "TransformPolicy",
    "ToolCall",
    "ToolRegistry",
    "UnknownToolError",
    "Validator",
    "WorkflowAuthorization",
    "WorkflowDAG",
    "WorkflowExecutor",
    "WorkflowStep",
    "WorkflowStepReceipt",
    "__version__",
    "agentdojo_scenarios_from_fixture",
    "emit_receipt_for_hook",
    "emit_receipts_for_hook",
    "evaluate_policy_scenarios",
    "evaluate_tenant_action",
    "execute_with_receipt",
    "injecagent_scenarios_from_fixture",
    "load_benchmark_suite",
    "load_evaluation_scenarios",
    "load_evaluation_suite",
    "canonical_json",
    "find_event",
    "make_signer",
    "new_event_id",
    "normalize_path_context",
    "receipt_to_governed_action",
    "record_to_governed_action",
    "replay_call",
    "replay_event",
    "run_smoke",
    "safe_result_hash",
    "sha256_json",
    "tool_call_from_hook_payload",
    "tool_calls_from_hook_payload",
    "verify_workflow_replay",
]
