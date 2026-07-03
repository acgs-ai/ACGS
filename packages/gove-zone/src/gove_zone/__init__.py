"""gove-zone: minimal governed agent runtime.

A small library that wraps AI agent tool calls with policy checks,
fail-closed decisions, replayable receipts, and a tamper-evident audit chain.
"""

from importlib import metadata as _metadata

from gove_zone.agent import ManagedAgent
from gove_zone.audit import GENESIS_HASH, AuditChainError, ChainHashAuditStore
from gove_zone.authz import (
    AuthzReason,
    AuthzRegistryError,
    PrincipalEntry,
    PrincipalRegistry,
    authz_enforce_from_env,
)
from gove_zone.benchmark_adapters import (
    agentdojo_scenarios_from_fixture,
    injecagent_scenarios_from_fixture,
    load_benchmark_suite,
)
from gove_zone.consumption import LedgerObservability, ReceiptConsumptionLedger
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
    AuthzDeniedError,
    ConsumptionLedgerError,
    DeniedError,
    EscalateError,
    GoveZoneError,
    PolicyError,
    ProductionProfileError,
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
    ReceiptValidationError,
    SigningError,
    UnknownToolError,
)
from gove_zone.escalation import (
    PendingApproval,
    approve_escalation,
    resume_with_receipt,
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
from gove_zone.mcp import mcp_tools_call, mcp_tools_list
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
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Receipt, Validator, safe_result_hash
from gove_zone.rejection import (
    alternative_from_record,
    discover_alternatives,
    rejection_dict,
)
from gove_zone.replay import (
    ReplayResult,
    find_event,
    replay_bundle,
    replay_call,
    replay_event,
    replay_from_side_store,
)
from gove_zone.replay_store import ReplaySideStore
from gove_zone.revocation import RevocationList, RevocationListError
from gove_zone.sandbox import (
    E2BSandbox,
    LocalProcessSandbox,
    SandboxError,
    SandboxProvider,
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
from gove_zone.verifier import (
    SCHEMA_VERSION,
    ProofPackRejectionReason,
    ProofPackVerificationResult,
    verify_proof_pack,
)
from gove_zone.workflow import (
    WorkflowDAG,
    WorkflowExecutor,
    WorkflowStep,
    WorkflowStepReceipt,
    verify_workflow_replay,
)
from gove_zone.yaml_policy import YAMLPolicy

# Single source of truth is the installed package metadata (pyproject `version`).
# The literal fallback matches that value for source/editable runs where the
# distribution is not installed; keep it in sync with pyproject on bumps.
try:
    __version__ = _metadata.version("gove-zone")
except _metadata.PackageNotFoundError:  # pragma: no cover - source/editable runs
    __version__ = "0.1.0a1"

__all__ = [
    "GENESIS_HASH",
    "AllowAllPolicy",
    "AuditChainError",
    "AuditError",
    "AuditEvent",
    "BoundaryPolicy",
    "AuthzDeniedError",
    "AuthzReason",
    "AuthzRegistryError",
    "ChainHashAuditStore",
    "PrincipalEntry",
    "PrincipalRegistry",
    "RevocationList",
    "RevocationListError",
    "authz_enforce_from_env",
    "CompositePolicy",
    "ConsumptionLedgerError",
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
    "GovernanceProfile",
    "GovernanceRequest",
    "GovernedExecutor",
    "GoveZoneError",
    "Kernel",
    "ManagedAgent",
    "SandboxProvider",
    "LocalProcessSandbox",
    "E2BSandbox",
    "SandboxError",
    "YAMLPolicy",
    "NullSigner",
    "PathBoundaryPolicy",
    "PendingApproval",
    "Policy",
    "PolicyBundleRef",
    "PolicyRule",
    "PolicyError",
    "ProductionProfileError",
    "ProofPackRejectionReason",
    "ProofPackVerificationResult",
    "ProposedAction",
    "Receipt",
    "ReceiptAlreadyUsedError",
    "LedgerObservability",
    "ReceiptConsumptionLedger",
    "ReceiptRejectionReason",
    "ReceiptSigner",
    "ReceiptValidationError",
    "ReceiptVerifier",
    "ReplayResult",
    "ReplaySideStore",
    "RuleSetPolicy",
    "SCHEMA_VERSION",
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
    "alternative_from_record",
    "approve_escalation",
    "discover_alternatives",
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
    "mcp_tools_call",
    "mcp_tools_list",
    "new_event_id",
    "normalize_path_context",
    "receipt_to_governed_action",
    "record_to_governed_action",
    "rejection_dict",
    "replay_bundle",
    "replay_call",
    "replay_event",
    "replay_from_side_store",
    "resume_with_receipt",
    "run_smoke",
    "safe_result_hash",
    "sha256_json",
    "tool_call_from_hook_payload",
    "tool_calls_from_hook_payload",
    "verify_proof_pack",
    "verify_workflow_replay",
]
