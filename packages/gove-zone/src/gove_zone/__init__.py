"""gove-zone: minimal governed agent runtime.

A small library that wraps AI agent tool calls with policy checks,
fail-closed decisions, replayable receipts, and a tamper-evident audit chain.
"""

from typing import TYPE_CHECKING

from gove_zone.agent import ManagedAgent
from gove_zone.audit import GENESIS_HASH, AuditChainError, ChainHashAuditStore
from gove_zone.authorization import (
    EXECUTION_REFUSAL_EVIDENCE_SCHEMA,
    EXECUTION_REFUSAL_REASON_CODES,
    REFUSAL_EVIDENCE_SCHEMA,
    AuthorizationError,
    AuthorizationReasonCode,
    EvidenceRef,
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    ExecutionRefusalPhase,
    PolicyArtifactAttestation,
    PolicyResolver,
    PrincipalResolver,
    RefusalEvidence,
    ResolvedPolicy,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    StrictJSONBudgetError,
    VerifiedPrincipal,
    validate_strict_json_budget,
)
from gove_zone.benchmark_adapters import (
    agentdojo_scenarios_from_fixture,
    injecagent_scenarios_from_fixture,
    load_benchmark_suite,
)
from gove_zone.consumption import (
    ConsumptionRecord,
    ConsumptionState,
    ReceiptConsumptionStore,
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
    ActionTier,
    Decision,
    DecisionRecord,
    RecordKind,
    canonical_json,
    sha256_json,
)
from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    GoveZoneError,
    PolicyError,
    ProductionProfileError,
    ReceiptValidationError,
    SideEffectCallableAccessError,
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
    adapter_artifact_digest,
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
from gove_zone.managed_execution import (
    ManagedExecutionDispatcher,
    ManagedExecutionInputs,
    ManagedExecutionProposal,
    ManagedExecutionProvider,
    ManagedExecutionRefusal,
    ManagedExecutionResult,
    ManagedExecutionRoute,
)
from gove_zone.mcp_gateway import (
    MCP_APPROVE_TOOL,
    MCP_GATEWAY_EXECUTION_BOUNDARY,
    MCP_RESUME_TOOL,
    MCP_TOOLS_APPROVE_AUTHORITY,
    MCP_TOOLS_APPROVE_OPERATION,
    MCP_TOOLS_CALL_OPERATION,
    MCP_TOOLS_RESUME_OPERATION,
    MCPActionGateway,
    MCPDownstreamCredential,
    MCPDownstreamCredentialProvider,
    MCPDownstreamToolList,
    MCPDownstreamToolResult,
    MCPDownstreamTransport,
    MCPEscalationPolicy,
    MCPGatewayConfig,
    MCPGatewayReasonCode,
    MCPGatewayResponse,
    MCPGatewayStatus,
    MCPPendingApproval,
    MCPRiskClass,
    MCPSchemaError,
    MCPToolDefinition,
    MCPToolListResponse,
    MCPToolPolicy,
)
from gove_zone.mcp_identity import (
    MCPIdentityError,
    MCPIdentityPolicy,
    MCPIdentityReasonCode,
    MCPIdentityVerifier,
    MCPPrincipalContext,
    MCPTokenClaims,
    MCPTokenVerifier,
    VerifiedMCPIdentity,
)
from gove_zone.mcp_security import (
    MCPOriginError,
    MCPOriginReasonCode,
    MCPOriginValidator,
    ValidatedMCPOrigin,
)
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
from gove_zone.rejection import rejection_dict
from gove_zone.release_gate import (
    ReleaseDeployment,
    ReleaseEvidenceClaim,
    ReleaseEvidenceRequirement,
    ReleaseGate,
    ReleaseGatePolicy,
    ReleaseGateRequirements,
    ReleaseProofContext,
    ReleaseProofSinkError,
)
from gove_zone.release_proof import (
    CONSUMPTION_EVIDENCE_MODE,
    ReleaseProofError,
    ReleaseProofPack,
    ReleaseProofPackExporter,
    ReleaseProofSources,
    ReleaseProofVerification,
    export_release_proof_pack,
    replay_release_proof_pack,
    verify_release_proof_pack,
)
from gove_zone.replay import (
    ReplayResult,
    execution_refusal_error,
    find_event,
    replay_bundle,
    replay_call,
    replay_event,
    replay_from_side_store,
)
from gove_zone.replay_store import ReplaySideStore
from gove_zone.sandbox import E2BSandbox, LocalProcessSandbox, SandboxError, SandboxProvider
from gove_zone.side_effect_kernel import (
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.signing import (
    Ed25519Signer,
    LifecycleAttestation,
    LifecycleVerifierRegistry,
    NullSigner,
    ReceiptSigner,
    make_signer,
)
from gove_zone.smoke import run_smoke
from gove_zone.spend_proof import (
    SPEND_PROOF_LANES,
    SPEND_PROOF_PAYLOAD_FILES,
    SPEND_PROOF_SCHEMA,
    SpendProofError,
    SpendProofPack,
    SpendProofPayloads,
    export_spend_proof_pack,
    replay_spend_proof_pack,
    verify_spend_proof_pack,
)
from gove_zone.spend_proof_export import (
    SpendGenuineProofExport,
    export_genuine_spend_proof,
    replay_exported_spend_proof,
    verify_exported_spend_proof,
)
from gove_zone.tenant import (
    TenantPolicyStore,
    TransformPolicy,
    evaluate_tenant_action,
)
from gove_zone.tier import ToolTierRegistry, effective_action_tier
from gove_zone.tool import ToolCall, ToolEffect, ToolRegistry, normalize_path_context
from gove_zone.workflow import (
    WorkflowDAG,
    WorkflowExecutor,
    WorkflowStep,
    WorkflowStepReceipt,
    verify_workflow_replay,
)
from gove_zone.yaml_policy import YAMLPolicy

__version__ = "0.1.0.dev0"

from gove_zone.disaster_pocs import (
    DISASTER_POCS_CLAIM_BOUNDARY,
    DISASTER_POCS_REPORT_SCHEMA,
    DISASTER_POCS_SCENARIOS,
    DisasterPoCError,
    run_disaster_pocs,
)

if TYPE_CHECKING:
    from gove_zone.mcp_http_transport import (
        MCPFixedHTTPTransport as MCPFixedHTTPTransport,
    )
    from gove_zone.mcp_http_transport import (
        MCPHTTPTransportConfig as MCPHTTPTransportConfig,
    )
    from gove_zone.mcp_http_transport import (
        MCPHTTPTransportError as MCPHTTPTransportError,
    )
    from gove_zone.mcp_proof_export import MCPGenuineProofLease

_MCP_OPTIONAL_DEPENDENCY_ROOTS = frozenset(
    {"anyio", "cryptography", "httpcore", "httpx", "mcp", "starlette", "uvicorn"}
)
_MCP_HTTP_EXPORTS = frozenset(
    {"MCPFixedHTTPTransport", "MCPHTTPTransportConfig", "MCPHTTPTransportError"}
)


def __getattr__(name: str) -> object:
    if name in _MCP_HTTP_EXPORTS:
        try:
            from gove_zone import mcp_http_transport
        except ImportError as exc:
            missing = exc.name
            root = missing.partition(".")[0] if missing else None
            if root not in _MCP_OPTIONAL_DEPENDENCY_ROOTS:
                raise
            raise AttributeError(
                f"{name} requires optional MCP dependencies; install gove-zone[mcp]"
            ) from None
        return getattr(mcp_http_transport, name)
    if name != "MCPGenuineProofLease":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        from gove_zone.mcp_proof_export import MCPGenuineProofLease
    except ImportError as exc:
        missing = exc.name
        root = missing.partition(".")[0] if missing else None
        if root not in _MCP_OPTIONAL_DEPENDENCY_ROOTS:
            raise
        raise ImportError(
            "MCPGenuineProofLease requires optional MCP dependencies; install 'gove-zone[mcp]'",
            name=missing,
        ) from exc
    globals()[name] = MCPGenuineProofLease
    return MCPGenuineProofLease


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "DISASTER_POCS_CLAIM_BOUNDARY",
    "DISASTER_POCS_REPORT_SCHEMA",
    "DISASTER_POCS_SCENARIOS",
    "DisasterPoCError",
    "run_disaster_pocs",
    "MCPFixedHTTPTransport",
    "MCPHTTPTransportConfig",
    "MCPHTTPTransportError",
    "MCPGenuineProofLease",
    "GENESIS_HASH",
    "AllowAllPolicy",
    "AuthorizationError",
    "AuthorizationReasonCode",
    "AuditChainError",
    "AuditError",
    "AuditEvent",
    "BoundaryPolicy",
    "ChainHashAuditStore",
    "CompositePolicy",
    "CONSUMPTION_EVIDENCE_MODE",
    "ConsumptionRecord",
    "ConsumptionState",
    "ActionTier",
    "Decision",
    "DecisionRecord",
    "RecordKind",
    "ToolTierRegistry",
    "effective_action_tier",
    "DecisionReceipt",
    "DeniedError",
    "E2BSandbox",
    "EvaluationReport",
    "EvaluationResult",
    "EvaluationScenario",
    "DenyAllPolicy",
    "Ed25519Signer",
    "EvidenceRef",
    "EscalateError",
    "ExecutionBoundary",
    "ExecutionReasonCode",
    "ExecutionRefusalEvidence",
    "ExecutionRefusalPhase",
    "EXECUTION_REFUSAL_EVIDENCE_SCHEMA",
    "EXECUTION_REFUSAL_REASON_CODES",
    "execution_refusal_error",
    "GateMode",
    "GateModeError",
    "GovernanceProfile",
    "GovernanceRequest",
    "GovernedExecutor",
    "GoveZoneError",
    "Kernel",
    "LifecycleAttestation",
    "LifecycleVerifierRegistry",
    "LocalProcessSandbox",
    "ManagedAgent",
    "ManagedExecutionDispatcher",
    "ManagedExecutionInputs",
    "ManagedExecutionProposal",
    "ManagedExecutionProvider",
    "ManagedExecutionRefusal",
    "ManagedExecutionResult",
    "ManagedExecutionRoute",
    "MCPActionGateway",
    "MCPDownstreamCredential",
    "MCPDownstreamCredentialProvider",
    "MCPDownstreamToolList",
    "MCPDownstreamToolResult",
    "MCPDownstreamTransport",
    "MCPEscalationPolicy",
    "MCPGatewayConfig",
    "MCPGatewayReasonCode",
    "MCPGatewayResponse",
    "MCPGatewayStatus",
    "MCPPendingApproval",
    "MCPRiskClass",
    "MCPSchemaError",
    "MCPIdentityError",
    "MCPIdentityPolicy",
    "MCPIdentityReasonCode",
    "MCPIdentityVerifier",
    "MCPOriginError",
    "MCPOriginReasonCode",
    "MCPOriginValidator",
    "MCPPrincipalContext",
    "MCPTokenClaims",
    "MCPTokenVerifier",
    "MCPToolDefinition",
    "MCPToolListResponse",
    "MCPToolPolicy",
    "MCP_APPROVE_TOOL",
    "MCP_GATEWAY_EXECUTION_BOUNDARY",
    "MCP_RESUME_TOOL",
    "MCP_TOOLS_APPROVE_AUTHORITY",
    "MCP_TOOLS_APPROVE_OPERATION",
    "MCP_TOOLS_CALL_OPERATION",
    "MCP_TOOLS_RESUME_OPERATION",
    "NullSigner",
    "PathBoundaryPolicy",
    "PendingApproval",
    "Policy",
    "PolicyArtifactAttestation",
    "PolicyBundleRef",
    "PolicyRule",
    "PolicyResolver",
    "PrincipalResolver",
    "REFUSAL_EVIDENCE_SCHEMA",
    "RefusalEvidence",
    "PolicyError",
    "ProductionProfileError",
    "ProposedAction",
    "Receipt",
    "ReceiptConsumptionStore",
    "ReceiptGatedSideEffectExecutor",
    "ReceiptSigner",
    "ReceiptValidationError",
    "ReceiptVerifier",
    "ReleaseDeployment",
    "ReleaseEvidenceClaim",
    "ReleaseEvidenceRequirement",
    "ReleaseGate",
    "ReleaseGatePolicy",
    "ReleaseGateRequirements",
    "ReleaseProofContext",
    "ReleaseProofError",
    "ReleaseProofPack",
    "ReleaseProofPackExporter",
    "ReleaseProofSinkError",
    "ReleaseProofSources",
    "ReleaseProofVerification",
    "ReplayResult",
    "ReplaySideStore",
    "RuleSetPolicy",
    "SandboxError",
    "SandboxProvider",
    "SigningError",
    "SPEND_PROOF_LANES",
    "SPEND_PROOF_PAYLOAD_FILES",
    "SPEND_PROOF_SCHEMA",
    "SpendGenuineProofExport",
    "SpendProofError",
    "SpendProofPack",
    "SpendProofPayloads",
    "ResolvedPolicy",
    "ResolvedPolicyRef",
    "SideEffectAuthorization",
    "SideEffectCallableAccessError",
    "SideEffectAuthorizationKernel",
    "SideEffectExecutionContext",
    "SideEffectExecutionError",
    "SideEffectRequest",
    "StrictJSONBudgetError",
    "TenantPolicyBinding",
    "TenantPolicyStore",
    "TransformPolicy",
    "ToolCall",
    "ToolEffect",
    "ToolRegistry",
    "UnknownToolError",
    "Validator",
    "VerifiedPrincipal",
    "VerifiedMCPIdentity",
    "ValidatedMCPOrigin",
    "WorkflowAuthorization",
    "WorkflowDAG",
    "WorkflowExecutor",
    "WorkflowStep",
    "WorkflowStepReceipt",
    "YAMLPolicy",
    "__version__",
    "agentdojo_scenarios_from_fixture",
    "approve_escalation",
    "adapter_artifact_digest",
    "emit_receipt_for_hook",
    "emit_receipts_for_hook",
    "evaluate_policy_scenarios",
    "evaluate_tenant_action",
    "export_release_proof_pack",
    "execute_with_receipt",
    "export_genuine_spend_proof",
    "export_spend_proof_pack",
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
    "rejection_dict",
    "replay_bundle",
    "replay_call",
    "replay_event",
    "replay_from_side_store",
    "replay_release_proof_pack",
    "resume_with_receipt",
    "replay_exported_spend_proof",
    "replay_spend_proof_pack",
    "run_smoke",
    "safe_result_hash",
    "sha256_json",
    "tool_call_from_hook_payload",
    "tool_calls_from_hook_payload",
    "validate_strict_json_budget",
    "verify_workflow_replay",
    "verify_exported_spend_proof",
    "verify_spend_proof_pack",
    "verify_release_proof_pack",
]
