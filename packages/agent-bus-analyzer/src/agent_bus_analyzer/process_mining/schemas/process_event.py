"""Strict, versioned normalized event contract for AI process mining."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from agent_bus_analyzer.process_mining._canonical import sha256_canonical, utc_datetime

PROCESS_EVENT_SCHEMA_VERSION: Literal["1.0"] = "1.0"
COLLECTOR_VERSION: Literal["1.0"] = "1.0"

NonEmptyStr = Annotated[str, Field(min_length=1, max_length=512)]
TenantId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$",
    ),
]
Sha256Hex = Annotated[
    str,
    Field(pattern=r"^[a-f0-9]{64}$", description="lower-case SHA-256 hex digest"),
]
PermissionId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@*-]{0,255}$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProcessEventKind(StrEnum):
    """Taxonomy spanning people, agents, governance, and failure signals."""

    HUMAN = "human"
    AGENT = "agent"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    POLICY_EVALUATION = "policy_evaluation"
    DECISION_RECEIPT = "decision_receipt"
    EVIDENCE_BUNDLE = "evidence_bundle"
    AUDIT = "audit"
    FAILURE = "failure"
    EXCEPTION = "exception"
    APPROVAL = "approval"
    DENIAL = "denial"


class ActorKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class GovernanceDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    ESCALATE = "escalate"
    INVESTIGATE = "investigate"


class SideEffectClassification(StrEnum):
    """Trusted classification of whether an observed tool can cause a side effect.

    ``UNKNOWN`` is intentionally distinct from read-only.  Observation payloads
    are not an authority source and therefore cannot downgrade an unknown tool
    execution to ``CONFIRMED_READ_ONLY``.
    """

    CONFIRMED_SIDE_EFFECT = "confirmed_side_effect"
    CONFIRMED_READ_ONLY = "confirmed_read_only"
    UNKNOWN = "unknown"


class SourceKind(StrEnum):
    ANALYZER_EVENT = "analyzer_event"
    GOVE_ZONE_AUDIT = "gove_zone_audit"
    API_EVENT = "api_event"
    TRAJECTORY_ROW = "trajectory_row"


class SourceChainStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    NOT_APPLICABLE = "not_applicable"


class CompletenessStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    NOT_APPLICABLE = "not_applicable"


class CaseIdSource(StrEnum):
    EXPLICIT_CASE_ID = "explicit_case_id"
    CORRELATION_ID = "correlation_id"
    CONVERSATION_ID = "conversation_id"
    SESSION_ID = "session_id"
    TRAJECTORY_ID = "trajectory_id"
    DECISION_REQUEST_HASH = "decision_request_hash"
    SOURCE_EVENT_ID = "source_event_id"
    CONTENT_HASH = "content_hash"


class CorrelationConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EventLifecycle(StrEnum):
    SCHEDULED = "scheduled"
    STARTED = "started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"
    UNKNOWN = "unknown"


class GovernanceReference(StrEnum):
    ACTOR_AUTHORITY_ID = "actor_authority_id"
    TOOL_NAME = "tool_name"
    ARGUMENT_HASH = "argument_hash"
    POLICY_ID = "policy_id"
    POLICY_VERSION = "policy_version"
    POLICY_BUNDLE_ID = "policy_bundle_id"
    POLICY_HASH = "policy_hash"
    EXECUTION_BOUNDARY = "execution_boundary"
    DECISION_RECEIPT_ID = "decision_receipt_id"
    DECISION_RECEIPT_HASH = "decision_receipt_hash"
    EVIDENCE_BUNDLE_IDS = "evidence_bundle_ids"
    AUDIT_EVENT_ID = "audit_event_id"
    AUDIT_EVENT_HASH = "audit_event_hash"


REQUIRED_SIDE_EFFECT_REFERENCES: tuple[GovernanceReference, ...] = tuple(GovernanceReference)


class EventProvenance(_StrictModel):
    source_kind: SourceKind
    source_system: NonEmptyStr
    source_record_id: NonEmptyStr
    source_schema_version: NonEmptyStr | None = None
    raw_record_hash: Sha256Hex
    collector_version: Literal["1.0"] = COLLECTOR_VERSION


class SourceIntegrity(_StrictModel):
    chain_status: SourceChainStatus
    source_event_hash: Sha256Hex | None = None
    source_previous_hash: Sha256Hex | None = None
    algorithm: Literal["sha256"] = "sha256"

    @model_validator(mode="after")
    def validate_chain_claim(self) -> Self:
        if self.chain_status is SourceChainStatus.VERIFIED and self.source_event_hash is None:
            raise ValueError("verified source chain requires source_event_hash")
        if self.chain_status is SourceChainStatus.NOT_APPLICABLE and (
            self.source_event_hash is not None or self.source_previous_hash is not None
        ):
            raise ValueError("not_applicable source chain cannot carry chain hashes")
        return self


class GovernanceContext(_StrictModel):
    """Governance linkage for an observed action; gaps remain explicit."""

    is_side_effect: bool = False
    side_effect_classification: SideEffectClassification = SideEffectClassification.UNKNOWN
    actor_authority_id: NonEmptyStr | None = None
    tool_name: NonEmptyStr | None = None
    argument_hash: Sha256Hex | None = None
    decision: GovernanceDecision | None = None
    policy_id: NonEmptyStr | None = None
    policy_version: NonEmptyStr | None = None
    policy_bundle_id: NonEmptyStr | None = None
    policy_hash: Sha256Hex | None = None
    execution_boundary: NonEmptyStr | None = None
    decision_receipt_id: NonEmptyStr | None = None
    decision_receipt_hash: Sha256Hex | None = None
    evidence_bundle_ids: tuple[NonEmptyStr, ...] = ()
    audit_event_id: NonEmptyStr | None = None
    audit_event_hash: Sha256Hex | None = None
    replay_verified: bool | None = None

    def model_post_init(self, __context: object) -> None:
        """Preserve legacy ``True`` while refusing to trust legacy ``False``.

        Older producers only emitted a boolean.  ``True`` remains a conservative
        confirmed-side-effect assertion; ``False`` means only that no side
        effect was declared and therefore normalizes to ``UNKNOWN``.  When the
        typed classification is supplied without the legacy projection, derive
        the projection so callers cannot accidentally create contradictory
        representations.
        """
        fields_set = self.model_fields_set
        if "side_effect_classification" not in fields_set:
            classification = (
                SideEffectClassification.CONFIRMED_SIDE_EFFECT
                if self.is_side_effect is True
                else SideEffectClassification.UNKNOWN
            )
            object.__setattr__(self, "side_effect_classification", classification)
        if "is_side_effect" not in fields_set:
            object.__setattr__(
                self,
                "is_side_effect",
                self.side_effect_classification is SideEffectClassification.CONFIRMED_SIDE_EFFECT,
            )

    @model_validator(mode="after")
    def require_consistent_side_effect_projection(self) -> Self:
        expected = self.side_effect_classification is SideEffectClassification.CONFIRMED_SIDE_EFFECT
        if self.is_side_effect is not expected:
            raise ValueError("is_side_effect must match side_effect_classification")
        return self

    @field_validator("evidence_bundle_ids")
    @classmethod
    def require_stable_evidence_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_bundle_ids must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("evidence_bundle_ids must use deterministic sorted order")
        return value


class EvidenceCompleteness(_StrictModel):
    status: CompletenessStatus
    missing_governance_references: tuple[GovernanceReference, ...] = ()
    evidence_coverage: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        missing = self.missing_governance_references
        if self.status is CompletenessStatus.INCOMPLETE and not missing:
            raise ValueError("incomplete evidence must identify missing references")
        if self.status is not CompletenessStatus.INCOMPLETE and missing:
            raise ValueError("only incomplete evidence may identify missing references")
        if self.status in {CompletenessStatus.COMPLETE, CompletenessStatus.NOT_APPLICABLE}:
            if self.evidence_coverage != 1.0:
                raise ValueError("complete or not_applicable evidence coverage must be 1.0")
        return self


def governance_completeness(governance: GovernanceContext) -> EvidenceCompleteness:
    """Derive evidence completeness rather than trusting a collector claim."""
    if not governance.is_side_effect:
        return EvidenceCompleteness(
            status=CompletenessStatus.NOT_APPLICABLE,
            missing_governance_references=(),
            evidence_coverage=1.0,
        )
    present: dict[GovernanceReference, bool] = {
        GovernanceReference.ACTOR_AUTHORITY_ID: governance.actor_authority_id is not None,
        GovernanceReference.TOOL_NAME: governance.tool_name is not None,
        GovernanceReference.ARGUMENT_HASH: governance.argument_hash is not None,
        GovernanceReference.POLICY_ID: governance.policy_id is not None,
        GovernanceReference.POLICY_VERSION: governance.policy_version is not None,
        GovernanceReference.POLICY_BUNDLE_ID: governance.policy_bundle_id is not None,
        GovernanceReference.POLICY_HASH: governance.policy_hash is not None,
        GovernanceReference.EXECUTION_BOUNDARY: governance.execution_boundary is not None,
        GovernanceReference.DECISION_RECEIPT_ID: governance.decision_receipt_id is not None,
        GovernanceReference.DECISION_RECEIPT_HASH: governance.decision_receipt_hash is not None,
        GovernanceReference.EVIDENCE_BUNDLE_IDS: bool(governance.evidence_bundle_ids),
        GovernanceReference.AUDIT_EVENT_ID: governance.audit_event_id is not None,
        GovernanceReference.AUDIT_EVENT_HASH: governance.audit_event_hash is not None,
    }
    missing = tuple(
        reference for reference in REQUIRED_SIDE_EFFECT_REFERENCES if not present[reference]
    )
    if not missing:
        return EvidenceCompleteness(
            status=CompletenessStatus.COMPLETE,
            missing_governance_references=(),
            evidence_coverage=1.0,
        )
    return EvidenceCompleteness(
        status=CompletenessStatus.INCOMPLETE,
        missing_governance_references=missing,
        evidence_coverage=(len(REQUIRED_SIDE_EFFECT_REFERENCES) - len(missing))
        / len(REQUIRED_SIDE_EFFECT_REFERENCES),
    )


class _ProcessEventCore(_StrictModel):
    schema_version: Literal["1.0"] = PROCESS_EVENT_SCHEMA_VERSION
    event_id: NonEmptyStr
    tenant_id: TenantId
    case_id: NonEmptyStr
    case_id_source: CaseIdSource
    correlation_confidence: CorrelationConfidence
    process_id: NonEmptyStr | None = None
    process_name: NonEmptyStr | None = None
    sequence: int | None = Field(default=None, ge=0)
    parent_event_id: NonEmptyStr | None = None
    correlation_references: tuple[NonEmptyStr, ...] = ()
    kind: ProcessEventKind
    activity: NonEmptyStr
    occurred_at: AwareDatetime
    ingested_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    lifecycle: EventLifecycle = EventLifecycle.COMPLETED
    outcome: EventOutcome = EventOutcome.UNKNOWN
    actor_id: NonEmptyStr | None = None
    actor_kind: ActorKind = ActorKind.UNKNOWN
    agent_id: NonEmptyStr | None = None
    tool_id: NonEmptyStr | None = None
    api_id: NonEmptyStr | None = None
    permission_ids: tuple[PermissionId, ...] = ()
    organization_id: NonEmptyStr | None = None
    provenance: EventProvenance
    integrity: SourceIntegrity
    governance: GovernanceContext
    completeness: EvidenceCompleteness
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("occurred_at", "ingested_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime) -> datetime:
        return utc_datetime(value)

    @field_validator("correlation_references")
    @classmethod
    def validate_correlation_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("correlation_references must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("correlation_references must use deterministic sorted order")
        return value

    @field_validator("permission_ids")
    @classmethod
    def validate_permission_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("permission_ids must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("permission_ids must use deterministic sorted order")
        return value

    @model_validator(mode="after")
    def reject_unsupported_correlation_claims(self) -> Self:
        if self.case_id_source in {CaseIdSource.SOURCE_EVENT_ID, CaseIdSource.CONTENT_HASH}:
            if self.correlation_confidence is not CorrelationConfidence.LOW:
                raise ValueError("source-id/hash case inference must have low confidence")
        return self


class ProcessEvent(_ProcessEventCore):
    """One immutable normalized event with a self-verifying content digest."""

    normalization_hash: Sha256Hex

    def normalization_payload(self) -> dict[str, object]:
        # Ingestion time is operational metadata.  The append-store envelope
        # binds it, while excluding it here keeps source normalization
        # deterministic across retries.
        return self.model_dump(mode="python", exclude={"normalization_hash", "ingested_at"})

    @model_validator(mode="after")
    def verify_derived_fields(self) -> Self:
        expected_completeness = governance_completeness(self.governance)
        if self.completeness != expected_completeness:
            raise ValueError("completeness does not match governance references")
        expected_hash = sha256_canonical(self.normalization_payload())
        if self.normalization_hash != expected_hash:
            raise ValueError("normalization_hash does not match canonical normalized event")
        return self


def validated_event_snapshot(event: ProcessEvent) -> ProcessEvent:
    """Revalidate an isolated serialized snapshot at an integrity boundary.

    ``frozen=True`` prevents field reassignment but cannot make arbitrary JSON
    containers deeply immutable.  Serializing and parsing again both severs
    mutable references and reruns the normalization-hash validator without
    changing the event's hash contract.
    """
    return ProcessEvent.model_validate_json(event.model_dump_json())


def build_process_event(data: Mapping[str, object]) -> ProcessEvent:
    """Validate core data, derive completeness and the normalization hash."""
    mutable = dict(data)
    governance_raw = mutable.get("governance")
    governance = (
        governance_raw
        if isinstance(governance_raw, GovernanceContext)
        else GovernanceContext.model_validate(governance_raw)
    )
    mutable["governance"] = governance
    mutable["completeness"] = governance_completeness(governance)
    core = _ProcessEventCore.model_validate(mutable)
    payload = core.model_dump(mode="python")
    normalization_payload = {key: value for key, value in payload.items() if key != "ingested_at"}
    return ProcessEvent(**payload, normalization_hash=sha256_canonical(normalization_payload))
