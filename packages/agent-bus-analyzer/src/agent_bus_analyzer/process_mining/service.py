"""Tenant-scoped, observer-only Process Intelligence application service.

The service composes normalized events and pure analytical miners.  It does
not expose policy activation, receipt issuance, tool execution, or any other
authorization capability.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from enum import StrEnum
from threading import RLock
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.analytics.metrics import analyze_bottlenecks
from agent_bus_analyzer.process_mining.analytics.recommendations import discover_policy_gaps
from agent_bus_analyzer.process_mining.errors import (
    ConflictingDuplicateError,
    TenantIsolationError,
)
from agent_bus_analyzer.process_mining.integrations.gove_zone import (
    ProductionConformanceProvider,
)
from agent_bus_analyzer.process_mining.miners.bpmn import export_bpmn
from agent_bus_analyzer.process_mining.miners.conformance import (
    CaptureState,
    ConformanceAttestation,
    ConformanceEvidence,
    ConformanceFinding,
    ConformanceOutcome,
    CorrelationState,
    ProofStatus,
    SideEffectState,
    attest_conformance,
    canonical_attestation_hash,
    hash_only_evidence_from_event,
)
from agent_bus_analyzer.process_mining.miners.discovery import discover_dfg
from agent_bus_analyzer.process_mining.miners.risk import (
    RiskSignal,
    detect_behavior_changes,
)
from agent_bus_analyzer.process_mining.miners.variants import detect_variants
from agent_bus_analyzer.process_mining.schemas.process_event import (
    CorrelationConfidence,
    ProcessEvent,
    ProcessEventKind,
    SideEffectClassification,
    SourceChainStatus,
)
from agent_bus_analyzer.process_mining.storage.event_store import (
    AppendResult,
    ChainVerificationResult,
)
from agent_bus_analyzer.process_mining.storage.protocols import ProcessEventStore

DEFAULT_PROCESS_ID = "discovered-process"
SERVICE_VERSION: Literal["process-service-1.0"] = "process-service-1.0"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProcessSummary(_StrictModel):
    tenant_id: str
    process_id: str
    process_name: str | None = None
    event_count: int = Field(ge=1)
    case_count: int = Field(ge=1)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evidence_coverage: float = Field(ge=0.0, le=1.0)
    source_chain_status: SourceChainStatus
    snapshot_id: str
    service_version: Literal["process-service-1.0"] = SERVICE_VERSION
    analytical_only: Literal[True] = True
    executable_authority: Literal[False] = False


class ProcessList(_StrictModel):
    items: tuple[ProcessSummary, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)


class ActivityView(_StrictModel):
    activity: str
    count: int = Field(ge=1)


class DirectlyFollowsView(_StrictModel):
    source: str
    target: str
    count: int = Field(ge=1)
    average_duration_seconds: float | None = Field(default=None, ge=0.0)
    p50_duration_seconds: float | None = Field(default=None, ge=0.0)
    p95_duration_seconds: float | None = Field(default=None, ge=0.0)
    excluded_duration_count: int = Field(ge=0)


class ProcessDetail(_StrictModel):
    summary: ProcessSummary
    algorithm_version: str
    activities: tuple[ActivityView, ...]
    directly_follows: tuple[DirectlyFollowsView, ...]
    incomplete_case_count: int = Field(ge=0)
    excluded_case_ids: tuple[str, ...]


class VariantView(_StrictModel):
    signature: tuple[str, ...]
    case_ids: tuple[str, ...]
    count: int = Field(ge=1)
    frequency: float = Field(ge=0.0, le=1.0)
    average_duration_seconds: float = Field(ge=0.0)
    incomplete_case_count: int = Field(ge=0)


class VariantList(_StrictModel):
    tenant_id: str
    process_id: str
    snapshot_id: str
    algorithm_version: str
    items: tuple[VariantView, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)


class ComplianceReport(_StrictModel):
    tenant_id: str
    process_id: str
    snapshot_id: str
    findings: tuple[ConformanceFinding, ...]
    relevant_event_count: int = Field(ge=0)
    allow_count: int = Field(ge=0)
    deny_count: int = Field(ge=0)
    investigate_count: int = Field(ge=0)
    compliance_score: float | None = Field(default=None, ge=0.0, le=1.0)
    verification_posture: Literal[
        "not_applicable",
        "non_authoritative",
        "production_verified",
        "mixed",
    ]
    analytical_only: Literal[True] = True
    executable_authority: Literal[False] = False


class RiskSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFinding(_StrictModel):
    risk_id: str
    tenant_id: str
    process_id: str
    case_id: str
    event_id: str
    severity: RiskSeverity
    category: str
    reasons: tuple[str, ...]
    evidence_references: tuple[str, ...]
    snapshot_id: str
    analytical_only: Literal[True] = True
    executable_authority: Literal[False] = False


class RiskList(_StrictModel):
    items: tuple[RiskFinding, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)


class PolicyRecommendation(_StrictModel):
    recommendation_id: str
    tenant_id: str
    process_id: str
    title: str
    rationale: str
    source_event_ids: tuple[str, ...]
    evidence_references: tuple[str, ...]
    status: Literal["proposal_only"] = "proposal_only"
    lifecycle_state: Literal["inactive"] = "inactive"
    algorithm_version: str | None = None
    activation_available: Literal[False] = False
    analytical_only: Literal[True] = True
    executable_authority: Literal[False] = False


class RecommendationList(_StrictModel):
    items: tuple[PolicyRecommendation, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)


ConformanceProvider = Callable[[ProcessEvent], ConformanceAttestation]
BaselineProvider = Callable[[str, str], Iterable[ProcessEvent] | None]


def _process_id(event: ProcessEvent) -> str:
    return event.process_id or DEFAULT_PROCESS_ID


def _validated_event_copy(event: ProcessEvent) -> ProcessEvent:
    """Revalidate the content hash and sever nested mutable aliases."""
    return ProcessEvent.model_validate_json(event.model_dump_json())


def _default_side_effect_state(event: ProcessEvent) -> SideEffectState:
    classification = event.governance.side_effect_classification
    if (
        event.kind is ProcessEventKind.TOOL_RESULT
        and classification is SideEffectClassification.CONFIRMED_SIDE_EFFECT
    ):
        return SideEffectState.EXECUTED
    # Neither an unknown observation nor a tool-call request proves execution
    # or an effective block.  Both remain fail-closed unknown.
    return SideEffectState.UNKNOWN


def _is_conformance_relevant(event: ProcessEvent) -> bool:
    return event.kind in {ProcessEventKind.TOOL_CALL, ProcessEventKind.TOOL_RESULT} and (
        event.governance.side_effect_classification
        is not SideEffectClassification.CONFIRMED_READ_ONLY
    )


def build_hash_only_conformance_evidence(event: ProcessEvent) -> ConformanceEvidence:
    """Project a normalized event without upgrading references into proof."""
    capture_raw = event.attributes.get("capture_state")
    capture = (
        CaptureState(str(capture_raw))
        if isinstance(capture_raw, str) and capture_raw in {state.value for state in CaptureState}
        else CaptureState.COMPLETE
    )
    correlation = (
        CorrelationState.EXACT
        if event.correlation_confidence is CorrelationConfidence.HIGH
        else CorrelationState.AMBIGUOUS
    )
    return hash_only_evidence_from_event(
        event,
        side_effect_state=_default_side_effect_state(event),
        capture_state=capture,
        correlation_state=correlation,
    )


def _default_conformance(event: ProcessEvent) -> ConformanceAttestation:
    return attest_conformance(build_hash_only_conformance_evidence(event))


class ProcessIntelligenceService:
    """Deterministic in-process application service keyed by trusted tenant.

    A deployment supplies one service instance populated from verified
    normalized events.  The optional ``ProcessEventStore`` persists newly ingested
    normalized events; source logs and runtime governance remain untouched.
    """

    def __init__(
        self,
        events: Iterable[ProcessEvent] = (),
        *,
        event_store: ProcessEventStore | None = None,
        conformance_provider: ConformanceProvider | None = None,
        baseline_events: Iterable[ProcessEvent] = (),
        baseline_provider: BaselineProvider | None = None,
    ) -> None:
        self._event_store = event_store
        self._conformance_provider = conformance_provider or _default_conformance
        self._attestation_verifier = (
            self._conformance_provider.attestation_verifier
            if isinstance(self._conformance_provider, ProductionConformanceProvider)
            else None
        )
        self._events: dict[str, dict[str, dict[str, ProcessEvent]]] = {}
        self._baseline_events: dict[str, dict[str, dict[str, ProcessEvent]]] = {}
        self._baseline_provider = baseline_provider
        self._lock = RLock()
        for event in sorted(
            events,
            key=lambda item: (item.tenant_id, _process_id(item), item.event_id),
        ):
            self._register(event)
        for event in sorted(
            baseline_events,
            key=lambda item: (item.tenant_id, _process_id(item), item.event_id),
        ):
            self._register_baseline(event)

    def _ensure_tenant_loaded(self, tenant_id: str) -> None:
        """Refresh only the tenant resolved from trusted caller identity.

        The current JSONL store has no cheap chain-head probe, so this is an
        O(n) verified refresh on each top-level query. That explicit cost is
        preferable to returning a permanently stale dashboard after an
        external observer appends to the same tenant partition.
        """
        if self._event_store is None:
            return
        verified_events = self._event_store.list_events(tenant_id=tenant_id)
        with self._lock:
            for event in verified_events:
                self._register(event)

    def _register(self, event: ProcessEvent) -> None:
        snapshot = _validated_event_copy(event)
        tenant_events = self._events.setdefault(snapshot.tenant_id, {})
        process_events = tenant_events.setdefault(_process_id(snapshot), {})
        existing = process_events.get(snapshot.event_id)
        if existing is not None and existing.normalization_hash != snapshot.normalization_hash:
            raise ConflictingDuplicateError(
                f"event_id {snapshot.event_id!r} has conflicting normalized content"
            )
        process_events[snapshot.event_id] = snapshot

    def _register_baseline(self, event: ProcessEvent) -> None:
        snapshot = _validated_event_copy(event)
        tenant_events = self._baseline_events.setdefault(snapshot.tenant_id, {})
        process_events = tenant_events.setdefault(_process_id(snapshot), {})
        existing = process_events.get(snapshot.event_id)
        if existing is not None and existing.normalization_hash != snapshot.normalization_hash:
            raise ConflictingDuplicateError(
                f"baseline event_id {snapshot.event_id!r} has conflicting content"
            )
        process_events[snapshot.event_id] = snapshot

    def _baseline_for_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> tuple[ProcessEvent, ...]:
        supplied = (
            self._baseline_provider(tenant_id, process_id)
            if self._baseline_provider is not None
            else None
        )
        if supplied is None:
            with self._lock:
                values = tuple(
                    self._baseline_events.get(tenant_id, {}).get(process_id, {}).values()
                )
        else:
            values = tuple(supplied)
        values = tuple(_validated_event_copy(event) for event in values)
        if any(
            event.tenant_id != tenant_id or _process_id(event) != process_id for event in values
        ):
            raise TenantIsolationError(
                "baseline provider returned an event outside the requested tenant/process"
            )
        return tuple(sorted(values, key=lambda event: (event.occurred_at, event.event_id)))

    def ingest_event(self, event: ProcessEvent) -> AppendResult | None:
        """Persist and register one normalized event; never mutate its source."""
        snapshot = _validated_event_copy(event)
        with self._lock:
            result = self._event_store.append(snapshot) if self._event_store is not None else None
            self._register(snapshot)
            return result

    def _events_for_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> tuple[ProcessEvent, ...] | None:
        self._ensure_tenant_loaded(tenant_id)
        with self._lock:
            process_events = self._events.get(tenant_id, {}).get(process_id)
            if process_events is None:
                return None
            return tuple(
                _validated_event_copy(event)
                for event in sorted(
                    process_events.values(),
                    key=lambda item: (item.occurred_at, item.event_id),
                )
            )

    def events_for_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> tuple[ProcessEvent, ...] | None:
        """Return immutable normalized events within one tenant boundary."""
        return self._events_for_process(tenant_id=tenant_id, process_id=process_id)

    @staticmethod
    def _snapshot_id(
        tenant_id: str,
        process_id: str,
        events: Iterable[ProcessEvent],
    ) -> str:
        return sha256_canonical(
            {
                "tenant_id": tenant_id,
                "process_id": process_id,
                "event_hashes": sorted(event.normalization_hash for event in events),
                "service_version": SERVICE_VERSION,
            }
        )

    @classmethod
    def _summary(
        cls,
        tenant_id: str,
        process_id: str,
        events: tuple[ProcessEvent, ...],
    ) -> ProcessSummary:
        names = sorted({event.process_name for event in events if event.process_name is not None})
        statuses = {event.integrity.chain_status for event in events}
        if statuses == {SourceChainStatus.VERIFIED}:
            source_chain_status = SourceChainStatus.VERIFIED
        elif statuses == {SourceChainStatus.NOT_APPLICABLE}:
            source_chain_status = SourceChainStatus.NOT_APPLICABLE
        else:
            source_chain_status = SourceChainStatus.UNVERIFIED
        side_effects = tuple(event for event in events if event.governance.is_side_effect)
        evidence_coverage = (
            sum(event.completeness.evidence_coverage for event in side_effects) / len(side_effects)
            if side_effects
            else 1.0
        )
        return ProcessSummary(
            tenant_id=tenant_id,
            process_id=process_id,
            process_name=names[0] if len(names) == 1 else None,
            event_count=len(events),
            case_count=len({event.case_id for event in events}),
            started_at=min(event.occurred_at for event in events),
            completed_at=max(event.occurred_at for event in events),
            evidence_coverage=evidence_coverage,
            source_chain_status=source_chain_status,
            snapshot_id=cls._snapshot_id(tenant_id, process_id, events),
        )

    def list_processes(
        self,
        *,
        tenant_id: str,
        offset: int = 0,
        limit: int = 50,
    ) -> ProcessList:
        self._ensure_tenant_loaded(tenant_id)
        with self._lock:
            tenant_events = self._events.get(tenant_id, {})
            summaries = tuple(
                self._summary(
                    tenant_id,
                    process_id,
                    tuple(process_events.values()),
                )
                for process_id, process_events in sorted(tenant_events.items())
            )
        return ProcessList(
            items=summaries[offset : offset + limit],
            total=len(summaries),
            offset=offset,
            limit=limit,
        )

    def get_process(self, *, tenant_id: str, process_id: str) -> ProcessDetail | None:
        events = self._events_for_process(tenant_id=tenant_id, process_id=process_id)
        if events is None:
            return None
        graph = discover_dfg(events, process_id=process_id)
        metrics = analyze_bottlenecks(events)
        incomplete_case_ids = {issue.case_id for issue in graph.incomplete_cases} | {
            event.case_id
            for event in events
            if event.integrity.chain_status is SourceChainStatus.UNVERIFIED
        }
        # Build metrics to force deterministic bottleneck validation even though
        # this compact endpoint currently exposes only the incomplete count.
        incomplete_count = max(metrics.incomplete_case_count, len(incomplete_case_ids))
        return ProcessDetail(
            summary=self._summary(tenant_id, process_id, events),
            algorithm_version=graph.algorithm_version,
            activities=tuple(
                ActivityView(activity=item.activity, count=item.count)
                for item in graph.activity_counts
            ),
            directly_follows=tuple(
                DirectlyFollowsView(
                    source=edge.source,
                    target=edge.target,
                    count=edge.count,
                    average_duration_seconds=edge.average_duration_seconds,
                    p50_duration_seconds=edge.p50_duration_seconds,
                    p95_duration_seconds=edge.p95_duration_seconds,
                    excluded_duration_count=edge.excluded_duration_count,
                )
                for edge in graph.edges
            ),
            incomplete_case_count=incomplete_count,
            excluded_case_ids=graph.excluded_case_ids,
        )

    def get_variants(
        self,
        *,
        tenant_id: str,
        process_id: str,
        offset: int = 0,
        limit: int = 50,
    ) -> VariantList | None:
        events = self._events_for_process(tenant_id=tenant_id, process_id=process_id)
        if events is None:
            return None
        analysis = detect_variants(events)
        items = tuple(
            VariantView(
                signature=item.signature,
                case_ids=item.case_ids,
                count=item.count,
                frequency=item.frequency,
                average_duration_seconds=item.average_duration_seconds,
                incomplete_case_count=item.incomplete_case_count,
            )
            for item in analysis.variants
        )
        return VariantList(
            tenant_id=tenant_id,
            process_id=process_id,
            snapshot_id=self._snapshot_id(tenant_id, process_id, events),
            algorithm_version=analysis.algorithm_version,
            items=items[offset : offset + limit],
            total=len(items),
            offset=offset,
            limit=limit,
        )

    def get_compliance(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> ComplianceReport | None:
        events = self._events_for_process(tenant_id=tenant_id, process_id=process_id)
        if events is None:
            return None
        findings_list: list[ConformanceFinding] = []
        for event in events:
            if not _is_conformance_relevant(event):
                continue
            attestation = ConformanceAttestation.model_validate_json(
                self._conformance_provider(event).model_dump_json()
            )
            evidence = attestation.evidence
            if evidence.tenant_id != event.tenant_id:
                raise TenantIsolationError(
                    "conformance provider returned evidence for another tenant"
                )
            if (
                evidence.case_id != event.case_id
                or evidence.event_id != event.event_id
                or evidence.event_normalization_hash != event.normalization_hash
            ):
                raise ValueError(
                    "conformance attestation identity does not match the observed event"
                )
            observed_bindings = (
                evidence.observed_action,
                evidence.observed_argument_hash,
                evidence.observed_audit_hash,
                evidence.observed_actor,
                evidence.observed_execution_boundary,
                evidence.observed_policy_bundle_id,
                evidence.observed_policy_hash,
            )
            event_bindings = (
                event.governance.tool_name,
                event.governance.argument_hash,
                event.governance.audit_event_hash,
                event.actor_id,
                event.governance.execution_boundary,
                event.governance.policy_bundle_id,
                event.governance.policy_hash,
            )
            if observed_bindings != event_bindings:
                raise ValueError("conformance attestation bindings do not match the observed event")
            finding = attest_conformance(evidence).finding
            verifier = self._attestation_verifier
            if verifier is not None and attestation.seal is not None:
                try:
                    verification = verifier(attestation)
                except Exception:
                    verification = None
                if (
                    verification is not None
                    and verification.verified
                    and verification.production_profile_verified
                    and verification.attestation_hash == canonical_attestation_hash(attestation)
                    and verification.verifier_name == attestation.seal.issuer_id
                    and verification.verifier_version == attestation.seal.verifier_version
                    and verification.key_id_hash == attestation.seal.key_id_hash
                ):
                    finding = attestation.finding
            findings_list.append(finding)
        findings = tuple(findings_list)
        allow_count = sum(item.outcome is ConformanceOutcome.ALLOW for item in findings)
        deny_count = sum(item.outcome is ConformanceOutcome.DENY for item in findings)
        investigate_count = sum(item.outcome is ConformanceOutcome.INVESTIGATE for item in findings)
        determinate_count = allow_count + deny_count
        score = (
            allow_count / determinate_count
            if findings and investigate_count == 0 and determinate_count > 0
            else None
        )
        verification_posture: Literal[
            "not_applicable",
            "non_authoritative",
            "production_verified",
            "mixed",
        ]
        if not findings:
            verification_posture = "not_applicable"
        elif all(item.production_profile_verified for item in findings):
            verification_posture = "production_verified"
        elif all(not item.receipt_verifier_succeeded for item in findings):
            verification_posture = "non_authoritative"
        else:
            verification_posture = "mixed"
        return ComplianceReport(
            tenant_id=tenant_id,
            process_id=process_id,
            snapshot_id=self._snapshot_id(tenant_id, process_id, events),
            findings=findings,
            relevant_event_count=len(findings),
            allow_count=allow_count,
            deny_count=deny_count,
            investigate_count=investigate_count,
            compliance_score=score,
            verification_posture=verification_posture,
        )

    def _risks_for_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
        events: tuple[ProcessEvent, ...],
    ) -> tuple[RiskFinding, ...]:
        report = self.get_compliance(tenant_id=tenant_id, process_id=process_id)
        assert report is not None
        risks: list[RiskFinding] = []
        for finding in report.findings:
            if finding.outcome is ConformanceOutcome.ALLOW:
                continue
            severity = (
                RiskSeverity.CRITICAL
                if finding.outcome is ConformanceOutcome.DENY
                else RiskSeverity.HIGH
                if finding.proof_status is ProofStatus.FAILED
                else RiskSeverity.MEDIUM
            )
            reasons = tuple(reason.value for reason in finding.reasons)
            risks.append(
                RiskFinding(
                    risk_id=sha256_canonical(
                        {
                            "tenant_id": tenant_id,
                            "process_id": process_id,
                            "event_id": finding.event_id,
                            "reasons": reasons,
                        }
                    ),
                    tenant_id=tenant_id,
                    process_id=process_id,
                    case_id=finding.case_id,
                    event_id=finding.event_id,
                    severity=severity,
                    category="governance_conformance",
                    reasons=reasons,
                    evidence_references=tuple(
                        reference
                        if isinstance(reference, str)
                        else (f"{reference.reference_type.value}:{reference.reference_id}")
                        for reference in finding.evidence_references
                    ),
                    snapshot_id=report.snapshot_id,
                )
            )
        covered = {risk.event_id for risk in risks}
        for event in events:
            if event.event_id in covered or event.kind not in {
                ProcessEventKind.FAILURE,
                ProcessEventKind.EXCEPTION,
            }:
                continue
            risks.append(
                RiskFinding(
                    risk_id=sha256_canonical(
                        {
                            "tenant_id": tenant_id,
                            "process_id": process_id,
                            "event_id": event.event_id,
                            "kind": event.kind.value,
                        }
                    ),
                    tenant_id=tenant_id,
                    process_id=process_id,
                    case_id=event.case_id,
                    event_id=event.event_id,
                    severity=RiskSeverity.HIGH,
                    category="observed_failure",
                    reasons=(event.kind.value,),
                    evidence_references=(),
                    snapshot_id=report.snapshot_id,
                )
            )
        baseline = self._baseline_for_process(
            tenant_id=tenant_id,
            process_id=process_id,
        )
        if baseline:
            behavior = detect_behavior_changes(baseline, events)
            risks.extend(
                self._risk_from_signal(
                    signal,
                    tenant_id=tenant_id,
                    process_id=process_id,
                    snapshot_id=report.snapshot_id,
                )
                for signal in behavior.signals
            )
        return tuple(sorted(risks, key=lambda item: (item.risk_id, item.event_id)))

    @staticmethod
    def _risk_from_signal(
        signal: RiskSignal,
        *,
        tenant_id: str,
        process_id: str,
        snapshot_id: str,
    ) -> RiskFinding:
        risk_id = sha256_canonical(
            {
                "tenant_id": tenant_id,
                "process_id": process_id,
                "algorithm": "behavior-risk-1.0",
                "kind": signal.kind.value,
                "subject": signal.subject,
                "event_ids": signal.event_ids,
                "case_ids": signal.case_ids,
            }
        )
        return RiskFinding(
            risk_id=risk_id,
            tenant_id=tenant_id,
            process_id=process_id,
            case_id=signal.case_ids[0] if signal.case_ids else "baseline-comparison",
            event_id=signal.event_ids[0] if signal.event_ids else f"risk-signal:{risk_id}",
            severity=RiskSeverity(signal.level.value),
            category=signal.kind.value,
            reasons=(
                signal.rationale,
                f"score:{signal.score}",
                f"subject:{signal.subject}",
                f"support:{signal.support}",
            ),
            evidence_references=signal.event_ids,
            snapshot_id=snapshot_id,
        )

    def _all_risks(
        self,
        *,
        tenant_id: str,
        process_id: str | None = None,
    ) -> tuple[RiskFinding, ...]:
        self._ensure_tenant_loaded(tenant_id)
        with self._lock:
            available = self._events.get(tenant_id, {})
            process_ids: tuple[str, ...] = (
                (process_id,) if process_id is not None and process_id in available else ()
            )
            if process_id is None:
                process_ids = tuple(sorted(available))
            risks = tuple(
                risk
                for selected_process_id in process_ids
                for risk in self._risks_for_process(
                    tenant_id=tenant_id,
                    process_id=selected_process_id,
                    events=tuple(available[selected_process_id].values()),
                )
            )
        return tuple(sorted(risks, key=lambda item: (item.risk_id, item.event_id)))

    def list_risks(
        self,
        *,
        tenant_id: str,
        process_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> RiskList:
        ordered = self._all_risks(tenant_id=tenant_id, process_id=process_id)
        return RiskList(
            items=ordered[offset : offset + limit],
            total=len(ordered),
            offset=offset,
            limit=limit,
        )

    def list_recommendations(
        self,
        *,
        tenant_id: str,
        process_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> RecommendationList:
        risks = self._all_risks(tenant_id=tenant_id, process_id=process_id)
        self._ensure_tenant_loaded(tenant_id)
        with self._lock:
            available = self._events.get(tenant_id, {})
            selected_process_ids: tuple[str, ...] = (
                (process_id,) if process_id is not None and process_id in available else ()
            )
            if process_id is None:
                selected_process_ids = tuple(sorted(available))
            current_by_process = {
                selected_process_id: tuple(available[selected_process_id].values())
                for selected_process_id in selected_process_ids
            }
        proposals: list[PolicyRecommendation] = []
        policy_gap_event_ids: set[str] = set()
        for selected_process_id, current_events in current_by_process.items():
            for gap in discover_policy_gaps(current_events):
                policy_gap_event_ids.update(gap.evidence_event_ids)
                proposals.append(
                    PolicyRecommendation(
                        recommendation_id=gap.proposal_id,
                        tenant_id=tenant_id,
                        process_id=selected_process_id,
                        title=f"Review policy gap for {gap.tool_name}",
                        rationale=gap.rationale,
                        source_event_ids=gap.evidence_event_ids,
                        evidence_references=gap.evidence_event_ids,
                        algorithm_version=gap.algorithm_version,
                    )
                )
        # A concrete, aggregated policy-gap proposal supersedes generic
        # per-event coverage advice for the same observations.
        proposals.extend(
            PolicyRecommendation(
                recommendation_id=sha256_canonical(
                    {"risk_id": risk.risk_id, "kind": "policy-gap-proposal"}
                ),
                tenant_id=tenant_id,
                process_id=risk.process_id,
                title=f"Review governance coverage for event {risk.event_id}",
                rationale=(
                    "Observed evidence requires independent governance review: "
                    + ", ".join(risk.reasons)
                ),
                source_event_ids=(risk.event_id,),
                evidence_references=risk.evidence_references,
                algorithm_version="risk-derived-proposal-1.0",
            )
            for risk in risks
            if risk.event_id not in policy_gap_event_ids
        )
        ordered = tuple(
            sorted(
                {proposal.recommendation_id: proposal for proposal in proposals}.values(),
                key=lambda proposal: proposal.recommendation_id,
            )
        )
        return RecommendationList(
            items=ordered[offset : offset + limit],
            total=len(ordered),
            offset=offset,
            limit=limit,
        )

    def export_bpmn(self, *, tenant_id: str, process_id: str) -> bytes | None:
        events = self._events_for_process(tenant_id=tenant_id, process_id=process_id)
        if events is None:
            return None
        return export_bpmn(discover_dfg(events, process_id=process_id))

    def verify_tenant_store(self, *, tenant_id: str) -> ChainVerificationResult | None:
        if self._event_store is None:
            return None
        return self._event_store.verify_chain(tenant_id)


def service_from_events(
    events: Iterable[ProcessEvent],
    *,
    event_store: ProcessEventStore | None = None,
) -> ProcessIntelligenceService:
    """Small explicit factory used by API startup and CLI commands."""
    return ProcessIntelligenceService(events, event_store=event_store)


def event_mapping(events: Iterable[ProcessEvent]) -> Mapping[str, ProcessEvent]:
    """Return a deterministic read-only-style mapping for integration code."""
    return {event.event_id: event for event in sorted(events, key=lambda item: item.event_id)}
