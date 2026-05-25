from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from governance.audit import AuditStore
from governance.models import (
    DECISION_SCHEMA_VERSION,
    ActionRequest,
    DecisionRecord,
    Principal,
    sha256_json,
    utc_now_iso,
)

EvaluationStatus = Literal["passed", "failed"]
DecisionName = Literal["allow", "deny", "transform", "escalate"]
JsonSource = Mapping[str, Any] | str | Path

GOVE_ZONE_EVALUATION_ACTION_TYPE = "evaluation.gove_zone_report"
_GOVE_ZONE_DECISIONS: set[str] = {"allow", "deny", "transform", "escalate"}


def _load_mapping(source: JsonSource) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("gove-zone evaluation report must be a JSON object")
    return cast(Mapping[str, Any], raw)


def _string(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"gove-zone evaluation report requires {field_name}")
    return text


def _int(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if number < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return number


def _float_or_none(value: Any, *, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be numeric or null")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be numeric or null") from exc
    if number < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return number


def _rate_or_none(value: Any, *, field_name: str) -> float | None:
    number = _float_or_none(value, field_name=field_name)
    if number is None:
        return None
    if number > 1:
        raise ValueError(f"{field_name} must be between 0 and 1")
    return number


def _strings(value: Any, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item) for item in value]
    raise ValueError(f"{field_name} must be a string or sequence")


def _decision(value: Any, *, field_name: str) -> DecisionName:
    decision = str(value or "").lower().strip()
    if decision not in _GOVE_ZONE_DECISIONS:
        raise ValueError(f"{field_name} must be one of {sorted(_GOVE_ZONE_DECISIONS)}")
    return cast(DecisionName, decision)


@dataclass(frozen=True)
class EvaluationScenarioEvidence:
    id: str
    category: str
    expected_decision: DecisionName
    actual_decision: DecisionName
    passed: bool
    matched_rules: list[str] = field(default_factory=list)
    reason: str = ""
    latency_ms: float | None = None
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> EvaluationScenarioEvidence:
        return cls(
            id=_string(raw.get("id"), field_name="results[].id"),
            category=_string(raw.get("category", "regression"), field_name="results[].category"),
            expected_decision=_decision(raw.get("expected_decision"), field_name="results[].expected_decision"),
            actual_decision=_decision(raw.get("actual_decision"), field_name="results[].actual_decision"),
            passed=bool(raw.get("passed")),
            matched_rules=_strings(raw.get("matched_rules"), field_name="results[].matched_rules"),
            reason=str(raw.get("reason", "")),
            latency_ms=_float_or_none(raw.get("latency_ms"), field_name="results[].latency_ms"),
            tags=_strings(raw.get("tags"), field_name="results[].tags"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationReportEvidence:
    dataset: str
    policy_version: str
    scenario_count: int
    passed: int
    failed: int
    status: EvaluationStatus
    report_hash: str
    normalized_report: dict[str, Any]
    attack_success_rate: float | None = None
    utility_retention_rate: float | None = None
    p95_latency_ms: float | None = None
    source: str = "gove-zone"
    ingested_at: str = field(default_factory=utc_now_iso)
    previous_hash: str | None = None
    event_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _event_evaluation_evidence(event: Mapping[str, Any]) -> dict[str, Any] | None:
    request = event.get("request")
    if not isinstance(request, Mapping):
        return None
    metadata = request.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    evidence = metadata.get("evaluation_evidence")
    if not isinstance(evidence, Mapping):
        return None
    status = str(evidence.get("status", ""))
    if status not in {"passed", "failed"}:
        return None
    return {
        **dict(evidence),
        "event_id": event.get("event_id"),
        "tenant": event.get("tenant"),
        "allow": bool(event.get("allow")),
        "previous_hash": event.get("previous_hash"),
        "event_hash": event.get("event_hash"),
        "claim_safe": status == "passed" and bool(event.get("allow")),
    }


def list_gove_zone_evaluation_evidence(
    audit_store: AuditStore,
    *,
    tenant: str,
    status: EvaluationStatus | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if audit_store is None:
        raise TypeError("audit_store is required")
    if limit < 1:
        raise ValueError("limit must be positive")

    evidence_items: list[dict[str, Any]] = []
    for event in audit_store.iter_events():
        if event.get("tenant") != tenant:
            continue
        request = event.get("request")
        metadata = request.get("metadata") if isinstance(request, Mapping) else None
        risk_tags = metadata.get("risk_tags") if isinstance(metadata, Mapping) else None
        if not isinstance(risk_tags, Sequence) or isinstance(risk_tags, (str, bytes, bytearray)):
            continue
        if "evaluation:gove-zone" not in risk_tags:
            continue
        evidence = _event_evaluation_evidence(event)
        if evidence is None:
            continue
        if status is not None and evidence.get("status") != status:
            continue
        evidence_items.append(evidence)
        if len(evidence_items) >= limit:
            break
    return evidence_items


def normalize_gove_zone_evaluation_report(source: JsonSource) -> EvaluationReportEvidence:
    raw = _load_mapping(source)
    raw_results = raw.get("results")
    if not isinstance(raw_results, Sequence) or isinstance(raw_results, (str, bytes, bytearray)):
        raise ValueError("gove-zone evaluation report requires a results sequence")

    results: list[EvaluationScenarioEvidence] = []
    for item in raw_results:
        if not isinstance(item, Mapping):
            raise ValueError("gove-zone evaluation report results must be JSON objects")
        results.append(EvaluationScenarioEvidence.from_mapping(cast(Mapping[str, Any], item)))

    scenario_count = _int(raw.get("scenario_count", len(results)), field_name="scenario_count")
    passed = _int(raw.get("passed", sum(1 for result in results if result.passed)), field_name="passed")
    failed = _int(raw.get("failed", sum(1 for result in results if not result.passed)), field_name="failed")
    computed_passed = sum(1 for result in results if result.passed)
    computed_failed = sum(1 for result in results if not result.passed)

    if scenario_count != len(results):
        raise ValueError("scenario_count does not match results length")
    if passed != computed_passed:
        raise ValueError("passed count does not match results")
    if failed != computed_failed:
        raise ValueError("failed count does not match results")
    if passed + failed != scenario_count:
        raise ValueError("passed plus failed must equal scenario_count")

    status: EvaluationStatus = "passed" if scenario_count > 0 and failed == 0 else "failed"
    source_name = _string(raw.get("source", "gove-zone"), field_name="source")
    normalized_report: dict[str, Any] = {
        "source": source_name,
        "dataset": _string(raw.get("dataset"), field_name="dataset"),
        "policy_version": _string(raw.get("policy_version"), field_name="policy_version"),
        "scenario_count": scenario_count,
        "passed": passed,
        "failed": failed,
        "attack_success_rate": _rate_or_none(raw.get("attack_success_rate"), field_name="attack_success_rate"),
        "utility_retention_rate": _rate_or_none(raw.get("utility_retention_rate"), field_name="utility_retention_rate"),
        "p95_latency_ms": _float_or_none(raw.get("p95_latency_ms"), field_name="p95_latency_ms"),
        "results": [result.to_dict() for result in results],
    }
    report_hash = sha256_json(normalized_report)
    return EvaluationReportEvidence(
        dataset=normalized_report["dataset"],
        policy_version=normalized_report["policy_version"],
        scenario_count=scenario_count,
        passed=passed,
        failed=failed,
        status=status,
        report_hash=report_hash,
        normalized_report=normalized_report,
        attack_success_rate=normalized_report["attack_success_rate"],
        utility_retention_rate=normalized_report["utility_retention_rate"],
        p95_latency_ms=normalized_report["p95_latency_ms"],
        source=source_name,
    )


def ingest_gove_zone_evaluation_report(
    source: JsonSource,
    *,
    audit_store: AuditStore,
    tenant: str = "default",
    actor_id: str = "gove-zone-evaluation-ingestor",
) -> EvaluationReportEvidence:
    if audit_store is None:
        raise TypeError("audit_store is required")
    evidence = normalize_gove_zone_evaluation_report(source)
    allow = evidence.status == "passed"
    reason_code = "GOVE_ZONE_EVALUATION_PASSED" if allow else "GOVE_ZONE_EVALUATION_FAILED"
    tool_input = {
        "source": evidence.source,
        "report_hash": evidence.report_hash,
        "dataset": evidence.dataset,
        "policy_version": evidence.policy_version,
        "status": evidence.status,
        "normalized_report": evidence.normalized_report,
    }
    risk_tags = ["evaluation:gove-zone"]
    if evidence.source != "gove-zone":
        risk_tags.append(f"evaluation:{evidence.source}")
    risk_tags.append(f"evaluation:{evidence.status}")
    request = ActionRequest(
        action_type=GOVE_ZONE_EVALUATION_ACTION_TYPE,
        resource=f"evaluation/{evidence.source}/{evidence.dataset}/{evidence.report_hash}",
        actor=Principal(id=actor_id, role="evaluation_ingestor", tenant=tenant),
        intent="Ingest gove-zone policy evaluation report as claim evidence",
        inputs_hash=sha256_json(tool_input),
        tenant=tenant,
        metadata={
            "risk_tags": risk_tags,
            "evaluation_evidence": evidence.to_dict(),
        },
        tool_input=tool_input,
    )
    decision = DecisionRecord(
        event_id=request.event_id,
        tenant=tenant,
        allow=allow,
        reasons=[
            (
                "gove-zone evaluation report passed all scenarios"
                if allow
                else "gove-zone evaluation report contains failed scenarios and is not claim-safe"
            )
        ],
        reason_codes=[reason_code],
        rule_ids=[reason_code],
        checks=[],
        request=request,
        policy_version="gove-zone-evaluation-report-v1",
        role_version="evaluation-ingestor-v1",
        decision_state="allow" if allow else "deny",
        effective_tool_input=tool_input,
        policy_bundle_hash=evidence.report_hash,
        role_bundle_hash="",
        decision_schema_version=DECISION_SCHEMA_VERSION,
    )
    stored = audit_store.append(decision)
    return EvaluationReportEvidence(
        **{
            **evidence.to_dict(),
            "previous_hash": stored.get("previous_hash"),
            "event_hash": stored.get("event_hash"),
        }
    )


__all__ = [
    "EvaluationReportEvidence",
    "EvaluationScenarioEvidence",
    "EvaluationStatus",
    "GOVE_ZONE_EVALUATION_ACTION_TYPE",
    "ingest_gove_zone_evaluation_report",
    "list_gove_zone_evaluation_evidence",
    "normalize_gove_zone_evaluation_report",
]
