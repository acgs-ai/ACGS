"""T013 — verify Pydantic instances conform to the checked-in JSON Schemas.

We do NOT assert byte-equivalence between Pydantic's exported schema and the
hand-authored ``contracts/*.schema.json`` — Pydantic v2 and Draft 2020-12
disagree on small structural details. Instead we instantiate concrete models,
serialize, and validate the JSON against the contract schemas. Drift between
model and contract surfaces either at construction (Pydantic validation error)
or at jsonschema validation time.

Cross-file ``$ref`` (``trace-query.schema.json`` references
``trace-event.schema.json``) is resolved via a ``referencing.Registry``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

from agent_bus_analyzer.models import (
    Event,
    Expired,
    RetentionPolicy,
    SingleTrace,
    TraceList,
    TraceListItem,
    WiringDefectFinding,
    WiringDefectSummary,
)

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"


def _load(name: str) -> dict[str, Any]:
    return json.loads((CONTRACTS_DIR / name).read_text())


def _registry() -> Registry:
    """Registry that resolves the cross-file refs used by the contracts.

    ``trace-query.schema.json`` does ``{"$ref": "trace-event.schema.json"}``;
    we register the event schema under that exact relative URL so the resolver
    finds it without needing network access.
    """
    event_schema = _load("trace-event.schema.json")
    return Registry().with_resource(
        "trace-event.schema.json",
        Resource.from_contents(event_schema),
    )


def _validate(instance: Any, schema: dict[str, Any]) -> None:
    validator = jsonschema.Draft202012Validator(schema, registry=_registry())
    validator.validate(instance)


def _payload(model: Any) -> Any:
    return json.loads(model.model_dump_json())


def _sample_event() -> Event:
    return Event(
        event_id="01234567-89ab-cdef-0123-456789abcdef",
        correlation_id="89abcdef-0123-4567-89ab-cdef01234567",
        causal_index=0,
        recorded_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        source_agent="claude:worker-03",
        target_handler_declared="policy.evaluate",
        target_handler_resolved="policy.evaluate",
        payload_ref="sha256:abc123",
        kind="dispatch",
        constitutional_hash="608508a9bd224290",
        event_hash="a" * 64,
        prev_hash=None,
        status="completed",
    )


def _sample_list_item() -> TraceListItem:
    return TraceListItem(
        correlation_id="89abcdef-0123-4567-89ab-cdef01234567",
        started_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        event_count=1,
        worst_event_status="completed",
        integrity_status="intact",
        constitutional_hash="608508a9bd224290",
    )


def test_event_conforms_to_trace_event_schema() -> None:
    schema = _load("trace-event.schema.json")
    _validate(_payload(_sample_event()), schema)


def test_decision_event_conforms() -> None:
    schema = _load("trace-event.schema.json")
    event = Event(
        event_id="01234567-89ab-cdef-0123-456789abcdef",
        correlation_id="89abcdef-0123-4567-89ab-cdef01234567",
        causal_index=1,
        recorded_at=datetime(2026, 5, 14, 12, 0, 1, tzinfo=UTC),
        source_agent="acgs:handler/policy-evaluator",
        payload_ref="sha256:def456",
        kind="decision",
        decision="deny",
        flagged_rule="rule.no-pii-in-output",
        audit_receipt_hash="b" * 64,
        constitutional_hash="608508a9bd224290",
        event_hash="c" * 64,
        prev_hash="a" * 64,
        status="policy-violation",
    )
    _validate(_payload(event), schema)


def test_trace_list_conforms() -> None:
    schema = _load("trace-query.schema.json")
    response = TraceList(items=[_sample_list_item()])
    _validate(_payload(response), schema)


def test_single_trace_conforms() -> None:
    schema = _load("trace-query.schema.json")
    response = SingleTrace(
        trace=_sample_list_item(),
        events=[_sample_event()],
        integrity_status="intact",
        rotation_at_index=None,
    )
    _validate(_payload(response), schema)


def test_wiring_defect_summary_conforms() -> None:
    schema = _load("trace-query.schema.json")
    finding = WiringDefectFinding(
        finding_id="89abcdef-0123-4567-89ab-cdef01234567",
        detected_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        kind="unwired_dispatch",
        handler_name="policy.evaluate",
        example_event_ids=["01234567-89ab-cdef-0123-456789abcdef"],
    )
    response = WiringDefectSummary(
        refreshed_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        findings=[finding],
    )
    _validate(_payload(response), schema)


def test_expired_conforms() -> None:
    schema = _load("trace-query.schema.json")
    response = Expired(
        correlation_id="89abcdef-0123-4567-89ab-cdef01234567",
        retention_policy=RetentionPolicy(
            max_age_days=90,
            purged_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        ),
    )
    _validate(_payload(response), schema)
