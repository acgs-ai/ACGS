"""Shared helpers for benchmark-result to evidence-report adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

JsonSource = Mapping[str, Any] | str | Path

_DECISIONS = {"allow", "deny", "transform", "escalate"}


def load_mapping(source: JsonSource) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("benchmark result fixture must be a JSON object")
    return cast(Mapping[str, Any], raw)


def sequence(value: Any, *, field_name: str, allow_none: bool = False) -> tuple[Any, ...]:
    if value is None and allow_none:
        return ()
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(value)
    raise ValueError(f"{field_name} must be a sequence")


def mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, Any], value)
    raise ValueError(f"{field_name} must be a JSON object")


def string(value: Any, *, field_name: str, default: str | None = None) -> str:
    if value is None:
        if default is None:
            raise ValueError(f"benchmark result fixture requires {field_name}")
        value = default
    text = str(value).strip()
    if not text:
        raise ValueError(f"benchmark result fixture requires {field_name}")
    return text


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def decision(value: Any, *, field_name: str, default: str | None = None) -> str:
    text = string(value, field_name=field_name, default=default).lower()
    if text not in _DECISIONS:
        raise ValueError(f"{field_name} must be one of {sorted(_DECISIONS)}")
    return text


def float_or_none(value: Any, *, field_name: str) -> float | None:
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


def strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value)
    raise ValueError("tags must be a string or sequence")


def unique_tags(*groups: Any) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for tag in strings(group):
            normalized = tag.strip()
            if normalized and normalized not in seen:
                tags.append(normalized)
                seen.add(normalized)
    return tags


def result_from_mapping(
    raw: Mapping[str, Any],
    *,
    benchmark_tag: str,
    default_category: str,
    default_expected: str,
    extra_tags: Sequence[str] = (),
) -> dict[str, Any]:
    category = string(raw.get("category"), field_name="category", default=default_category)
    expected = decision(
        first_present(raw.get("expected_decision"), raw.get("expected")),
        field_name="expected_decision",
        default=default_expected,
    )
    actual = decision(
        first_present(raw.get("actual_decision"), raw.get("decision"), raw.get("actual")),
        field_name="actual_decision",
    )
    computed_passed = actual == expected
    if raw.get("passed") is not None and bool(raw.get("passed")) != computed_passed:
        raise ValueError("passed marker does not match expected_decision and actual_decision")
    return {
        "id": string(
            first_present(raw.get("id"), raw.get("task_id"), raw.get("case_id")),
            field_name="id",
        ),
        "category": category,
        "expected_decision": expected,
        "actual_decision": actual,
        "passed": computed_passed,
        "matched_rules": list(strings(raw.get("matched_rules"))),
        "reason": str(raw.get("reason", "")),
        "latency_ms": float_or_none(raw.get("latency_ms"), field_name="latency_ms"),
        "tags": unique_tags((benchmark_tag,), extra_tags, raw.get("tags")),
    }


def _rate(results: Sequence[Mapping[str, Any]], *, category: str) -> float | None:
    category_results = [result for result in results if result.get("category") == category]
    if not category_results:
        return None
    allowed = sum(1 for result in category_results if result.get("actual_decision") == "allow")
    return allowed / len(category_results)


def _p95_latency(results: Sequence[Mapping[str, Any]]) -> float | None:
    latencies = sorted(float(result["latency_ms"]) for result in results if result.get("latency_ms") is not None)
    if not latencies:
        return None
    index = max(0, min(len(latencies) - 1, int((len(latencies) * 0.95) - 1)))
    return latencies[index]


def build_report(
    *,
    source: str,
    dataset: str,
    policy_version: str,
    results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not results:
        raise ValueError("benchmark result fixture requires at least one result")
    passed = sum(1 for result in results if bool(result.get("passed")))
    failed = len(results) - passed
    p95 = _p95_latency(results)
    return {
        "source": source,
        "dataset": dataset,
        "policy_version": policy_version,
        "scenario_count": len(results),
        "passed": passed,
        "failed": failed,
        "attack_success_rate": _rate(results, category="attack"),
        "utility_retention_rate": _rate(results, category="utility"),
        "p95_latency_ms": None if p95 is None else round(p95, 6),
        "results": [dict(result) for result in results],
    }
