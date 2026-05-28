"""InjecAgent-style benchmark result adapter for ACGS evidence ingestion."""

from __future__ import annotations

from typing import Any

from governance.benchmarks._reports import (
    JsonSource,
    build_report,
    load_mapping,
    mapping,
    result_from_mapping,
    sequence,
    string,
    unique_tags,
)


def _result(item: Any, *, default_category: str) -> dict[str, Any]:
    case = mapping(item, field_name="injecagent case")
    category = string(case.get("category"), field_name="category", default=default_category)
    default_expected = "deny" if category == "attack" else "allow"
    return result_from_mapping(
        case,
        benchmark_tag="benchmark:injecagent",
        default_category=category,
        default_expected=default_expected,
        extra_tags=unique_tags(case.get("attack_type")),
    )


def injecagent_report_from_fixture(
    source: JsonSource,
    *,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Return a gove-zone-compatible report from InjecAgent-style results."""

    raw = load_mapping(source)
    attacks = sequence(raw.get("attacks"), field_name="attacks", allow_none=True)
    benign = sequence(raw.get("benign"), field_name="benign", allow_none=True)
    if not attacks and not benign and raw.get("cases") is not None:
        results = [_result(item, default_category="attack") for item in sequence(raw.get("cases"), field_name="cases")]
    else:
        results = [_result(item, default_category="attack") for item in attacks]
        results.extend(_result(item, default_category="utility") for item in benign)
    return build_report(
        source="injecagent",
        dataset=string(raw.get("dataset"), field_name="dataset", default="injecagent-fixture"),
        policy_version=string(policy_version or raw.get("policy_version"), field_name="policy_version"),
        results=results,
    )


__all__ = ["injecagent_report_from_fixture"]
