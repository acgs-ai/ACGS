"""ToolEmu-style benchmark result adapter for ACGS evidence ingestion.

This adapter converts local, reviewable ToolEmu-inspired result fixtures into
the normalized ``gove-zone eval`` report shape. It does not run ToolEmu's
LM-emulated sandbox; upstream-suite execution remains a separate evidence
source.
"""

from __future__ import annotations

from typing import Any

from governance.benchmarks._reports import (
    JsonSource,
    build_report,
    first_present,
    load_mapping,
    mapping,
    result_from_mapping,
    sequence,
    string,
    unique_tags,
)


def _result(item: Any) -> dict[str, Any]:
    case = mapping(item, field_name="toolemu test case")
    category = string(
        case.get("category"),
        field_name="category",
        default=(
            "attack"
            if first_present(case.get("risk_type"), case.get("hazards"), case.get("unsafe_condition"))
            else "utility"
        ),
    )
    default_expected = "deny" if category == "attack" else "allow"
    normalized_case = {
        **case,
        "id": string(
            first_present(
                case.get("id"),
                case.get("case_id"),
                case.get("test_case_id"),
                case.get("scenario_id"),
            ),
            field_name="id",
        ),
    }
    return result_from_mapping(
        normalized_case,
        benchmark_tag="benchmark:toolemu",
        default_category=category,
        default_expected=default_expected,
        extra_tags=unique_tags(case.get("risk_type"), case.get("domain"), case.get("hazards")),
    )


def toolemu_report_from_fixture(
    source: JsonSource,
    *,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Return a gove-zone-compatible report from ToolEmu-style results."""

    raw = load_mapping(source)
    test_cases = sequence(
        first_present(raw.get("test_cases"), raw.get("cases"), raw.get("scenarios")),
        field_name="test_cases",
    )
    return build_report(
        source="toolemu",
        dataset=string(raw.get("dataset"), field_name="dataset", default="toolemu-fixture"),
        policy_version=string(policy_version or raw.get("policy_version"), field_name="policy_version"),
        results=[_result(item) for item in test_cases],
    )


__all__ = ["toolemu_report_from_fixture"]
