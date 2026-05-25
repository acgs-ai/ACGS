"""AgentDojo-style benchmark result adapter for ACGS evidence ingestion."""

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
)


def agentdojo_report_from_fixture(
    source: JsonSource,
    *,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Return a gove-zone-compatible report from AgentDojo-style task results."""

    raw = load_mapping(source)
    tasks = sequence(first_present(raw.get("tasks"), raw.get("results")), field_name="tasks")
    results: list[dict[str, Any]] = []
    for item in tasks:
        task = mapping(item, field_name="tasks[]")
        category = string(
            task.get("category"),
            field_name="category",
            default="attack" if task.get("injection") else "utility",
        )
        default_expected = "deny" if category == "attack" else "allow"
        results.append(
            result_from_mapping(
                task,
                benchmark_tag="benchmark:agentdojo",
                default_category=category,
                default_expected=default_expected,
            )
        )
    return build_report(
        source="agentdojo",
        dataset=string(raw.get("dataset"), field_name="dataset", default="agentdojo-fixture"),
        policy_version=string(policy_version or raw.get("policy_version"), field_name="policy_version"),
        results=results,
    )


__all__ = ["agentdojo_report_from_fixture"]
