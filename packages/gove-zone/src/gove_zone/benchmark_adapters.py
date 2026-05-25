"""Adapters from common benchmark-shaped fixtures to evaluation scenarios.

The adapters are intentionally small and deterministic: they do not run an
agent loop or import upstream benchmark packages. They convert reviewable
fixture JSON into :class:`gove_zone.evaluation.EvaluationScenario` values so a
policy bundle can be replayed locally before evidence is promoted to claims.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from gove_zone.evaluation import EvaluationScenario, JsonSource, load_evaluation_suite
from gove_zone.tool import normalize_path_context

BenchmarkFormat = str


def _load_mapping(source: JsonSource) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("benchmark fixture must be a JSON object")
    return cast(Mapping[str, Any], raw)


def _sequence(value: Any, *, field_name: str, allow_none: bool = False) -> tuple[Any, ...]:
    if value is None and allow_none:
        return ()
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(value)
    raise ValueError(f"{field_name} must be a sequence")


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, Any], value)
    raise ValueError(f"{field_name} must be a JSON object")


def _mapping_or_empty(value: Any, *, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    raise ValueError(f"{field_name} must be a JSON object")


def _string(value: Any, *, field_name: str, default: str | None = None) -> str:
    if value is None:
        if default is None:
            raise ValueError(f"benchmark fixture requires {field_name}")
        value = default
    text = str(value).strip()
    if not text:
        raise ValueError(f"benchmark fixture requires {field_name}")
    return text


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value)
    raise ValueError("tags must be a string or sequence")


def _unique_tags(*tag_groups: Any) -> tuple[str, ...]:
    tags: list[str] = []
    seen: set[str] = set()
    for group in tag_groups:
        for tag in _strings(group):
            normalized = tag.strip()
            if normalized and normalized not in seen:
                tags.append(normalized)
                seen.add(normalized)
    return tuple(tags)


def _tool_call_items(raw: Mapping[str, Any], *, field_name: str) -> tuple[Mapping[str, Any], ...]:
    for key in ("tool_calls", "tool_invocations", "actions"):
        calls = raw.get(key)
        if calls is None:
            continue
        items = _sequence(calls, field_name=field_name)
        return tuple(_mapping(item, field_name=f"{field_name}[]") for item in items)
    return (raw,)


def _tool_name(call: Mapping[str, Any], parent: Mapping[str, Any]) -> str:
    return _string(
        _first_present(
            call.get("tool"),
            call.get("tool_name"),
            call.get("name"),
            call.get("function"),
            call.get("target_tool"),
            call.get("api"),
            parent.get("tool_name"),
            parent.get("target_tool"),
            parent.get("tool"),
            parent.get("function"),
            parent.get("api"),
        ),
        field_name="tool",
    )


def _args(call: Mapping[str, Any], parent: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _first_present(
        call.get("args"),
        call.get("arguments"),
        call.get("parameters"),
        call.get("input"),
        call.get("payload"),
        parent.get("args"),
        parent.get("arguments"),
        parent.get("parameters"),
        parent.get("input"),
        parent.get("payload"),
    )
    return _mapping_or_empty(candidate, field_name="args")


def _path(
    call: Mapping[str, Any],
    parent: Mapping[str, Any],
    args: Mapping[str, Any],
) -> tuple[str, ...]:
    for candidate in (
        call.get("path"),
        args.get("path"),
        args.get("file_path"),
        args.get("resource_path"),
        parent.get("path"),
        parent.get("resource_path"),
    ):
        path = normalize_path_context(candidate)
        if path:
            return path
    return ()


def _state(call: Mapping[str, Any], parent: Mapping[str, Any]) -> dict[str, Any]:
    merged = _mapping_or_empty(parent.get("state"), field_name="state")
    merged.update(_mapping_or_empty(call.get("state"), field_name="state"))
    return merged


def _goal(*parts: Any) -> str:
    text_parts = [str(part).strip() for part in parts if str(part or "").strip()]
    return "\n\n".join(text_parts)


def _scenario_id(base_id: str, *, index: int, count: int) -> str:
    if count == 1:
        return base_id
    return f"{base_id}#{index + 1}"


def _scenario_from_call(
    *,
    base_id: str,
    call: Mapping[str, Any],
    parent: Mapping[str, Any],
    index: int,
    count: int,
    category: str,
    default_actor: str,
    default_expected: str,
    benchmark_tag: str,
    goal: str,
    extra_tags: Sequence[str] = (),
) -> EvaluationScenario:
    args = _args(call, parent)
    path = _path(call, parent, args)
    if path and "path" not in args:
        args = {**args, "path": "/".join(path)}
    scenario = {
        "id": _scenario_id(base_id, index=index, count=count),
        "category": category,
        "actor": _string(
            _first_present(call.get("actor"), parent.get("actor")),
            field_name="actor",
            default=default_actor,
        ),
        "tool": _tool_name(call, parent),
        "args": args,
        "path": path,
        "state": _state(call, parent),
        "goal": _goal(call.get("goal"), goal),
        "expected_decision": _string(
            _first_present(call.get("expected_decision"), parent.get("expected_decision")),
            field_name="expected_decision",
            default=default_expected,
        ),
        "tags": _unique_tags((benchmark_tag,), extra_tags, parent.get("tags"), call.get("tags")),
    }
    return EvaluationScenario.from_dict(scenario)


def agentdojo_scenarios_from_fixture(source: JsonSource) -> tuple[EvaluationScenario, ...]:
    """Convert an AgentDojo-style task fixture into evaluation scenarios.

    Supported local fixture shape: ``{"dataset": ..., "tasks": [...]}``, where
    each task has an id, expected decision, state, and one or more tool calls.
    One scenario is emitted per tool call.
    """

    raw = _load_mapping(source)
    tasks = _sequence(raw.get("tasks"), field_name="tasks")
    scenarios: list[EvaluationScenario] = []
    for task_index, item in enumerate(tasks):
        task = _mapping(item, field_name="tasks[]")
        base_id = _string(
            _first_present(task.get("id"), task.get("task_id"), task.get("case_id")),
            field_name="tasks[].id",
        )
        category = _string(
            task.get("category"),
            field_name="tasks[].category",
            default="attack" if task.get("injection") else "utility",
        )
        default_expected = "deny" if category == "attack" else "allow"
        calls = _tool_call_items(task, field_name="tasks[].tool_calls")
        task_goal = _goal(
            task.get("user_task"),
            task.get("goal"),
            task.get("instruction"),
            task.get("prompt"),
            f"Adversarial instruction: {task['injection']}" if task.get("injection") else "",
        )
        for call_index, call in enumerate(calls):
            scenarios.append(
                _scenario_from_call(
                    base_id=base_id if len(calls) == 1 else f"{base_id}-call-{call_index + 1}",
                    call=call,
                    parent=task,
                    index=0 if len(calls) == 1 else call_index,
                    count=1,
                    category=category,
                    default_actor="agentdojo-fixture-agent",
                    default_expected=default_expected,
                    benchmark_tag="benchmark:agentdojo",
                    goal=task_goal,
                )
            )
        if not calls:
            raise ValueError(f"AgentDojo task at index {task_index} has no tool calls")
    return tuple(scenarios)


def injecagent_scenarios_from_fixture(source: JsonSource) -> tuple[EvaluationScenario, ...]:
    """Convert an InjecAgent-style fixture into evaluation scenarios."""

    raw = _load_mapping(source)
    attack_items = _sequence(raw.get("attacks"), field_name="attacks", allow_none=True)
    benign_items = _sequence(raw.get("benign"), field_name="benign", allow_none=True)
    categorized_items: tuple[tuple[str | None, Any], ...]
    if not attack_items and not benign_items and raw.get("cases") is not None:
        case_items = _sequence(raw.get("cases"), field_name="cases")
        categorized_items = tuple((None, item) for item in case_items)
    else:
        categorized_items = tuple(("attack", item) for item in attack_items) + tuple(
            ("utility", item) for item in benign_items
        )

    scenarios: list[EvaluationScenario] = []
    for default_category, item in categorized_items:
        case = _mapping(item, field_name="injecagent case")
        base_id = _string(
            _first_present(case.get("case_id"), case.get("id"), case.get("task_id")),
            field_name="case_id",
        )
        category = _string(
            case.get("category"),
            field_name="category",
            default=default_category or "attack",
        )
        default_expected = "deny" if category == "attack" else "allow"
        calls = _tool_call_items(case, field_name="tool_calls")
        case_goal = _goal(case.get("instruction"), case.get("prompt"), case.get("goal"))
        extra_tags = _unique_tags(case.get("attack_type"))
        for call_index, call in enumerate(calls):
            scenarios.append(
                _scenario_from_call(
                    base_id=base_id if len(calls) == 1 else f"{base_id}-call-{call_index + 1}",
                    call=call,
                    parent=case,
                    index=0 if len(calls) == 1 else call_index,
                    count=1,
                    category=category,
                    default_actor="injecagent-fixture-agent",
                    default_expected=default_expected,
                    benchmark_tag="benchmark:injecagent",
                    goal=case_goal,
                    extra_tags=extra_tags,
                )
            )
    return tuple(scenarios)


def toolemu_scenarios_from_fixture(source: JsonSource) -> tuple[EvaluationScenario, ...]:
    """Convert a ToolEmu-style high-stakes tool fixture into scenarios.

    Supported local fixture shape: ``{"dataset": ..., "test_cases": [...]}``
    (or ``cases`` / ``scenarios``). Each case may carry one or more
    ``tool_invocations`` plus risk metadata such as ``risk_type``, ``domain``,
    and ``hazards``. This adapter only replays proposed tool calls through the
    local policy bundle; it does not run the upstream LM-emulated sandbox.
    """

    raw = _load_mapping(source)
    items = _sequence(
        _first_present(raw.get("test_cases"), raw.get("cases"), raw.get("scenarios")),
        field_name="test_cases",
    )
    scenarios: list[EvaluationScenario] = []
    for item in items:
        case = _mapping(item, field_name="test_cases[]")
        base_id = _string(
            _first_present(
                case.get("id"),
                case.get("case_id"),
                case.get("test_case_id"),
                case.get("scenario_id"),
            ),
            field_name="test_cases[].id",
        )
        default_category = (
            "attack"
            if _first_present(
                case.get("risk_type"), case.get("hazards"), case.get("unsafe_condition")
            )
            else "utility"
        )
        category = _string(
            case.get("category"),
            field_name="test_cases[].category",
            default=default_category,
        )
        default_expected = "deny" if category == "attack" else "allow"
        calls = _tool_call_items(case, field_name="test_cases[].tool_invocations")
        case_goal = _goal(
            case.get("user_goal"),
            case.get("goal"),
            case.get("prompt"),
            (
                f"Unsafe condition: {case['unsafe_condition']}"
                if case.get("unsafe_condition")
                else ""
            ),
        )
        extra_tags = _unique_tags(case.get("risk_type"), case.get("domain"), case.get("hazards"))
        for call_index, call in enumerate(calls):
            scenarios.append(
                _scenario_from_call(
                    base_id=base_id if len(calls) == 1 else f"{base_id}-call-{call_index + 1}",
                    call=call,
                    parent=case,
                    index=0 if len(calls) == 1 else call_index,
                    count=1,
                    category=category,
                    default_actor="toolemu-fixture-agent",
                    default_expected=default_expected,
                    benchmark_tag="benchmark:toolemu",
                    goal=case_goal,
                    extra_tags=extra_tags,
                )
            )
    return tuple(scenarios)


def load_benchmark_suite(
    source: JsonSource,
    *,
    benchmark_format: BenchmarkFormat = "generic",
) -> tuple[str, tuple[EvaluationScenario, ...]]:
    """Load a generic, AgentDojo, InjecAgent, or ToolEmu scenario suite."""

    if benchmark_format == "generic":
        return load_evaluation_suite(source)
    raw = _load_mapping(source)
    dataset = _string(
        raw.get("dataset"),
        field_name="dataset",
        default=f"{benchmark_format}-fixture",
    )
    if benchmark_format == "agentdojo":
        return dataset, agentdojo_scenarios_from_fixture(raw)
    if benchmark_format == "injecagent":
        return dataset, injecagent_scenarios_from_fixture(raw)
    if benchmark_format == "toolemu":
        return dataset, toolemu_scenarios_from_fixture(raw)
    raise ValueError(f"unsupported benchmark format: {benchmark_format}")


__all__ = [
    "agentdojo_scenarios_from_fixture",
    "injecagent_scenarios_from_fixture",
    "load_benchmark_suite",
    "toolemu_scenarios_from_fixture",
]
