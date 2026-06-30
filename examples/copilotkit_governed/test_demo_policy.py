from __future__ import annotations

from gove_zone import Decision
from gove_zone.tool import ToolCall

from examples.copilotkit_governed.demo import CopilotKitDemoPolicy


def _decide(args: dict[str, object]) -> Decision:
    record = CopilotKitDemoPolicy().evaluate(
        ToolCall(name="runtime.file.write", args=args, actor="copilotkit-copilot")
    )
    return record.decision


def test_demo_policy_ignores_forbidden_words_in_keys() -> None:
    assert _decide({"secrets/path_label": "public/report.json", "content": "ok"}) is Decision.ALLOW


def test_demo_policy_denies_nested_forbidden_string_values() -> None:
    assert _decide(
        {"paths": ["public/report.json", {"target": "/home/u/.ssh/id_rsa"}]}
    ) is Decision.DENY
