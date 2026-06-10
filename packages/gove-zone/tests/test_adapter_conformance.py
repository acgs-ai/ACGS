"""Adapter conformance harness — end-to-end parity across runtime families.

Every supported runtime wire shape encodes the SAME logical tool call
(``file.write`` with identical arguments, goal, and organizational state).
Each payload is driven through the PUBLIC :func:`emit_receipts_for_hook`
entry point only — never the private payload resolver — and must produce:

* the same normalized ``runtime.file.write`` tool name,
* the same argument hash, path, goal, and state hash,
* an identical audit-event key set,
* a verifying hash chain after the append,
* identical DENY behavior under an enforcing policy, and
* the fail-closed ``runtime.malformed_batch`` DENY for unsafe batches,

in both OBSERVE and ENFORCE gate modes. This is the executable form of the
"gate position is framework-neutral" claim (docs/INTEGRATION_MATRIX.md).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision
from gove_zone.integration import (
    GateMode,
    current_gate_mode,
    emit_receipt_for_hook,
    emit_receipts_for_hook,
    tool_call_from_hook_payload,
)
from gove_zone.policy import DenyAllPolicy

ACTION_KIND = "conformance"
ACTOR = "conformance-bridge"
GOAL = "persist governed conformance evidence"
STATE = {"trust_tier": "analyst"}

CANONICAL_TOOL = "file.write"
CANONICAL_ARGS = {"path": "repo/out/manifest.json", "content": "evidence"}
CANONICAL_ARGS_JSON = json.dumps(CANONICAL_ARGS)

EXPECTED_TOOL = f"runtime.{CANONICAL_TOOL}"
EXPECTED_PATH = ("repo", "out", "manifest.json")

# One entry per runtime family. Every payload is the same logical call —
# same tool name, arguments, goal, and state — in that family's wire shape.
FAMILY_PAYLOADS: dict[str, dict[str, Any]] = {
    "claude-hook": {
        "tool_name": CANONICAL_TOOL,
        "tool_input": CANONICAL_ARGS,
        "goal": GOAL,
        "state": STATE,
    },
    "codex-apply-patch-hook": {
        # Codex hook events use the same {tool_name, tool_input} contract as
        # Claude hooks; conformance pins that the branch stays shared.
        "tool_name": CANONICAL_TOOL,
        "tool_input": dict(CANONICAL_ARGS),
        "goal": GOAL,
        "state": STATE,
    },
    "mcp-tools-call": {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": CANONICAL_TOOL, "arguments": CANONICAL_ARGS},
        "goal": GOAL,
        "state": STATE,
    },
    "function-call-json-args": {
        "type": "function_call",
        "name": CANONICAL_TOOL,
        "arguments": CANONICAL_ARGS_JSON,
        "goal": GOAL,
        "state": STATE,
    },
    "openai-chat-tool-calls": {
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": CANONICAL_TOOL, "arguments": CANONICAL_ARGS_JSON},
            }
        ],
        "goal": GOAL,
        "state": STATE,
    },
    "openai-responses-output": {
        "output": [
            {
                "id": "fc_1",
                "call_id": "call_1",
                "type": "function_call",
                "name": CANONICAL_TOOL,
                "arguments": CANONICAL_ARGS_JSON,
            }
        ],
        "goal": GOAL,
        "state": STATE,
    },
    "openai-responses-nested": {
        "response": {
            "intent": GOAL,
            "context": STATE,
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "planning"}],
                },
                {
                    "type": "function_call",
                    "name": CANONICAL_TOOL,
                    "arguments": CANONICAL_ARGS_JSON,
                },
            ],
        }
    },
    "langchain-tool-call": {
        "tool_calls": [{"name": CANONICAL_TOOL, "args": CANONICAL_ARGS}],
        "goal": GOAL,
        "state": STATE,
    },
    "generic-name-args": {
        "name": CANONICAL_TOOL,
        "args": CANONICAL_ARGS,
        "goal": GOAL,
        "state": STATE,
    },
    "generic-tool-dict": {
        "tool": {"name": CANONICAL_TOOL, "args": CANONICAL_ARGS},
        "goal": GOAL,
        "state": STATE,
    },
}

# Multi-call batches: the same two logical calls per batching family.
BATCH_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("shell.run", {"path": "scripts/verify.sh", "command": "make verify"}),
    (CANONICAL_TOOL, CANONICAL_ARGS),
]
EXPECTED_BATCH_TOOLS = [f"runtime.{name}" for name, _ in BATCH_CALLS]

BATCH_PAYLOADS: dict[str, dict[str, Any]] = {
    "openai-chat-batch": {
        "goal": GOAL,
        "state": STATE,
        "tool_calls": [
            {
                "id": f"call_{index}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
            for index, (name, args) in enumerate(BATCH_CALLS)
        ],
    },
    "openai-responses-batch": {
        "response": {
            "intent": GOAL,
            "context": STATE,
            "output": [
                {"type": "function_call", "name": name, "arguments": json.dumps(args)}
                for name, args in BATCH_CALLS
            ],
        }
    },
}

MALFORMED_BATCH_PAYLOADS: dict[str, dict[str, Any]] = {
    "malformed-tool-calls": {
        "goal": GOAL,
        "state": STATE,
        "tool_calls": [
            {
                "id": "call_without_name",
                "type": "function",
                "function": {"arguments": CANONICAL_ARGS_JSON},
            },
            "not-a-tool-call",
        ],
    },
    "malformed-responses-output": {
        "response": {
            "intent": GOAL,
            "context": STATE,
            "output": [
                {
                    "type": "function_call",
                    "name": "shell.run",
                    "arguments": json.dumps({"path": "scripts/verify.sh"}),
                },
                {"type": "function_call", "arguments": CANONICAL_ARGS_JSON},
            ],
        }
    },
}

MODES = (GateMode.OBSERVE, GateMode.ENFORCE)


@pytest.fixture(params=MODES, ids=[mode.value for mode in MODES])
def gate_mode(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> GateMode:
    """Isolated audit dir + the requested gate mode, parametrized over both."""
    mode: GateMode = request.param
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH", raising=False)
    if mode is GateMode.ENFORCE:
        monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "enforce")
        # The passive auditor emits unsigned audit-anchor receipts; the dev
        # profile acknowledges that under enforcement (production + enforce +
        # no signer fails loud by design and is covered in
        # test_integration_hook.py).
        monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
    else:
        monkeypatch.delenv("GOVE_ZONE_GATE_MODE", raising=False)
        monkeypatch.delenv("GOVE_ZONE_PROFILE", raising=False)
    assert current_gate_mode() is mode
    return mode


def _audit_path() -> Path:
    import os

    return Path(os.environ["CLAUDE_PROJECT_DIR"]) / ".gove-zone" / "audit.jsonl"


def _audit_events() -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in _audit_path().read_text(encoding="utf-8").strip().splitlines()
    ]


def _assert_chain_verifies(expected_events: int) -> None:
    store = ChainHashAuditStore(str(_audit_path()))
    verdict = store.verify_chain()
    assert verdict["valid"] is True
    assert verdict["checked"] == expected_events


# The public normalization of the reference (Claude hook) payload is the
# parity yardstick every other family must match.
_REFERENCE = tool_call_from_hook_payload(
    FAMILY_PAYLOADS["claude-hook"],
    action_kind=ACTION_KIND,
    actor=ACTOR,
)


@pytest.mark.parametrize("family", sorted(FAMILY_PAYLOADS))
def test_single_call_family_end_to_end(family: str, gate_mode: GateMode) -> None:
    receipts = emit_receipts_for_hook(
        FAMILY_PAYLOADS[family],
        action_kind=ACTION_KIND,
        actor=ACTOR,
    )

    assert receipts is not None
    assert len(receipts) == 1
    receipt = receipts[0]
    record = receipt.record

    assert record.decision is Decision.ALLOW
    assert record.tool == EXPECTED_TOOL
    assert record.argument_hash == _REFERENCE.argument_hash()
    assert record.path == EXPECTED_PATH
    assert record.goal == GOAL
    assert record.state_hash == _REFERENCE.state_hash()
    assert record.decision_request_hash == _REFERENCE.decision_request_hash()
    assert receipt.actor == ACTOR
    assert receipt.audit_hash and receipt.audit_hash != "0" * 64

    events = _audit_events()
    assert len(events) == 1
    assert events[0]["decision"] == "allow"
    assert events[0]["tool"] == EXPECTED_TOOL
    assert events[0]["matched_rules"] == [f"action_kind:{ACTION_KIND}"]
    _assert_chain_verifies(expected_events=1)


def test_cross_family_parity_in_one_chain(gate_mode: GateMode) -> None:
    """All families append into one chain and are pairwise indistinguishable
    except for per-event identifiers (event_id, hashes, timestamps)."""
    fingerprints: set[tuple[Any, ...]] = set()
    event_key_sets: set[frozenset[str]] = set()

    for family, payload in sorted(FAMILY_PAYLOADS.items()):
        receipts = emit_receipts_for_hook(payload, action_kind=ACTION_KIND, actor=ACTOR)
        assert receipts is not None and len(receipts) == 1, family
        record = receipts[0].record
        fingerprints.add(
            (
                record.decision,
                record.tool,
                record.argument_hash,
                record.path,
                record.goal,
                record.state_hash,
                record.decision_request_hash,
                record.matched_rules,
                record.policy_version,
            )
        )

    events = _audit_events()
    assert len(events) == len(FAMILY_PAYLOADS)
    for event in events:
        event_key_sets.add(frozenset(event))

    assert len(fingerprints) == 1, "families diverged on the equivalent call"
    assert len(event_key_sets) == 1, "families produced different audit-event key sets"
    _assert_chain_verifies(expected_events=len(FAMILY_PAYLOADS))


def test_deny_behavior_identical_across_families(gate_mode: GateMode) -> None:
    """A denying policy yields the same DENY receipt fields for every family,
    in both modes — a recorded DENY is a successful emission, never executable,
    and never raises under enforcement."""
    deny_fingerprints: set[tuple[Any, ...]] = set()

    for family, payload in sorted(FAMILY_PAYLOADS.items()):
        receipt = emit_receipt_for_hook(
            payload,
            action_kind=ACTION_KIND,
            actor=ACTOR,
            policy=DenyAllPolicy(),
        )
        assert receipt is not None, family
        record = receipt.record
        assert record.decision is Decision.DENY, family
        assert receipt.result_hash is None, "DENY must never carry an execution result"
        deny_fingerprints.add(
            (
                record.decision,
                record.tool,
                record.argument_hash,
                record.policy_version,
                record.matched_rules,
                record.reason,
                record.decision_request_hash,
            )
        )

    assert len(deny_fingerprints) == 1, "DENY behavior diverged across families"
    events = _audit_events()
    assert len(events) == len(FAMILY_PAYLOADS)
    assert {event["decision"] for event in events} == {"deny"}
    _assert_chain_verifies(expected_events=len(FAMILY_PAYLOADS))


@pytest.mark.parametrize("batch_family", sorted(BATCH_PAYLOADS))
def test_batched_multi_call_expands_per_child(batch_family: str, gate_mode: GateMode) -> None:
    receipts = emit_receipts_for_hook(
        BATCH_PAYLOADS[batch_family],
        action_kind=ACTION_KIND,
        actor=ACTOR,
    )

    assert receipts is not None
    assert [receipt.record.tool for receipt in receipts] == EXPECTED_BATCH_TOOLS
    assert {receipt.record.goal for receipt in receipts} == {GOAL}
    assert {receipt.record.decision for receipt in receipts} == {Decision.ALLOW}

    events = _audit_events()
    assert [event["tool"] for event in events] == EXPECTED_BATCH_TOOLS
    _assert_chain_verifies(expected_events=len(BATCH_CALLS))


@pytest.mark.parametrize("batch_family", sorted(BATCH_PAYLOADS))
def test_batched_deny_blocks_via_single_receipt_api(batch_family: str, gate_mode: GateMode) -> None:
    """The compatibility single-receipt API surfaces the blocking DENY receipt
    for batches identically across batching families."""
    receipt = emit_receipt_for_hook(
        BATCH_PAYLOADS[batch_family],
        action_kind=ACTION_KIND,
        actor=ACTOR,
        policy=DenyAllPolicy(),
    )

    assert receipt is not None
    assert receipt.record.decision is Decision.DENY
    assert receipt.record.tool == EXPECTED_BATCH_TOOLS[0]
    _assert_chain_verifies(expected_events=len(BATCH_CALLS))


@pytest.mark.parametrize("malformed_family", sorted(MALFORMED_BATCH_PAYLOADS))
def test_malformed_batch_fails_closed_in_every_mode(
    malformed_family: str, gate_mode: GateMode
) -> None:
    """Unsafe batches synthesize the fail-closed runtime.malformed_batch DENY —
    never a partial expansion — in observe and enforce alike, and never raise:
    the deny is the successful, recorded outcome."""
    receipts = emit_receipts_for_hook(
        MALFORMED_BATCH_PAYLOADS[malformed_family],
        action_kind=ACTION_KIND,
        actor=ACTOR,
    )

    assert receipts is not None
    assert len(receipts) == 1
    record = receipts[0].record
    assert record.decision is Decision.DENY
    assert record.tool == "runtime.malformed_batch"
    assert record.policy_version == "runtime-malformed-batch/v0"
    assert record.matched_rules == ("malformed_batch",)
    assert record.goal == GOAL

    blocking = emit_receipt_for_hook(
        MALFORMED_BATCH_PAYLOADS[malformed_family],
        action_kind=ACTION_KIND,
        actor=ACTOR,
    )
    assert blocking is not None
    assert blocking.record.decision is Decision.DENY
    assert blocking.record.tool == "runtime.malformed_batch"

    events = _audit_events()
    assert len(events) == 2
    assert {event["decision"] for event in events} == {"deny"}
    _assert_chain_verifies(expected_events=2)
