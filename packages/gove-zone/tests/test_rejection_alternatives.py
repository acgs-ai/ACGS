"""Tests for the simulate → rejection-envelope wiring (``allowed_alternatives``).

PR-1 shipped the envelope with ``allowed_alternatives`` omitted (absence ==
"not computed"); PR-2 shipped the read-only ``Kernel.simulate`` primitive. This
wiring lets a denied caller probe candidate variants via simulation and have the
envelope advertise the ones that would pass — without the envelope ever echoing
raw arguments, and without any execution or audit mutation.

Properties tested directly:

- **Tri-state contract:** key absent == "not computed"; present (even empty)
  == "computed". The default keeps PR-1's behaviour byte-for-byte.
- **Fail-closed projection:** ``alternative_from_record`` only projects
  ALLOW/TRANSFORM; ``rejection_dict`` refuses entries carrying raw inputs.
- **Read-only discovery:** ``discover_alternatives`` executes nothing and
  leaves the audit chain head unchanged — asserted, not assumed.
"""

from __future__ import annotations

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    EscalateError,
    Kernel,
    UnknownToolError,
    alternative_from_record,
    discover_alternatives,
    new_event_id,
    rejection_dict,
    sha256_json,
)


def _record(decision: Decision, **overrides: object) -> DecisionRecord:
    base: dict = {
        "decision": decision,
        "tool": "do.thing",
        "argument_hash": sha256_json({"x": 1}),
        "policy_version": "test/v1",
        "event_id": new_event_id(),
        "matched_rules": ("R:test",),
        "reason": "because",
    }
    if decision is Decision.TRANSFORM:
        base["transformed_args"] = {"x": "redacted"}
    base.update(overrides)
    return DecisionRecord(**base)


def _kernel(tmp_path) -> tuple[Kernel, list[dict]]:
    """Kernel with a boundary policy that denies args containing 'forbidden'."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    ran: list[dict] = []
    kernel = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["forbidden"], rule_id="P-ALT"),
        audit=audit,
        actor="agent-x",
    )

    @kernel.tool("do.thing")
    def thing(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "did it"

    return kernel, ran


# ---------------------------------------------------------------- tri-state


def test_envelope_omits_alternatives_by_default() -> None:
    env = rejection_dict(
        _record(Decision.DENY),
        "a" * 64,
        resumable=False,
        resolution="revise_and_retry",
    )
    assert "allowed_alternatives" not in env  # absence == "not computed"


def test_envelope_carries_computed_alternatives_even_when_empty() -> None:
    env = rejection_dict(
        _record(Decision.DENY),
        "a" * 64,
        resumable=False,
        resolution="revise_and_retry",
        allowed_alternatives=[],
    )
    # present-but-empty == "computed: none permitted" — distinct from absence.
    assert env["allowed_alternatives"] == []


# ------------------------------------------------- fail-closed projection


def test_alternative_from_record_projects_allow_and_transform() -> None:
    for decision in (Decision.ALLOW, Decision.TRANSFORM):
        record = _record(decision)
        entry = alternative_from_record(record)
        assert entry == {
            "tool": "do.thing",
            "decision": decision.value,
            "argument_hash": record.argument_hash,
            "decision_request_hash": record.decision_request_hash,
            "policy_version": "test/v1",
        }
        # leak posture: no raw inputs in the projection
        assert "args" not in entry
        assert "transformed_args" not in entry


def test_alternative_from_record_rejects_deny_and_escalate() -> None:
    for decision in (Decision.DENY, Decision.ESCALATE):
        with pytest.raises(ValueError, match="ALLOW/TRANSFORM"):
            alternative_from_record(_record(decision))


def _valid_alternative(**overrides: object) -> dict:
    entry: dict = {
        "tool": "do.thing",
        "decision": "allow",
        "argument_hash": "c" * 64,
        "decision_request_hash": "d" * 64,
        "policy_version": "test/v1",
    }
    entry.update(overrides)
    return entry


def _reject_alternatives(alternatives: list[dict], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        rejection_dict(
            _record(Decision.DENY),
            "a" * 64,
            resumable=False,
            resolution="revise_and_retry",
            allowed_alternatives=alternatives,
        )


def test_rejection_dict_refuses_raw_inputs_in_alternatives() -> None:
    # Positive allowlist: raw-input keys are unknown keys, hence refused —
    # including when smuggled alongside an otherwise-valid entry.
    for leaky_key in ("args", "transformed_args", "state"):
        _reject_alternatives([_valid_alternative(**{leaky_key: {"x": 1}})], "unknown keys")


def test_rejection_dict_refuses_unknown_keys_and_nested_payloads() -> None:
    # Any key outside the closed schema is refused — there is no nesting
    # loophole because there is no carrier key to nest under.
    _reject_alternatives([_valid_alternative(meta={"args": {"secret": 1}})], "unknown keys")
    _reject_alternatives([_valid_alternative(raw_prompt="leak")], "unknown keys")


def test_rejection_dict_refuses_incomplete_or_mistyped_alternatives() -> None:
    incomplete = _valid_alternative()
    del incomplete["argument_hash"]
    _reject_alternatives([incomplete], "missing required keys")
    _reject_alternatives([_valid_alternative(tool={"name": "do.thing"})], "must be str")
    _reject_alternatives([_valid_alternative(candidate_index="0")], "must be int")


# ---------------------------------------------------- read-only discovery


def test_discover_alternatives_end_to_end(tmp_path) -> None:
    kernel, ran = _kernel(tmp_path)

    # The original call is denied — the dispatch IS audited (that is the deal).
    with pytest.raises(DeniedError) as excinfo:
        kernel.dispatch("do.thing", {"note": "this is forbidden"}, goal="g")
    head_after_deny = kernel.audit.last_hash()

    candidates = [
        {"tool": "do.thing", "args": {"note": "still forbidden"}, "goal": "g"},
        {"tool": "do.thing", "args": {"note": "sanitized"}, "goal": "g"},
    ]
    alternatives = discover_alternatives(kernel, candidates)

    # Discovery is read-only: nothing executed, audit head unchanged.
    assert ran == []
    assert kernel.audit.last_hash() == head_after_deny

    # Only the passing variant is advertised, mapped back by index.
    assert [a["candidate_index"] for a in alternatives] == [1]
    assert alternatives[0]["tool"] == "do.thing"
    assert alternatives[0]["decision"] == "allow"

    # Wire into the envelope through the error's passthrough.
    env = excinfo.value.to_rejection_dict(allowed_alternatives=alternatives)
    assert env["allowed_alternatives"] == alternatives
    assert env["status"] == "deny"
    # The envelope still never carries raw candidate arguments.
    assert "args" not in env["allowed_alternatives"][0]


def test_discover_alternatives_propagates_unknown_tool(tmp_path) -> None:
    kernel, _ = _kernel(tmp_path)
    with pytest.raises(UnknownToolError):
        discover_alternatives(kernel, [{"tool": "not.registered", "args": {}}])


def test_discover_alternatives_rejects_malformed_candidates(tmp_path) -> None:
    kernel, _ = _kernel(tmp_path)
    # No silent coercion: a missing/non-str tool and a non-str goal raise
    # instead of being str()-bent into a different (still denied) probe.
    with pytest.raises(ValueError, match="requires a str 'tool'"):
        discover_alternatives(kernel, [{"args": {"x": 1}}])
    with pytest.raises(ValueError, match="requires a str 'tool'"):
        discover_alternatives(kernel, [{"tool": 123}])
    with pytest.raises(ValueError, match="'goal' must be str"):
        discover_alternatives(kernel, [{"tool": "do.thing", "goal": None}])


def test_escalate_to_rejection_dict_passthrough() -> None:
    exc = EscalateError(_record(Decision.ESCALATE), "b" * 64)
    env = exc.to_rejection_dict(
        allowed_alternatives=[
            {
                "tool": "do.thing",
                "decision": "allow",
                "argument_hash": "c" * 64,
                "decision_request_hash": "d" * 64,
                "policy_version": "test/v1",
            }
        ]
    )
    assert env["status"] == "escalate"
    assert env["allowed_alternatives"][0]["decision"] == "allow"
    # default stays omitted on the escalate path too
    assert "allowed_alternatives" not in exc.to_rejection_dict()
