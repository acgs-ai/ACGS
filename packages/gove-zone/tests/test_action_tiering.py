"""Explore-vs-commit action tiering — negative-path first.

Tiering routes which POLICY RULES match (a read-only probe vs an irreversible
side effect), it never bypasses the receipt gate. These tests are the
deliverable: they prove that a declared ``explore`` tier can never grant
leniency for a tool the registry marks side-effecting, that the tier is
hash-bound into the receipt, and that legacy tier-less receipts still verify.

Constraint anchors (see the design brief): C1 fail-closed preserved,
C4 commit-default for unknown/missing, C5 declared tier is untrusted and the
registry is authoritative, C6 tier binds into ``receipt_hash``, C7 backward
compat for legacy receipts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    ActionTier,
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    DeniedError,
    GovernedExecutor,
    Kernel,
    ReceiptValidationError,
    RuleSetPolicy,
    ToolCall,
    ToolTierRegistry,
    Validator,
    execute_with_receipt,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _commit_deny_policy(*, tool_tiers: dict[str, str]) -> RuleSetPolicy:
    """A bundle whose one rule denies ``fs.write`` ONLY at the commit tier."""
    return RuleSetPolicy.from_dict(
        {
            "id": "tiering/v1",
            "tool_tiers": tool_tiers,
            "rules": [
                {
                    "id": "COMMIT_WRITE_DENY",
                    "effect": "deny",
                    "tools": ["fs.write"],
                    "tiers": ["commit"],
                    "reason": "writes must not run under the commit tier here",
                }
            ],
        }
    )


def _mint_receipt(
    *,
    decision: str = "allow",
    action: str = "fs.write",
    args: dict[str, Any] | None = None,
    action_tier: str | None = None,
) -> DecisionReceipt:
    effective_args = args if args is not None else {"path": "safe.txt"}
    from gove_zone.decision import sha256_json

    record = DecisionRecord(
        decision=Decision(decision),
        tool=action,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_tier",
        action_tier=action_tier,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-tier",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )


# ---------------------------------------------------------------------------
# T1 — declared explore on a commit-registered tool is evaluated as commit
# (executor/kernel wiring test, not a bare unit call), and DENY blocks the
# side effect.
# ---------------------------------------------------------------------------


def test_t1_declared_explore_on_commit_tool_evaluated_as_commit_and_denied(
    tmp_path: Path,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    # fs.write registered commit-only; declaring explore must NOT downgrade it.
    kernel = Kernel(
        policy=_commit_deny_policy(tool_tiers={"fs.write": "commit"}),
        audit=audit,
        actor="agent-7",
    )
    executed: list[str] = []

    @kernel.tool("fs.write")
    def write(path: str) -> str:
        executed.append(path)
        return path

    with pytest.raises(DeniedError) as exc:
        kernel.dispatch(
            "fs.write",
            {"path": "prod.db"},
            goal="probe",
            state={"action_tier": "explore"},  # UNTRUSTED misdeclaration
        )

    assert executed == []  # side effect did NOT run
    assert exc.value.record.matched_rules == ("COMMIT_WRITE_DENY",)
    assert exc.value.record.action_tier == ActionTier.COMMIT.value


def test_t1b_explore_registered_tool_declared_explore_is_lenient(
    tmp_path: Path,
) -> None:
    # Same rule (commit-tier only) but fs.write is genuinely explore-capable.
    kernel = Kernel(
        policy=_commit_deny_policy(tool_tiers={"fs.write": "explore"}),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="agent-7",
    )
    executed: list[str] = []

    @kernel.tool("fs.write")
    def write(path: str) -> str:
        executed.append(path)
        return path

    result, receipt = kernel.dispatch(
        "fs.write",
        {"path": "scratch"},
        goal="probe",
        state={"action_tier": "explore"},
    )
    assert result == "scratch"
    assert executed == ["scratch"]
    assert receipt.record.action_tier == ActionTier.EXPLORE.value


# ---------------------------------------------------------------------------
# T2 — missing / garbage declared tier defaults to commit.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("declared", [None, "", "EXPLORE ", "admin", "mutate", 42])
def test_t2_unknown_or_missing_declared_tier_defaults_commit(declared: Any) -> None:
    assert ActionTier.coerce(declared) is ActionTier.COMMIT
    # And through the registry: an explore-capable tool still resolves to commit
    # when the declaration is missing/garbage.
    reg = ToolTierRegistry.from_dict({"fs.read": "explore"})
    state = {} if declared is None else {"action_tier": declared}
    call = ToolCall(name="fs.read", state=state)
    assert reg.effective_tier(call) is ActionTier.COMMIT


def test_t2b_explore_only_when_exactly_explore() -> None:
    reg = ToolTierRegistry.from_dict({"fs.read": "explore"})
    call = ToolCall(name="fs.read", state={"action_tier": "explore"})
    assert reg.effective_tier(call) is ActionTier.EXPLORE


# ---------------------------------------------------------------------------
# T3 — tampering the tier in a serialized receipt breaks the hash → verify fails.
# ---------------------------------------------------------------------------


def test_t3_tampered_action_tier_fails_hash(tmp_path: Path) -> None:
    receipt = _mint_receipt(action_tier="commit")
    d = receipt.to_dict()
    # C6/C7: the strict `commit` default is folded out of both the wire form and
    # the hash payload, so a pre-field receipt is byte-identical...
    assert "action_tier" not in d
    d["action_tier"] = "explore"  # ...but this post-issuance swap adds a key the
    tampered = DecisionReceipt.from_dict(d)  # stored hash never covered.

    with pytest.raises(ReceiptValidationError) as exc:
        tampered.verify()
    assert "receipt_hash mismatch" in str(exc.value)


def test_t3c_downgrading_an_explore_receipt_to_commit_also_fails_hash() -> None:
    # The inverse direction: an explore receipt IS hash-bound, so dropping the
    # key to make it look like a legacy commit receipt breaks verification.
    receipt = _mint_receipt(action_tier="explore")
    d = receipt.to_dict()
    assert d["action_tier"] == "explore"
    del d["action_tier"]
    tampered = DecisionReceipt.from_dict(d)

    assert tampered.action_tier == ActionTier.COMMIT.value
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        tampered.verify()


def test_t3b_tampered_tier_refused_at_gate(tmp_path: Path) -> None:
    receipt = _mint_receipt(action_tier="commit")
    d = receipt.to_dict()
    d["action_tier"] = "explore"
    tampered = DecisionReceipt.from_dict(d)
    called: list[str] = []

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=lambda path: called.append(path),
            args={"path": "safe.txt"},
            receipt=tampered,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="fs.write",
            expected_actor="anonymous",
            require_signature=False,
        )
    assert called == []


# ---------------------------------------------------------------------------
# T4 — legacy receipt (no action_tier key). Two honest halves:
#   (i)  from_dict on a dict missing the key DEFAULTS the field to "commit"
#        (the deserialization-compat part that IS true, C7);
#   (ii) a receipt whose receipt_hash was genuinely computed WITHOUT
#        action_tier in the hashed dict (i.e. by pre-schema code that never had
#        the field) FAILS verify() with a receipt_hash mismatch.
#
# This is fail-closed and CORRECT. compute_hash() always re-includes
# action_tier (the dataclass default "commit" is in to_dict()), so the recomputed
# hash covers a field the old hash never did → mismatch. Accepting such a receipt
# would require dropping action_tier from the hashed dict, weakening the C6 hash
# binding so a tampered tier could slip past verify(). We do NOT do that: the
# `commit` default is folded out of the hash payload (it is exactly what a
# pre-schema receipt means), so legacy receipts verify unchanged while any
# explore receipt — and any tier swap in either direction — is hash-bound.
# ---------------------------------------------------------------------------


def test_t4a_from_dict_missing_tier_defaults_commit() -> None:
    # (i) The deserialization-compat claim that genuinely holds: a dict from
    # before the field existed rehydrates with action_tier == "commit" (C4/C7).
    receipt = _mint_receipt(action_tier=None)  # minted with the commit default
    d = receipt.to_dict()
    assert "action_tier" not in d  # a commit receipt IS the pre-field wire form
    legacy = DecisionReceipt.from_dict(d)

    assert legacy.action_tier == ActionTier.COMMIT.value


def test_t4b_pre_schema_receipt_still_verifies_as_commit() -> None:
    # (ii) A GENUINELY pre-schema receipt: its receipt_hash was computed by old
    # code over a payload that never contained action_tier. Because `commit` is
    # folded OUT of the hash payload (it is the strict default and is exactly
    # what a pre-schema receipt means), that stored hash is still the hash this
    # code computes — the field is additive, not a wire break.
    receipt = _mint_receipt(action_tier=None)
    d = receipt.to_dict()
    pre_schema_hash = d["receipt_hash"]
    assert "action_tier" not in d  # legacy on-wire form: no tier key at all
    legacy = DecisionReceipt.from_dict(d)

    assert legacy.action_tier == ActionTier.COMMIT.value
    assert legacy.receipt_hash == pre_schema_hash
    legacy.verify()  # C7: no break for receipts issued before the field existed


def test_t4c_legacy_hash_still_binds_every_other_field() -> None:
    # The commit-tier fold-out must not become a general hash escape hatch: a
    # tier-less receipt still has every other field bound.
    receipt = _mint_receipt(action_tier=None)
    d = receipt.to_dict()
    d["tenant_id"] = "tenant-B"

    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        DecisionReceipt.from_dict(d).verify()


def test_t4d_commit_receipt_hash_is_unchanged_by_the_new_field() -> None:
    # The frozen-vector guarantee, stated directly: adding action_tier must not
    # move the hash of a commit-tier receipt.
    from gove_zone.decision import sha256_json

    receipt = _mint_receipt(action_tier="commit")
    payload = receipt.to_dict()
    payload.pop("receipt_hash")
    payload.pop("signature")
    assert "action_tier" not in payload  # the pre-field payload, byte for byte

    assert receipt.receipt_hash == sha256_json(payload)


# ---------------------------------------------------------------------------
# T5 — explore ALLOW receipt executes for an explore tool; the same receipt
# is refused when the registry marks its action commit-only (belt-and-suspenders).
# ---------------------------------------------------------------------------


def test_t5_explore_receipt_executes_for_explore_tool() -> None:
    receipt = _mint_receipt(action_tier="explore")
    reg = ToolTierRegistry.from_dict({"fs.write": "explore"})
    called: list[str] = []

    execute_with_receipt(
        tool_fn=lambda path: called.append(path),
        args={"path": "safe.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="fs.write",
        expected_actor="anonymous",
        require_signature=False,
        tool_tier_registry=reg,
    )
    assert called == ["safe.txt"]


def test_t5b_explore_receipt_refused_when_action_is_commit_only() -> None:
    receipt = _mint_receipt(action_tier="explore")
    reg = ToolTierRegistry.from_dict({"fs.write": "commit"})  # commit-only tool
    called: list[str] = []

    with pytest.raises(ReceiptValidationError) as exc:
        execute_with_receipt(
            tool_fn=lambda path: called.append(path),
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="fs.write",
            expected_actor="anonymous",
            require_signature=False,
            tool_tier_registry=reg,
        )
    assert "commit" in str(exc.value).lower()
    assert called == []


# ---------------------------------------------------------------------------
# T6 — a rule with tiers=∅ matches every tier (no regression on old bundles).
# ---------------------------------------------------------------------------


def test_t6_empty_tiers_matches_all_tiers(tmp_path: Path) -> None:
    # No "tiers" key + no tool_tiers → behaves exactly like a pre-tiering bundle.
    policy = RuleSetPolicy.from_dict(
        {
            "id": "legacy/v1",
            "rules": [{"id": "ALWAYS_DENY", "effect": "deny", "tools": ["fs.write"]}],
        }
    )
    rule = policy.rules[0]
    assert rule.tiers == frozenset()
    explore_call = ToolCall(name="fs.write", state={"action_tier": "explore"})
    commit_call = ToolCall(name="fs.write", state={"action_tier": "commit"})
    assert rule.matches(explore_call, effective_tier=ActionTier.EXPLORE)
    assert rule.matches(commit_call, effective_tier=ActionTier.COMMIT)


# ---------------------------------------------------------------------------
# T7 — the audit chain carries the tier fields and still verifies.
# ---------------------------------------------------------------------------


def test_t7_audit_chain_contains_tier_and_verifies(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=_commit_deny_policy(tool_tiers={"fs.read": "explore"}),
        audit=audit,
        actor="agent-7",
    )

    @kernel.tool("fs.read")
    def read(path: str) -> str:
        return path

    kernel.dispatch("fs.read", {"path": "x"}, state={"action_tier": "explore"})

    [event] = list(audit.iter_events())
    assert event["action_tier"] == ActionTier.EXPLORE.value
    assert event["declared_action_tier"] == "explore"
    assert audit.verify_chain()["valid"]


# ---------------------------------------------------------------------------
# T8 — DENY / ESCALATE stay non-executable regardless of the explore tier.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("decision", ["deny", "escalate"])
def test_t8_deny_escalate_non_executable_under_explore(decision: str) -> None:
    receipt = _mint_receipt(decision=decision, action_tier="explore")
    with pytest.raises(ReceiptValidationError):
        receipt.verify()


# ---------------------------------------------------------------------------
# T9 — an explore receipt presented at a gate with NO tier registry is refused.
# The registry is what grants explore leniency; its absence must not be read as
# permission (C4 fail-closed, and the executor-side check can only ever be
# stricter than the policy-side evaluation, never more lenient).
# ---------------------------------------------------------------------------


def test_t9_explore_receipt_refused_when_registry_is_omitted() -> None:
    receipt = _mint_receipt(action_tier="explore")
    called: list[str] = []

    def adapter(path: str) -> None:
        called.append(path)

    with pytest.raises(ReceiptValidationError, match="requires a tool tier registry"):
        execute_with_receipt(
            tool_fn=adapter,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="fs.write",
            expected_actor="anonymous",
            require_signature=False,
        )
    assert called == []


def test_t9b_explore_receipt_refused_when_action_is_commit_only() -> None:
    receipt = _mint_receipt(action_tier="explore")
    called: list[str] = []

    def adapter(path: str) -> None:
        called.append(path)

    with pytest.raises(ReceiptValidationError, match="commit-only"):
        execute_with_receipt(
            tool_fn=adapter,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="fs.write",
            expected_actor="anonymous",
            require_signature=False,
            tool_tier_registry=ToolTierRegistry.from_dict({"fs.write": "commit"}),
        )
    assert called == []


def test_t9c_explore_receipt_executes_for_an_explore_registered_tool() -> None:
    receipt = _mint_receipt(action_tier="explore")
    called: list[str] = []

    def adapter(path: str) -> None:
        called.append(path)

    execute_with_receipt(
        tool_fn=adapter,
        args={"path": "safe.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="fs.write",
        expected_actor="anonymous",
        require_signature=False,
        tool_tier_registry=ToolTierRegistry.from_dict({"fs.write": "explore"}),
    )
    assert called == ["safe.txt"]


# ---------------------------------------------------------------------------
# T10 — the SAME checks reached through the GovernedExecutor dispatcher rather
# than a direct execute_with_receipt call. The registry is constructor-only on
# the executor, so these prove the constructor value is actually threaded to the
# gate: a passing T9 says nothing about the dispatcher path
# (`~/.claude/rules/review-handler-wiring.md`).
# ---------------------------------------------------------------------------


def _tiering_executor(registry: ToolTierRegistry | None) -> tuple[GovernedExecutor, list[str]]:
    called: list[str] = []
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,
        tool_tier_registry=registry,
    )
    executor.register("fs.write", lambda path: called.append(path))
    return executor, called


def test_t10_executor_threads_its_registry_and_honours_an_explore_receipt() -> None:
    executor, called = _tiering_executor(ToolTierRegistry.from_dict({"fs.write": "explore"}))
    executor.execute("fs.write", {"path": "safe.txt"}, _mint_receipt(action_tier="explore"))
    assert called == ["safe.txt"]


def test_t10b_executor_without_a_registry_refuses_an_explore_receipt() -> None:
    executor, called = _tiering_executor(None)
    with pytest.raises(ReceiptValidationError, match="requires a tool tier registry"):
        executor.execute("fs.write", {"path": "safe.txt"}, _mint_receipt(action_tier="explore"))
    assert called == []


def test_t10c_executor_registry_refuses_an_explore_receipt_for_a_commit_only_tool() -> None:
    executor, called = _tiering_executor(ToolTierRegistry.from_dict({"fs.write": "commit"}))
    with pytest.raises(ReceiptValidationError, match="commit-only"):
        executor.execute("fs.write", {"path": "safe.txt"}, _mint_receipt(action_tier="explore"))
    assert called == []


def test_t10d_executor_has_no_per_call_tier_registry_escape_hatch() -> None:
    """A per-call registry would let one call widen explore leniency (C5)."""
    executor, called = _tiering_executor(None)
    with pytest.raises(TypeError):
        executor.execute(  # type: ignore[call-arg]
            "fs.write",
            {"path": "safe.txt"},
            _mint_receipt(action_tier="explore"),
            tool_tier_registry=ToolTierRegistry.from_dict({"fs.write": "explore"}),
        )
    assert called == []


# ---------------------------------------------------------------------------
# Codex-review regression — a frozen ToolTierRegistry must also freeze its
# mapping CONTENTS, so a registry mutated after a policy caches its version
# cannot flip decisions while the content-addressed version stays unchanged
# (the "changed registry => changed version" binding).
# ---------------------------------------------------------------------------


def test_tool_tier_registry_contents_are_immutable() -> None:
    reg = ToolTierRegistry.from_dict({"fs.write": "commit"})
    with pytest.raises(TypeError):
        reg.tiers["fs.write"] = ActionTier.EXPLORE  # type: ignore[index]
    assert reg.max_tier("fs.write") is ActionTier.COMMIT


def test_registry_mutation_cannot_desync_version_from_decision() -> None:
    policy = _commit_deny_policy(tool_tiers={"fs.write": "commit"})
    call = ToolCall(actor="a", name="fs.write", args={}, state={"action_tier": "explore"})
    version_before = policy.version
    decision_before = policy.evaluate(call).decision
    # An explore declaration on a commit-only tool resolves to commit -> DENY.
    assert str(decision_before) == "deny"
    # Attempting to widen the tool to explore in place must fail (frozen contents),
    # so the cached version and the decision remain coupled.
    with pytest.raises(TypeError):
        policy._tier_registry.tiers["fs.write"] = ActionTier.EXPLORE  # type: ignore[union-attr,index]
    assert policy.version == version_before
    assert str(policy.evaluate(call).decision) == "deny"
