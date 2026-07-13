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
    assert d["action_tier"] == "commit"  # C6: present in the hashed dict
    d["action_tier"] = "explore"  # post-issuance swap, hash NOT recomputed
    tampered = DecisionReceipt.from_dict(d)

    with pytest.raises(ReceiptValidationError) as exc:
        tampered.verify()
    assert "receipt_hash mismatch" in str(exc.value)


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
# binding so a tampered/omitted tier could slip past verify(). We do NOT do that:
# an unverifiable pre-schema receipt is refused, not waved through.
# ---------------------------------------------------------------------------


def test_t4a_from_dict_missing_tier_defaults_commit() -> None:
    # (i) The deserialization-compat claim that genuinely holds: a dict from
    # before the field existed rehydrates with action_tier == "commit" (C4/C7).
    receipt = _mint_receipt(action_tier=None)  # minted with the commit default
    d = receipt.to_dict()
    del d["action_tier"]  # simulate a receipt from before the field existed
    legacy = DecisionReceipt.from_dict(d)

    assert legacy.action_tier == ActionTier.COMMIT.value


def test_t4b_pre_schema_hash_without_tier_fails_verify() -> None:
    # (ii) A GENUINELY pre-schema receipt: its receipt_hash was computed by old
    # code over a dict that never contained action_tier. We reproduce that hash
    # honestly — excluding action_tier from the hashed payload (exactly as
    # compute_hash did before the field existed) — and pin it as receipt_hash.
    from gove_zone.decision import sha256_json

    receipt = _mint_receipt(action_tier=None)
    old_payload = receipt.to_dict()
    del old_payload["action_tier"]  # old code had no such key in the hashed dict
    old_payload.pop("receipt_hash", None)
    old_payload.pop("signature", None)
    pre_schema_hash = sha256_json(old_payload)

    d = receipt.to_dict()
    del d["action_tier"]  # legacy on-wire form: no tier key
    d["receipt_hash"] = pre_schema_hash  # hash computed WITHOUT action_tier
    legacy = DecisionReceipt.from_dict(d)

    # from_dict still defaults the field to "commit", and compute_hash() re-includes
    # it — so the recomputed hash covers a field the stored hash never did.
    assert legacy.action_tier == ActionTier.COMMIT.value
    with pytest.raises(ReceiptValidationError) as exc:
        legacy.verify()
    assert "receipt_hash mismatch" in str(exc.value)  # fail-closed, C6 intact


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
