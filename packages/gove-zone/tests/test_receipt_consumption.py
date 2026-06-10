"""Tests for single-use receipt consumption (gove_zone.consumption).

These close audit finding F1/AUDIT-02: ``DecisionReceipt.verify`` is stateless,
so without external state one valid ALLOW (approval) receipt authorizes N
executions. The positive and negative paths here drive the real gate —
``GovernedExecutor.execute`` / ``execute_with_receipt`` with a
``ReceiptConsumptionLedger`` — through the full ESCALATE → approve → resume
bridge, not the ledger in isolation, so the burn point (after verify, before
the side effect) is proven where it matters.
"""

from __future__ import annotations

import dataclasses
import json
import multiprocessing
from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    ConsumptionLedgerError,
    Decision,
    DecisionRecord,
    EscalateError,
    GovernedExecutor,
    Kernel,
    PendingApproval,
    Policy,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
    ReceiptValidationError,
    Validator,
    approve_escalation,
    new_event_id,
    resume_with_receipt,
    sha256_json,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.tool import ToolCall

TENANT = "tenant-acme"
BOUNDARY = "prod/api"
PROPOSER = "agent-x"
BUNDLE = "bundle-1"
PHASH = "policyhash-abc"


class _EscalatePolicy(Policy):
    @property
    def version(self) -> str:
        return "test-escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE:needs-human",),
            reason="needs human approval",
        )


def _spy():
    calls: list[str] = []

    def fn(path: str) -> str:
        calls.append(path)
        return f"wrote {path}"

    return fn, calls


def _escalated(tmp_path, *, args: dict | None = None):
    args = {"path": "/tmp/safe"} if args is None else args
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=_EscalatePolicy(), audit=audit, actor=PROPOSER)

    @kernel.tool("write_file")
    def _never(**kwargs):  # pragma: no cover - must never run on ESCALATE
        raise AssertionError("kernel tool must not run on an ESCALATE dispatch")

    with pytest.raises(EscalateError) as ei:
        kernel.dispatch("write_file", args, goal="do the thing")
    return ei.value, audit


def _approve(pending: PendingApproval, audit: ChainHashAuditStore, **over) -> DecisionReceipt:
    kw = dict(
        validator=Validator("human-alice", "approver"),
        authority="grant:write",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=BUNDLE,
        policy_hash=PHASH,
        audit=audit,
    )
    kw.update(over)
    return approve_escalation(pending, **kw)


def _executor(*, ledger: ReceiptConsumptionLedger | None = None):
    # Explicit unsigned dev profile: these tests exercise the consumption gate,
    # not signature verification (covered by test_receipt_signing).
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=PROPOSER,
        require_signature=False,
        consumption_ledger=ledger,
    )
    ex.register("write_file", fn)
    return ex, calls


def _approved(tmp_path) -> tuple[PendingApproval, DecisionReceipt, ChainHashAuditStore]:
    err, audit = _escalated(tmp_path)
    assert err.pending is not None
    return err.pending, _approve(err.pending, audit), audit


# --- the F1 scenario: approve once, run once ---------------------------------


def test_resume_replay_blocked_with_ledger(tmp_path):
    pending, receipt, _ = _approved(tmp_path)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex, calls = _executor(ledger=ledger)

    assert resume_with_receipt(ex, pending, receipt) == "wrote /tmp/safe"
    with pytest.raises(ReceiptAlreadyUsedError) as ei:
        resume_with_receipt(ex, pending, receipt)
    assert calls == ["/tmp/safe"]
    assert ei.value.audit_event_hash == receipt.audit_event_hash


def test_replay_without_ledger_pins_stateless_gate(tmp_path):
    # Documents the opt-in posture: no ledger -> the stateless gate still
    # executes a valid receipt N times. This is the behavior F1 names; the
    # ledger is the fix, not a silent default change.
    pending, receipt, _ = _approved(tmp_path)
    ex, calls = _executor(ledger=None)
    resume_with_receipt(ex, pending, receipt)
    resume_with_receipt(ex, pending, receipt)
    assert calls == ["/tmp/safe", "/tmp/safe"]


def test_per_call_ledger_on_resume(tmp_path):
    # resume_with_receipt's own consumption_ledger kwarg reaches the gate even
    # when the executor was constructed without one.
    pending, receipt, _ = _approved(tmp_path)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex, calls = _executor(ledger=None)
    resume_with_receipt(ex, pending, receipt, consumption_ledger=ledger)
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex, pending, receipt, consumption_ledger=ledger)
    assert calls == ["/tmp/safe"]


# --- burn-point semantics -----------------------------------------------------


def test_verify_failure_does_not_burn(tmp_path):
    # A failed presentation (tampered args) must not waste the approval: the
    # gate consumes only after verify passes. The correct call still runs.
    pending, receipt, _ = _approved(tmp_path)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex, calls = _executor(ledger=ledger)

    tampered = dataclasses.replace(pending, args={"path": "/etc/shadow"})
    with pytest.raises(ReceiptValidationError):
        resume_with_receipt(ex, tampered, receipt)
    assert not ledger.is_consumed(receipt.audit_event_hash)

    assert resume_with_receipt(ex, pending, receipt) == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


def test_tool_failure_still_burns(tmp_path):
    # At-most-once, not exactly-once: the burn lands before the side effect,
    # so a tool crash consumes the approval. Recovery is a fresh approval —
    # never a replay window.
    pending, receipt, _ = _approved(tmp_path)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=PROPOSER,
        require_signature=False,
        consumption_ledger=ledger,
    )
    attempts: list[str] = []

    def flaky(path: str) -> str:
        attempts.append(path)
        raise RuntimeError("tool exploded")

    ex.register("write_file", flaky)
    with pytest.raises(RuntimeError):
        resume_with_receipt(ex, pending, receipt)
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex, pending, receipt)
    assert attempts == ["/tmp/safe"]


def test_reminted_receipt_same_anchor_blocked(tmp_path):
    # The consumption key is the audit anchor, not the receipt artifact: a
    # second receipt re-minted from the SAME approval event (different free
    # text, internally consistent receipt_hash) does not grant a second run.
    pending, receipt, _ = _approved(tmp_path)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex, calls = _executor(ledger=ledger)

    reminted = dataclasses.replace(receipt, subject="re-minted variant")
    reminted = dataclasses.replace(reminted, receipt_hash=reminted.compute_hash())
    assert reminted.receipt_hash != receipt.receipt_hash
    assert reminted.audit_event_hash == receipt.audit_event_hash

    resume_with_receipt(ex, pending, receipt)
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex, pending, reminted)
    assert calls == ["/tmp/safe"]


def test_two_distinct_approvals_each_run_once(tmp_path):
    # Each approval appends its own audit event -> its own anchor -> exactly
    # one execution per approval. "Approved twice" legitimately means "may run
    # twice", once per approval.
    err, audit = _escalated(tmp_path)
    pending = err.pending
    assert pending is not None
    first = _approve(pending, audit)
    second = _approve(pending, audit)
    assert first.audit_event_hash != second.audit_event_hash

    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ex, calls = _executor(ledger=ledger)
    resume_with_receipt(ex, pending, first)
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex, pending, first)
    resume_with_receipt(ex, pending, second)
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex, pending, second)
    assert calls == ["/tmp/safe", "/tmp/safe"]


# --- ledger fail-closed behavior ----------------------------------------------


def test_missing_audit_anchor_fails_closed(tmp_path):
    pending, receipt, _ = _approved(tmp_path)
    blank = dataclasses.replace(receipt, audit_event_hash="")
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    with pytest.raises(ReceiptValidationError, match="no audit_event_hash"):
        ledger.consume(blank)
    assert not (tmp_path / "consumed.jsonl").exists()


def test_corrupt_ledger_refuses_execution(tmp_path):
    # If freshness cannot be PROVEN, the gate must not run the tool — a broken
    # ledger never silently degrades to stateless (replayable) verification.
    pending, receipt, _ = _approved(tmp_path)
    ledger_path = tmp_path / "consumed.jsonl"
    ledger_path.write_text("this is not json\n", encoding="utf-8")
    ex, calls = _executor(ledger=ReceiptConsumptionLedger(ledger_path))
    with pytest.raises(ConsumptionLedgerError):
        resume_with_receipt(ex, pending, receipt)
    assert calls == []


def test_ledger_persists_across_instances(tmp_path):
    pending, receipt, _ = _approved(tmp_path)
    path = tmp_path / "consumed.jsonl"
    ex, calls = _executor(ledger=ReceiptConsumptionLedger(path))
    resume_with_receipt(ex, pending, receipt)

    # A brand-new ledger object (fresh process restart) sees the same file.
    ex2, calls2 = _executor(ledger=ReceiptConsumptionLedger(path))
    with pytest.raises(ReceiptAlreadyUsedError):
        resume_with_receipt(ex2, pending, receipt)
    assert calls == ["/tmp/safe"] and calls2 == []


def test_consume_entry_is_auditable(tmp_path):
    pending, receipt, _ = _approved(tmp_path)
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    entry = ledger.consume(receipt)
    assert entry["consumed_key"] == receipt.audit_event_hash
    assert entry["receipt_hash"] == receipt.compute_hash()
    assert entry["tenant_id"] == TENANT
    assert entry["proposed_action"] == "write_file"
    persisted = json.loads(path.read_text(encoding="utf-8").strip())
    assert persisted == entry
    assert ledger.is_consumed(receipt.audit_event_hash)


# --- concurrency ----------------------------------------------------------------


def _consume_worker(ledger_path: str, receipt_json: str, results) -> None:
    from gove_zone import ReceiptAlreadyUsedError, ReceiptConsumptionLedger
    from gove_zone.receipt import DecisionReceipt

    receipt = DecisionReceipt.from_dict(json.loads(receipt_json))
    try:
        ReceiptConsumptionLedger(ledger_path).consume(receipt)
        results.put("consumed")
    except ReceiptAlreadyUsedError:
        results.put("replayed")


def test_concurrent_consumers_single_winner(tmp_path: Path) -> None:
    # N processes race to consume the same receipt: the exclusive file lock
    # serializes check-then-append, so exactly one wins and every loser gets
    # ReceiptAlreadyUsedError — never a double execution.
    _, receipt, _ = _approved(tmp_path)
    ledger_path = str(tmp_path / "consumed.jsonl")
    receipt_json = receipt.to_json()

    ctx = multiprocessing.get_context("fork")
    results = ctx.Queue()
    workers = [
        ctx.Process(target=_consume_worker, args=(ledger_path, receipt_json, results))
        for _ in range(8)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)
    outcomes = [results.get(timeout=5) for _ in range(8)]
    assert outcomes.count("consumed") == 1
    assert outcomes.count("replayed") == 7
