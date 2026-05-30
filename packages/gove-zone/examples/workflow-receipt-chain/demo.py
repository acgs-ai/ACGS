"""Workflow receipt chain — the per-step invariant, proven end to end.

    No valid step receipt — bound to this workflow, this step, and its satisfied
    predecessors — no side effect for that step.

Run it (from the monorepo root):

    uv run --package gove-zone python \\
        packages/gove-zone/examples/workflow-receipt-chain/demo.py

This is an executable proof, not a slide. A 3-step DAG (fetch -> transform ->
write) is governed step by step through the real :class:`WorkflowExecutor`,
which composes the proven single-action receipt gate with a workflow envelope.
Each scenario asserts the expected outcome; if any invariant is violated the
script exits non-zero. It demonstrates:

    1. the DAG validates and executes in topological order under valid receipts
    2. a reordered step (predecessor not yet run) is blocked — tool NOT called
    3. a cross-workflow step receipt is blocked — tool NOT called
    4. a DAG-tampered step receipt is blocked — tool NOT called
    5. offline replay PASSES on the recorded good chain
    6. offline replay FAILS when an envelope is tampered

Every negative scenario asserts the side effect did NOT run — not merely that an
error was raised — because the inner gate executes atomically (a wrong check
order would fire the side effect before the rejection).

Status: foundational / Alpha. This proves the local workflow invariant. It is
NOT a production, compliance, or regulator-ready certification.
"""

from __future__ import annotations

import dataclasses
import sys
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    Validator,
    WorkflowAuthorization,
    WorkflowDAG,
    WorkflowExecutor,
    WorkflowStep,
    WorkflowStepReceipt,
    verify_workflow_replay,
)
from gove_zone.decision import sha256_json

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTOR = "agent-1"
VALIDATOR = Validator("constitutional-council")
# Plan validator distinct from every step actor (ACTOR) and the runner (ACTOR),
# so the cross-level (b) separation holds for this clean chain.
PLAN_VALIDATOR = Validator("plan-council")
AUTHORITY = "tenant-A/write-grant"
WORKFLOW_ID = "wf-run-1"


class Tool:
    """A stand-in side effect. Counts how many times it actually ran."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.calls = 0

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        return f"{self.label}:executed"


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _inner(action: str, args: dict[str, Any], event_id: str) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(args),
        policy_version="v1",
        event_id=event_id,
        actor=ACTOR,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-" + event_id,
        validator=VALIDATOR,
        authority=AUTHORITY,
    )


def main() -> int:
    dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "transform": WorkflowStep("transform", "runtime.data.transform", ("fetch",)),
            "write": WorkflowStep("write", "runtime.file.write", ("transform",)),
        }
    )
    dag.validate()

    # Plan-level governance: a distinct plan validator authorizes the DAG. The
    # workflow executor now REQUIRES this authorization (breaking change); every
    # step receipt is bound to it via authorization_hash.
    authorization = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=WORKFLOW_ID,
        plan_proposer=ACTOR,
        plan_validator=PLAN_VALIDATOR,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="fetch, transform, and write",
    )

    args_by_step = {
        "fetch": {"url": "https://example/data"},
        "transform": {"op": "normalize"},
        "write": {"path": "out.txt", "content": "ok"},
    }

    print("\ngove-zone — workflow receipt chain proof")
    print("Invariant: no valid step receipt for a step, no side effect for that step.\n")

    # Build envelopes in topological order so each successor references its
    # predecessor's already-computed step_receipt_hash.
    def build_chain() -> dict[str, WorkflowStepReceipt]:
        envelopes: dict[str, WorkflowStepReceipt] = {}
        for sid in ("fetch", "transform", "write"):
            step = dag.steps[sid]
            inner = _inner(step.action, args_by_step[sid], "ev-" + sid)
            pred_hashes = {p: envelopes[p].step_receipt_hash for p in step.predecessor_step_ids}
            envelopes[sid] = WorkflowStepReceipt.from_inner(
                inner,
                workflow_id=WORKFLOW_ID,
                step_id=sid,
                predecessor_step_ids=step.predecessor_step_ids,
                predecessor_receipt_hashes=pred_hashes,
                dag_hash=dag.dag_hash(),
                authorization_hash=authorization.authorization_hash,
            )
        return envelopes

    def fresh_executor() -> tuple[WorkflowExecutor, dict[str, Tool]]:
        tools = {sid: Tool(sid) for sid in dag.steps}
        g = GovernedExecutor(tenant_id=TENANT, execution_boundary=BOUNDARY, expected_actor=ACTOR)
        for sid, step in dag.steps.items():
            g.register(step.action, tools[sid].run)
        return (
            WorkflowExecutor(
                workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=authorization
            ),
            tools,
        )

    # 1. In-order gated execution.
    print("[1] DAG executes in topological order under valid step receipts")
    envelopes = build_chain()
    wf, tools = fresh_executor()
    for sid in ("fetch", "transform", "write"):
        wf.execute_step(sid, args_by_step[sid], envelopes[sid])
    if not all(tools[sid].calls == 1 for sid in dag.steps):
        _fail("not every step executed exactly once")
    _ok("fetch → transform → write each executed exactly once, in order")

    # 2. Reorder: transform before fetch is blocked.
    print("[2] Reordered step (predecessor not yet run) is blocked")
    wf, tools = fresh_executor()
    # Fabricate a transform envelope claiming fetch ran (it has not).
    t_inner = _inner("runtime.data.transform", args_by_step["transform"], "ev-t-reorder")
    t_env = WorkflowStepReceipt.from_inner(
        t_inner,
        workflow_id=WORKFLOW_ID,
        step_id="transform",
        predecessor_step_ids=("fetch",),
        predecessor_receipt_hashes={"fetch": "deadbeef"},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    try:
        wf.execute_step("transform", args_by_step["transform"], t_env)
        _fail("reordered step reached execution")
    except ReceiptValidationError as exc:
        if tools["transform"].calls != 0:
            _fail("side effect ran despite reorder")
        _ok(f"blocked, tool NOT called: {exc}")

    # 3. Cross-workflow: a step receipt from another run cannot execute here.
    print("[3] Cross-workflow step receipt is blocked")
    wf, tools = fresh_executor()
    f_inner = _inner("runtime.http.get", args_by_step["fetch"], "ev-f-cross")
    cross_env = WorkflowStepReceipt.from_inner(
        f_inner,
        workflow_id="some-other-run",  # not WORKFLOW_ID
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    try:
        wf.execute_step("fetch", args_by_step["fetch"], cross_env)
        _fail("cross-workflow receipt reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite cross-workflow receipt")
        _ok(f"blocked, tool NOT called: {exc}")

    # 4. DAG tamper: a step receipt bound to a different plan is blocked.
    print("[4] DAG-tampered step receipt is blocked")
    wf, tools = fresh_executor()
    altered_dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "exfiltrate": WorkflowStep("exfiltrate", "runtime.net.post", ()),
        }
    )
    f_inner2 = _inner("runtime.http.get", args_by_step["fetch"], "ev-f-dag")
    tampered_env = WorkflowStepReceipt.from_inner(
        f_inner2,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=altered_dag.dag_hash(),  # bound to a DIFFERENT plan
        authorization_hash=authorization.authorization_hash,
    )
    try:
        wf.execute_step("fetch", args_by_step["fetch"], tampered_env)
        _fail("DAG-tampered receipt reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite DAG tamper")
        _ok(f"blocked, tool NOT called: {exc}")

    # 5. Replay PASSES on the recorded good chain.
    print("[5] Offline replay verifies the recorded good chain")
    envelopes = build_chain()
    try:
        verify_workflow_replay(dag, list(envelopes.values()), authorization=authorization)
        _ok("replay verified: chain is internally consistent + topologically faithful")
    except ReceiptValidationError as exc:
        _fail(f"replay rejected a good chain: {exc}")

    # 6. Replay FAILS when an envelope is tampered.
    print("[6] Offline replay rejects a tampered chain")
    chain = list(envelopes.values())
    chain[0] = dataclasses.replace(chain[0], workflow_id="other-run")  # stale hash
    try:
        verify_workflow_replay(dag, chain, authorization=authorization)
        _fail("replay accepted a tampered chain")
    except ReceiptValidationError as exc:
        _ok(f"tampered chain rejected: {exc}")

    print(
        "\n\033[32mAll workflow invariants held. "
        "No valid step receipt, no side effect for that step.\033[0m\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
