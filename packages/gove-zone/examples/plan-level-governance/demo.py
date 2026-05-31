"""Plan-level governance — the plan invariant, proven end to end.

    No authorized plan, no workflow step executes.

Run it (from the monorepo root):

    uv run --package gove-zone python \\
        packages/gove-zone/examples/plan-level-governance/demo.py

This is an executable proof, not a slide. A plan proposer proposes a 3-step DAG
(fetch -> transform -> write); a DISTINCT plan validator authorizes it (a
:class:`WorkflowAuthorization`); step receipts are bound to that authorization;
and execution runs through the real :class:`WorkflowExecutor`, which now REQUIRES
the authorization (breaking change) and verifies it on every step (checks A-E)
before the existing envelope checks and the atomic inner gate-and-execute.

The cross-level rule is decision **(b) strict separation**: no principal is both
a proposer (plan or any step) and a validator (plan or any step). It demonstrates:

    1. an authorized plan executes step by step under valid receipts
    2. a MISSING authorization cannot construct the executor (fail-closed)
    3. a TAMPERED authorization is blocked — tool NOT called (check A)
    4. a SELF-VALIDATED plan can never be minted (plan MACI in from_plan)
    5. a CROSS-PLAN authorization (wrong workflow_id) is blocked — tool NOT called (B)
    6. a step LIFTED to a different plan is blocked — tool NOT called (D)
    7. CROSS-LEVEL collusion (one principal proposes a step + validates the plan)
       is blocked — tool NOT called (E); plus the runner-anchor variant (C)
    8. offline replay PASSES on the recorded good chain
    9. offline replay FAILS when the authorization is tampered

Every negative scenario asserts the side effect did NOT run — not merely that an
error was raised — because the inner gate executes atomically.

Status: foundational / Alpha. This proves the local plan invariant. It is NOT a
production, compliance, or regulator-ready certification.
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
RUNNER = "agent-1"  # the principal operating the executor (== governed.expected_actor)
STEP_VALIDATOR = Validator("constitutional-council")
PLAN_PROPOSER = "agent-1"  # may equal the runner: proposing your own plan is fine
PLAN_VALIDATOR = Validator("plan-council")  # distinct authorizing principal
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


def _inner(
    action: str, args: dict[str, Any], event_id: str, *, actor: str = RUNNER
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(args),
        policy_version="v1",
        event_id=event_id,
        actor=actor,
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
        validator=STEP_VALIDATOR,
        authority=AUTHORITY,
    )


def main() -> int:  # noqa: C901 - linear scenario script, intentionally flat
    dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "transform": WorkflowStep("transform", "runtime.data.transform", ("fetch",)),
            "write": WorkflowStep("write", "runtime.file.write", ("transform",)),
        }
    )
    dag.validate()

    args_by_step = {
        "fetch": {"url": "https://example/data"},
        "transform": {"op": "normalize"},
        "write": {"path": "out.txt", "content": "ok"},
    }

    print("\ngove-zone — plan-level governance proof")
    print("Invariant: no authorized plan, no workflow step executes.\n")

    # The plan proposer proposes the DAG; the DISTINCT plan validator authorizes it.
    authorization = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=WORKFLOW_ID,
        plan_proposer=PLAN_PROPOSER,
        plan_validator=PLAN_VALIDATOR,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="fetch, transform, and write",
    )

    def build_chain(auth_hash: str) -> dict[str, WorkflowStepReceipt]:
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
                authorization_hash=auth_hash,
            )
        return envelopes

    def fresh_executor(auth: WorkflowAuthorization) -> tuple[WorkflowExecutor, dict[str, Tool]]:
        tools = {sid: Tool(sid) for sid in dag.steps}
        g = GovernedExecutor(tenant_id=TENANT, execution_boundary=BOUNDARY, expected_actor=RUNNER)
        for sid, step in dag.steps.items():
            g.register(step.action, tools[sid].run)
        return WorkflowExecutor(
            workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth
        ), tools

    # 1. Authorized plan executes in order.
    print("[1] Authorized plan executes step by step under valid receipts")
    envelopes = build_chain(authorization.authorization_hash)
    wf, tools = fresh_executor(authorization)
    for sid in ("fetch", "transform", "write"):
        wf.execute_step(sid, args_by_step[sid], envelopes[sid])
    if not all(tools[sid].calls == 1 for sid in dag.steps):
        _fail("not every step executed exactly once")
    _ok("plan validator authorized; fetch → transform → write each ran exactly once")

    # 2. Missing authorization: the executor cannot even be constructed.
    print("[2] A missing authorization cannot construct the executor (fail-closed)")
    g = GovernedExecutor(tenant_id=TENANT, execution_boundary=BOUNDARY, expected_actor=RUNNER)
    g.register("runtime.http.get", Tool("fetch").run)
    try:
        WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g)  # type: ignore[call-arg]
        _fail("executor constructed without an authorization")
    except TypeError as exc:
        _ok(f"blocked at construction: {exc}")

    # 3. Tampered authorization: hash no longer matches → check A, tool NOT called.
    print("[3] A tampered authorization is blocked")
    tampered = dataclasses.replace(authorization, authority="tenant-A/escalated-grant")
    wf, tools = fresh_executor(tampered)
    env = build_chain(tampered.authorization_hash)["fetch"]
    try:
        wf.execute_step("fetch", args_by_step["fetch"], env)
        _fail("tampered authorization reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite tampered authorization")
        _ok(f"blocked, tool NOT called: {exc}")

    # 4. Self-validated plan: can never be minted (plan MACI in from_plan).
    print("[4] A self-validated plan can never be authorized")
    try:
        WorkflowAuthorization.from_plan(
            dag.dag_hash(),
            workflow_id=WORKFLOW_ID,
            plan_proposer="same-principal",
            plan_validator=Validator("same-principal"),
            authority=AUTHORITY,
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            declared_goal="g",
        )
        _fail("self-validated plan was minted")
    except ReceiptValidationError as exc:
        _ok(f"plan authorization refused at issuance: {exc}")

    # 5. Cross-plan authorization: wrong workflow_id → check B, tool NOT called.
    print("[5] A cross-plan authorization (wrong workflow_id) is blocked")
    cross = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id="some-other-run",  # not WORKFLOW_ID
        plan_proposer=PLAN_PROPOSER,
        plan_validator=PLAN_VALIDATOR,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="g",
    )
    wf, tools = fresh_executor(cross)
    env = build_chain(cross.authorization_hash)["fetch"]
    try:
        wf.execute_step("fetch", args_by_step["fetch"], env)
        _fail("cross-plan authorization reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite cross-plan authorization")
        _ok(f"blocked, tool NOT called: {exc}")

    # 6. Cross-plan step lift: a step bound to authorization A under B → check D.
    print("[6] A step lifted from a different plan is blocked")
    auth_b = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=WORKFLOW_ID,
        plan_proposer=PLAN_PROPOSER,
        plan_validator=PLAN_VALIDATOR,
        authority="tenant-A/grant-B",  # different authority → different hash
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="g",
    )
    wf, tools = fresh_executor(auth_b)
    # The step is minted under the ORIGINAL authorization, run under auth_b.
    lifted = build_chain(authorization.authorization_hash)["fetch"]
    try:
        wf.execute_step("fetch", args_by_step["fetch"], lifted)
        _fail("cross-plan step lift reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite cross-plan step lift")
        _ok(f"blocked, tool NOT called: {exc}")

    # 7. Cross-level collusion: a principal X is BOTH the plan validator and a step
    #    proposer → check E. (E reads inner.actor before the inner gate pins it to
    #    the runner, so an actor = X ≠ runner reaches E un-pinned.)
    print(
        "[7] Cross-level collusion (one principal proposes a step + validates the plan) is blocked"
    )
    colluder = "colluder-X"
    colluding = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=WORKFLOW_ID,
        plan_proposer=PLAN_PROPOSER,
        plan_validator=Validator(colluder),  # X validates the plan
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="g",
    )
    wf, tools = fresh_executor(colluding)
    # The fetch step is proposed by X (inner.actor == colluder).
    colluding_inner = _inner(
        "runtime.http.get", args_by_step["fetch"], "ev-collude", actor=colluder
    )
    colluding_env = WorkflowStepReceipt.from_inner(
        colluding_inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=colluding.authorization_hash,
    )
    try:
        wf.execute_step("fetch", args_by_step["fetch"], colluding_env)
        _fail("cross-level collusion reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite cross-level collusion")
        _ok(f"blocked, tool NOT called: {exc}")

    # 7b. The runner-anchor manifestation of (b): the runner cannot be the plan
    #     validator of the plan it runs → check C.
    print("[7b] Runner anchor (runner is the plan validator) is blocked")
    runner_collusion = WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=WORKFLOW_ID,
        plan_proposer="external-proposer",  # ≠ runner so plan MACI passes
        plan_validator=Validator(RUNNER),  # the runner validates the plan it runs
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="g",
    )
    wf, tools = fresh_executor(runner_collusion)
    env = build_chain(runner_collusion.authorization_hash)["fetch"]
    try:
        wf.execute_step("fetch", args_by_step["fetch"], env)
        _fail("runner self-authorization reached execution")
    except ReceiptValidationError as exc:
        if tools["fetch"].calls != 0:
            _fail("side effect ran despite runner self-authorization")
        _ok(f"blocked, tool NOT called: {exc}")

    # 8. Replay PASSES on the recorded good chain.
    print("[8] Offline replay verifies the recorded good chain")
    envelopes = build_chain(authorization.authorization_hash)
    try:
        verify_workflow_replay(dag, list(envelopes.values()), authorization=authorization)
        _ok("replay verified: authorization integral, plan MACI + cross-level separation hold")
    except ReceiptValidationError as exc:
        _fail(f"replay rejected a good chain: {exc}")

    # 9. Replay FAILS when the authorization is tampered.
    print("[9] Offline replay rejects a tampered authorization")
    bad_auth = dataclasses.replace(authorization, authority="escalated")  # stale hash
    try:
        verify_workflow_replay(dag, list(envelopes.values()), authorization=bad_auth)
        _fail("replay accepted a tampered authorization")
    except ReceiptValidationError as exc:
        _ok(f"tampered authorization rejected: {exc}")

    print(
        "\n\033[32mAll plan-level invariants held. "
        "No authorized plan, no workflow step executes.\033[0m\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
