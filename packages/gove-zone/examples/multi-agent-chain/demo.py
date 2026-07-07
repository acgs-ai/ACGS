"""Multi-agent governance chain — a delegation DAG that replays offline.

Invariant demonstrated: authority can be delegated down a chain of agents but
only ever narrowed, every execution in the chain is receipt-gated, and the
whole chain — who delegated what to whom, which receipt authorized which tool
call, and what evidence it produced — replays offline, fail-closed.

Run from the monorepo root:

    uv run --package gove-zone python packages/gove-zone/examples/multi-agent-chain/demo.py

Scenarios:

1. Governed chain: orchestrator delegates a narrowed scope to a worker; the
   worker proposes, a distinct validator mints the receipt, the gated tool
   call produces evidence — full DAG replay passes.
2. A delegation cycle between agents is rejected (cycles cannot manufacture
   authority).
3. A worker re-delegating MORE than it holds is rejected (narrowing only).
4. A worker acting outside its delegated scope is rejected.
5. A tampered receipt fails replay exactly as it would fail at the gate.
6. An ungoverned tool call — no gating receipt edge — fails replay.
7. A side effect with no evidence reference fails replay.
"""

from __future__ import annotations

import dataclasses
import sys

from gove_zone import (
    AuthorityGrant,
    AuthorityViolationError,
    DagReplayError,
    DagValidationError,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    EdgeKind,
    GovernanceDAG,
    GovernanceEdge,
    GovernanceNode,
    NodeKind,
    ReceiptValidationError,
    Validator,
    verify_dag_replay,
)
from gove_zone.decision import sha256_json

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ORCHESTRATOR = "agent-orchestrator"
WORKER = "agent-worker"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-A/write-grant"
WRITE = "runtime.file.write"
READ = "runtime.http.get"

FAILURES: list[str] = []


def _ok(label: str) -> None:
    print(f"  OK   {label}")


def _fail(label: str) -> None:
    print(f"  FAIL {label}")
    FAILURES.append(label)


def _mint_receipt(*, action: str, args: dict[str, str], actor: str) -> DecisionReceipt:
    """Mint an ALLOW receipt the way a policy gate would (distinct validator)."""
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(args),
        policy_version="v1",
        event_id="ev-write-1",
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
        request_id="req-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
    )


def _governed_chain(receipt: DecisionReceipt, *, evidence_ref: str) -> GovernanceDAG:
    """Agent A --delegates--> Agent B --proposes--> receipt --gates--> tool call
    --produces--> evidence."""
    return GovernanceDAG(
        nodes={
            ORCHESTRATOR: GovernanceNode(ORCHESTRATOR, NodeKind.AGENT),
            WORKER: GovernanceNode(WORKER, NodeKind.AGENT),
            "decision-1": GovernanceNode("decision-1", NodeKind.DECISION, action=WRITE),
            "receipt-1": GovernanceNode("receipt-1", NodeKind.RECEIPT, ref=receipt.receipt_hash),
            "call-1": GovernanceNode("call-1", NodeKind.TOOL_CALL, action=WRITE),
            "evidence-1": GovernanceNode("evidence-1", NodeKind.SIDE_EFFECT, ref=evidence_ref),
        },
        edges=(
            GovernanceEdge(ORCHESTRATOR, WORKER, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE,)),
            GovernanceEdge(WORKER, "decision-1", EdgeKind.APPROVAL),
            GovernanceEdge("decision-1", "receipt-1", EdgeKind.APPROVAL),
            GovernanceEdge("receipt-1", "call-1", EdgeKind.EXECUTION),
            GovernanceEdge(WORKER, "call-1", EdgeKind.EXECUTION),
            GovernanceEdge("call-1", "evidence-1", EdgeKind.EXECUTION),
        ),
    )


def main() -> int:
    args = {"path": "reports/out.txt", "content": "governed"}
    roots = {
        ORCHESTRATOR: AuthorityGrant(ORCHESTRATOR, "tenant-A/root-grant", frozenset({WRITE, READ}))
    }
    receipt = _mint_receipt(action=WRITE, args=args, actor=WORKER)
    evidence_ref = "sha256:" + sha256_json({"written": args["path"]})

    print("Scenario 1: governed multi-agent chain replays clean")
    dag = _governed_chain(receipt, evidence_ref=evidence_ref)
    try:
        verify_dag_replay(dag, {"receipt-1": receipt}, roots=roots)
        _ok(f"chain verified (dag_hash={dag.dag_hash()[:16]}...)")
    except ReceiptValidationError as exc:
        _fail(f"governed chain unexpectedly rejected: {exc}")

    print("Scenario 2: delegation cycle rejected")
    cyclic = GovernanceDAG(
        nodes={
            ORCHESTRATOR: GovernanceNode(ORCHESTRATOR, NodeKind.AGENT),
            WORKER: GovernanceNode(WORKER, NodeKind.AGENT),
        },
        edges=(
            GovernanceEdge(ORCHESTRATOR, WORKER, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE,)),
            GovernanceEdge(WORKER, ORCHESTRATOR, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE,)),
        ),
    )
    try:
        cyclic.validate()
        _fail("delegation cycle was accepted")
    except DagValidationError:
        _ok("cycle detected and rejected")

    print("Scenario 3: broadened re-delegation rejected (narrowing only)")
    third = "agent-subworker"
    broadened = GovernanceDAG(
        nodes={
            ORCHESTRATOR: GovernanceNode(ORCHESTRATOR, NodeKind.AGENT),
            WORKER: GovernanceNode(WORKER, NodeKind.AGENT),
            third: GovernanceNode(third, NodeKind.AGENT),
        },
        edges=(
            GovernanceEdge(ORCHESTRATOR, WORKER, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE,)),
            # Worker only holds WRITE but tries to hand out READ as well.
            GovernanceEdge(WORKER, third, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE, READ)),
        ),
    )
    try:
        verify_dag_replay(broadened, {}, roots=roots)
        _fail("broadened delegation was accepted")
    except AuthorityViolationError:
        _ok("broadened delegation rejected")

    print("Scenario 4: acting outside delegated scope rejected")
    out_of_scope = GovernanceDAG(
        nodes={
            ORCHESTRATOR: GovernanceNode(ORCHESTRATOR, NodeKind.AGENT),
            WORKER: GovernanceNode(WORKER, NodeKind.AGENT),
            "decision-x": GovernanceNode("decision-x", NodeKind.DECISION, action=READ),
        },
        edges=(
            GovernanceEdge(ORCHESTRATOR, WORKER, EdgeKind.AUTHORITY_DELEGATION, scope=(WRITE,)),
            GovernanceEdge(WORKER, "decision-x", EdgeKind.APPROVAL),
        ),
    )
    try:
        verify_dag_replay(out_of_scope, {}, roots=roots)
        _fail("out-of-scope proposal was accepted")
    except AuthorityViolationError:
        _ok("out-of-scope proposal rejected")

    print("Scenario 5: tampered receipt fails replay")
    tampered = dataclasses.replace(receipt, declared_goal="exfiltrate the report")
    try:
        verify_dag_replay(dag, {"receipt-1": tampered}, roots=roots)
        _fail("tampered receipt was accepted")
    except ReceiptValidationError:
        _ok("tampered receipt rejected")

    print("Scenario 6: ungoverned tool call fails replay")
    rogue_nodes = dict(dag.nodes)
    rogue_nodes["call-rogue"] = GovernanceNode("call-rogue", NodeKind.TOOL_CALL, action=WRITE)
    rogue = GovernanceDAG(
        nodes=rogue_nodes,
        edges=(*dag.edges, GovernanceEdge(WORKER, "call-rogue", EdgeKind.EXECUTION)),
    )
    try:
        verify_dag_replay(rogue, {"receipt-1": receipt}, roots=roots)
        _fail("ungoverned tool call was accepted")
    except DagReplayError:
        _ok("ungoverned tool call rejected (no receipt, no side effect)")

    print("Scenario 7: side effect without evidence fails replay")
    unevidenced = _governed_chain(receipt, evidence_ref="")
    try:
        verify_dag_replay(unevidenced, {"receipt-1": receipt}, roots=roots)
        _fail("missing evidence was accepted")
    except DagReplayError:
        _ok("missing evidence rejected")

    print()
    if FAILURES:
        print(f"Status: {len(FAILURES)} scenario(s) FAILED")
        return 1
    print(
        "Status: foundational demo of the multi-agent governance DAG. Alpha "
        "software — structural tracking and offline replay, NOT a production "
        "security boundary on its own; executor gates remain the enforcement "
        "point."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
