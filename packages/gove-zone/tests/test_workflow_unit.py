"""Direct unit tests for :mod:`gove_zone.workflow`.

Exercises the module's own public surface: the DAG model
(:class:`WorkflowStep` / :class:`WorkflowDAG`), the step envelope
(:class:`WorkflowStepReceipt`), the live gate (:class:`WorkflowExecutor`) and
offline :func:`verify_workflow_replay`. Every rejection row asserts the tool
spy stayed at ``calls == 0``: the un-run side effect is the property, not the
exception type.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
from typing import Any

import pytest

from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.executor import GovernedExecutor
from gove_zone.plan import WorkflowAuthorization
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.workflow import (
    WorkflowDAG,
    WorkflowExecutor,
    WorkflowStep,
    WorkflowStepReceipt,
    verify_workflow_replay,
)

TENANT = "tenant-wf-unit"
BOUNDARY = "wf-unit-sandbox"
RUNNER = "runner-unit"
STEP_VALIDATOR = Validator("step-council")
PLAN_VALIDATOR = Validator("plan-council")
AUTHORITY = "tenant-wf-unit/write-grant"
WORKFLOW_ID = "wf-unit-1"
ACTION = "runtime.file.write"


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    def __init__(
        self,
        key: bytes = b"wf-unit-key",
        key_id: str = "wf-key-1",
        algorithm: str = "test-hmac-sha256",
    ) -> None:
        self._key = key
        self.key_id = key_id
        self.algorithm = algorithm

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class Tool:
    """A stand-in side effect that counts how many times it actually ran."""

    def __init__(self) -> None:
        self.calls = 0
        self.last_args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        self.last_args = kwargs
        return "executed"


def _single_step_dag() -> WorkflowDAG:
    dag = WorkflowDAG(steps={"only": WorkflowStep("only", ACTION, ())})
    dag.validate()
    return dag


def _authorization(
    dag: WorkflowDAG,
    *,
    plan_proposer: str = RUNNER,
    plan_validator: Validator = PLAN_VALIDATOR,
    workflow_id: str = WORKFLOW_ID,
    signer: Any = None,
) -> WorkflowAuthorization:
    return WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=workflow_id,
        plan_proposer=plan_proposer,
        plan_validator=plan_validator,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="run the unit plan",
        signer=signer,
    )


def _inner(
    *,
    action: str = ACTION,
    args: dict[str, Any] | None = None,
    actor: str = RUNNER,
    validator: Validator = STEP_VALIDATOR,
    event_id: str = "ev-1",
) -> DecisionReceipt:
    payload = args if args is not None else {"path": "out.txt"}
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(payload),
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
        request_id=f"req-{event_id}",
        validator=validator,
        authority=AUTHORITY,
    )


def _governed(tool: Tool, *, action: str = ACTION, actor: str = RUNNER) -> GovernedExecutor:
    governed = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=actor,
        require_signature=False,
    )
    governed.register(action, tool.run)
    return governed


# --- WorkflowStep / WorkflowDAG ----------------------------------------------- #


def test_workflow_step_defaults_to_no_predecessors() -> None:
    step = WorkflowStep("a", "act")
    assert step.predecessor_step_ids == ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        step.action = "other"  # type: ignore[misc]


def test_empty_dag_validates_and_hashes() -> None:
    dag = WorkflowDAG(steps={})
    dag.validate()  # no nodes to consume; no raise == pass
    assert dag.dag_hash() == sha256_json({})


def test_dag_hash_changes_when_a_step_action_changes() -> None:
    a = WorkflowDAG(steps={"s": WorkflowStep("s", "act.one", ())})
    b = WorkflowDAG(steps={"s": WorkflowStep("s", "act.two", ())})
    assert a.dag_hash() != b.dag_hash()


def test_dag_hash_changes_when_an_edge_is_added() -> None:
    base = WorkflowDAG(steps={"a": WorkflowStep("a", "act", ()), "b": WorkflowStep("b", "act", ())})
    linked = WorkflowDAG(
        steps={"a": WorkflowStep("a", "act", ()), "b": WorkflowStep("b", "act", ("a",))}
    )
    assert base.dag_hash() != linked.dag_hash()


def test_dag_hash_ignores_duplicate_predecessor_declarations_in_validation() -> None:
    """A repeated edge is deduplicated for indegree, so the DAG still validates."""
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "act", ()),
            "b": WorkflowStep("b", "act", ("a", "a")),
        }
    )
    dag.validate()  # no raise == pass


def test_dag_validate_rejects_a_three_node_cycle() -> None:
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "act", ("c",)),
            "b": WorkflowStep("b", "act", ("a",)),
            "c": WorkflowStep("c", "act", ("b",)),
        }
    )
    with pytest.raises(ReceiptValidationError, match="cycle"):
        dag.validate()


# --- WorkflowStepReceipt -------------------------------------------------------- #


def test_from_inner_unsigned_defaults_and_self_consistent_hash() -> None:
    dag = _single_step_dag()
    envelope = WorkflowStepReceipt.from_inner(
        _inner(),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
    )
    assert envelope.signature_algorithm == "none"
    assert envelope.signing_key_id == ""
    assert envelope.signature == "unsigned_local"
    assert envelope.authorization_hash == ""
    assert envelope.compute_step_hash() == envelope.step_receipt_hash


def test_from_inner_accepts_a_predecessor_list_and_normalizes_to_a_tuple() -> None:
    dag = WorkflowDAG(
        steps={"a": WorkflowStep("a", ACTION, ()), "b": WorkflowStep("b", ACTION, ("a",))}
    )
    envelope = WorkflowStepReceipt.from_inner(
        _inner(),
        workflow_id=WORKFLOW_ID,
        step_id="b",
        predecessor_step_ids=["a"],
        predecessor_receipt_hashes={"a": "hash-a"},
        dag_hash=dag.dag_hash(),
    )
    assert envelope.predecessor_step_ids == ("a",)


def test_step_hash_excludes_step_hash_and_signature() -> None:
    dag = _single_step_dag()
    envelope = WorkflowStepReceipt.from_inner(
        _inner(),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
    )
    tampered = dataclasses.replace(envelope, step_receipt_hash="bogus", signature="forged")
    assert tampered.compute_step_hash() == envelope.step_receipt_hash


def test_step_hash_binds_the_authorization_hash() -> None:
    dag = _single_step_dag()
    common = {
        "workflow_id": WORKFLOW_ID,
        "step_id": "only",
        "predecessor_step_ids": (),
        "predecessor_receipt_hashes": {},
        "dag_hash": dag.dag_hash(),
    }
    unbound = WorkflowStepReceipt.from_inner(_inner(), **common)  # type: ignore[arg-type]
    bound = WorkflowStepReceipt.from_inner(
        _inner(),
        authorization_hash="auth-hash",
        **common,  # type: ignore[arg-type]
    )
    assert unbound.step_receipt_hash != bound.step_receipt_hash


def test_signed_envelope_binds_key_id_then_signs_the_hash() -> None:
    dag = _single_step_dag()
    signer = FakeSigner()
    envelope = WorkflowStepReceipt.from_inner(
        _inner(),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        signer=signer,
    )
    assert envelope.signature_algorithm == signer.algorithm
    assert envelope.signing_key_id == signer.key_id
    assert envelope.compute_step_hash() == envelope.step_receipt_hash
    assert signer.verify(envelope.step_receipt_hash.encode("utf-8"), envelope.signature)


# --- WorkflowExecutor ------------------------------------------------------------ #


def test_executor_seeds_the_cross_level_separation_sets() -> None:
    dag = _single_step_dag()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(Tool()),
        authorization=_authorization(dag, plan_proposer="plan-author"),
    )
    assert executor.proposers == {"plan-author", RUNNER}
    assert executor.validators == {PLAN_VALIDATOR.validator_id}
    assert executor.ledger == {}


def test_execute_step_runs_the_tool_and_records_the_ledger() -> None:
    dag = _single_step_dag()
    authorization = _authorization(dag)
    tool = Tool()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool),
        authorization=authorization,
    )
    args = {"path": "out.txt"}
    envelope = WorkflowStepReceipt.from_inner(
        _inner(args=args),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )

    assert executor.execute_step("only", args, envelope) == "executed"
    assert tool.calls == 1
    assert executor.ledger == {"only": envelope.step_receipt_hash}
    assert executor.validators == {PLAN_VALIDATOR.validator_id, STEP_VALIDATOR.validator_id}


def test_execute_step_without_an_envelope_fails_closed() -> None:
    dag = _single_step_dag()
    tool = Tool()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool),
        authorization=_authorization(dag),
    )
    with pytest.raises(ReceiptValidationError, match="No step receipt provided"):
        executor.execute_step("only", {"path": "out.txt"}, None)
    assert tool.calls == 0


def test_execute_step_rejects_an_envelope_presented_at_another_position() -> None:
    """Positional binding: one approved envelope cannot drive a twin step."""
    dag = WorkflowDAG(
        steps={"left": WorkflowStep("left", ACTION, ()), "right": WorkflowStep("right", ACTION, ())}
    )
    dag.validate()
    authorization = _authorization(dag)
    tool = Tool()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool),
        authorization=authorization,
    )
    args = {"path": "out.txt"}
    envelope = WorkflowStepReceipt.from_inner(
        _inner(args=args),
        workflow_id=WORKFLOW_ID,
        step_id="left",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )

    with pytest.raises(ReceiptValidationError, match="presented at position"):
        executor.execute_step("right", args, envelope)
    assert tool.calls == 0


def test_execute_step_rejects_a_runner_that_is_its_own_plan_validator() -> None:
    dag = _single_step_dag()
    authorization = _authorization(
        dag, plan_proposer="plan-author", plan_validator=Validator(RUNNER)
    )
    tool = Tool()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool),
        authorization=authorization,
    )
    args = {"path": "out.txt"}
    envelope = WorkflowStepReceipt.from_inner(
        _inner(args=args),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )

    with pytest.raises(ReceiptValidationError, match="runner self-authorization"):
        executor.execute_step("only", args, envelope)
    assert tool.calls == 0


def test_execute_step_rejects_replay_of_an_executed_step() -> None:
    dag = _single_step_dag()
    authorization = _authorization(dag)
    tool = Tool()
    executor = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool),
        authorization=authorization,
    )
    args = {"path": "out.txt"}
    envelope = WorkflowStepReceipt.from_inner(
        _inner(args=args),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    executor.execute_step("only", args, envelope)

    with pytest.raises(ReceiptValidationError, match="already executed"):
        executor.execute_step("only", args, envelope)
    assert tool.calls == 1


# --- verify_workflow_replay -------------------------------------------------------- #


def _recorded_chain() -> tuple[WorkflowDAG, WorkflowAuthorization, list[WorkflowStepReceipt]]:
    """A two-step chain (``a -> b``) as it would be recorded after a clean run."""
    dag = WorkflowDAG(
        steps={"a": WorkflowStep("a", ACTION, ()), "b": WorkflowStep("b", ACTION, ("a",))}
    )
    dag.validate()
    authorization = _authorization(dag, plan_proposer="plan-author")
    first = WorkflowStepReceipt.from_inner(
        _inner(event_id="ev-a"),
        workflow_id=WORKFLOW_ID,
        step_id="a",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    second = WorkflowStepReceipt.from_inner(
        _inner(event_id="ev-b"),
        workflow_id=WORKFLOW_ID,
        step_id="b",
        predecessor_step_ids=("a",),
        predecessor_receipt_hashes={"a": first.step_receipt_hash},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    return dag, authorization, [first, second]


def test_replay_accepts_a_clean_recorded_chain() -> None:
    dag, authorization, chain = _recorded_chain()
    verify_workflow_replay(dag, chain, authorization=authorization)  # no raise == pass


def test_replay_rejects_an_empty_chain() -> None:
    dag, authorization, _ = _recorded_chain()
    with pytest.raises(ReceiptValidationError, match="no step receipts to replay"):
        verify_workflow_replay(dag, [], authorization=authorization)


def test_replay_rejects_a_tampered_authorization() -> None:
    dag, authorization, chain = _recorded_chain()
    tampered = dataclasses.replace(authorization, declared_goal="a different plan")
    with pytest.raises(ReceiptValidationError, match="authorization_hash mismatch"):
        verify_workflow_replay(dag, chain, authorization=tampered)


def test_replay_rejects_a_duplicated_step_id() -> None:
    dag, authorization, chain = _recorded_chain()
    with pytest.raises(ReceiptValidationError, match="duplicate step_id"):
        verify_workflow_replay(dag, [chain[0], chain[0]], authorization=authorization)


def test_replay_rejects_a_substituted_predecessor_hash() -> None:
    dag, authorization, chain = _recorded_chain()
    forged = dataclasses.replace(chain[1], predecessor_receipt_hashes={"a": "some-other-hash"})
    forged = dataclasses.replace(forged, step_receipt_hash=forged.compute_step_hash())
    with pytest.raises(ReceiptValidationError, match="predecessor 'a' receipt hash mismatch"):
        verify_workflow_replay(dag, [chain[0], forged], authorization=authorization)


def test_replay_rejects_cross_level_collusion() -> None:
    """The plan validator may not also be a step actor."""
    dag = _single_step_dag()
    authorization = _authorization(dag, plan_proposer="plan-author")
    envelope = WorkflowStepReceipt.from_inner(
        _inner(actor=PLAN_VALIDATOR.validator_id),
        workflow_id=WORKFLOW_ID,
        step_id="only",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        verify_workflow_replay(dag, [envelope], authorization=authorization)


def test_replay_rejects_a_chain_bound_to_another_dag() -> None:
    dag, authorization, chain = _recorded_chain()
    other = WorkflowDAG(
        steps={"a": WorkflowStep("a", "act.other", ()), "b": WorkflowStep("b", ACTION, ("a",))}
    )
    with pytest.raises(ReceiptValidationError, match="different DAG"):
        verify_workflow_replay(other, chain, authorization=authorization)


def test_replay_requires_signatures_once_a_verifier_is_supplied() -> None:
    """Passing a verifier turns replay signature-required (unsigned → reject)."""
    dag, authorization, chain = _recorded_chain()
    with pytest.raises(ReceiptValidationError, match="unsigned authorization rejected"):
        verify_workflow_replay(dag, chain, authorization=authorization, verifier=FakeSigner())
