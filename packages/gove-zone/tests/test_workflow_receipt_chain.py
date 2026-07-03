"""Workflow receipt chain — the per-step governance gate, proven through the
real :class:`WorkflowExecutor`.

Every negative-path test asserts the tool spy was **NOT called**
(``tool.calls == 0``), not merely that ``ReceiptValidationError`` was raised.
Because the inner gate verifies-and-executes atomically (step 8), a wrong check
order would let the side effect fire before the raise. The envelope-rejection
rows therefore pair a **valid, executable inner receipt** with a **broken
envelope**: if step 8 ran before steps 1-7, the side effect would fire and
``tool.calls == 0`` would FAIL — that is what discriminates the load-bearing
order. See the BLOCKER section of ``docs/workflow-receipt-chain.md``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

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
from gove_zone.signing import ReceiptSigner

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTOR = "agent-1"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-A/write-grant"
WORKFLOW_ID = "wf-run-1"
# Plan validator that is NEVER a step actor or the runner, so the cross-level
# (b) separation holds for the existing happy/negative paths (every step actor
# is ACTOR == the runner; every step validator is VALIDATOR).
PLAN_VALIDATOR = Validator("plan-council")


def _auth(
    dag: WorkflowDAG,
    *,
    workflow_id: str = WORKFLOW_ID,
    plan_proposer: str = ACTOR,
    plan_validator: Validator = PLAN_VALIDATOR,
    signer: ReceiptSigner | None = None,
) -> WorkflowAuthorization:
    """Mint a clean plan authorization bound to *dag* for the existing tests.

    ``plan_proposer`` defaults to the runner (``ACTOR``) — proposing your own
    plan is allowed — and ``plan_validator`` is a principal that is never a step
    actor or the runner, so cross-level (b) holds.
    """
    return WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=workflow_id,
        plan_proposer=plan_proposer,
        plan_validator=plan_validator,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        declared_goal="run the plan",
        signer=signer,
    )


class Tool:
    """A stand-in side effect that counts how many times it actually ran."""

    def __init__(self, label: str = "tool") -> None:
        self.label = label
        self.calls = 0
        self.last_args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        self.last_args = kwargs
        return f"{self.label}:executed"


def _inner_receipt(
    *,
    action: str,
    args: dict[str, Any],
    actor: str = ACTOR,
    validator: Validator = VALIDATOR,
    event_id: str = "ev-1",
    signer: ReceiptSigner | None = None,
) -> DecisionReceipt:
    """Mint a valid, executable inner ALLOW DecisionReceipt for *action*/*args*.

    Mirrors the helpers in ``test_maci_role_separation`` / ``test_receipt_signing``:
    build a DecisionRecord then ``from_record`` with a distinct Validator. The
    ``argument_hash`` binds the exact args so the inner gate's ALLOW binding
    passes; ``proposed_action`` equals the DAG step's action.
    """
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
        validator=validator,
        authority=AUTHORITY,
        signer=signer,
    )


def _governed(tool: Tool, action: str, *, actor: str = ACTOR) -> GovernedExecutor:
    # Inner step receipts in these workflow tests are unsigned; envelope and
    # authorization signing are exercised separately via WorkflowExecutor's own
    # require_signature. Run the inner gate in explicit dev mode.
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=actor,
        require_signature=False,
    )
    g.register(action, tool.run)
    return g


def _three_step_dag() -> WorkflowDAG:
    """fetch -> transform -> write."""
    dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "transform": WorkflowStep("transform", "runtime.data.transform", ("fetch",)),
            "write": WorkflowStep("write", "runtime.file.write", ("transform",)),
        }
    )
    dag.validate()
    return dag


# --------------------------------------------------------------------------- #
# DAG model
# --------------------------------------------------------------------------- #


def test_dag_validate_accepts_acyclic() -> None:
    _three_step_dag()  # validates inside; no raise == pass


def test_dag_validate_rejects_missing_predecessor() -> None:
    dag = WorkflowDAG(steps={"a": WorkflowStep("a", "act", ("ghost",))})
    with pytest.raises(ReceiptValidationError, match="missing predecessor"):
        dag.validate()


def test_dag_validate_rejects_cycle() -> None:
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "act", ("b",)),
            "b": WorkflowStep("b", "act", ("a",)),
        }
    )
    with pytest.raises(ReceiptValidationError, match="cycle"):
        dag.validate()


def test_dag_validate_rejects_self_dependency() -> None:
    dag = WorkflowDAG(steps={"a": WorkflowStep("a", "act", ("a",))})
    with pytest.raises(ReceiptValidationError, match="itself as a predecessor"):
        dag.validate()


def test_dag_validate_rejects_id_mismatch() -> None:
    dag = WorkflowDAG(steps={"a": WorkflowStep("b", "act", ())})
    with pytest.raises(ReceiptValidationError, match="step id mismatch"):
        dag.validate()


def test_dag_hash_is_order_independent_in_predecessors() -> None:
    d1 = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "act", ()),
            "b": WorkflowStep("b", "act", ()),
            "c": WorkflowStep("c", "act", ("a", "b")),
        }
    )
    d2 = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "act", ()),
            "b": WorkflowStep("b", "act", ()),
            "c": WorkflowStep("c", "act", ("b", "a")),
        }
    )
    assert d1.dag_hash() == d2.dag_hash()


def test_step_hash_binds_inner_receipt() -> None:
    """A different inner receipt → different step_receipt_hash (the envelope is
    cryptographically bound to the exact inner receipt it wraps)."""
    dag = _three_step_dag()
    args = {"url": "https://example/data"}
    inner_a = _inner_receipt(action="runtime.http.get", args=args, event_id="ev-a")
    inner_b = _inner_receipt(action="runtime.http.get", args=args, event_id="ev-b")
    assert inner_a.receipt_hash != inner_b.receipt_hash
    env_a = WorkflowStepReceipt.from_inner(
        inner_a,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
    )
    env_b = WorkflowStepReceipt.from_inner(
        inner_b,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
    )
    assert env_a.step_receipt_hash != env_b.step_receipt_hash


# --------------------------------------------------------------------------- #
# Happy path — full DAG executes in order
# --------------------------------------------------------------------------- #


def _build_chain(
    dag: WorkflowDAG,
    tool: Tool,
    *,
    workflow_id: str = WORKFLOW_ID,
    authorization_hash: str = "",
) -> tuple[dict[str, WorkflowStepReceipt], dict[str, dict[str, Any]]]:
    """Build envelopes for fetch->transform->write in topological order, so each
    successor can reference its predecessor's already-computed step_receipt_hash.
    Returns the envelopes and the per-step args."""
    args_by_step = {
        "fetch": {"url": "https://example/data"},
        "transform": {"op": "normalize"},
        "write": {"path": "out.txt", "content": "ok"},
    }
    envelopes: dict[str, WorkflowStepReceipt] = {}
    for sid in ("fetch", "transform", "write"):
        step = dag.steps[sid]
        inner = _inner_receipt(action=step.action, args=args_by_step[sid], event_id="ev-" + sid)
        pred_hashes = {p: envelopes[p].step_receipt_hash for p in step.predecessor_step_ids}
        envelopes[sid] = WorkflowStepReceipt.from_inner(
            inner,
            workflow_id=workflow_id,
            step_id=sid,
            predecessor_step_ids=step.predecessor_step_ids,
            predecessor_receipt_hashes=pred_hashes,
            dag_hash=dag.dag_hash(),
            authorization_hash=authorization_hash,
        )
    return envelopes, args_by_step


def test_happy_path_multistep_executes_in_order() -> None:
    dag = _three_step_dag()
    tool = Tool()
    # One GovernedExecutor with all three actions registered.
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        require_signature=False,  # explicit dev mode: unsigned inner step receipt
    )
    for sid in ("fetch", "transform", "write"):
        g.register(dag.steps[sid].action, tool.run)
    auth = _auth(dag)
    wf = WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth)

    envelopes, args = _build_chain(dag, tool, authorization_hash=auth.authorization_hash)
    for sid in ("fetch", "transform", "write"):
        wf.execute_step(sid, args[sid], envelopes[sid])

    assert tool.calls == 3
    assert set(wf.ledger) == {"fetch", "transform", "write"}


# --------------------------------------------------------------------------- #
# Rejection matrix — every row through the real executor, tool NOT called
# --------------------------------------------------------------------------- #


def _single_step_setup(
    tool: Tool, *, action: str = "runtime.http.get"
) -> tuple[WorkflowDAG, WorkflowExecutor, WorkflowAuthorization]:
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", action, ())})
    dag.validate()
    auth = _auth(dag)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID, dag=dag, governed=_governed(tool, action), authorization=auth
    )
    return dag, wf, auth


def test_missing_step_receipt_rejected_tool_not_called() -> None:
    tool = Tool()
    _, wf, _ = _single_step_setup(tool)
    with pytest.raises(ReceiptValidationError, match="No step receipt"):
        wf.execute_step("fetch", {"url": "u"}, None)
    assert tool.calls == 0


def test_tampered_envelope_field_rejected_tool_not_called() -> None:
    """Valid inner + tampered envelope field (stale hash) → step 2 rejects,
    BEFORE step 8 could run the executable inner."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    # Tamper a hashed field WITHOUT recomputing step_receipt_hash.
    tampered = dataclasses.replace(env, step_id="other")
    with pytest.raises(ReceiptValidationError, match="step_receipt_hash mismatch"):
        wf.execute_step("fetch", args, tampered)
    assert tool.calls == 0


def test_forged_recomputed_envelope_rejected_without_private_key() -> None:
    """RESIDUAL-CLOSURE GATE PROOF (matrix row: forged/recomputed envelope, no key
    → step 3 when engaged).

    The direct analog of the inner gate's
    ``test_forged_recomputed_receipt_rejected_without_private_key``: an attacker
    tampers a hashed envelope field AND recomputes a CONSISTENT
    ``step_receipt_hash`` (so step 2 passes), but lacks the private key, so the
    stale signature no longer attests the new hash. Step 3 rejects with "invalid
    envelope signature" — and it fires BEFORE the DAG-binding checks that the
    tampered ``dag_hash`` would otherwise trip, so the match is meaningful. This is
    the test that exercises the closure SECURITY.md claims for envelope signing."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    tool = Tool()
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", "runtime.http.get", ())})
    dag.validate()
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    # require_signature reaches authorization check A first, so the authorization
    # must be signed by the same verifier to survive A and let the envelope
    # signature check (step 3) be the discriminating reject.
    auth = _auth(dag, signer=signer)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=verifier,
        require_signature=True,
    )
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
        signer=signer,
    )
    # Tamper a hashed field + recompute a CONSISTENT step_receipt_hash, but do NOT
    # re-sign (no private key). Signature still attests the ORIGINAL hash.
    forged = dataclasses.replace(env, dag_hash="evil-plan")
    forged = dataclasses.replace(forged, step_receipt_hash=forged.compute_step_hash())
    assert forged.compute_step_hash() == forged.step_receipt_hash  # step 2 would PASS
    with pytest.raises(ReceiptValidationError, match="invalid envelope signature"):
        wf.execute_step("fetch", args, forged)
    assert tool.calls == 0


def test_signed_envelope_no_verifier_rejected_tool_not_called() -> None:
    """A signed envelope presented with NO verifier configured is a hard
    rejection (fail-closed), regardless of require_signature → step 3."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    tool = Tool()
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", "runtime.http.get", ())})
    dag.validate()
    # No verifier configured on the executor. Unsigned authorization passes check
    # A (require_signature=False); the signed *envelope* with no verifier is the
    # discriminating reject (step 3).
    auth = _auth(dag)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=None,
        require_signature=False,
    )
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    signer = Ed25519Signer.generate()
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
        signer=signer,
    )
    with pytest.raises(ReceiptValidationError, match="signed step receipt requires"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


def test_unsigned_envelope_rejected_when_signature_required() -> None:
    """require_signature=True + unsigned envelope → step 3 rejects."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    tool = Tool()
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", "runtime.http.get", ())})
    dag.validate()
    # require_signature=True reaches authorization check A first; sign the
    # authorization (and configure its verifier) so A passes and the unsigned
    # *envelope* is the discriminating reject (step 3).
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    auth = _auth(dag, signer=signer)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=verifier,
        require_signature=True,
    )
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="unsigned step receipt rejected"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


def test_signed_envelope_verifies_and_executes() -> None:
    """Positive: envelope signed by the private key passes the public-key gate."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    tool = Tool()
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", "runtime.http.get", ())})
    dag.validate()
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    auth = _auth(dag, signer=signer)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=verifier,
        require_signature=True,
    )
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
        signer=signer,
    )
    assert wf.execute_step("fetch", args, env) == "tool:executed"
    assert tool.calls == 1


def test_cross_workflow_receipt_rejected_tool_not_called() -> None:
    """Valid inner + envelope for a DIFFERENT workflow_id → step 4 rejects."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id="some-other-run",  # not WORKFLOW_ID
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="cross-workflow"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


def test_dag_altered_rejected_tool_not_called() -> None:
    """Valid inner + envelope bound to a DIFFERENT dag_hash → step 5 rejects."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    other_dag = WorkflowDAG(
        steps={"fetch": WorkflowStep("fetch", "runtime.http.get", ())},
    )
    # Make a structurally different DAG hash by adding a step.
    other_dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "extra": WorkflowStep("extra", "x", ()),
        }
    )
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=other_dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    assert other_dag.dag_hash() != dag.dag_hash()
    with pytest.raises(ReceiptValidationError, match="dag_hash mismatch"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


def test_step_not_in_plan_rejected_tool_not_called() -> None:
    """Valid inner, correct dag_hash, but step_id absent from the DAG → step 5."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="ghost",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="not in the approved DAG"):
        wf.execute_step("ghost", args, env)
    assert tool.calls == 0


def test_declared_predecessors_mismatch_rejected_tool_not_called() -> None:
    """Envelope declares predecessors that don't match the DAG → step 5."""
    dag = _three_step_dag()
    tool = Tool()
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        require_signature=False,  # explicit dev mode: unsigned inner step receipt
    )
    g.register("runtime.data.transform", tool.run)
    auth = _auth(dag)
    wf = WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth)
    args = {"op": "normalize"}
    inner = _inner_receipt(action="runtime.data.transform", args=args)
    # DAG says transform's predecessor is ("fetch",); declare () instead. The
    # envelope is internally consistent (hash recomputed by from_inner).
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="transform",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="do not match the approved DAG"):
        wf.execute_step("transform", args, env)
    assert tool.calls == 0


def test_replayed_step_rejected_tool_not_called() -> None:
    """A step run twice in one run → step 6. The second valid envelope must NOT
    re-fire the side effect."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    assert wf.execute_step("fetch", args, env) == "tool:executed"
    assert tool.calls == 1
    with pytest.raises(ReceiptValidationError, match="already executed"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 1  # the replay did NOT run the side effect again


def test_reorder_predecessor_not_run_rejected_tool_not_called() -> None:
    """transform executed before fetch → step 7 (predecessor not in ledger)."""
    dag = _three_step_dag()
    tool = Tool()
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        require_signature=False,  # explicit dev mode: unsigned inner step receipt
    )
    g.register("runtime.data.transform", tool.run)
    auth = _auth(dag)
    wf = WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth)
    args = {"op": "normalize"}
    inner = _inner_receipt(action="runtime.data.transform", args=args)
    # Correct declared predecessors, but a fabricated predecessor hash (fetch has
    # not run). Step 7's ledger-miss fires first.
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="transform",
        predecessor_step_ids=("fetch",),
        predecessor_receipt_hashes={"fetch": "deadbeef"},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="reorder rejected"):
        wf.execute_step("transform", args, env)
    assert tool.calls == 0


def test_predecessor_substitution_rejected_tool_not_called() -> None:
    """fetch ran, but transform's envelope references a DIFFERENT predecessor
    receipt hash than the one in the ledger → step 7 substitution."""
    dag = _three_step_dag()
    fetch_tool = Tool("fetch")
    transform_tool = Tool("transform")
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        require_signature=False,  # explicit dev mode: unsigned inner step receipt
    )
    g.register("runtime.http.get", fetch_tool.run)
    g.register("runtime.data.transform", transform_tool.run)
    auth = _auth(dag)
    wf = WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth)

    # Run fetch legitimately.
    fetch_args = {"url": "u"}
    fetch_inner = _inner_receipt(action="runtime.http.get", args=fetch_args, event_id="ev-f")
    fetch_env = WorkflowStepReceipt.from_inner(
        fetch_inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    wf.execute_step("fetch", fetch_args, fetch_env)
    assert fetch_tool.calls == 1

    # transform references a WRONG fetch hash (substitution).
    t_args = {"op": "normalize"}
    t_inner = _inner_receipt(action="runtime.data.transform", args=t_args, event_id="ev-t")
    t_env = WorkflowStepReceipt.from_inner(
        t_inner,
        workflow_id=WORKFLOW_ID,
        step_id="transform",
        predecessor_step_ids=("fetch",),
        predecessor_receipt_hashes={"fetch": "not-the-real-fetch-hash"},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="predecessor substitution"):
        wf.execute_step("transform", t_args, t_env)
    assert transform_tool.calls == 0


def test_tampered_inner_receipt_rejected_tool_not_called() -> None:
    """Envelope envelope-checks all pass, but the inner receipt is tampered →
    step 8 (the existing inner gate) rejects."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    inner = _inner_receipt(action="runtime.http.get", args=args)
    # Tamper the inner WITHOUT recomputing its hash. The envelope binds
    # inner.receipt_hash (unchanged), so steps 1-7 still pass; step 8 rejects.
    tampered_inner = dataclasses.replace(inner, tenant_id="tenant-EVIL")
    env = WorkflowStepReceipt.from_inner(
        tampered_inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


def test_substituted_args_rejected_tool_not_called() -> None:
    """Inner receipt issued for args A; execute_step called with args B → step 8
    (existing argument_hash binding)."""
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    issued_args = {"url": "approved"}
    inner = _inner_receipt(action="runtime.http.get", args=issued_args)
    env = WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="argument mismatch"):
        wf.execute_step("fetch", {"url": "EVIL"}, env)
    assert tool.calls == 0


def test_self_validated_inner_rejected_tool_not_called() -> None:
    """Inner whose validator == invoking actor is rejected, tool NOT called.

    Under plan-level governance the cross-level (b) check (E) now fires FIRST:
    the inner ``actor`` is the runner (the inner gate requires ``actor ==
    expected_actor``), so forging ``validator_id == actor`` makes the runner both
    a proposer (seeded into the cross-level set) and this step's validator — a
    cross-level collusion that E catches before the atomic inner gate (step 8)
    could re-derive the same conclusion via its MACI self-validation guard. Either
    way the side effect never runs; E is the strictly stronger reject here.
    """
    tool = Tool()
    dag, wf, auth = _single_step_setup(tool)
    args = {"url": "u"}
    # Mint with a distinct validator, then forge validator_id == actor and
    # recompute a consistent inner hash (the envelope binds the new hash).
    inner = _inner_receipt(action="runtime.http.get", args=args)
    forged_inner = dataclasses.replace(inner, validator_id=inner.actor)
    forged_inner = dataclasses.replace(forged_inner, receipt_hash=forged_inner.compute_hash())
    env = WorkflowStepReceipt.from_inner(
        forged_inner,
        workflow_id=WORKFLOW_ID,
        step_id="fetch",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        wf.execute_step("fetch", args, env)
    assert tool.calls == 0


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #


def test_replay_passes_on_good_chain() -> None:
    dag = _three_step_dag()
    tool = Tool()
    auth = _auth(dag)
    envelopes, _ = _build_chain(dag, tool, authorization_hash=auth.authorization_hash)
    # No raise == pass.
    verify_workflow_replay(dag, list(envelopes.values()), authorization=auth)


def test_replay_fails_when_envelope_tampered() -> None:
    dag = _three_step_dag()
    tool = Tool()
    auth = _auth(dag)
    envelopes, _ = _build_chain(dag, tool, authorization_hash=auth.authorization_hash)
    chain = list(envelopes.values())
    # Tamper one envelope's hashed field without recomputing its hash.
    chain[0] = dataclasses.replace(chain[0], workflow_id="other-run")
    with pytest.raises(ReceiptValidationError):
        verify_workflow_replay(dag, chain, authorization=auth)


def test_replay_fails_on_predecessor_hash_mismatch() -> None:
    """An internally-consistent envelope (hash recomputed) that points at the
    wrong predecessor hash breaks topological consistency."""
    dag = _three_step_dag()
    tool = Tool()
    auth = _auth(dag)
    envelopes, _ = _build_chain(dag, tool, authorization_hash=auth.authorization_hash)
    chain = list(envelopes.values())
    # Rebuild transform's envelope with a bogus (but self-consistent) predecessor
    # hash for fetch.
    transform = envelopes["transform"]
    bad = WorkflowStepReceipt.from_inner(
        transform.inner,
        workflow_id=WORKFLOW_ID,
        step_id="transform",
        predecessor_step_ids=("fetch",),
        predecessor_receipt_hashes={"fetch": "bogus-hash"},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    chain = [envelopes["fetch"], bad, envelopes["write"]]
    with pytest.raises(ReceiptValidationError, match="predecessor"):
        verify_workflow_replay(dag, chain, authorization=auth)


def test_replay_signed_chain_verifies() -> None:
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    dag = _three_step_dag()
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    auth = _auth(dag, signer=signer)
    args_by_step = {
        "fetch": {"url": "u"},
        "transform": {"op": "normalize"},
        "write": {"path": "out.txt", "content": "ok"},
    }
    envelopes: dict[str, WorkflowStepReceipt] = {}
    for sid in ("fetch", "transform", "write"):
        step = dag.steps[sid]
        inner = _inner_receipt(action=step.action, args=args_by_step[sid], event_id="ev-" + sid)
        pred_hashes = {p: envelopes[p].step_receipt_hash for p in step.predecessor_step_ids}
        envelopes[sid] = WorkflowStepReceipt.from_inner(
            inner,
            workflow_id=WORKFLOW_ID,
            step_id=sid,
            predecessor_step_ids=step.predecessor_step_ids,
            predecessor_receipt_hashes=pred_hashes,
            dag_hash=dag.dag_hash(),
            authorization_hash=auth.authorization_hash,
            signer=signer,
        )
    verify_workflow_replay(dag, list(envelopes.values()), authorization=auth, verifier=verifier)


def test_replay_rejects_revoked_inner_key() -> None:
    """B2 wiring through the offline replay gate: an inner DecisionReceipt signed
    by a revoked, in-scope signing key_id is rejected (SIGNING_KEY_REVOKED) on
    replay when a RevocationList is supplied — the revocation check fires before
    verifier resolution, so it reports the precise revoked reason."""
    pytest.importorskip("cryptography")
    from gove_zone import Ed25519Signer, RevocationList
    from gove_zone.errors import ReceiptRejectionReason

    dag = _three_step_dag()
    inner_signer = Ed25519Signer.generate(key_id="inner-compromised")
    auth = _auth(dag)
    args_by_step = {
        "fetch": {"url": "u"},
        "transform": {"op": "normalize"},
        "write": {"path": "out.txt", "content": "ok"},
    }
    envelopes: dict[str, WorkflowStepReceipt] = {}
    for sid in ("fetch", "transform", "write"):
        step = dag.steps[sid]
        inner = _inner_receipt(
            action=step.action,
            args=args_by_step[sid],
            event_id="ev-" + sid,
            signer=inner_signer,  # inner receipts signed by the to-be-revoked key
        )
        pred_hashes = {p: envelopes[p].step_receipt_hash for p in step.predecessor_step_ids}
        envelopes[sid] = WorkflowStepReceipt.from_inner(
            inner,
            workflow_id=WORKFLOW_ID,
            step_id=sid,
            predecessor_step_ids=step.predecessor_step_ids,
            predecessor_receipt_hashes=pred_hashes,
            dag_hash=dag.dag_hash(),
            authorization_hash=auth.authorization_hash,
        )
    with pytest.raises(ReceiptValidationError, match="signing key revoked") as ei:
        verify_workflow_replay(
            dag,
            list(envelopes.values()),
            authorization=auth,
            revoked_keys=RevocationList(["inner-compromised"]),
        )
    assert ei.value.reason_code == ReceiptRejectionReason.SIGNING_KEY_REVOKED


def test_step_receipt_for_one_position_rejected_at_another() -> None:
    """A receipt issued for step 'a' cannot be presented at twin step 'b'.

    Twin steps share action + (no) predecessors + args, so the inner gate and
    every other envelope check would pass. The envelope's step_id is hash-bound
    but must ALSO be bound to the position it is presented for (check 4b): one
    approved step receipt must not drive side effects at two DAG positions. The
    no-replay check (step 6) keys on the caller-supplied position, so it alone
    does not stop cross-position reuse. Without 4b, env_a would execute at 'b'
    (tool.calls == 1); the assertion below discriminates that.
    """
    tool = Tool()
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "runtime.act", ()),
            "b": WorkflowStep("b", "runtime.act", ()),
        }
    )
    dag.validate()
    auth = _auth(dag)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.act"),
        authorization=auth,
    )
    args = {"k": "v"}
    env_a = WorkflowStepReceipt.from_inner(
        _inner_receipt(action="runtime.act", args=args, event_id="ev-a"),
        workflow_id=WORKFLOW_ID,
        step_id="a",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="presented at position"):
        wf.execute_step("b", args, env_a)
    assert tool.calls == 0
    assert "b" not in wf.ledger
