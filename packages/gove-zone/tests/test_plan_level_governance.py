"""Plan-level governance — every rejection-matrix row proven through the real
:class:`WorkflowExecutor.execute_step` and :func:`verify_workflow_replay`.

The plan increment makes the workflow plan a governed object: a plan proposer
proposes the DAG; a distinct plan validator authorizes it (a
:class:`WorkflowAuthorization`); steps execute only under that authorization. The
cross-level rule is decision **(b) strict separation**: no principal is both a
proposer (plan or any step) and a validator (plan or any step).

Every negative-path test asserts the tool spy was **NOT called**
(``tool.calls == 0``), not merely that ``ReceiptValidationError`` was raised —
because the authorization checks (A-E) and the envelope checks all run before the
atomic inner gate-and-execute (step 8). A wrong check order would let the side
effect fire before the rejection.
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
RUNNER = "agent-1"  # the principal operating the executor (== governed.expected_actor)
STEP_VALIDATOR = Validator("constitutional-council")
PLAN_VALIDATOR = Validator("plan-council")  # never a step actor or the runner
AUTHORITY = "tenant-A/write-grant"
WORKFLOW_ID = "wf-run-1"


class Tool:
    """A stand-in side effect that counts how many times it actually ran."""

    def __init__(self, label: str = "tool") -> None:
        self.label = label
        self.calls = 0

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        return f"{self.label}:executed"


def _inner_receipt(
    *,
    action: str,
    args: dict[str, Any],
    actor: str = RUNNER,
    validator: Validator = STEP_VALIDATOR,
    event_id: str = "ev-1",
) -> DecisionReceipt:
    """Mint a valid, executable inner ALLOW receipt (mirrors the chain tests)."""
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
    )


def _governed(tool: Tool, action: str, *, actor: str = RUNNER) -> GovernedExecutor:
    # Inner step receipts here are unsigned; authorization/envelope signing is
    # exercised separately. Run the inner gate in explicit dev mode.
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=actor,
        require_signature=False,
    )
    g.register(action, tool.run)
    return g


def _auth(
    dag: WorkflowDAG,
    *,
    workflow_id: str = WORKFLOW_ID,
    plan_proposer: str = RUNNER,
    plan_validator: Validator = PLAN_VALIDATOR,
    authority: str = AUTHORITY,
    tenant_id: str = TENANT,
    execution_boundary: str = BOUNDARY,
    expires_at: str = "",
    signer: ReceiptSigner | None = None,
) -> WorkflowAuthorization:
    """A clean plan authorization bound to *dag*.

    Default ``plan_proposer`` is the runner (proposing your own plan is fine);
    ``plan_validator`` is a principal that is never a step actor or the runner, so
    cross-level (b) holds.
    """
    return WorkflowAuthorization.from_plan(
        dag.dag_hash(),
        workflow_id=workflow_id,
        plan_proposer=plan_proposer,
        plan_validator=plan_validator,
        authority=authority,
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        declared_goal="run the plan",
        expires_at=expires_at,
        signer=signer,
    )


def _single_step_dag(action: str = "runtime.http.get") -> WorkflowDAG:
    dag = WorkflowDAG(steps={"fetch": WorkflowStep("fetch", action, ())})
    dag.validate()
    return dag


def _step_env(
    dag: WorkflowDAG,
    *,
    authorization_hash: str,
    args: dict[str, Any] | None = None,
    actor: str = RUNNER,
    validator: Validator = STEP_VALIDATOR,
    action: str = "runtime.http.get",
    step_id: str = "fetch",
) -> WorkflowStepReceipt:
    a = args if args is not None else {"url": "u"}
    inner = _inner_receipt(action=action, args=a, actor=actor, validator=validator)
    return WorkflowStepReceipt.from_inner(
        inner,
        workflow_id=WORKFLOW_ID,
        step_id=step_id,
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=authorization_hash,
    )


# --------------------------------------------------------------------------- #
# WorkflowAuthorization unit behavior
# --------------------------------------------------------------------------- #


def test_from_plan_binds_hash_and_is_self_consistent() -> None:
    dag = _single_step_dag()
    auth = _auth(dag)
    assert auth.authorization_hash == auth.compute_authorization_hash()
    assert auth.signature == "unsigned_local"
    assert auth.signature_algorithm == "none"


def test_from_plan_rejects_self_validated_plan() -> None:
    """Plan MACI at issuance: plan validator == plan proposer is refused."""
    dag = _single_step_dag()
    with pytest.raises(ReceiptValidationError, match="self-validation"):
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


def test_authorization_hash_changes_with_dag() -> None:
    d1 = _single_step_dag()
    d2 = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "extra": WorkflowStep("extra", "x", ()),
        }
    )
    assert _auth(d1).authorization_hash != _auth(d2).authorization_hash


# --------------------------------------------------------------------------- #
# Happy path through the gate
# --------------------------------------------------------------------------- #


def test_missing_authorization_cannot_construct_executor() -> None:
    """Matrix row 'Missing authorization | A': there is no silent-ungoverned path.
    The authorization is a required field, so omitting it is a construction-time
    TypeError — a missing authorization can never reach a step gate."""
    dag = _single_step_dag()
    g = _governed(Tool(), "runtime.http.get")
    with pytest.raises(TypeError):
        WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g)  # type: ignore[call-arg]


def test_authorized_step_executes() -> None:
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    assert wf.execute_step("fetch", {"url": "u"}, env) == "tool:executed"
    assert tool.calls == 1


def test_plan_proposer_may_equal_runner() -> None:
    """A runner proposing its own plan is fine, as long as a DISTINCT validator
    authorized it and the runner validates nothing."""
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag, plan_proposer=RUNNER, plan_validator=PLAN_VALIDATOR)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    assert wf.execute_step("fetch", {"url": "u"}, env) == "tool:executed"
    assert tool.calls == 1


# --------------------------------------------------------------------------- #
# Rejection matrix — A: authorization integrity
# --------------------------------------------------------------------------- #


def test_missing_step_receipt_still_rejected_first() -> None:
    """The presence check precedes the authorization checks that dereference the
    receipt (D/E), so a None receipt still raises 'No step receipt'."""
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    with pytest.raises(ReceiptValidationError, match="No step receipt"):
        wf.execute_step("fetch", {"url": "u"}, None)
    assert tool.calls == 0


def test_tampered_authorization_hash_rejected_tool_not_called() -> None:
    """A authorization whose hash no longer matches its fields → check A."""
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag)
    # Tamper a hashed field WITHOUT recomputing authorization_hash.
    tampered = dataclasses.replace(auth, authority="tenant-A/escalated-grant")
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=tampered,
    )
    env = _step_env(dag, authorization_hash=tampered.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="authorization_hash mismatch"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_forged_recomputed_authorization_rejected_without_private_key() -> None:
    """Signed authorization, attacker tampers a field AND recomputes a consistent
    authorization_hash (so check A's hash passes), but lacks the private key →
    check A signature rejects. Mirrors the envelope/inner forged-recompute proof."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    dag = _single_step_dag()
    tool = Tool()
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    auth = _auth(dag, signer=signer)
    # Tamper authority + recompute a CONSISTENT hash, but do NOT re-sign.
    forged = dataclasses.replace(auth, authority="tenant-A/escalated-grant")
    forged = dataclasses.replace(forged, authorization_hash=forged.compute_authorization_hash())
    assert forged.compute_authorization_hash() == forged.authorization_hash  # A's hash PASSES
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=forged,
        verifier=verifier,
        require_signature=True,
    )
    env = _step_env(dag, authorization_hash=forged.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="invalid authorization signature"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_signed_authorization_no_verifier_rejected_tool_not_called() -> None:
    """A signed authorization presented with no verifier is a hard reject → A."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    dag = _single_step_dag()
    tool = Tool()
    signer = Ed25519Signer.generate()
    auth = _auth(dag, signer=signer)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=None,
        require_signature=False,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="signed authorization requires"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_unsigned_authorization_with_require_signature_rejected_tool_not_called() -> None:
    """``require_signature=True`` + an unsigned authorization → check A rejects.

    Mirrors the envelope-side unsigned-but-required rejection. Check A runs before
    the envelope checks, so the authorization message is the one that fires.
    """
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag)  # unsigned (signer=None)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=None,
        require_signature=True,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="unsigned authorization rejected"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_authorization_unknown_signing_key_rejected_tool_not_called() -> None:
    """A signed authorization whose ``signing_key_id`` is absent from a Mapping
    verifier → check A rejects (``unknown authorization signing key``). Mirrors the
    inner/envelope unknown-key path."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    dag = _single_step_dag()
    tool = Tool()
    signer = Ed25519Signer.generate()
    auth = _auth(dag, signer=signer)
    # A verifier map that does NOT contain this authorization's signing key.
    other = Ed25519Signer.generate()
    verifier = {other.key_id: Ed25519Signer.from_public_bytes(other.public_bytes())}
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
        verifier=verifier,
        require_signature=True,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="unknown authorization signing key"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_signed_authorization_verifies_and_executes() -> None:
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from gove_zone import Ed25519Signer

    dag = _single_step_dag()
    tool = Tool()
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
    # require_signature is shared with the envelope gate, so the step envelope is
    # signed too; the positive path here proves authorization signing is accepted.
    inner = _inner_receipt(action="runtime.http.get", args={"url": "u"})
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
    assert wf.execute_step("fetch", {"url": "u"}, env) == "tool:executed"
    assert tool.calls == 1


# --------------------------------------------------------------------------- #
# Rejection matrix — B: plan binding
# --------------------------------------------------------------------------- #


def test_cross_plan_workflow_id_rejected_tool_not_called() -> None:
    """Authorization minted for a different workflow_id than the run → check B."""
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag, workflow_id="some-other-run")
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="cross-plan authorization"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_cross_plan_dag_hash_rejected_tool_not_called() -> None:
    """Authorization bound to a different DAG than the executor runs → check B."""
    dag = _single_step_dag()
    other_dag = WorkflowDAG(
        steps={
            "fetch": WorkflowStep("fetch", "runtime.http.get", ()),
            "extra": WorkflowStep("extra", "x", ()),
        }
    )
    tool = Tool()
    auth = _auth(other_dag)  # workflow_id matches, dag_hash does not
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="authorization dag_hash mismatch"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_expired_authorization_rejected_tool_not_called() -> None:
    """A genuinely-issued authorization used past its expiry → check B."""
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag, expires_at="2000-01-01T00:00:00+00:00")
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="authorization expired"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_authorization_tenant_mismatch_rejected_tool_not_called() -> None:
    dag = _single_step_dag()
    tool = Tool()
    auth = _auth(dag, tenant_id="tenant-EVIL")
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="authorization tenant mismatch"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


# --------------------------------------------------------------------------- #
# Rejection matrix — C: plan MACI + runner anchor
# --------------------------------------------------------------------------- #


def test_runner_is_plan_validator_rejected_tool_not_called() -> None:
    """The runner cannot be the authority that authorized the plan it runs.

    ``from_plan`` permits a non-runner proposer with the runner as validator (that
    is valid plan MACI), but the executor's runner anchor (check C) rejects it:
    ``runner`` comes from runtime context, not the authorization, so a plan author
    cannot satisfy it by editing fields."""
    dag = _single_step_dag()
    tool = Tool()
    # plan_proposer != runner so from_plan's MACI passes; plan_validator == runner.
    auth = _auth(dag, plan_proposer="external-proposer", plan_validator=Validator(RUNNER))
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="runner self-authorization"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


# --------------------------------------------------------------------------- #
# Rejection matrix — D: step → authorization binding (cross-plan step lift)
# --------------------------------------------------------------------------- #


def test_step_lifted_to_different_plan_rejected_tool_not_called() -> None:
    """A step receipt bound to authorization A presented under authorization B is
    rejected → check D. A and B share workflow_id + dag_hash (so B passes) but
    differ in authority, hence a different authorization_hash."""
    dag = _single_step_dag()
    tool = Tool()
    auth_a = _auth(dag, authority="tenant-A/grant-A")
    auth_b = _auth(dag, authority="tenant-A/grant-B")
    assert auth_a.authorization_hash != auth_b.authorization_hash
    assert auth_a.dag_hash == auth_b.dag_hash and auth_a.workflow_id == auth_b.workflow_id
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth_b,
    )
    # The step was minted under A, but the executor runs under B.
    env = _step_env(dag, authorization_hash=auth_a.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="step lifted from a different plan"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


# --------------------------------------------------------------------------- #
# Rejection matrix — E: cross-level separation (decision (b), strict)
# --------------------------------------------------------------------------- #


def test_cross_level_collusion_plan_validator_is_step_proposer() -> None:
    """One principal X is the plan validator AND a step proposer → check E.

    The locked decision (b): no principal is both a proposer (plan or any step)
    and a validator (plan or any step). Here X validates the plan and proposes the
    step — authorizing the plan that grants its own step's authority to execute.

    Crucially, check E reads ``step_receipt.inner.actor`` BEFORE the atomic inner
    gate (step 8) that would pin ``actor == runner``. So an inner whose ``actor``
    is X (≠ runner) reaches E un-pinned: E sees X in both the proposer set (as the
    step actor) and the validator set (as the plan validator) and rejects. The
    side effect never runs; that the inner would *also* later fail the actor-anchor
    is irrelevant — E fires first.
    """
    dag = _single_step_dag()
    tool = Tool()
    colluder = "colluder-X"  # ≠ runner and ≠ plan_proposer
    auth = _auth(dag, plan_proposer=RUNNER, plan_validator=Validator(colluder))
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    # inner.actor == the plan validator (X). Its inner validator defaults to a
    # distinct principal, so the inner is mintable.
    env = _step_env(dag, authorization_hash=auth.authorization_hash, actor=colluder)
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_self_validated_plan_rejected_at_gate_via_check_c() -> None:
    """Even a hand-forged authorization that bypasses from_plan's MACI (validator
    == proposer, hash recomputed to stay consistent) is rejected at the gate by
    check C — the executor re-checks plan MACI on every step."""
    dag = _single_step_dag()
    tool = Tool()
    clean = _auth(dag, plan_proposer="P", plan_validator=PLAN_VALIDATOR)
    forged = dataclasses.replace(clean, plan_validator_id="P")  # validator == proposer
    forged = dataclasses.replace(forged, authorization_hash=forged.compute_authorization_hash())
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=forged,
    )
    env = _step_env(dag, authorization_hash=forged.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="plan self-validation"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_runner_anchor_runner_is_plan_validator() -> None:
    """The runner-anchor manifestation of cross-level (b): the runner cannot be the
    plan validator of the plan it runs → check C.

    When the colluding step proposer *is* the runner, the inner gate's actor
    requirement forces it, and the runner is seeded into the proposer set, so a
    plan validated by the runner is rejected at check C (the runner-side of (b)).
    ``runner`` comes from runtime context, not the authorization, so a plan author
    cannot satisfy it by editing fields.
    """
    dag = _single_step_dag()
    tool = Tool()
    # plan_proposer != runner (so from_plan's plan-MACI passes); plan_validator is
    # the runner.
    auth = _auth(dag, plan_proposer="external-proposer", plan_validator=Validator(RUNNER))
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash)
    with pytest.raises(ReceiptValidationError, match="runner self-authorization"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_cross_level_collusion_step_validator_is_plan_proposer() -> None:
    """A step validator that is also the plan proposer → check E."""
    dag = _single_step_dag()
    tool = Tool()
    proposer = "plan-author"
    # plan_proposer = plan-author (≠ runner). A later step's validator is also
    # plan-author → it would validate a step while having proposed the plan.
    auth = _auth(dag, plan_proposer=proposer, plan_validator=PLAN_VALIDATOR)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.http.get"),
        authorization=auth,
    )
    env = _step_env(dag, authorization_hash=auth.authorization_hash, validator=Validator(proposer))
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        wf.execute_step("fetch", {"url": "u"}, env)
    assert tool.calls == 0


def test_cross_level_separation_persists_across_steps() -> None:
    """The cross-level set persists across ``execute_step`` calls: after step 'a'
    runs cleanly, a SUCCESSOR step 'b' whose validator collides with the seeded
    plan proposer is still rejected — and step 'b's side effect never runs, while
    step 'a' ran exactly once."""
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "runtime.act", ()),
            "b": WorkflowStep("b", "runtime.act", ("a",)),
        }
    )
    dag.validate()
    tool = Tool()
    g = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=RUNNER,
        require_signature=False,  # explicit dev mode: unsigned inner step receipt
    )
    g.register("runtime.act", tool.run)
    # plan_proposer P (≠ runner) is a seeded proposer; a later step validated by P
    # is cross-level collusion. Distinct plan_validator keeps plan MACI + runner
    # anchor clean.
    proposer = "plan-author"
    auth = _auth(dag, plan_proposer=proposer, plan_validator=PLAN_VALIDATOR)
    wf = WorkflowExecutor(workflow_id=WORKFLOW_ID, dag=dag, governed=g, authorization=auth)

    # Step a: clean (actor = runner, validator = a fresh principal).
    a_inner = _inner_receipt(
        action="runtime.act", args={"k": "a"}, validator=Validator("val-a"), event_id="ev-a"
    )
    a_env = WorkflowStepReceipt.from_inner(
        a_inner,
        workflow_id=WORKFLOW_ID,
        step_id="a",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    assert wf.execute_step("a", {"k": "a"}, a_env) == "tool:executed"
    assert tool.calls == 1

    # Step b: validator == the seeded plan proposer → E rejects on this later call.
    b_inner = _inner_receipt(
        action="runtime.act", args={"k": "b"}, validator=Validator(proposer), event_id="ev-b"
    )
    b_env = WorkflowStepReceipt.from_inner(
        b_inner,
        workflow_id=WORKFLOW_ID,
        step_id="b",
        predecessor_step_ids=("a",),
        predecessor_receipt_hashes={"a": a_env.step_receipt_hash},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        wf.execute_step("b", {"k": "b"}, b_env)
    assert tool.calls == 1  # step b's side effect never ran


def test_rejected_step_does_not_pollute_cross_level_state() -> None:
    """A step rejected by E must not commit its actor/validator to the persistent
    sets — a subsequent legitimate retry with a clean receipt still succeeds."""
    dag = _single_step_dag(action="runtime.act")
    tool = Tool()
    proposer = "plan-author"
    auth = _auth(dag, plan_proposer=proposer, plan_validator=PLAN_VALIDATOR)
    wf = WorkflowExecutor(
        workflow_id=WORKFLOW_ID,
        dag=dag,
        governed=_governed(tool, "runtime.act"),
        authorization=auth,
    )
    # First attempt: a colluding validator (== the seeded plan proposer) → E
    # rejects before commit.
    bad = _step_env(
        dag,
        authorization_hash=auth.authorization_hash,
        action="runtime.act",
        validator=Validator(proposer),
        args={"k": "v"},
    )
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        wf.execute_step("fetch", {"k": "v"}, bad)
    assert tool.calls == 0
    assert proposer not in wf.validators  # the rejected step did NOT pollute state

    # Clean retry succeeds (a fresh distinct validator).
    good = _step_env(
        dag,
        authorization_hash=auth.authorization_hash,
        action="runtime.act",
        validator=STEP_VALIDATOR,
        args={"k": "v"},
    )
    assert wf.execute_step("fetch", {"k": "v"}, good) == "tool:executed"
    assert tool.calls == 1


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #


def _two_step_chain(dag: WorkflowDAG, auth: WorkflowAuthorization) -> list[WorkflowStepReceipt]:
    envelopes: dict[str, WorkflowStepReceipt] = {}
    args = {"a": {"k": "a"}, "b": {"k": "b"}}
    for sid in ("a", "b"):
        step = dag.steps[sid]
        inner = _inner_receipt(action=step.action, args=args[sid], event_id="ev-" + sid)
        pred = {p: envelopes[p].step_receipt_hash for p in step.predecessor_step_ids}
        envelopes[sid] = WorkflowStepReceipt.from_inner(
            inner,
            workflow_id=WORKFLOW_ID,
            step_id=sid,
            predecessor_step_ids=step.predecessor_step_ids,
            predecessor_receipt_hashes=pred,
            dag_hash=dag.dag_hash(),
            authorization_hash=auth.authorization_hash,
        )
    return list(envelopes.values())


def _ab_dag() -> WorkflowDAG:
    dag = WorkflowDAG(
        steps={
            "a": WorkflowStep("a", "runtime.act", ()),
            "b": WorkflowStep("b", "runtime.act", ("a",)),
        }
    )
    dag.validate()
    return dag


def test_replay_passes_with_authorization() -> None:
    dag = _ab_dag()
    auth = _auth(dag)
    verify_workflow_replay(dag, _two_step_chain(dag, auth), authorization=auth)


def test_replay_rejects_tampered_authorization() -> None:
    dag = _ab_dag()
    auth = _auth(dag)
    chain = _two_step_chain(dag, auth)
    tampered = dataclasses.replace(auth, authority="escalated")  # stale hash
    with pytest.raises(ReceiptValidationError, match="authorization_hash mismatch"):
        verify_workflow_replay(dag, chain, authorization=tampered)


def test_replay_rejects_step_bound_to_other_authorization() -> None:
    """Every step's authorization_hash must match the presented authorization."""
    dag = _ab_dag()
    auth_a = _auth(dag, authority="grant-A")
    auth_b = _auth(dag, authority="grant-B")
    chain = _two_step_chain(dag, auth_a)  # steps bound to A
    with pytest.raises(ReceiptValidationError, match="does not match the authorization"):
        verify_workflow_replay(dag, chain, authorization=auth_b)


def test_replay_rejects_self_validated_plan() -> None:
    """Replay enforces plan MACI even though from_plan would refuse minting: a
    hand-built authorization with validator == proposer is caught offline."""
    dag = _ab_dag()
    auth = _auth(dag)
    # Hand-forge a self-validated authorization with a consistent hash.
    forged = dataclasses.replace(auth, plan_validator_id=auth.plan_proposer)
    forged = dataclasses.replace(forged, authorization_hash=forged.compute_authorization_hash())
    chain = _two_step_chain(dag, forged)
    with pytest.raises(ReceiptValidationError, match="plan self-validation"):
        verify_workflow_replay(dag, chain, authorization=forged)


def test_replay_rejects_cross_level_collusion() -> None:
    """Offline cross-level (b): a step validator that is also the plan proposer is
    rejected over the recorded set (no runner offline)."""
    dag = _ab_dag()
    proposer = "plan-author"
    auth = _auth(dag, plan_proposer=proposer, plan_validator=PLAN_VALIDATOR)
    # Build a chain where step 'a' is validated by the plan proposer.
    a_inner = _inner_receipt(
        action="runtime.act", args={"k": "a"}, validator=Validator(proposer), event_id="ev-a"
    )
    a_env = WorkflowStepReceipt.from_inner(
        a_inner,
        workflow_id=WORKFLOW_ID,
        step_id="a",
        predecessor_step_ids=(),
        predecessor_receipt_hashes={},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    b_inner = _inner_receipt(action="runtime.act", args={"k": "b"}, event_id="ev-b")
    b_env = WorkflowStepReceipt.from_inner(
        b_inner,
        workflow_id=WORKFLOW_ID,
        step_id="b",
        predecessor_step_ids=("a",),
        predecessor_receipt_hashes={"a": a_env.step_receipt_hash},
        dag_hash=dag.dag_hash(),
        authorization_hash=auth.authorization_hash,
    )
    with pytest.raises(ReceiptValidationError, match="cross-level collusion"):
        verify_workflow_replay(dag, [a_env, b_env], authorization=auth)
