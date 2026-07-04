"""Workflow receipt chain — per-step governance over a declared DAG.

This module is **additive**: it composes the proven single-action receipt gate
(:func:`gove_zone.executor.execute_with_receipt` /
:class:`gove_zone.executor.GovernedExecutor`) with a thin workflow envelope. The
audited :class:`~gove_zone.receipt.DecisionReceipt` is never modified. The
invariant grows from

    "No valid Decision Receipt, no side effect."

to

    "No valid step receipt — bound to this workflow, this step, and its
    satisfied predecessors — no side effect for that step."

The load-bearing property is the **order of checks** in
:meth:`WorkflowExecutor.execute_step`: every envelope check (steps 1-7) runs
**before** the atomic inner gate-and-execute (step 8). Because the inner gate
verifies-and-executes in one call, a reordered/cross-workflow step's side effect
would otherwise fire before the envelope rejection. See ``BLOCKER`` in
``docs/workflow-receipt-chain.md``.

See ``SECURITY.md`` ("Workflow receipt chaining") for the honest scope of the
guarantee: workflow chaining adds **no** cryptographic guarantee beyond the
per-step receipts and their envelopes; unsigned offline replay proves internal
chain consistency and topological faithfulness, not unforgeability.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gove_zone.revocation import RevocationList

from gove_zone.decision import sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.executor import GovernedExecutor
from gove_zone.plan import WorkflowAuthorization
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import ReceiptSigner


@dataclass(frozen=True)
class WorkflowStep:
    """A single node in a :class:`WorkflowDAG`.

    ``predecessor_step_ids`` are the step ids that must have executed before this
    step. They are part of the DAG structure bound into ``dag_hash``.
    """

    step_id: str
    action: str
    predecessor_step_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkflowDAG:
    """A declared workflow plan: a set of steps with predecessor edges.

    ``dag_hash`` binds the canonical structure into every step envelope, so step
    injection or plan alteration is detected at the gate. ``validate`` is
    fail-closed: missing predecessors, duplicate ids, or cycles all raise.
    """

    steps: dict[str, WorkflowStep]

    def validate(self) -> None:
        """Fail-closed structural validation of the DAG.

        Rejects: duplicate step ids (the ``step_id`` key must match the node's
        own ``step_id``), predecessors that reference non-existent steps, a step
        depending on itself, and any cycle (topological sort must succeed).
        """
        # Duplicate / mismatched ids: the dict key must equal the node's step_id.
        for key, step in self.steps.items():
            if key != step.step_id:
                raise ReceiptValidationError(
                    f"DAG step id mismatch: key {key!r} != step.step_id {step.step_id!r}"
                )

        # Every declared predecessor must exist; no self-dependency.
        for step in self.steps.values():
            for pred in step.predecessor_step_ids:
                if pred not in self.steps:
                    raise ReceiptValidationError(
                        f"DAG step {step.step_id!r} references missing predecessor {pred!r}"
                    )
                if pred == step.step_id:
                    raise ReceiptValidationError(
                        f"DAG step {step.step_id!r} declares itself as a predecessor"
                    )

        # Cycle detection via Kahn topological sort — must consume every node.
        indegree: dict[str, int] = {sid: 0 for sid in self.steps}
        for step in self.steps.values():
            indegree[step.step_id] = len(set(step.predecessor_step_ids))
        ready = [sid for sid, deg in indegree.items() if deg == 0]
        successors: dict[str, list[str]] = {sid: [] for sid in self.steps}
        for step in self.steps.values():
            for pred in set(step.predecessor_step_ids):
                successors[pred].append(step.step_id)

        visited = 0
        queue = list(ready)
        while queue:
            current = queue.pop()
            visited += 1
            for nxt in successors[current]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    queue.append(nxt)
        if visited != len(self.steps):
            raise ReceiptValidationError("DAG contains a cycle (topological sort failed)")

    def dag_hash(self) -> str:
        """``sha256_json`` of the canonical DAG structure.

        Canonical form: ``{step_id: {"action": action, "predecessors":
        sorted(predecessor_step_ids)}}``. Sorting the predecessors makes the hash
        order-independent in the edge declaration.
        """
        canonical = {
            sid: {
                "action": step.action,
                "predecessors": sorted(step.predecessor_step_ids),
            }
            for sid, step in self.steps.items()
        }
        return sha256_json(canonical)


@dataclass(frozen=True)
class WorkflowStepReceipt:
    """Envelope binding a single-action :class:`DecisionReceipt` to a DAG position.

    ``step_receipt_hash`` covers every field **except** ``step_receipt_hash`` and
    ``signature``, and **includes ``inner.receipt_hash``** — so the envelope is
    cryptographically bound to the exact inner receipt it wraps (a different inner
    receipt yields a different ``step_receipt_hash``). ``signature_algorithm`` and
    ``signing_key_id`` are inside the hash (anti-downgrade); ``signature`` signs
    the hash and stays out of it — identical discipline to the inner receipt.
    """

    inner: DecisionReceipt
    workflow_id: str
    step_id: str
    predecessor_step_ids: tuple[str, ...]
    predecessor_receipt_hashes: dict[str, str]
    dag_hash: str
    authorization_hash: str = ""
    step_receipt_hash: str = ""
    signature_algorithm: str = "none"
    signing_key_id: str = ""
    signature: str = "unsigned_local"

    def _hash_payload(self) -> dict[str, Any]:
        return {
            "inner_receipt_hash": self.inner.receipt_hash,
            "workflow_id": self.workflow_id,
            "step_id": self.step_id,
            "predecessor_step_ids": sorted(self.predecessor_step_ids),
            "predecessor_receipt_hashes": dict(self.predecessor_receipt_hashes),
            "dag_hash": self.dag_hash,
            "authorization_hash": self.authorization_hash,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
        }

    def compute_step_hash(self) -> str:
        """``sha256_json`` of every field except ``step_receipt_hash`` and
        ``signature``, including the inner receipt's ``receipt_hash``."""
        return sha256_json(self._hash_payload())

    @classmethod
    def from_inner(
        cls,
        inner: DecisionReceipt,
        *,
        workflow_id: str,
        step_id: str,
        predecessor_step_ids: tuple[str, ...] | list[str],
        predecessor_receipt_hashes: dict[str, str],
        dag_hash: str,
        authorization_hash: str = "",
        signer: ReceiptSigner | None = None,
    ) -> WorkflowStepReceipt:
        """Build an envelope, compute its hash, and optionally sign it.

        Mirrors :meth:`DecisionReceipt.from_record`: the signer's ``algorithm``
        and ``key_id`` are bound into ``step_receipt_hash`` (anti-downgrade), then
        ``signature`` is the signer's signature over that hash. With
        ``signer=None`` (default) the envelope is unsigned
        (``signature_algorithm="none"``, ``signature="unsigned_local"``).
        ``authorization_hash`` binds the envelope to the
        :class:`~gove_zone.plan.WorkflowAuthorization` it executes under (default
        ``""`` keeps it self-consistent; the executor requires a match).
        """
        envelope = cls(
            inner=inner,
            workflow_id=workflow_id,
            step_id=step_id,
            predecessor_step_ids=tuple(predecessor_step_ids),
            predecessor_receipt_hashes=dict(predecessor_receipt_hashes),
            dag_hash=dag_hash,
            authorization_hash=authorization_hash,
            signature_algorithm=signer.algorithm if signer is not None else "none",
            signing_key_id=signer.key_id if signer is not None else "",
        )
        # Compute the hash AFTER alg+key_id are set so they bind into it
        # (anti-downgrade), THEN sign that hash so the signature attests it.
        h = envelope.compute_step_hash()
        signature = signer.sign(h.encode("utf-8")) if signer is not None else "unsigned_local"
        return dataclasses.replace(envelope, step_receipt_hash=h, signature=signature)


def _verify_envelope_signature(
    receipt: WorkflowStepReceipt,
    *,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None,
    require_signature: bool,
) -> None:
    """Envelope signature check, mirroring the inner gate's discipline.

    - ``require_signature=True`` + unsigned envelope → reject.
    - A signed envelope (``signature_algorithm != "none"``) MUST be verified
      regardless of ``require_signature``; presenting one with no verifier is a
      hard rejection (fail-closed). ``signature_algorithm`` / ``signing_key_id``
      are bound into ``step_receipt_hash`` (anti-downgrade), already checked.
    """
    if require_signature and receipt.signature_algorithm == "none":
        raise ReceiptValidationError("unsigned step receipt rejected: signature required")
    if receipt.signature_algorithm == "none":
        return
    resolved: ReceiptSigner | None
    if isinstance(verifier, Mapping):
        if receipt.signing_key_id not in verifier:
            raise ReceiptValidationError("unknown envelope signing key")
        resolved = verifier[receipt.signing_key_id]
    elif verifier is not None:
        resolved = verifier
    else:
        raise ReceiptValidationError("signed step receipt requires a configured verifier")
    if resolved.algorithm != receipt.signature_algorithm:
        raise ReceiptValidationError("envelope signature algorithm mismatch")
    if not resolved.verify(receipt.step_receipt_hash.encode("utf-8"), receipt.signature):
        raise ReceiptValidationError("invalid envelope signature")


def _verify_authorization_signature(
    authorization: WorkflowAuthorization,
    *,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None,
    require_signature: bool,
) -> None:
    """Plan-authorization signature check, mirroring the envelope's discipline.

    - ``require_signature=True`` + unsigned authorization → reject.
    - A signed authorization (``signature_algorithm != "none"``) MUST be verified
      regardless of ``require_signature``; presenting one with no verifier is a
      hard rejection (fail-closed). ``signature_algorithm`` / ``signing_key_id``
      are bound into ``authorization_hash`` (anti-downgrade), already checked.
    """
    if require_signature and authorization.signature_algorithm == "none":
        raise ReceiptValidationError("unsigned authorization rejected: signature required")
    if authorization.signature_algorithm == "none":
        return
    resolved: ReceiptSigner | None
    if isinstance(verifier, Mapping):
        if authorization.signing_key_id not in verifier:
            raise ReceiptValidationError("unknown authorization signing key")
        resolved = verifier[authorization.signing_key_id]
    elif verifier is not None:
        resolved = verifier
    else:
        raise ReceiptValidationError("signed authorization requires a configured verifier")
    if resolved.algorithm != authorization.signature_algorithm:
        raise ReceiptValidationError("authorization signature algorithm mismatch")
    if not resolved.verify(
        authorization.authorization_hash.encode("utf-8"), authorization.signature
    ):
        raise ReceiptValidationError("invalid authorization signature")


@dataclass
class WorkflowExecutor:
    """The per-run workflow gate.

    Constructed with a ``workflow_id``, a validated :class:`WorkflowDAG`, and a
    :class:`GovernedExecutor` (carrying tenant, boundary, ``expected_actor``, and
    the inner-receipt verifier/require_signature). The envelope signature config
    (``verifier`` / ``require_signature``) is **separate** from the inner gate's:
    the envelope hash and the inner receipt hash are different artifacts and may
    be signed by different keys.

    ``ledger`` maps ``{step_id: step_receipt_hash}`` for steps already executed in
    this run; it is **trusted runtime state** and is what detects replay,
    reordering, and predecessor substitution.

    **Plan-level governance (breaking).** A :class:`WorkflowAuthorization` is now
    **required**: there is no silent-ungoverned path. The runner — the principal
    operating this executor — is ``governed.expected_actor`` (consistent with the
    single-action gate, where ``expected_actor == receipt.actor``). The
    authorization is verified on **every** :meth:`execute_step` call (it is
    independently callable), before the envelope checks and the atomic inner
    gate-and-execute. ``proposers`` / ``validators`` accumulate the cross-level
    separation set (decision (b), strict): ``proposers`` seeds
    ``{plan_proposer, runner}`` and gains each executed step's ``inner.actor``;
    ``validators`` seeds ``{plan_validator_id}`` and gains each executed step's
    ``inner.validator_id``; no principal may be in both. The persistent sets are
    updated only when a step succeeds, alongside the ledger write.
    """

    workflow_id: str
    dag: WorkflowDAG
    governed: GovernedExecutor
    authorization: WorkflowAuthorization
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None
    require_signature: bool = False
    ledger: dict[str, str] = field(default_factory=dict)
    proposers: set[str] = field(init=False, default_factory=set)
    validators: set[str] = field(init=False, default_factory=set)

    def __post_init__(self) -> None:
        # Seed the cross-level (b) separation sets. The runner is folded in as a
        # proposer (it cannot be any step's validator); plan_proposer MAY equal
        # the runner. These persist across execute_step calls and grow as steps
        # succeed.
        self.proposers = {self.authorization.plan_proposer, self.governed.expected_actor}
        self.validators = {self.authorization.plan_validator_id}

    def _verify_authorization(self, step_receipt: WorkflowStepReceipt) -> tuple[str, str]:
        """Checks A–E from ``docs/plan-level-governance.md``.

        Runs on every call before the envelope checks and the atomic inner
        gate-and-execute. Returns the ``(actor, validator_id)`` this step would
        add to the cross-level sets on success (the caller commits them only after
        the side effect runs). Raises :class:`ReceiptValidationError` on every
        rejection.
        """
        authorization = self.authorization
        runner = self.governed.expected_actor

        # A. Authorization integrity. (`authorization` is a required field, so it
        #    is never None here; the type system enforces presence.)
        if authorization.compute_authorization_hash() != authorization.authorization_hash:
            raise ReceiptValidationError(
                "authorization_hash mismatch: tampered or recomputed authorization"
            )
        _verify_authorization_signature(
            authorization,
            verifier=self.verifier,
            require_signature=self.require_signature,
        )

        # B. Plan binding.
        if authorization.workflow_id != self.workflow_id:
            raise ReceiptValidationError(
                f"cross-plan authorization: expected workflow_id {self.workflow_id!r}, "
                f"got {authorization.workflow_id!r}"
            )
        if authorization.dag_hash != self.dag.dag_hash():
            raise ReceiptValidationError(
                "authorization dag_hash mismatch: authorization bound to a different plan"
            )
        if authorization.tenant_id != self.governed.tenant_id:
            raise ReceiptValidationError(
                f"authorization tenant mismatch: expected {self.governed.tenant_id!r}, "
                f"got {authorization.tenant_id!r}"
            )
        if authorization.execution_boundary != self.governed.execution_boundary:
            raise ReceiptValidationError(
                f"authorization boundary mismatch: expected "
                f"{self.governed.execution_boundary!r}, got {authorization.execution_boundary!r}"
            )
        if authorization.expires_at:
            from datetime import UTC, datetime

            try:
                expires_dt = datetime.fromisoformat(authorization.expires_at)
                now_dt = datetime.now(UTC)
                is_expired = now_dt > expires_dt
            except (ValueError, TypeError) as err:
                raise ReceiptValidationError(
                    f"unparseable authorization expiry: {authorization.expires_at!r}"
                ) from err
            if is_expired:
                raise ReceiptValidationError(f"authorization expired at {authorization.expires_at}")

        # C. Plan MACI + runner anchor.
        if authorization.plan_validator_id == authorization.plan_proposer:
            raise ReceiptValidationError(
                "plan self-validation: plan validator must differ from plan proposer "
                f"(both are {authorization.plan_proposer!r})"
            )
        if authorization.plan_validator_id == runner:
            raise ReceiptValidationError(
                f"runner self-authorization: the runner ({runner!r}) cannot be the "
                "plan validator of the plan it runs"
            )

        # D. Step → authorization binding.
        if step_receipt.authorization_hash != authorization.authorization_hash:
            raise ReceiptValidationError(
                "step receipt authorization_hash does not match the authorization "
                "(step lifted from a different plan)"
            )

        # E. Cross-level separation (decision (b), strict). Compute the candidate
        #    union with THIS step's actor/validator; reject if it intersects. The
        #    candidate is committed by the caller only on success.
        candidate_actor = step_receipt.inner.actor
        candidate_validator = step_receipt.inner.validator_id
        candidate_proposers = self.proposers | {candidate_actor}
        candidate_validators = self.validators | {candidate_validator}
        overlap = candidate_proposers & candidate_validators
        if overlap:
            raise ReceiptValidationError(
                "cross-level collusion: principal(s) are both proposer and validator "
                f"in this workflow ({sorted(overlap)})"
            )
        return candidate_actor, candidate_validator

    def execute_step(
        self,
        step_id: str,
        args: dict[str, Any],
        step_receipt: WorkflowStepReceipt | None,
    ) -> Any:
        """Gate and execute one workflow step.

        Order of checks is load-bearing: ALL envelope checks (1-7) complete
        before the atomic inner gate-and-execute (8). Every rejection raises
        :class:`ReceiptValidationError`; the side effect runs only after all
        checks pass.
        """
        # 1. Envelope present. (Must precede the authorization checks D/E, which
        #    dereference step_receipt.)
        if step_receipt is None:
            raise ReceiptValidationError("No step receipt provided for governed workflow step")

        # A-E. Plan-level governance: authorization integrity + plan binding +
        #      plan MACI/runner anchor + step→authorization binding + cross-level
        #      separation. Verified on EVERY call, BEFORE the envelope checks and
        #      the atomic inner gate-and-execute. Returns the actor/validator this
        #      step would add to the cross-level sets (committed only on success).
        candidate = self._verify_authorization(step_receipt)

        # 2. Envelope hash (tampered envelope).
        expected_hash = step_receipt.compute_step_hash()
        if step_receipt.step_receipt_hash != expected_hash:
            raise ReceiptValidationError(
                f"step_receipt_hash mismatch: expected {expected_hash}, "
                f"got {step_receipt.step_receipt_hash}"
            )

        # 3. Envelope signature (when engaged).
        _verify_envelope_signature(
            step_receipt,
            verifier=self.verifier,
            require_signature=self.require_signature,
        )

        # 4. Workflow binding (cross-workflow).
        if step_receipt.workflow_id != self.workflow_id:
            raise ReceiptValidationError(
                f"cross-workflow step receipt: expected workflow_id {self.workflow_id!r}, "
                f"got {step_receipt.workflow_id!r}"
            )

        # 4b. Positional binding. The envelope's step_id is hash-bound but is
        #     otherwise never tied to the position it is presented for. Without
        #     this, one approved receipt can drive side effects at multiple DAG
        #     positions whenever twin / fan-out steps share action + predecessors
        #     + args (the no-replay check at step 6 keys on the caller-supplied
        #     position, so it does not stop cross-position reuse). Bind the
        #     envelope to the position it claims.
        if step_receipt.step_id != step_id:
            raise ReceiptValidationError(
                f"step receipt for {step_receipt.step_id!r} presented at position {step_id!r}"
            )

        # 5. DAG binding (plan altered / step not in plan / declared deps wrong).
        if step_receipt.dag_hash != self.dag.dag_hash():
            raise ReceiptValidationError(
                "dag_hash mismatch: step receipt bound to a different plan"
            )
        if step_id not in self.dag.steps:
            raise ReceiptValidationError(f"step {step_id!r} is not in the approved DAG")
        dag_predecessors = sorted(self.dag.steps[step_id].predecessor_step_ids)
        if sorted(step_receipt.predecessor_step_ids) != dag_predecessors:
            raise ReceiptValidationError(
                f"declared predecessors {sorted(step_receipt.predecessor_step_ids)} do not "
                f"match the approved DAG {dag_predecessors}"
            )

        # 6. No replay (step already executed in this run).
        if step_id in self.ledger:
            raise ReceiptValidationError(f"step {step_id!r} already executed (replay rejected)")

        # 7. Predecessor satisfaction (ordering + substitution).
        for pred in dag_predecessors:
            if pred not in self.ledger:
                raise ReceiptValidationError(
                    f"predecessor {pred!r} has not executed yet (reorder rejected)"
                )
            recorded = step_receipt.predecessor_receipt_hashes.get(pred)
            if recorded != self.ledger[pred]:
                raise ReceiptValidationError(
                    f"predecessor {pred!r} receipt hash does not match the executed step "
                    "(predecessor substitution rejected)"
                )

        # 8. Inner gate + execute (atomic, LAST). The single-action gate runs the
        #    full check (actor anchor, args binding, policy, boundary, signature,
        #    self-validation) and only then the side effect.
        action = self.dag.steps[step_id].action
        result = self.governed.execute(action, args, step_receipt.inner)

        # 9. Record in the ledger, commit the cross-level set updates (only on
        #    success, so a rejected step never pollutes the separation state), and
        #    return.
        self.ledger[step_id] = step_receipt.step_receipt_hash
        actor, validator_id = candidate
        self.proposers.add(actor)
        self.validators.add(validator_id)
        return result


def verify_workflow_replay(
    dag: WorkflowDAG,
    step_receipts: list[WorkflowStepReceipt],
    *,
    authorization: WorkflowAuthorization,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    revoked_keys: RevocationList | None = None,
) -> None:
    """Offline re-verification of a recorded workflow run (no ledger).

    Proves the recorded chain is internally consistent, topologically faithful to
    the approved DAG, and executed under an integral, plan-MACI-separated
    :class:`WorkflowAuthorization`. Raises :class:`ReceiptValidationError` on any
    failure.

    Checks:
    - **authorization integrity** — ``compute_authorization_hash()`` matches, and
      the signature verifies when present / required;
    - **plan binding** — the authorization's ``dag_hash`` == ``dag.dag_hash()``
      and its ``workflow_id`` matches the chain's;
    - **plan MACI** — ``plan_validator_id != plan_proposer``;
    - all envelopes share one ``dag_hash`` == ``dag.dag_hash()`` and one
      ``workflow_id``;
    - each envelope's ``compute_step_hash()`` matches its ``step_receipt_hash``,
      and its ``authorization_hash`` equals the authorization's;
      signatures verify when present / required;
    - topological consistency: every step's predecessors appear before it, and
      each ``predecessor_receipt_hashes[p]`` equals predecessor ``p``'s actual
      ``step_receipt_hash``;
    - **cross-level separation (b)** over the recorded set:
      ``{plan_proposer} ∪ {step actors}`` disjoint from
      ``{plan_validator_id} ∪ {step validator_ids}``;
    - each inner :class:`DecisionReceipt` independently verifies — pass
      ``revoked_keys`` (a :class:`gove_zone.revocation.RevocationList`) to reject
      an inner receipt signed by a revoked, in-scope signing ``key_id`` on replay
      (default ``None`` preserves prior behavior). The envelope/authorization
      signatures are a distinct key population and are NOT revocation-checked here.

    Honesty: there is **no runner** offline (it is runtime-only and deliberately
    not in the authorization), so replay enforces plan MACI but **not** the runner
    anchor (``plan_validator_id != runner``). Unsigned replay proves internal
    consistency and topological faithfulness, NOT unforgeability (see
    ``SECURITY.md``).
    """
    dag.validate()
    expected_dag_hash = dag.dag_hash()

    if not step_receipts:
        raise ReceiptValidationError("no step receipts to replay")

    workflow_id = step_receipts[0].workflow_id

    # Authorization integrity + plan binding + plan MACI.
    if authorization.compute_authorization_hash() != authorization.authorization_hash:
        raise ReceiptValidationError("replay: authorization_hash mismatch (tampered authorization)")
    _verify_authorization_signature(
        authorization, verifier=verifier, require_signature=verifier is not None
    )
    if authorization.dag_hash != expected_dag_hash:
        raise ReceiptValidationError("replay: authorization bound to a different DAG")
    if authorization.workflow_id != workflow_id:
        raise ReceiptValidationError("replay: authorization workflow_id does not match the chain")
    if authorization.plan_validator_id == authorization.plan_proposer:
        raise ReceiptValidationError(
            "replay: plan self-validation (plan validator == plan proposer)"
        )

    # Per-envelope integrity, binding, and signature.
    for sr in step_receipts:
        if sr.workflow_id != workflow_id:
            raise ReceiptValidationError("replay: step receipts span more than one workflow_id")
        if sr.dag_hash != expected_dag_hash:
            raise ReceiptValidationError("replay: step receipt bound to a different DAG")
        if sr.authorization_hash != authorization.authorization_hash:
            raise ReceiptValidationError(
                f"replay: step {sr.step_id!r} authorization_hash does not match the authorization"
            )
        if sr.step_id not in dag.steps:
            raise ReceiptValidationError(f"replay: step {sr.step_id!r} is not in the DAG")
        if sr.compute_step_hash() != sr.step_receipt_hash:
            raise ReceiptValidationError(
                f"replay: step_receipt_hash mismatch for step {sr.step_id!r}"
            )
        _verify_envelope_signature(sr, verifier=verifier, require_signature=verifier is not None)
        dag_predecessors = sorted(dag.steps[sr.step_id].predecessor_step_ids)
        if sorted(sr.predecessor_step_ids) != dag_predecessors:
            raise ReceiptValidationError(
                f"replay: declared predecessors for step {sr.step_id!r} do not match the DAG"
            )

    # Cross-level separation (b) over the recorded set (no runner offline).
    replay_proposers = {authorization.plan_proposer} | {sr.inner.actor for sr in step_receipts}
    replay_validators = {authorization.plan_validator_id} | {
        sr.inner.validator_id for sr in step_receipts
    }
    cross_overlap = replay_proposers & replay_validators
    if cross_overlap:
        raise ReceiptValidationError(
            "replay: cross-level collusion — principal(s) are both proposer and validator "
            f"({sorted(cross_overlap)})"
        )

    # Topological consistency: walk in an order where predecessors precede a step,
    # confirming each predecessor_receipt_hash equals the predecessor's own hash.
    by_id = {sr.step_id: sr for sr in step_receipts}
    if len(by_id) != len(step_receipts):
        raise ReceiptValidationError("replay: duplicate step_id among step receipts")

    executed: dict[str, str] = {}
    remaining = dict(by_id)
    while remaining:
        progressed = False
        for sid in list(remaining):
            sr = remaining[sid]
            preds = sorted(dag.steps[sid].predecessor_step_ids)
            if all(p in executed for p in preds):
                for p in preds:
                    if sr.predecessor_receipt_hashes.get(p) != executed[p]:
                        raise ReceiptValidationError(
                            f"replay: predecessor {p!r} receipt hash mismatch for step {sid!r}"
                        )
                executed[sid] = sr.step_receipt_hash
                del remaining[sid]
                progressed = True
        if not progressed:
            raise ReceiptValidationError(
                "replay: chain is not topologically consistent (unsatisfiable predecessors)"
            )

    # Each inner receipt independently verifies. ``revoked_keys`` (B2) is
    # threaded so a recorded inner DecisionReceipt signed by a revoked, in-scope
    # signing key_id is rejected (SIGNING_KEY_REVOKED) on replay too, not only at
    # the live gate. (The envelope/authorization signatures are a DISTINCT key
    # population — caller/plan credentials — and are intentionally NOT covered
    # here; see revocation.py scope note.)
    for sr in step_receipts:
        sr.inner.verify(revoked_keys=revoked_keys)
