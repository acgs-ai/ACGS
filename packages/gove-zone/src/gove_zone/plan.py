"""Plan-level governance — the workflow plan as a governed object.

This module is **additive** on top of the workflow receipt chain
(:mod:`gove_zone.workflow`). The workflow layer binds a declared
:class:`~gove_zone.workflow.WorkflowDAG` into every step envelope via ``dag_hash``,
but the DAG itself is *unauthenticated structure*: any integrator can declare a
plan and mint step receipts for it. There is no proposer≠validator authority
decision over the **plan**.

This increment adds it. A **plan proposer** proposes the DAG; a **distinct plan
validator** (≠ proposer) authorizes it, producing a :class:`WorkflowAuthorization`.
Steps execute only under that authorization. The invariant grows from

    "No valid step receipt … no side effect for that step."

to add

    "No authorized plan, no workflow step executes."

:class:`WorkflowAuthorization` mirrors :class:`~gove_zone.receipt.DecisionReceipt`
exactly: ``compute_authorization_hash()`` excludes ``authorization_hash`` and
``signature`` and binds ``dag_hash`` / ``plan_proposer`` / ``plan_validator_id`` /
the signing algorithm + key id; :meth:`WorkflowAuthorization.from_plan` is
fail-closed on plan self-validation, computes the hash, then optionally signs it.

See ``SECURITY.md`` ("Plan-level governance") for the honest scope: this is
plan-level *role separation enforced by the verifier* (integrator-trusted,
signing-closed). It is **not** multi-agent governance — principals are opaque
strings; the cross-level check proves *distinctness of strings*, not authenticated
identity.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from gove_zone.decision import sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.receipt import Validator
from gove_zone.signing import ReceiptSigner


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True)
class WorkflowAuthorization:
    """A plan receipt: a distinct plan validator's authorization of a DAG.

    The plan-level analog of :class:`~gove_zone.receipt.DecisionReceipt`.
    ``authorization_hash`` covers every field **except** ``authorization_hash``
    and ``signature``, and binds ``dag_hash`` (the exact plan authorized),
    ``plan_proposer`` / ``plan_validator_id`` (the MACI principals), and
    ``signature_algorithm`` / ``signing_key_id`` (anti-downgrade). ``signature``
    signs that hash and stays out of it — identical discipline to the inner
    receipt and the step envelope.
    """

    workflow_id: str
    dag_hash: str
    plan_proposer: str
    plan_validator_id: str
    plan_validator_role: str
    authority: str
    tenant_id: str
    execution_boundary: str
    declared_goal: str
    policy_hash: str = ""
    constraints: Mapping[str, Any] = field(default_factory=dict)
    issued_at: str = ""
    expires_at: str = ""
    authorization_hash: str = ""
    signature_algorithm: str = "none"
    signing_key_id: str = ""
    signature: str = "unsigned_local"

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraints", _freeze_json(self.constraints))

    def _hash_payload(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "dag_hash": self.dag_hash,
            "plan_proposer": self.plan_proposer,
            "plan_validator_id": self.plan_validator_id,
            "plan_validator_role": self.plan_validator_role,
            "authority": self.authority,
            "tenant_id": self.tenant_id,
            "execution_boundary": self.execution_boundary,
            "declared_goal": self.declared_goal,
            "policy_hash": self.policy_hash,
            "constraints": _plain_json(self.constraints),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
        }

    def compute_authorization_hash(self) -> str:
        """``sha256_json`` of every field except ``authorization_hash`` and
        ``signature``, binding ``dag_hash`` / proposer / validator / alg / key_id."""
        return sha256_json(self._hash_payload())

    @classmethod
    def from_plan(
        cls,
        dag_hash: str,
        *,
        workflow_id: str,
        plan_proposer: str,
        plan_validator: Validator,
        authority: str,
        tenant_id: str,
        execution_boundary: str,
        declared_goal: str,
        policy_hash: str = "",
        constraints: dict[str, Any] | None = None,
        issued_at: str = "",
        expires_at: str = "",
        signer: ReceiptSigner | None = None,
    ) -> WorkflowAuthorization:
        """Authorize *dag_hash* with a distinct MACI plan *plan_validator*.

        Fail-closed (plan MACI): the validator must differ from the proposer. A
        self-validated plan — where the proposer would also be its own authority
        — can never be minted. Mirrors :meth:`DecisionReceipt.from_record` /
        :meth:`WorkflowStepReceipt.from_inner`: bind ``signature_algorithm`` /
        ``signing_key_id`` into the hash (anti-downgrade), compute the hash, THEN
        sign that hash so the signature attests it. With ``signer=None`` (default)
        the authorization is unsigned.
        """
        if plan_validator.validator_id == plan_proposer:
            raise ReceiptValidationError(
                "self-validation forbidden: plan validator must differ from plan proposer "
                f"(both are {plan_proposer!r})"
            )

        authorization = cls(
            workflow_id=workflow_id,
            dag_hash=dag_hash,
            plan_proposer=plan_proposer,
            plan_validator_id=plan_validator.validator_id,
            plan_validator_role=plan_validator.role,
            authority=authority,
            tenant_id=tenant_id,
            execution_boundary=execution_boundary,
            declared_goal=declared_goal,
            policy_hash=policy_hash,
            constraints=dict(constraints) if constraints else {},
            issued_at=issued_at,
            expires_at=expires_at,
            signature_algorithm=signer.algorithm if signer is not None else "none",
            signing_key_id=signer.key_id if signer is not None else "",
        )
        # Compute the hash AFTER alg+key_id are set so they bind into it
        # (anti-downgrade), THEN sign that hash so the signature attests it.
        h = authorization.compute_authorization_hash()
        signature = signer.sign(h.encode("utf-8")) if signer is not None else "unsigned_local"
        return dataclasses.replace(authorization, authorization_hash=h, signature=signature)
