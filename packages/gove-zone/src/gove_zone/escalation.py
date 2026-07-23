"""ESCALATE → human approval → resume: the governed bridge.

The kernel raises :class:`~gove_zone.errors.EscalateError` when a policy returns
ESCALATE; the dispatch dead-ends there with no execution. This module turns that
dead-end into a resumable, human-gated, fully-governed path **without adding any
new gate logic** — it only wires together two halves that already exist:

1. The kernel attaches a :class:`PendingApproval` (the escalated record + audit
   anchor + the exact proposed args) to the ``EscalateError`` it raises.
2. A **human** approver calls :func:`approve_escalation`, which derives a fresh
   ``Decision.ALLOW`` record from the escalated one, re-stamps the argument hash
   to bind the exact args, appends the approval as its own audit event, and mints
   a :class:`~gove_zone.receipt.DecisionReceipt` with the human as the distinct
   MACI :class:`~gove_zone.receipt.Validator` (``from_record`` already forbids
   ``validator == proposer``).
3. :func:`resume_with_receipt` executes the original tool **only** through the
   existing :class:`~gove_zone.executor.GovernedExecutor` gate, so
   ``DecisionReceipt.verify`` re-checks actor binding, argument binding,
   tenant/boundary/policy, ``decision == ALLOW`` (an ESCALATE/DENY receipt is
   rejected by verify check 4) and any required signature before a single side
   effect runs.

Fail-closed properties (each is enforced by *existing* code — this module only
connects the halves):

* **Resume is never a re-run.** Execution routes through
  :func:`~gove_zone.executor.execute_with_receipt`; a valid ALLOW receipt is
  mandatory.
* **Human ≠ agent.** The approver must differ from the proposing agent —
  enforced at issuance (``from_record``) and again at the gate (verify check 2b,
  with ``expected_actor`` = the proposer).
* **Exact args are bound.** ``argument_hash`` is re-stamped here and re-checked
  by verify check 10b at resume, so an approved write of ``/tmp/safe`` cannot be
  resumed as a write of ``/etc/shadow``.
* **The approval is itself a governed, audit-chained decision.**
* **The original ESCALATE decision can never authorize execution.** A receipt
  minted from it still carries ``decision == "escalate"`` and is rejected by
  verify check 4.

No allow/deny/escalate verdict is delegated to a model: the post-approval verdict
is a human decision recorded deterministically; the deterministic gate is
untouched.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.executor import GovernedExecutor
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.signing import ReceiptSigner


@dataclass(frozen=True)
class PendingApproval:
    """A captured ESCALATE awaiting human approval.

    Bundles the escalated :class:`DecisionRecord`, the audit anchor of the
    escalation event, and the exact proposed args. Deployment config
    (tenant/boundary/policy hashes) is **not** captured here — it is supplied by
    the approver, who holds the same configuration as the resuming
    :class:`~gove_zone.executor.GovernedExecutor`.

    Fail-closed: construction rejects any non-ESCALATE record, so a
    ``PendingApproval`` can only ever represent a genuine escalation awaiting a
    decision.
    """

    record: DecisionRecord
    audit_hash: str
    args: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.record.decision is not Decision.ESCALATE:
            raise ReceiptValidationError(
                "PendingApproval requires an ESCALATE record (fail-closed); "
                f"got {self.record.decision.value!r}"
            )


def approve_escalation(
    pending: PendingApproval,
    *,
    validator: Validator,
    authority: str,
    tenant_id: str,
    execution_boundary: str,
    policy_bundle_id: str,
    policy_hash: str,
    audit: ChainHashAuditStore,
    request_id: str | None = None,
    subject: str = "",
    constraints: dict[str, Any] | None = None,
    approval_chain_summary: dict[str, Any] | None = None,
    expires_at: str = "",
    signer: ReceiptSigner | None = None,
) -> DecisionReceipt:
    """Approve an escalated call and mint an ALLOW receipt for resume.

    Fail-closed: refuses any non-ESCALATE record. The derived record's
    ``argument_hash`` is re-stamped to ``sha256_json(dict(pending.args))`` so the
    gate's argument-binding check (verify #10b) authorizes exactly these args.
    ``decision_request_hash`` is preserved, binding the approval to the same
    original request. The approval is appended to *audit* as its own governed
    event, then minted via :meth:`DecisionReceipt.from_record` with *validator*
    as the distinct MACI principal — ``from_record`` raises if ``validator``
    equals the proposer.

    The approver is responsible for supplying ``tenant_id`` /
    ``execution_boundary`` / ``policy_*`` that match the resuming
    :class:`~gove_zone.executor.GovernedExecutor`; a mismatch fails closed at the
    gate (verify checks 5/6/11/12). For a one-shot approval window, set
    ``expires_at`` (verify check 13). To cryptographically close the
    recomputed-receipt residual, pass a private-key ``signer`` and resume with
    ``require_signature=True`` plus the matching verifier.

    Limitations (inherited from the stateless gate; tracked for a follow-up
    single-use change):

    * **Approvals are not single-use.** ``DecisionReceipt.verify`` holds no
      memory of prior uses, so one approval receipt can be resumed more than
      once — exactly as an ordinary kernel ALLOW receipt can. "Approved once"
      does NOT imply "executed once". Bound the window with ``expires_at`` (or
      pin ``expected_audit_hash`` at resume) until a used-receipt ledger exists.
    * **Re-approving the same pending reuses the approval ``event_id``**
      (``<original>:approved``), so two approvals of one escalation are not
      individually addressable via ``event_id`` lookup. The hash chain is not
      affected (it keys on ``event_hash``/``previous_hash``).
    """
    if pending.record.decision is not Decision.ESCALATE:
        raise ReceiptValidationError(
            "approve_escalation only approves ESCALATE records (fail-closed); "
            f"got {pending.record.decision.value!r}"
        )

    # Reject self-validation BEFORE touching the audit chain. ``from_record``
    # re-checks this, but doing it here keeps a rejected self-approval from
    # appending a spurious ALLOW event that never authorizes execution.
    proposer = pending.record.actor or "anonymous"
    if validator.validator_id == proposer:
        raise ReceiptValidationError(
            "self-validation forbidden: validator must differ from proposer "
            f"(both are {proposer!r})"
        )

    approved_args = dict(pending.args)
    approved = dataclasses.replace(
        pending.record,
        decision=Decision.ALLOW,
        # Re-stamp so verify #10b binds the EXACT args that will execute, no
        # matter what the escalating policy put in argument_hash.
        argument_hash=sha256_json(approved_args),
        matched_rules=(
            *pending.record.matched_rules,
            f"HUMAN_APPROVED:{validator.validator_id}",
        ),
        reason=((pending.record.reason + "; ") if pending.record.reason else "")
        + f"escalation approved by validator {validator.validator_id}",
        # Distinct audit identity for the approval; the original ESCALATE event
        # stays in the chain unchanged.
        event_id=pending.record.event_id + ":approved",
        # ALLOW carries no transformed args; the gate binds the original args.
        transformed_args=None,
        # decision_request_hash is intentionally preserved (binds to the same
        # original request).
    )

    # The approval is a governed decision in its own right: anchor it in the
    # chain. Source previous_audit_hash from the append result, NOT a separate
    # pre-read: ``append`` computes ``previous_hash`` under the store's exclusive
    # lock against the real in-chain predecessor, so the receipt's chain-linkage
    # claim stays accurate even when another writer advances the head
    # concurrently (a lock-free ``last_hash()`` pre-read could be superseded
    # before the locked write and record a stale anchor).
    approval_event = audit.append(approved)
    approval_audit_hash = str(approval_event["event_hash"])
    previous_audit_hash = str(approval_event["previous_hash"])

    effective_request_id = request_id or pending.record.decision_request_hash or approved.event_id

    return DecisionReceipt.from_record(
        approved,
        audit_hash=approval_audit_hash,
        previous_audit_hash=previous_audit_hash,
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy_bundle_id=policy_bundle_id,
        policy_hash=policy_hash,
        request_id=effective_request_id,
        validator=validator,
        authority=authority,
        subject=subject,
        constraints=constraints,
        approval_chain_summary=approval_chain_summary,
        expires_at=expires_at,
        signer=signer,
    )


def resume_with_receipt(
    executor: GovernedExecutor,
    pending: PendingApproval,
    receipt: DecisionReceipt,
    *,
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    expected_policy_version: str | None = None,
    expected_validator_id: str | None = None,
    expected_validator_role: str | None = None,
    expected_authority: str | None = None,
    expected_constraints: Mapping[str, Any] | None = None,
    expected_request_id: str | None = None,
    expected_audit_hash: str | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool | None = None,
    now_iso: str | None = None,
) -> Any:
    """Resume an approved escalation by executing through the existing gate.

    Routes to :meth:`~gove_zone.executor.GovernedExecutor.execute`, anchoring
    ``expected_actor`` to the original proposer so the MACI binding (verify #2b)
    holds: the receipt must have been issued *for this proposer* and validated by
    a *different* principal. No execution path bypasses
    :meth:`~gove_zone.receipt.DecisionReceipt.verify`.

    The caller must have registered the tool under ``pending.record.tool`` on
    *executor*, and *executor* must carry the same tenant/boundary as the
    receipt. The executor's signing posture also flows through: a production
    executor (the default, ``require_signature=True``) needs a verifier and a
    signed approval, else it fails closed with
    :class:`~gove_zone.errors.ProductionProfileError`; construct a dev executor
    (``require_signature=False``) for unsigned operation.
    """
    return executor.execute(
        pending.record.tool,
        dict(pending.args),
        receipt,
        expected_actor=pending.record.actor,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
        expected_policy_version=expected_policy_version,
        expected_validator_id=expected_validator_id,
        expected_validator_role=expected_validator_role,
        expected_authority=expected_authority,
        expected_constraints=expected_constraints,
        expected_request_id=expected_request_id,
        expected_audit_hash=expected_audit_hash,
        verifier=verifier,
        require_signature=require_signature,
        now_iso=now_iso,
    )
