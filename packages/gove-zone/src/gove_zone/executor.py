"""Governed executor and receipt-gate runner.

Guarantees that high-risk tool execution fail-closes before any side effects
can be run.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.errors import (
    PRODUCTION_NO_VERIFIER_MSG,
    ProductionProfileError,
    ReceiptValidationError,
)
from gove_zone.policy import Policy
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import ReceiptSigner


def execute_with_receipt(
    tool_fn: Callable[..., Any],
    args: dict[str, Any],
    receipt: DecisionReceipt | None,
    *,
    expected_tenant_id: str,
    expected_execution_boundary: str,
    expected_action: str,
    expected_actor: str,
    expected_audit_hash: str | None = None,
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    policy: Policy | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool = True,
    require_expiry: bool = False,
    consumption_ledger: ReceiptConsumptionLedger | None = None,
) -> Any:
    """Execute *tool_fn* with *args* iff *receipt* is valid and matches constraints.

    Refuses execution with ReceiptValidationError if:
    - No receipt is provided
    - Receipt verification fails (altered, tampered, invalid hashes, wrong tenant/boundary)
    - Receipt is denied or escalated
    - Transformations in a TRANSFORM receipt do not match execution arguments

    **Production profile is the default.** ``require_signature`` defaults to
    ``True`` — the secure "production profile" posture: an unsigned receipt is
    rejected and a signed receipt is cryptographically verified against
    ``verifier``. A production gate invoked with no ``verifier`` fails closed loud
    (:class:`~gove_zone.errors.ProductionProfileError`) naming both exits, rather
    than silently downgrading or auto-generating a key. To run the explicit
    unsigned "dev mode", pass ``require_signature=False`` (or resolve a
    :meth:`gove_zone.profile.GovernanceProfile.dev` bundle).

    ``expected_actor`` (the invoking principal's identity, from the caller's
    runtime context — NOT read from the receipt) is **required**. It anchors the
    MACI self-validation/proposer-binding check against an identity the receipt
    author cannot forge by editing receipt fields, so the strong check is the
    default at the gate rather than an opt-in. Omitting it is a ``TypeError``
    (it has no default); passing an empty string fails closed with
    ``ReceiptValidationError``. The relocated trust lives with the integrator:
    this does not manufacture an authenticated identity the architecture lacks —
    signed issuance (``require_signature=True`` + a trusted verifier) is the
    cryptographic closure.

    ``policy`` (opt-in) binds the gate to the policy object it is currently
    enforcing. When supplied and ``expected_policy_hash`` is left ``None``, the
    gate derives ``expected_policy_hash=policy.version`` so receipt check 11
    (policy-hash match) becomes load-bearing on the live path: a receipt whose
    ``policy_hash`` does not match the policy this gate enforces is rejected with
    ``ReceiptRejectionReason.POLICY_HASH_MISMATCH``. This is the gate-side
    closure for an otherwise-advisory field — the expected hash is taken from the
    policy the gate independently holds, never from the receipt, so the check
    cannot be made vacuous by a tampered receipt. An explicit
    ``expected_policy_hash`` always wins; if both are given and disagree, the
    call fails closed before execution (a contradictory contract). When ``policy``
    is ``None`` behavior is unchanged. NOTE: ``policy.version`` for
    :class:`~gove_zone.policy.RuleSetPolicy` embeds only a 64-bit-truncated
    content digest, so this binds at ~2**64 second-preimage strength, not full
    SHA-256; it is a same-policy identity check, not a collision-proof seal.

    ``require_expiry`` (opt-in, default ``False``) mandates a liveness/TTL
    bound: when ``True`` a receipt whose ``expires_at`` is empty is rejected
    (:class:`~gove_zone.errors.ReceiptValidationError`,
    :data:`~gove_zone.errors.ReceiptRejectionReason.EXPIRY_REQUIRED`) rather
    than being treated as never-expiring. The strict production profile
    (:meth:`gove_zone.profile.GovernanceProfile.production_strict`) sets it so a
    long-lived bearer receipt cannot authorize indefinitely. Default ``False``
    leaves every existing caller unaffected.

    ``consumption_ledger`` (opt-in) makes the receipt **single-use**:
    ``verify`` alone is stateless, so without a ledger one valid receipt
    authorizes N executions. When a
    :class:`~gove_zone.consumption.ReceiptConsumptionLedger` is supplied, the
    receipt's audit anchor is atomically burned *after* verification passes
    and *before* the tool runs — a replay raises
    :class:`~gove_zone.errors.ReceiptAlreadyUsedError` with no side effect,
    and concurrent presenters serialize on the ledger lock so at most one
    executes. At-most-once semantics: a tool failure after the burn does NOT
    un-burn the receipt; recovery is a fresh decision/approval. Verification
    failures burn nothing.
    """
    if not expected_actor or not expected_actor.strip():
        raise ReceiptValidationError(
            "expected_actor is required for governed execution (fail-closed)"
        )
    if require_signature and verifier is None:
        raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)
    if receipt is None:
        raise ReceiptValidationError("No receipt provided for governed execution")

    # Gate-side policy binding: derive the expected policy hash from the policy
    # this gate is currently enforcing (never from the receipt). An explicit
    # expected_policy_hash wins; a contradictory pair fails closed before any
    # side effect.
    if policy is not None:
        gate_policy_hash = policy.version
        if expected_policy_hash is None:
            expected_policy_hash = gate_policy_hash
        elif expected_policy_hash != gate_policy_hash:
            raise ReceiptValidationError(
                "contradictory policy contract: expected_policy_hash "
                f"{expected_policy_hash!r} disagrees with the bound policy version "
                f"{gate_policy_hash!r}"
            )

    # verify will check missing fields, signature, hashes, decision type,
    # tenant, boundary, action, audit hash, transform mismatches, and — when
    # expected_actor is supplied — that the receipt was issued for this caller
    # and that the caller is not also the validator.
    receipt.verify(
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_audit_hash=expected_audit_hash,
        expected_args=args,
        expected_action=expected_action,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
        expected_actor=expected_actor,
        verifier=verifier,
        require_signature=require_signature,
        require_expiry=require_expiry,
    )

    # Burn-before-execute: consume only after verify passes (a failed
    # presentation must not waste the approval), but before the side effect
    # (so a concurrent replay loses the ledger race, not the execution race).
    if consumption_ledger is not None:
        consumption_ledger.consume(receipt)

    return tool_fn(**args)


class GovernedExecutor:
    """A wrapper for a tool registry that enforces receipt-gated execution.

    ``expected_actor`` (the proposing principal's identity) is supplied at
    construction time as the default contract for all calls made through this
    executor, and may be overridden per-call when needed. It is **required**:
    construction with no ``expected_actor`` is a ``TypeError`` and an empty
    string fails closed with ``ReceiptValidationError``. Supplying it activates
    the strong caller-anchored proposer-binding check in
    :meth:`DecisionReceipt.verify` (check 2b) by default, anchoring the MACI
    self-validation guard against an identity the receipt author cannot forge by
    editing receipt fields. There is no silent downgrade to the weak
    ``validator_id == actor`` heuristic (check 2c) through this gate; 2c remains
    only as residual defense for direct :meth:`DecisionReceipt.verify` calls.

    **Production profile is the default.** ``require_signature`` defaults to
    ``True``. An executor constructed in this posture with no ``verifier`` (and
    none supplied per-call) fails closed loud
    (:class:`~gove_zone.errors.ProductionProfileError`) when ``execute`` runs.
    For the explicit unsigned dev mode, construct with ``require_signature=False``
    (or feed a :meth:`gove_zone.profile.GovernanceProfile.dev` bundle).

    ``policy`` (opt-in) binds this executor to the policy it is currently
    enforcing; when set, every ``execute`` derives ``expected_policy_hash`` from
    ``policy.version`` (unless an explicit ``expected_policy_hash`` is passed),
    making receipt check 11 load-bearing — a receipt minted under a different
    policy is rejected at the gate. It follows the same per-call-override pattern
    as the other fields (per-call ``policy`` replaces the constructor one for that
    call; ``None`` per-call falls back to the constructor policy, so a per-call
    argument can never silently *disable* the binding). See
    :func:`execute_with_receipt` for the precedence and truncation caveats.

    ``consumption_ledger`` follows the same per-call-override pattern, with one
    sharp edge: a per-call ledger **replaces** (never augments) the constructor
    ledger for that call, and burns recorded in one store are invisible to the
    other — always pass the same logical store. Passing ``None`` per-call falls
    back to the constructor ledger, so a per-call argument can never silently
    *disable* single-use enforcement.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
        expected_actor: str,
        policy: Policy | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = True,
        require_expiry: bool = False,
        consumption_ledger: ReceiptConsumptionLedger | None = None,
    ) -> None:
        if not expected_actor or not expected_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for GovernedExecutor (fail-closed)"
            )
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.expected_actor = expected_actor
        self.policy = policy
        self.verifier = verifier
        self.require_signature = require_signature
        self.require_expiry = require_expiry
        self.consumption_ledger = consumption_ledger
        self.registry: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        self.registry[name] = fn

    def execute(
        self,
        action: str,
        args: dict[str, Any],
        receipt: DecisionReceipt | None,
        *,
        expected_audit_hash: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
        expected_actor: str | None = None,
        policy: Policy | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool | None = None,
        require_expiry: bool | None = None,
        consumption_ledger: ReceiptConsumptionLedger | None = None,
    ) -> Any:
        if action not in self.registry:
            raise KeyError(f"Tool {action!r} not registered with executor")
        tool_fn = self.registry[action]
        # Per-call values override the constructor defaults. expected_actor is
        # required at construction, so the effective anchor is always set unless a
        # per-call override blanks it — defend against expected_actor="" here.
        effective_actor = expected_actor if expected_actor is not None else self.expected_actor
        if not effective_actor or not effective_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for governed execution (fail-closed)"
            )
        effective_verifier = verifier if verifier is not None else self.verifier
        effective_require = (
            require_signature if require_signature is not None else self.require_signature
        )
        effective_require_expiry = (
            require_expiry if require_expiry is not None else self.require_expiry
        )
        effective_ledger = (
            consumption_ledger if consumption_ledger is not None else self.consumption_ledger
        )
        effective_policy = policy if policy is not None else self.policy
        return execute_with_receipt(
            tool_fn=tool_fn,
            args=args,
            receipt=receipt,
            expected_tenant_id=self.tenant_id,
            expected_execution_boundary=self.execution_boundary,
            expected_action=action,
            expected_audit_hash=expected_audit_hash,
            expected_policy_hash=expected_policy_hash,
            expected_policy_bundle_id=expected_policy_bundle_id,
            policy=effective_policy,
            expected_actor=effective_actor,
            verifier=effective_verifier,
            require_signature=effective_require,
            require_expiry=effective_require_expiry,
            consumption_ledger=effective_ledger,
        )
