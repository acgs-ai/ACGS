"""Governed executor and receipt-gate runner.

Guarantees that high-risk tool execution fail-closes before any side effects
can be run.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from gove_zone.authz import PrincipalRegistry
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.errors import (
    PRODUCTION_NO_VERIFIER_MSG,
    AuthzDeniedError,
    ProductionProfileError,
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.policy import Policy
from gove_zone.receipt import (
    DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    DecisionReceipt,
    validate_receipt_clock_skew_seconds,
)
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, RECEIPT_V2, ReceiptTrustRegistry


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
    expected_constraints: dict[str, Any] | None = None,
    expected_project_id: str | None = None,
    expected_environment_id: str | None = None,
    expected_validator_role: str | None = None,
    expected_authority: str | None = None,
    policy: Policy | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool = True,
    require_expiry: bool = False,
    revoked_keys: RevocationList | None = None,
    trust_registry: ReceiptTrustRegistry | None = None,
    trust_purpose: str = DECISION_RECEIPT_PURPOSE,
    max_clock_skew_seconds: int = DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    consumption_ledger: ReceiptConsumptionLedger | None = None,
    authz_enforce: bool = False,
    principal_registry: PrincipalRegistry | None = None,
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

    ``expected_authority`` / ``expected_validator_role`` (opt-in, default
    ``None``) pin the MACI grant the receipt must carry: when supplied they are
    forwarded to :meth:`DecisionReceipt.verify` (checks 12b/12c) so a receipt
    whose ``authority`` grant or ``validator_role`` does not match what this gate
    requires is rejected before any side effect. Both are hash-bound fields, so a
    tampered receipt cannot satisfy the check; leaving them ``None`` preserves the
    prior behavior exactly (the fields are not consulted). This closes the
    gate-side gap where an authority/role grant was enforceable only via a direct
    ``verify()`` call, never through the executor gate — least-privilege
    deployments can now bind the required grant at the gate.

    ``require_expiry`` (opt-in, default ``False``) mandates a liveness/TTL
    bound: when ``True`` a receipt whose ``expires_at`` is empty is rejected
    (:class:`~gove_zone.errors.ReceiptValidationError`,
    :data:`~gove_zone.errors.ReceiptRejectionReason.EXPIRY_REQUIRED`) rather
    than being treated as never-expiring. The strict production profile
    (:meth:`gove_zone.profile.GovernanceProfile.production_strict`) sets it so a
    long-lived bearer receipt cannot authorize indefinitely. Default ``False``
    leaves every existing caller unaffected.

    ``max_clock_skew_seconds`` threads the receipt not-before liveness bound to
    :meth:`DecisionReceipt.verify`: a signed receipt whose issuance timestamp is
    farther in the verifier's future is rejected before any ledger burn or side
    effect. The default is the library's five-minute skew allowance.

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

    ``authz_enforce`` (opt-in, default ``False``) + ``principal_registry`` add
    principal authorization at the executor gate (B13): when enabled,
    ``expected_actor`` must be an allowlisted principal permitted for
    ``expected_action`` or the call raises
    :class:`~gove_zone.errors.AuthzDeniedError` before any side effect. This is a
    strictly additional AND-gate over receipt verification — it can only deny,
    never permit, so it cannot weaken any existing guarantee. It runs before
    receipt verification and the ledger burn. ``authz_enforce=True`` with no
    registry is a fail-closed misconfiguration (``ValueError``). Default
    ``False`` leaves every existing caller byte-for-byte unchanged.
    """
    bounded_clock_skew_seconds = validate_receipt_clock_skew_seconds(max_clock_skew_seconds)
    if not expected_actor or not expected_actor.strip():
        raise ReceiptValidationError(
            "expected_actor is required for governed execution (fail-closed)"
        )
    # Principal authorization (B13): when enabled, the acting principal must be
    # an allowlisted principal permitted for this action — a strictly additional
    # AND-gate over receipt verification (it can only deny, never permit). Off by
    # default; enforcing with no registry is a fail-closed misconfiguration.
    if authz_enforce:
        if principal_registry is None:
            raise ValueError("authz_enforce=True requires a principal_registry (fail-closed)")
        denial = principal_registry.authorize(expected_actor, expected_action)
        if denial is not None:
            raise AuthzDeniedError(denial, expected_actor, expected_action)
    if receipt is None:
        if require_signature and verifier is None and trust_registry is None:
            raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)
        raise ReceiptValidationError("No receipt provided for governed execution")
    is_v2 = receipt.receipt_schema_version == RECEIPT_V2
    if is_v2 and trust_registry is None:
        raise ReceiptValidationError(
            "receipt v2 requires a scoped trust registry",
            reason_code=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
        )
    if is_v2 and (expected_project_id is None or expected_environment_id is None):
        raise ReceiptValidationError(
            "receipt v2 requires expected_project_id and expected_environment_id",
            reason_code=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
        )
    if require_signature and verifier is None and not (is_v2 and trust_registry is not None):
        raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)

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
        expected_constraints=expected_constraints,
        expected_project_id=expected_project_id,
        expected_environment_id=expected_environment_id,
        expected_validator_role=expected_validator_role,
        expected_authority=expected_authority,
        expected_actor=expected_actor,
        verifier=verifier,
        require_signature=require_signature,
        require_expiry=require_expiry,
        revoked_keys=revoked_keys,
        trust_registry=trust_registry,
        trust_purpose=trust_purpose,
        max_clock_skew_seconds=bounded_clock_skew_seconds,
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
        expected_authority: str | None = None,
        expected_validator_role: str | None = None,
        expected_project_id: str | None = None,
        expected_environment_id: str | None = None,
        policy: Policy | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = True,
        require_expiry: bool = False,
        revoked_keys: RevocationList | None = None,
        trust_registry: ReceiptTrustRegistry | None = None,
        trust_purpose: str = DECISION_RECEIPT_PURPOSE,
        max_clock_skew_seconds: int = DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
        consumption_ledger: ReceiptConsumptionLedger | None = None,
        authz_enforce: bool = False,
        principal_registry: PrincipalRegistry | None = None,
    ) -> None:
        if not expected_actor or not expected_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for GovernedExecutor (fail-closed)"
            )
        # authz_enforce / principal_registry are constructor-only (never per-call):
        # a per-call override could silently *disable* enforcement, the same
        # footgun the ledger/policy fields avoid. Fail closed if enforcing
        # without a registry.
        if authz_enforce and principal_registry is None:
            raise ValueError("authz_enforce=True requires a principal_registry (fail-closed)")
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.expected_actor = expected_actor
        self.expected_authority = expected_authority
        self.expected_validator_role = expected_validator_role
        self.expected_project_id = expected_project_id
        self.expected_environment_id = expected_environment_id
        self.policy = policy
        self.verifier = verifier
        self.require_signature = require_signature
        self.require_expiry = require_expiry
        self.trust_registry = trust_registry
        self.trust_purpose = trust_purpose
        self.max_clock_skew_seconds = validate_receipt_clock_skew_seconds(max_clock_skew_seconds)
        # Revocation config is constructor-only (never a per-call arg on
        # execute): a per-call empty/weaker list could silently disable a
        # security control — the same foot-gun authz_enforce/ledger avoid. The
        # executor's revocation posture flows through to resume_with_receipt.
        self.revoked_keys = revoked_keys
        self.consumption_ledger = consumption_ledger
        self.authz_enforce = authz_enforce
        self.principal_registry = principal_registry
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
        expected_constraints: dict[str, Any] | None = None,
        expected_actor: str | None = None,
        expected_authority: str | None = None,
        expected_validator_role: str | None = None,
        policy: Policy | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool | None = None,
        require_expiry: bool | None = None,
        consumption_ledger: ReceiptConsumptionLedger | None = None,
        max_clock_skew_seconds: int | None = None,
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
        effective_skew = validate_receipt_clock_skew_seconds(
            max_clock_skew_seconds
            if max_clock_skew_seconds is not None
            else self.max_clock_skew_seconds
        )
        effective_trust_registry = self.trust_registry
        effective_policy = policy if policy is not None else self.policy
        # Per-call None falls back to the constructor pin, so a per-call argument
        # can never silently *disable* an authority/role bound at construction.
        effective_authority = (
            expected_authority if expected_authority is not None else self.expected_authority
        )
        effective_validator_role = (
            expected_validator_role
            if expected_validator_role is not None
            else self.expected_validator_role
        )
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
            expected_constraints=expected_constraints,
            expected_project_id=self.expected_project_id,
            expected_environment_id=self.expected_environment_id,
            expected_validator_role=effective_validator_role,
            expected_authority=effective_authority,
            policy=effective_policy,
            expected_actor=effective_actor,
            verifier=effective_verifier,
            require_signature=effective_require,
            require_expiry=effective_require_expiry,
            revoked_keys=self.revoked_keys,
            trust_registry=effective_trust_registry,
            trust_purpose=self.trust_purpose,
            max_clock_skew_seconds=effective_skew,
            consumption_ledger=effective_ledger,
            authz_enforce=self.authz_enforce,
            principal_registry=self.principal_registry,
        )
