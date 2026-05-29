"""Receipt — the full proof-of-decision artifact for one dispatch.

A :class:`Receipt` is what the kernel returns alongside a successful tool
result. It packages the :class:`~gove_zone.decision.DecisionRecord`, the
audit chain hash, the actor identity, and a digest of the result. Receipts
are the unit of replay (see :mod:`gove_zone.replay`).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.signing import ReceiptSigner


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def safe_result_hash(value: Any) -> str:
    """Hash *value* deterministically.

    Falls back to ``repr(value)[:512]`` for non-JSON-serializable values so
    the receipt always carries a hash even when a tool returns objects we
    cannot canonicalize.
    """
    try:
        json.dumps(value, sort_keys=True, default=str)
        return sha256_json(value)
    except (TypeError, ValueError):
        return sha256_json({"_repr": repr(value)[:512]})


@dataclass(frozen=True)
class Receipt:
    """Proof-of-decision: the decision, the audit anchor, and the outcome.

    Attributes:
        record: the policy's frozen :class:`DecisionRecord`.
        audit_hash: ``event_hash`` returned by the audit store on append.
        actor: opaque identity string ("anonymous" by default).
        result_hash: SHA-256 of the canonical-JSON of the tool result, or
            ``None`` if the dispatch did not execute (DENY/ESCALATE).
        error_class: class name of the exception raised by tool execution,
            or ``None`` if execution succeeded or never ran.
    """

    record: DecisionRecord
    audit_hash: str
    actor: str = "anonymous"
    result_hash: str | None = None
    error_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.record.to_dict(),
            "audit_hash": self.audit_hash,
            "actor": self.actor,
            "result_hash": self.result_hash,
            "error_class": self.error_class,
        }


@dataclass(frozen=True)
class Validator:
    """MACI validating principal. Distinct from the proposer (ToolCall.actor).

    A ``Validator`` issues the authority decision; the proposer never can. This
    is the type/role boundary that structurally prevents self-validation: an
    agent may *propose* an action but can never *validate* its own authority to
    execute it. Fail-closed at construction — an empty id or role is rejected.
    """

    validator_id: str
    role: str = "validator"

    def __post_init__(self) -> None:
        if not self.validator_id:
            raise ValueError("Validator.validator_id is required (fail-closed)")
        if not self.role:
            raise ValueError("Validator.role is required (fail-closed)")


@dataclass(frozen=True)
class DecisionReceipt:
    """Canonical public Decision Receipt schema for AI-agent execution.

    Designed for deterministic serialisation, canonical hashing, and fail-closed validation.

    MACI role separation: ``actor`` is the proposer (the ToolCall actor) while
    ``validator_id`` / ``validator_role`` identify the distinct principal that
    issued the authority decision, and ``authority`` is the grant it conferred.
    These three fields are bound into ``receipt_hash`` (via ``to_dict``), enforcing
    validator≠proposer at issuance and at the gate when the caller supplies its
    identity via ``expected_actor``.

    Ed25519 asymmetric signing closes the recomputed-receipt residual **when
    engaged**: ``signature`` is a private-key signature over ``receipt_hash``; the
    gate verifies it with the matching public key. ``signature_algorithm`` and
    ``signing_key_id`` are bound into ``receipt_hash`` (anti-downgrade: an attacker
    cannot change the algorithm or key without breaking the hash), while
    ``signature`` itself stays OUT of ``compute_hash`` (the signature signs the
    hash). An unsigned receipt keeps ``signature_algorithm="none"``,
    ``signing_key_id=""``, ``signature="unsigned_local"``.

    **Precondition for closure.** The residual is closed only when receipts are
    issued with a private-key signer AND the gate is configured with a matching
    public-key verifier plus ``require_signature=True``. Default deployments are
    unsigned. Residuals not addressed: private-key custody, key distribution /
    trust establishment, and revocation (no PKI; the verifier map is static).
    """

    receipt_id: str
    request_id: str
    tenant_id: str
    actor: str
    proposed_action: str
    declared_goal: str
    execution_boundary: str
    policy_bundle_id: str
    policy_version: str
    policy_hash: str
    decision: str
    matched_rules: list[str]
    constraints: dict[str, Any]
    transformations: list[dict[str, Any]]
    approval_chain_summary: dict[str, Any]
    timestamp: str
    previous_audit_hash: str
    audit_event_hash: str
    subject: str = ""
    expires_at: str = ""
    authority: str = ""
    validator_id: str = ""
    validator_role: str = ""
    argument_hash: str = ""
    receipt_hash: str = ""
    signature_algorithm: str = "none"
    signing_key_id: str = ""
    signature: str = "unsigned_local"

    def to_dict(self) -> dict[str, Any]:
        transformations_list: Any = []
        if isinstance(self.transformations, list):
            for t in self.transformations:
                if isinstance(t, dict):
                    transformations_list.append(dict(t))
                else:
                    transformations_list.append(t)
        else:
            transformations_list = self.transformations

        return {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "subject": self.subject,
            "proposed_action": self.proposed_action,
            "declared_goal": self.declared_goal,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
            "constraints": (
                dict(self.constraints) if isinstance(self.constraints, dict) else self.constraints
            ),
            "transformations": transformations_list,
            "approval_chain_summary": (
                dict(self.approval_chain_summary)
                if isinstance(self.approval_chain_summary, dict)
                else self.approval_chain_summary
            ),
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "authority": self.authority,
            "validator_id": self.validator_id,
            "validator_role": self.validator_role,
            "argument_hash": self.argument_hash,
            "previous_audit_hash": self.previous_audit_hash,
            "audit_event_hash": self.audit_event_hash,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "receipt_hash": self.receipt_hash,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DecisionReceipt:
        return cls(
            receipt_id=d["receipt_id"],
            request_id=d["request_id"],
            tenant_id=d["tenant_id"],
            actor=d["actor"],
            subject=d.get("subject", ""),
            proposed_action=d["proposed_action"],
            declared_goal=d["declared_goal"],
            execution_boundary=d["execution_boundary"],
            policy_bundle_id=d["policy_bundle_id"],
            policy_version=d["policy_version"],
            policy_hash=d["policy_hash"],
            decision=d["decision"],
            matched_rules=list(d["matched_rules"]),
            constraints=dict(d.get("constraints", {})),
            transformations=[dict(t) for t in d.get("transformations", [])],
            approval_chain_summary=dict(d.get("approval_chain_summary", {})),
            timestamp=d["timestamp"],
            expires_at=d.get("expires_at", ""),
            authority=d.get("authority", ""),
            validator_id=d.get("validator_id", ""),
            validator_role=d.get("validator_role", ""),
            argument_hash=d.get("argument_hash", ""),
            previous_audit_hash=d["previous_audit_hash"],
            audit_event_hash=d["audit_event_hash"],
            receipt_hash=d.get("receipt_hash", ""),
            signature_algorithm=d.get("signature_algorithm", "none"),
            signing_key_id=d.get("signing_key_id", ""),
            signature=d.get("signature", "unsigned_local"),
        )

    @classmethod
    def from_json(cls, text: str) -> DecisionReceipt:
        return cls.from_dict(json.loads(text))

    def compute_hash(self) -> str:
        d = self.to_dict()
        d.pop("receipt_hash", None)
        d.pop("signature", None)
        return sha256_json(d)

    @classmethod
    def from_record(
        cls,
        record: DecisionRecord,
        audit_hash: str,
        previous_audit_hash: str,
        tenant_id: str,
        execution_boundary: str,
        policy_bundle_id: str,
        policy_hash: str,
        request_id: str,
        *,
        validator: Validator,
        authority: str,
        subject: str = "",
        constraints: dict[str, Any] | None = None,
        approval_chain_summary: dict[str, Any] | None = None,
        expires_at: str = "",
        signer: ReceiptSigner | None = None,
    ) -> DecisionReceipt:
        """Mint a receipt for *record*, binding a distinct MACI *validator*.

        Fail-closed: the validator must differ from the proposer
        (``record.actor``). A self-validated receipt — where the proposer would
        also be its own authority — can never be minted. The proposer/validator
        linkage is recorded in ``approval_chain_summary``.

        If *signer* is provided, its ``algorithm`` and ``key_id`` are bound into
        ``receipt_hash`` (anti-downgrade) and ``signature`` is the signer's
        signature over the hash. With ``signer=None`` (default) the receipt is
        unsigned (``signature_algorithm="none"``, ``signature="unsigned_local"``),
        fully backward-compatible.
        """
        from gove_zone.errors import ReceiptValidationError

        proposer = record.actor or "anonymous"
        if validator.validator_id == proposer:
            raise ReceiptValidationError(
                "self-validation forbidden: validator must differ from proposer "
                f"(both are {proposer!r})"
            )

        transformations: list[dict[str, Any]] = []
        if record.transformed_args:
            for k, v in record.transformed_args.items():
                transformations.append({"field": k, "value": v})

        linkage: dict[str, Any] = dict(approval_chain_summary or {})
        linkage.update(
            {
                "proposer": proposer,
                "validator_id": validator.validator_id,
                "validator_role": validator.role,
                "authority": authority,
            }
        )

        import dataclasses

        receipt = cls(
            receipt_id=record.event_id,
            request_id=request_id,
            tenant_id=tenant_id,
            actor=proposer,
            subject=subject,
            proposed_action=record.tool,
            declared_goal=record.goal or "",
            execution_boundary=execution_boundary,
            policy_bundle_id=policy_bundle_id,
            policy_version=record.policy_version,
            policy_hash=policy_hash,
            decision=record.decision.value,
            matched_rules=list(record.matched_rules),
            constraints=constraints or {},
            transformations=transformations,
            approval_chain_summary=linkage,
            timestamp=record.timestamp_iso,
            expires_at=expires_at,
            authority=authority,
            validator_id=validator.validator_id,
            validator_role=validator.role,
            argument_hash=record.argument_hash,
            previous_audit_hash=previous_audit_hash,
            audit_event_hash=audit_hash,
            signature_algorithm=signer.algorithm if signer is not None else "none",
            signing_key_id=signer.key_id if signer is not None else "",
        )
        # Compute the hash AFTER alg+key_id are set so they bind into it
        # (anti-downgrade), THEN sign that hash so the signature attests it.
        h = receipt.compute_hash()
        signature = signer.sign(h.encode("utf-8")) if signer is not None else "unsigned_local"
        return dataclasses.replace(receipt, receipt_hash=h, signature=signature)

    def verify(
        self,
        *,
        expected_tenant_id: str | None = None,
        expected_execution_boundary: str | None = None,
        expected_audit_hash: str | None = None,
        expected_args: dict[str, Any] | None = None,
        expected_action: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
        expected_validator_role: str | None = None,
        expected_authority: str | None = None,
        expected_actor: str | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = False,
        now_iso: str | None = None,
    ) -> None:
        from gove_zone.decision import Decision
        from gove_zone.errors import ReceiptValidationError

        # 1. Missing fields
        required_fields = [
            "receipt_id",
            "request_id",
            "tenant_id",
            "actor",
            "proposed_action",
            "execution_boundary",
            "policy_bundle_id",
            "policy_version",
            "policy_hash",
            "decision",
            "timestamp",
            "previous_audit_hash",
            "audit_event_hash",
            "validator_id",
            "validator_role",
            "authority",
            "argument_hash",
        ]
        for field_name in required_fields:
            val = getattr(self, field_name)
            if val is None or val == "":
                raise ReceiptValidationError(f"Missing or empty required field: {field_name}")

        # 2. Check receipt hash (reject altered fields or invalid hash)
        if not self.receipt_hash:
            raise ReceiptValidationError("receipt_hash is missing")
        expected_hash = self.compute_hash()
        if self.receipt_hash != expected_hash:
            raise ReceiptValidationError(
                f"Altered field or invalid hash: receipt_hash mismatch. "
                f"Expected {expected_hash}, got {self.receipt_hash}"
            )

        # 2a. Asymmetric signature check. Placed AFTER the receipt_hash check
        # because the signature attests an intact hash: a tampered field is caught
        # above before we trust the signature. Fail-closed: a verification
        # *failure* raises ReceiptValidationError (stays on the single gate path),
        # never SigningError.
        #
        # Two distinct failure modes with distinct semantics:
        #
        #   (i)  ``require_signature=True`` + ``algorithm=="none"``: the gate
        #        demands a signed receipt but this one is unsigned → reject.
        #        ``require_signature`` governs ONLY unsigned receipts.
        #
        #   (ii) ``algorithm != "none"``: the receipt CLAIMS a signature. It MUST
        #        be verified, period — regardless of ``require_signature``. A signed
        #        receipt presented without a verifier is rejected. This is the
        #        fail-closed rule: a receipt that advertises a signature cannot
        #        silently skip cryptographic verification.
        #
        # signature_algorithm and signing_key_id are bound into receipt_hash, so
        # an attacker cannot downgrade the algorithm or swap the key without
        # breaking check 2 above.
        if require_signature and self.signature_algorithm == "none":
            raise ReceiptValidationError("unsigned receipt rejected: signature required")
        if self.signature_algorithm != "none":
            # Resolve the verifier — a missing verifier is a hard rejection here
            # (the receipt claims a signature; we must check it).
            resolved: ReceiptSigner | None
            if isinstance(verifier, Mapping):
                if self.signing_key_id not in verifier:
                    raise ReceiptValidationError("unknown signing key")
                resolved = verifier[self.signing_key_id]
            elif verifier is not None:
                resolved = verifier
            else:
                raise ReceiptValidationError("signed receipt requires a configured verifier")
            if resolved.algorithm != self.signature_algorithm:
                raise ReceiptValidationError("signature algorithm mismatch")
            if not resolved.verify(self.receipt_hash.encode("utf-8"), self.signature):
                raise ReceiptValidationError("invalid signature")

        # 2b. MACI actor-anchor check (authoritative when caller supplies identity).
        # expected_actor is the identity of the INVOKING PRINCIPAL at the gate,
        # supplied from outside the receipt (like expected_tenant_id), so a
        # receipt author cannot satisfy it by editing the receipt's own fields.
        # Two enforcement steps when expected_actor is provided:
        #   (i)  actor mismatch  — this receipt was not issued for this caller.
        #   (ii) self-validation — the caller IS the validator, so the caller
        #        would be authorising its own action.
        if expected_actor is not None:
            if self.actor != expected_actor:
                raise ReceiptValidationError(
                    f"actor mismatch: receipt not issued for this caller "
                    f"(expected {expected_actor!r}, got {self.actor!r})"
                )
            if self.validator_id == expected_actor:
                raise ReceiptValidationError(
                    f"self-validation: validator is the invoking principal ({expected_actor!r})"
                )

        # 2c. Naive self-validation fallback (heuristic only, no expected_actor).
        # Catches only the obvious case where validator_id and actor on the
        # receipt happen to be identical. A forger who sets actor to a phantom
        # value while keeping validator_id as the real proposer bypasses this
        # check; real proposer-binding requires expected_actor above (and
        # ultimately authenticated/signed issuance, which is roadmap).
        if self.validator_id == self.actor:
            raise ReceiptValidationError(
                f"self-validation: validator must differ from proposer (both are {self.actor!r})"
            )

        # 2d. approval_chain_summary consistency: the issued summary must agree
        # with the top-level validator_id and actor fields, which are bound into
        # receipt_hash. Divergence means the receipt was either constructed
        # inconsistently or the summary was hand-edited after hashing.
        acs = self.approval_chain_summary if isinstance(self.approval_chain_summary, dict) else {}
        if acs:
            if acs.get("validator_id") != self.validator_id:
                raise ReceiptValidationError(
                    "approval_chain_summary.validator_id disagrees with receipt"
                )
            if acs.get("proposer") != self.actor:
                raise ReceiptValidationError(
                    "approval_chain_summary.proposer disagrees with receipt"
                )

        # 3. Unknown decisions
        try:
            Decision(self.decision)
        except ValueError as err:
            raise ReceiptValidationError(f"Unknown decision: {self.decision}") from err

        # 4. Denied and escalated receipts
        if self.decision == Decision.DENY:
            raise ReceiptValidationError("Denied receipt cannot authorize execution")
        if self.decision == Decision.ESCALATE:
            raise ReceiptValidationError("Escalated receipt cannot authorize execution")

        # 5. Wrong tenant
        if expected_tenant_id is not None and self.tenant_id != expected_tenant_id:
            raise ReceiptValidationError(
                f"Tenant mismatch: expected {expected_tenant_id}, got {self.tenant_id}"
            )

        # 6. Wrong execution boundary
        if (
            expected_execution_boundary is not None
            and self.execution_boundary != expected_execution_boundary
        ):
            raise ReceiptValidationError(
                f"Execution boundary mismatch: expected {expected_execution_boundary}, "
                f"got {self.execution_boundary}"
            )

        # 7. Action mismatch
        if expected_action is not None and self.proposed_action != expected_action:
            raise ReceiptValidationError(
                f"Action mismatch: expected {expected_action}, got {self.proposed_action}"
            )

        # 8. Audit hash mismatch
        if expected_audit_hash is not None and self.audit_event_hash != expected_audit_hash:
            raise ReceiptValidationError(
                f"Audit hash mismatch: expected {expected_audit_hash}, got {self.audit_event_hash}"
            )

        # 9. Malformed transformations
        if not isinstance(self.transformations, list):
            raise ReceiptValidationError("transformations must be a list")
        for tx in self.transformations:
            if not isinstance(tx, dict):
                raise ReceiptValidationError("each transformation must be a dictionary")
            if "field" not in tx or "value" not in tx:
                raise ReceiptValidationError(
                    "transformation dictionary must contain 'field' and 'value' keys"
                )
            if not isinstance(tx["field"], str):
                raise ReceiptValidationError("transformation 'field' key must be a string")

        # 10. Transform mismatch
        if self.decision == Decision.TRANSFORM.value and expected_args is not None:
            for tx in self.transformations:
                f = tx["field"]
                val = tx["value"]
                if f not in expected_args:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' is missing from arguments"
                    )
                if expected_args[f] != val:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' expected '{val}', "
                        f"got '{expected_args[f]}'"
                    )

            # 10c. Exact-match binding for TRANSFORM — symmetric with ALLOW (#10b).
            # A governed TRANSFORM must fully specify what runs; fields left
            # unspecified would execute un-approved, which is the same class of
            # hole the ALLOW argument_hash check closes. transformed_args is the
            # complete approved execution set by construction (from_record turns
            # every key of DecisionRecord.transformed_args into a transformations
            # entry), so the executed args must equal that set exactly.
            approved = {tx["field"]: tx["value"] for tx in self.transformations}
            if dict(expected_args) != approved:
                raise ReceiptValidationError(
                    "transform mismatch: executed arguments do not exactly match the approved "
                    "transformed arguments (extra, missing, or altered fields)"
                )

        # 10b. ALLOW argument binding: for ALLOW decisions, verify that the args
        # the gate is about to execute were exactly what the receipt authorized.
        # argument_hash is sha256_json(dict(args)) — same canonicalization as
        # ToolCall.argument_hash(). This closes the substitution gap: a valid
        # ALLOW receipt for write_file(path=/tmp/safe) cannot authorize
        # write_file(path=/etc/shadow). Only triggered when expected_args is
        # provided (execute_with_receipt always provides it). Not enforced on
        # TRANSFORM because the executed args are the transformed args, which
        # differ from the original proposed args that argument_hash covers;
        # the transform-field check (#10) already binds TRANSFORM execution.
        if self.decision == Decision.ALLOW.value and expected_args is not None:
            from gove_zone.decision import sha256_json as _sha256_json

            computed_arg_hash = _sha256_json(dict(expected_args))
            if self.argument_hash != computed_arg_hash:
                raise ReceiptValidationError(
                    "argument mismatch: receipt not issued for these arguments"
                )

        # 11. Policy hash mismatch
        if expected_policy_hash is not None and self.policy_hash != expected_policy_hash:
            raise ReceiptValidationError(
                f"Policy hash mismatch: expected {expected_policy_hash}, got {self.policy_hash}"
            )

        # 12. Policy bundle ID mismatch
        if (
            expected_policy_bundle_id is not None
            and self.policy_bundle_id != expected_policy_bundle_id
        ):
            raise ReceiptValidationError(
                f"Policy bundle ID mismatch: expected {expected_policy_bundle_id}, "
                f"got {self.policy_bundle_id}"
            )

        # 12b. Validator role mismatch (optional)
        if expected_validator_role is not None and self.validator_role != expected_validator_role:
            raise ReceiptValidationError(
                f"Validator role mismatch: expected {expected_validator_role}, "
                f"got {self.validator_role}"
            )

        # 12c. Authority mismatch (optional)
        if expected_authority is not None and self.authority != expected_authority:
            raise ReceiptValidationError(
                f"Authority mismatch: expected {expected_authority}, got {self.authority}"
            )

        # 13. Expiry (only enforced when expires_at is set). expires_at is bound
        # into receipt_hash, so a tampered expiry is already caught by check 2;
        # this rejects a genuinely-issued receipt used past its lifetime. The
        # clock is injectable so expiry is deterministically testable; in
        # production it defaults to the real UTC wall clock. Fail-closed.
        if self.expires_at:
            current = now_iso if now_iso is not None else _now_iso()
            # Compare timezone-aware datetimes, not strings: a lexicographic
            # compare is wrong across UTC offsets and would fail OPEN (accept an
            # expired receipt). Unparseable / mixed-awareness timestamps are
            # treated as a validation failure, never silently accepted.
            try:
                current_dt = datetime.fromisoformat(current)
                expires_dt = datetime.fromisoformat(self.expires_at)
                is_expired = current_dt > expires_dt
            except (ValueError, TypeError) as err:
                raise ReceiptValidationError(
                    f"Unparseable or mismatched expiry timestamp: "
                    f"expires_at={self.expires_at!r}, now={current!r}"
                ) from err
            if is_expired:
                raise ReceiptValidationError(
                    f"Receipt expired at {self.expires_at} (now {current})"
                )
