"""Offline, standalone proof-pack verifier (backlog B4 / fixture-spec §8).

The product claim is: *a relying party outside the enforcement runtime can
independently verify a Decision Receipt before accepting the action.* This module
is that independent verifier. It consumes a **proof pack** — a self-contained
directory of receipts + an audit chain + a manifest (optionally a consumption
ledger and replay material) — and returns a structured, machine-readable verdict
**without trusting, importing, or running the enforcement kernel**.

Independence (fixture-spec §5.4). The module's top-level imports are restricted to
the receipt/verify surface — :mod:`acgs_proofpack_verifier.receipt`,
:mod:`acgs_proofpack_verifier.errors`, :mod:`acgs_proofpack_verifier.audit`,
:mod:`acgs_proofpack_verifier.consumption`, :mod:`acgs_proofpack_verifier.decision`.
It does **not** import :mod:`acgs_proofpack_verifier.kernel`,
:mod:`acgs_proofpack_verifier.executor`, or
:mod:`acgs_proofpack_verifier.policy` at module scope. The optional *decision-replay* tier
(``replay_bundle``) re-derives recorded decisions and therefore needs the policy
engine; that import is **lazy**, performed only when a pack actually ships replay
material. So verifying a pack's integrity never pulls the engine; re-deriving its
decisions does, and only then. A static guard test pins this boundary.

Fail-closed (fixture-spec §7). :func:`verify_proof_pack` never raises: every failure
path — missing manifest, unreadable chain, corrupt ledger, unsupported schema, an
unexpected exception — resolves to ``valid=False`` with a stable
:class:`ProofPackRejectionReason` (or a receipt-level
:class:`~acgs_proofpack_verifier.errors.ReceiptRejectionReason`). A verifier that fails *open* is
worse than none, so uncertainty is always rejection.

Leak-safety (fixture-spec §7). The distributable pack carries receipts, the audit
chain, and a manifest — never the raw ``expected_*`` gate context. The binding
fields (``actor``, ``argument_hash``, ``authority``, ``policy_hash`` …) are bound
into ``receipt_hash`` (see :meth:`~acgs_proofpack_verifier.receipt.DecisionReceipt.compute_hash`),
so a passing ``receipt_hash == compute_hash()`` *is* the proof those fields are
intact. ``argument_hash_verified`` / ``authority_verified`` therefore mean
"the field is bound and intact", computed with no raw arguments present. The
result object carries only reason codes and booleans, never raw args or state.

What ``valid=True`` does **not** mean: see ``docs/PROOF_PATH.md`` — in particular the
trust-anchor circularity (a key shipped beside the signer is not "independent
trust") and that decision-replay is only performed when the pack ships replay
material.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from acgs_proofpack_verifier.consumption import ReceiptConsumptionLedger
from acgs_proofpack_verifier.errors import (
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from acgs_proofpack_verifier.receipt import DecisionReceipt

if TYPE_CHECKING:
    # Type-only import: keeps the §5.4 independence guard (no engine import at module
    # scope) green. ``revocation`` is stdlib-only and fail-closed; it is only ever
    # *passed in* by the relying party, never constructed here.
    from acgs_proofpack_verifier.revocation import RevocationList

SCHEMA_VERSION = "gove-zone/proof-pack/v1"

# Receipt-level reason codes that indicate the cryptographic signature itself
# failed (as opposed to a semantic/binding rejection). Used to decide the
# per-receipt ``signature_verified`` tri-state.
_SIGNATURE_REASONS = frozenset(
    {
        ReceiptRejectionReason.SIGNATURE_INVALID,
        ReceiptRejectionReason.SIGNATURE_ALG_MISMATCH,
        ReceiptRejectionReason.SIGNING_KEY_UNKNOWN,
        ReceiptRejectionReason.SIGNING_KEY_REVOKED,
        ReceiptRejectionReason.SIGNED_RECEIPT_NO_VERIFIER,
        ReceiptRejectionReason.UNSIGNED_REJECTED,
    }
)

# Receipt-level reasons proving the receipt_hash binding is broken/absent — when
# these fire, no field-binding claim can be made (downstream checks never ran).
_BINDING_BROKEN_REASONS = frozenset(
    {
        ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
        ReceiptRejectionReason.RECEIPT_HASH_MISSING,
        ReceiptRejectionReason.MISSING_REQUIRED_FIELD,
    }
)


class ProofPackRejectionReason(StrEnum):
    """Stable, machine-readable pack-level failure codes.

    Receipt-level failures surface the receipt's own
    :class:`~acgs_proofpack_verifier.errors.ReceiptRejectionReason` verbatim; these codes cover
    the proof-pack envelope (manifest, schema, chain, anchoring, replay, ledger).
    StrEnum values equal the member names so they serialise as plain strings.
    """

    PROOFPACK_NOT_FOUND = "PROOFPACK_NOT_FOUND"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    MANIFEST_MALFORMED = "MANIFEST_MALFORMED"
    SCHEMA_VERSION_MISSING = "SCHEMA_VERSION_MISSING"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    AUDIT_CHAIN_MISSING = "AUDIT_CHAIN_MISSING"
    AUDIT_CHAIN_UNREADABLE = "AUDIT_CHAIN_UNREADABLE"
    AUDIT_CHAIN_BROKEN = "AUDIT_CHAIN_BROKEN"
    RECEIPT_FILE_MISSING = "RECEIPT_FILE_MISSING"
    RECEIPT_MALFORMED = "RECEIPT_MALFORMED"
    RECEIPT_NOT_ANCHORED = "RECEIPT_NOT_ANCHORED"
    RECEIPT_UNEXPECTED_ACCEPT = "RECEIPT_UNEXPECTED_ACCEPT"
    RECEIPT_UNEXPECTED_REJECT = "RECEIPT_UNEXPECTED_REJECT"
    RECEIPT_WRONG_REASON = "RECEIPT_WRONG_REASON"
    REPLAY_MATERIAL_MALFORMED = "REPLAY_MATERIAL_MALFORMED"
    REPLAY_MISMATCH = "REPLAY_MISMATCH"
    CONSUMPTION_LEDGER_UNPROVABLE = "CONSUMPTION_LEDGER_UNPROVABLE"
    RECEIPT_ALREADY_USED = "RECEIPT_ALREADY_USED"
    VERIFIER_ERROR = "VERIFIER_ERROR"


@dataclass(frozen=True)
class ReceiptVerification:
    """Per-receipt verdict within a proof pack."""

    name: str
    receipt_hash: str
    decision: str
    declared_verdict: str  # "accept" | "reject"
    observed_verdict: str  # "accept" | "reject"
    matches_declared: bool
    signature_verified: bool | None
    argument_hash_verified: bool | None
    authority_verified: bool | None
    anchored_in_audit_chain: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "receipt_hash": self.receipt_hash,
            "decision": self.decision,
            "declared_verdict": self.declared_verdict,
            "observed_verdict": self.observed_verdict,
            "matches_declared": self.matches_declared,
            "signature_verified": self.signature_verified,
            "argument_hash_verified": self.argument_hash_verified,
            "authority_verified": self.authority_verified,
            "anchored_in_audit_chain": self.anchored_in_audit_chain,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ProofPackVerificationResult:
    """Structured offline verification verdict for one proof pack.

    ``valid`` is the single fail-closed gate a relying party keys on; the
    sub-fields explain *why*. The goal's per-receipt ``receipt_hash`` lives in
    each :class:`ReceiptVerification` under ``receipts``. ``reasons`` is the
    deterministic, machine-readable failure list (empty iff ``valid``).
    """

    valid: bool
    schema_version: str | None
    events_total: int
    events_matched: int
    signature_verified: bool | None
    audit_chain_verified: bool
    argument_hash_verified: bool | None
    authority_verified: bool | None
    replay_verified: bool | None
    anti_replay_status: str | None  # "not_present" | "fresh" | "replayed" | "unprovable"
    receipts: list[ReceiptVerification] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_version": self.schema_version,
            "events_total": self.events_total,
            "events_matched": self.events_matched,
            "signature_verified": self.signature_verified,
            "audit_chain_verified": self.audit_chain_verified,
            "argument_hash_verified": self.argument_hash_verified,
            "authority_verified": self.authority_verified,
            "replay_verified": self.replay_verified,
            "anti_replay_status": self.anti_replay_status,
            "receipts": [r.to_dict() for r in self.receipts],
            "reasons": list(self.reasons),
        }


def _fail(reason: str, schema_version: str | None = None) -> ProofPackVerificationResult:
    """Construct a terminal fail-closed result carrying a single ``reason``."""
    return ProofPackVerificationResult(
        valid=False,
        schema_version=schema_version,
        events_total=0,
        events_matched=0,
        signature_verified=None,
        audit_chain_verified=False,
        argument_hash_verified=None,
        authority_verified=None,
        replay_verified=None,
        anti_replay_status=None,
        receipts=[],
        reasons=[reason],
    )


def _verify_one_receipt(
    name: str,
    receipt: DecisionReceipt,
    entry: dict[str, Any],
    chain_event_hashes: set[str],
    *,
    verifier: Any,
    require_signature: bool,
    now_iso: str | None,
    revoked_keys: RevocationList | None,
) -> ReceiptVerification:
    """Verify a single receipt against its declared verdict (no raw args needed)."""
    reasons: list[str] = []

    # Binding integrity is computable directly from the receipt alone (the bound
    # fields are exactly what compute_hash() covers) — independent of verify()'s
    # control flow, so the field-binding flags are honest even when verify() takes
    # an early exit.
    binding_intact = bool(receipt.receipt_hash) and receipt.compute_hash() == receipt.receipt_hash
    signed = receipt.signature_algorithm != "none"

    declared_verdict = str(entry.get("declared_verdict", "accept"))
    declared_reason = entry.get("reason_code")

    # Signature-requirement policy. Deriving the requirement from the receipt's own
    # ``signature_algorithm`` alone is a fail-open: a forger mints an UNSIGNED accept
    # receipt (algorithm="none"), recomputes receipt_hash, anchors it, and the
    # signature check never runs — even when the relying party supplied a trust
    # anchor. So when ``require_signature`` is in force (the caller supplied a
    # verifier, or asked explicitly), a declared-ACCEPT receipt MUST carry a
    # signature: an unsigned/downgraded accept is rejected (UNSIGNED_REJECTED),
    # making the trust anchor load-bearing on every path. Declared-reject receipts
    # keep the self-declared posture (they are expected to fail anyway).
    require_sig_for_this = signed or (require_signature and declared_verdict == "accept")

    observed_verdict = "accept"
    observed_reason: ReceiptRejectionReason | None = None
    try:
        # NO expected_* context: the pack is leak-safe and carries none. This
        # verifies receipt integrity (fields, hash, signature, self-validation,
        # decision class, transform shape, expiry) — the offline-provable surface.
        receipt.verify(
            verifier=verifier,
            require_signature=require_sig_for_this,
            now_iso=now_iso,
            revoked_keys=revoked_keys,
        )
    except ReceiptValidationError as exc:
        observed_verdict = "reject"
        observed_reason = exc.reason_code

    matches_declared = True
    if declared_verdict == "accept":
        if observed_verdict != "accept":
            matches_declared = False
            reasons.append(ProofPackRejectionReason.RECEIPT_UNEXPECTED_REJECT)
            if observed_reason is not None:
                reasons.append(str(observed_reason))
    else:  # declared reject
        if observed_verdict == "accept":
            matches_declared = False
            reasons.append(ProofPackRejectionReason.RECEIPT_UNEXPECTED_ACCEPT)
        elif declared_reason is not None and str(observed_reason) != str(declared_reason):
            matches_declared = False
            reasons.append(ProofPackRejectionReason.RECEIPT_WRONG_REASON)
            if observed_reason is not None:
                reasons.append(str(observed_reason))

    # Field-binding tri-states.
    if observed_reason in _BINDING_BROKEN_REASONS:
        argument_hash_verified: bool | None = False
        authority_verified: bool | None = False
    else:
        argument_hash_verified = binding_intact
        authority_verified = binding_intact and bool(receipt.authority)

    # Signature tri-state: None when unsigned or when the hash check short-circuited
    # before the signature check (2a) could run; True/False otherwise.
    if not signed:
        signature_verified: bool | None = None
    elif not binding_intact:
        signature_verified = None
    elif observed_reason in _SIGNATURE_REASONS:
        signature_verified = False
    else:
        signature_verified = True

    anchored = bool(receipt.audit_event_hash) and receipt.audit_event_hash in chain_event_hashes
    if declared_verdict == "accept" and not anchored:
        reasons.append(ProofPackRejectionReason.RECEIPT_NOT_ANCHORED)

    return ReceiptVerification(
        name=name,
        receipt_hash=receipt.receipt_hash,
        decision=receipt.decision,
        declared_verdict=declared_verdict,
        observed_verdict=observed_verdict,
        matches_declared=matches_declared,
        signature_verified=signature_verified,
        argument_hash_verified=argument_hash_verified,
        authority_verified=authority_verified,
        anchored_in_audit_chain=anchored,
        reasons=reasons,
    )


def verify_proof_pack(
    pack_dir: str | Path,
    *,
    verifier: Any = None,
    require_signature: bool | None = None,
    now_iso: str | None = None,
    revoked_keys: RevocationList | None = None,
) -> ProofPackVerificationResult:
    """Verify a proof pack offline and return a structured, fail-closed verdict.

    Args:
        pack_dir: directory containing ``manifest.json`` and the artifacts it lists.
        verifier: an :class:`~acgs_proofpack_verifier.signing.ReceiptSigner` (public-key) or a
            ``{key_id: signer}`` mapping used to check signed receipts. ``None``
            verifies unsigned (dev) packs only; a signed receipt with no verifier
            is rejected (fail-closed, see ``DecisionReceipt.verify``).
        require_signature: whether declared-accept receipts MUST be signed. ``None``
            (default) means "required iff a ``verifier`` was supplied" — supplying a
            trust anchor is taken as a demand that signatures be checked, so an
            unsigned/downgraded accept receipt cannot slip past a relying party who
            passed a key. Pass ``True`` to mandate signing regardless, ``False`` to
            verify a dev/unsigned pack even with a verifier present.
        now_iso: injected clock for deterministic expiry checks; defaults to wall
            clock inside ``verify()``.
        revoked_keys: an optional :class:`~acgs_proofpack_verifier.revocation.RevocationList` of
            revoked signing ``key_id``s, supplied out-of-band by the relying party
            (additive, default ``None`` = no revocation applied). A signed receipt
            whose ``signing_key_id`` is on the list is rejected
            (:data:`ReceiptRejectionReason.SIGNING_KEY_REVOKED`), so a key
            compromised *after* the pack was minted cannot be verified as valid
            offline. Fail-closed and off-by-default: omitting it preserves the
            current verdict exactly.

    Returns:
        A :class:`ProofPackVerificationResult`. Never raises — any error is folded
        into ``valid=False`` with a stable reason.
    """
    effective_require = require_signature if require_signature is not None else verifier is not None
    try:
        return _verify_proof_pack_inner(
            pack_dir,
            verifier=verifier,
            require_signature=effective_require,
            now_iso=now_iso,
            revoked_keys=revoked_keys,
        )
    except Exception:  # noqa: BLE001 — fail-closed: never let an exception escape into "accept".
        return _fail(ProofPackRejectionReason.VERIFIER_ERROR)


def _verify_proof_pack_inner(
    pack_dir: str | Path,
    *,
    verifier: Any,
    require_signature: bool,
    now_iso: str | None,
    revoked_keys: RevocationList | None,
) -> ProofPackVerificationResult:
    from acgs_proofpack_verifier.audit import ChainHashAuditStore

    root = Path(pack_dir)
    if not root.is_dir():
        return _fail(ProofPackRejectionReason.PROOFPACK_NOT_FOUND)

    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return _fail(ProofPackRejectionReason.MANIFEST_MISSING)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not an object")
    except (ValueError, OSError):
        return _fail(ProofPackRejectionReason.MANIFEST_MALFORMED)

    schema_version = manifest.get("schema_version")
    if not schema_version:
        return _fail(ProofPackRejectionReason.SCHEMA_VERSION_MISSING)
    if schema_version != SCHEMA_VERSION:
        return _fail(ProofPackRejectionReason.SCHEMA_VERSION_UNSUPPORTED, schema_version)

    reasons: list[str] = []

    # --- Audit chain -------------------------------------------------------
    audit_rel = manifest.get("audit_chain", "audit.jsonl")
    audit_path = root / audit_rel
    chain_event_hashes: set[str] = set()
    audit_chain_verified = False
    chain_checked = 0
    chain_failures = 0
    if not audit_path.is_file():
        reasons.append(ProofPackRejectionReason.AUDIT_CHAIN_MISSING)
    else:
        store = ChainHashAuditStore(audit_path)
        try:
            chain = store.verify_chain()
            for event in store.iter_events():
                h = event.get("event_hash")
                if isinstance(h, str) and h:
                    chain_event_hashes.add(h)
        except Exception:  # noqa: BLE001 — unreadable/corrupt chain is fail-closed.
            reasons.append(ProofPackRejectionReason.AUDIT_CHAIN_UNREADABLE)
            chain = {"valid": False, "checked": 0, "failures": []}
        audit_chain_verified = bool(chain.get("valid"))
        chain_checked = int(chain.get("checked", len(chain_event_hashes)))
        chain_failures = len(chain.get("failures", []))
        if not audit_chain_verified:
            reasons.append(ProofPackRejectionReason.AUDIT_CHAIN_BROKEN)

    # --- Receipts ----------------------------------------------------------
    receipts: list[ReceiptVerification] = []
    receipt_entries = manifest.get("receipts", [])
    for entry in receipt_entries:
        name = str(entry.get("name") or entry.get("file", "receipt"))
        rel = entry.get("file")
        if not rel:
            reasons.append(ProofPackRejectionReason.RECEIPT_FILE_MISSING)
            continue
        rpath = root / rel
        if not rpath.is_file():
            reasons.append(ProofPackRejectionReason.RECEIPT_FILE_MISSING)
            continue
        try:
            receipt = DecisionReceipt.from_json(rpath.read_text(encoding="utf-8"))
        except (ValueError, KeyError, OSError):
            reasons.append(ProofPackRejectionReason.RECEIPT_MALFORMED)
            continue
        rv = _verify_one_receipt(
            name,
            receipt,
            entry,
            chain_event_hashes,
            verifier=verifier,
            require_signature=require_signature,
            now_iso=now_iso,
            revoked_keys=revoked_keys,
        )
        receipts.append(rv)
        reasons.extend(r for r in rv.reasons if r not in reasons)

    accept_receipts = [r for r in receipts if r.declared_verdict == "accept"]

    # --- Anti-replay (consumption ledger) ----------------------------------
    anti_replay_status: str | None = "not_present"
    ledger_rel = manifest.get("consumption_ledger")
    if ledger_rel:
        ledger_path = root / ledger_rel
        if not ledger_path.is_file():
            anti_replay_status = "unprovable"
            reasons.append(ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE)
        else:
            ledger = ReceiptConsumptionLedger(ledger_path)
            try:
                report = ledger.verify_ledger()
                if not report.get("valid", False):
                    anti_replay_status = "unprovable"
                    reasons.append(ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE)
                else:
                    replayed = False
                    for r in accept_receipts:
                        receipt_path = root / next(
                            e["file"]
                            for e in receipt_entries
                            if str(e.get("name") or e.get("file")) == r.name
                        )
                        anchor = DecisionReceipt.from_json(
                            receipt_path.read_text(encoding="utf-8")
                        ).audit_event_hash
                        if ledger.is_consumed(anchor):
                            replayed = True
                            break
                    anti_replay_status = "replayed" if replayed else "fresh"
                    if replayed:
                        reasons.append(ProofPackRejectionReason.RECEIPT_ALREADY_USED)
            except Exception:  # noqa: BLE001 — corrupt/torn ledger is fail-closed.
                anti_replay_status = "unprovable"
                if ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE not in reasons:
                    reasons.append(ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE)

    # --- Decision replay (optional tier; lazy engine import) ----------------
    replay_verified: bool | None = None
    events_total = chain_checked
    events_matched = max(chain_checked - chain_failures, 0) if audit_chain_verified else 0
    replay_spec = manifest.get("replay")
    if replay_spec:
        # The decision-replay tier re-runs the policy engine and depends on the
        # full gove-zone runtime (policy/replay/replay_store), which this
        # dependency-minimal verifier intentionally does not vendor. Offline
        # integrity/receipt/audit verification never sets a replay spec; when one
        # is present it fails CLOSED here (REPLAY_MATERIAL_MALFORMED) rather than
        # silently skipping replay — a pack that declares replay it cannot prove
        # must not verify as valid.
        reasons.append(ProofPackRejectionReason.REPLAY_MATERIAL_MALFORMED)
        replay_verified = False

    # --- Aggregate ---------------------------------------------------------
    def _and(flags: list[bool | None]) -> bool | None:
        present = [f for f in flags if f is not None]
        if not present:
            return None
        return all(present)

    agg_signature = _and([r.signature_verified for r in accept_receipts])
    agg_argument = _and([r.argument_hash_verified for r in accept_receipts])
    agg_authority = _and([r.authority_verified for r in accept_receipts])

    valid = (
        audit_chain_verified
        and all(r.matches_declared for r in receipts)
        and all(r.anchored_in_audit_chain for r in accept_receipts)
        and replay_verified is not False
        and anti_replay_status not in ("replayed", "unprovable")
        and not any(
            r
            in (
                ProofPackRejectionReason.RECEIPT_FILE_MISSING,
                ProofPackRejectionReason.RECEIPT_MALFORMED,
                ProofPackRejectionReason.AUDIT_CHAIN_MISSING,
            )
            for r in reasons
        )
        and bool(accept_receipts or receipts)
    )

    return ProofPackVerificationResult(
        valid=valid,
        schema_version=schema_version,
        events_total=events_total,
        events_matched=events_matched,
        signature_verified=agg_signature,
        audit_chain_verified=audit_chain_verified,
        argument_hash_verified=agg_argument,
        authority_verified=agg_authority,
        replay_verified=replay_verified,
        anti_replay_status=anti_replay_status,
        receipts=receipts,
        reasons=reasons,
    )
