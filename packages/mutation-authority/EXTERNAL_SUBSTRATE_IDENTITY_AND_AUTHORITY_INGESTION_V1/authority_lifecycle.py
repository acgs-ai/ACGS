"""Authority-evidence lifecycle for REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1.

Extends the trusted V1 baseline (it does NOT modify `authority_router`); it adds
the explicit lifecycle a real-evidence onboarding flow needs:

    DISCOVERED -> VALIDATED -> INGESTED -> ACTIVE -> SUPERSEDED / REVOKED

The one fact this layer localizes and refuses to automate is the legal judgment
"this artifact *is* valid authority." That judgment lives in a **validation
attestation** — an authorized human/legal validator's signed statement — and a
record without a well-formed attestation can never rise above DISCOVERED, so it
never routes. The software binds, checks scope/class/period, and derives state
deterministically; it does not decide that a document constitutes authority.

Lifecycle state is DERIVED from stored facts (attestation, effective period,
supersession, revocation, registry membership), never stored as an authoritative
mutable field — so it cannot be forged by writing a value (the count-manipulation
attack class).
"""

from __future__ import annotations

from typing import Any

from _canonical import hash_obj
from authority_router import (
    COUNSEL_OR_RIGHTS_AUTHORITY,
    DATA_CONTROLLER,
    EvidenceError,
    in_effect,
    validate_evidence,
)

# Lifecycle states.
DISCOVERED = "DISCOVERED"
VALIDATED = "VALIDATED"
INGESTED = "INGESTED"
ACTIVE = "ACTIVE"
SUPERSEDED = "SUPERSEDED"
REVOKED = "REVOKED"
LIFECYCLE_STATES = (DISCOVERED, VALIDATED, INGESTED, ACTIVE, SUPERSEDED, REVOKED)

# Fields a validation attestation must carry to be a real human/legal gate.
# `record_binding` cryptographically ties the attestation to the record content
# it validated — a record whose identity/scope/source changes after validation
# no longer matches its attestation (identity-drift attack).
_ATTESTATION_FIELDS = (
    "validator_identity",
    "validation_method",
    "validated_at",
    "record_binding",
)

# Per-class required fields beyond the V1 base schema. A real appointment/
# engagement artifact carries these; a placeholder does not.
_CLASS_REQUIREMENTS = {
    DATA_CONTROLLER: ("issuer_or_appointing_party",),
    COUNSEL_OR_RIGHTS_AUTHORITY: (
        "jurisdiction",
        "appointment_authority",
        "verification_metadata",
    ),
}


class OnboardingError(ValueError):
    """A record fails the onboarding contract — reject, do not onboard."""


# Authority qualification is NOT commercial-rights ownership, licensing
# permission, or contractual entitlement. An evidence record that tries to
# carry any such claim is a fabricated commercial-rights inference and is
# rejected outright — the boundary is structural, not conventional.
_COMMERCIAL_CLAIM_FIELDS = (
    "rights_assertion",
    "commercial_rights",
    "ownership",
    "license",
    "licensing_permission",
    "contractual_entitlement",
    "rights_granted",
)


def attestation_binding(record: dict[str, Any]) -> str:
    """The digest a validation attestation must carry in `record_binding`.

    Computed over the identity-bearing content the validator actually reviewed:
    who the evidence names, what it covers, and the exact source document. Any
    post-validation change to these fields breaks the binding, so the record
    drops back to DISCOVERED (fail closed) instead of routing on a stale
    attestation."""
    return hash_obj(
        {
            "authority_evidence_id": record.get("authority_evidence_id"),
            "authority_type": record.get("authority_type"),
            "subject_identity": record.get("subject_identity"),
            "authority_scope": record.get("authority_scope"),
            "source_digest": record.get("source_digest"),
            "effective_from": record.get("effective_from"),
            "effective_until": record.get("effective_until"),
        }
    )


def has_valid_attestation(record: dict[str, Any]) -> bool:
    """True iff the record carries a well-formed validation attestation whose
    `record_binding` still matches the record content. This is the human/legal
    gate; the software never synthesizes it, and a drifted record fails it."""
    att = record.get("validation")
    if not isinstance(att, dict):
        return False
    for f in _ATTESTATION_FIELDS:
        v = att.get(f)
        if not isinstance(v, str) or not v.strip():
            return False
    return att["record_binding"] == attestation_binding(record)


def validate_onboarding_record(record: dict[str, Any]) -> None:
    """Full onboarding validation: the V1 base schema, plus the per-class real-
    artifact fields, plus (if present) a well-formed attestation. Raises
    OnboardingError on any failure. Does NOT assert the underlying legal fact."""
    try:
        validate_evidence(record)
    except EvidenceError as exc:
        raise OnboardingError(str(exc)) from exc

    claimed = [f for f in _COMMERCIAL_CLAIM_FIELDS if record.get(f) is not None]
    if claimed:
        raise OnboardingError(
            f"authority evidence may not carry commercial-claim fields: {claimed} — "
            "authority qualification is not rights ownership, licensing, or entitlement"
        )

    atype = record["authority_type"]
    missing = [f for f in _CLASS_REQUIREMENTS.get(atype, ()) if not record.get(f)]
    if missing:
        raise OnboardingError(f"{atype} evidence missing real-artifact fields: {missing}")
    if atype == COUNSEL_OR_RIGHTS_AUTHORITY and not isinstance(
        record.get("verification_metadata"), dict
    ):
        raise OnboardingError("counsel verification_metadata must be an object")

    # An attestation, if present, must be well formed. Absence is allowed here
    # (the record is simply DISCOVERED); a malformed one is a hard error.
    if "validation" in record and not has_valid_attestation(record):
        raise OnboardingError(
            "validation attestation present but malformed "
            f"(needs {list(_ATTESTATION_FIELDS)} as non-empty strings)"
        )


def derive_lifecycle_state(
    record: dict[str, Any],
    *,
    instant: str | None,
    superseded_ids: set[str],
    in_registry: bool,
) -> str:
    """Deterministically derive the lifecycle state from stored facts. Never
    reads a stored `lifecycle_state` field — state is a function, not a value.

    Order matters: revocation and supersession dominate; then the attestation
    gate; then registry membership; then temporal effect.
    """
    if record.get("revoked_at"):
        return REVOKED
    if record.get("authority_evidence_id") in superseded_ids:
        return SUPERSEDED
    if not has_valid_attestation(record):
        return DISCOVERED
    if not in_registry or not record.get("ingestion_receipt"):
        return VALIDATED
    if not in_effect(record, instant):
        return INGESTED  # on file, but outside its effective period (or future)
    return ACTIVE


def superseded_ids_of(records: list[dict[str, Any]]) -> set[str]:
    return {r.get("supersedes") for r in records if r.get("supersedes")}


def active_records(records: list[dict[str, Any]], instant: str | None) -> list[dict[str, Any]]:
    """The subset eligible to drive routing: lifecycle-ACTIVE only. A record
    that is DISCOVERED (no attestation), VALIDATED, INGESTED-but-inactive,
    SUPERSEDED, or REVOKED is excluded — fail closed."""
    sids = superseded_ids_of(records)
    out = []
    for r in records:
        try:
            validate_onboarding_record(r)
        except OnboardingError:
            continue  # malformed never routes
        state = derive_lifecycle_state(r, instant=instant, superseded_ids=sids, in_registry=True)
        if state == ACTIVE:
            out.append(r)
    return out


def lifecycle_distribution(records: list[dict[str, Any]], instant: str | None) -> dict[str, int]:
    """Count records by derived lifecycle state (registry members)."""
    sids = superseded_ids_of(records)
    dist = dict.fromkeys(LIFECYCLE_STATES, 0)
    for r in records:
        try:
            validate_onboarding_record(r)
        except OnboardingError:
            # Malformed records are not counted as any lifecycle state; they are
            # rejected upstream. Count them separately by the caller if needed.
            continue
        state = derive_lifecycle_state(r, instant=instant, superseded_ids=sids, in_registry=True)
        dist[state] += 1
    return dist
