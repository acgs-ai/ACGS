"""EXTERNAL_VALIDATOR_ONBOARDING_V1 — evidence-backed validator onboarding.

Converts a future real validator, appointed by a real external human
authority, into a verifiable trust object. Replaces the assumption of local
trust at registration with explicit onboarding evidence:

  * an appointment record (VALIDATOR_APPOINTMENT_SCHEMA.json) transcribed from
    real appointment artifacts, bound to their bytes by sha256 digests;
  * a key binding with an ownership proof — a signature over the appointment
    binding made with the bound key, proving the appointee controls it;
  * a REGISTER event that carries the appointment binding and evidence
    digests, so registration provenance is verifiable forever after.

Key-ceremony lifecycle — DERIVED from stored facts on every read, never
stored, never manually writable (the same defense as evidence lifecycle):

    DISCOVERED           appointment malformed / evidence digests absent
    APPOINTMENT_PENDING  evidence-backed appointment, key not provably owned
    KEY_BOUND            key ownership proven, not (verifiably) registered
    ACTIVE               registered against this appointment, in period
    ROTATED              registered, in period, signing under a successor key
    REVOKED              revoked or past the appointment's effective period

Software never creates appointment facts: this module validates and derives;
`onboard_validator.py` refuses to register anything it cannot verify. Any
inconsistent state fails closed to the lowest applicable state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import _ed25519
from _canonical import canonical_json, hash_obj, hmac_verify, sha256_hex
from validator_trust import (
    ED25519,
    KEY_ALGORITHMS,
    _load_key,
    _parse_z,
    chain_intact,
)

# Ceremony states (derived only).
DISCOVERED = "DISCOVERED"
APPOINTMENT_PENDING = "APPOINTMENT_PENDING"
KEY_BOUND = "KEY_BOUND"
ACTIVE = "ACTIVE"
ROTATED = "ROTATED"
REVOKED = "REVOKED"
CEREMONY_STATES = (DISCOVERED, APPOINTMENT_PENDING, KEY_BOUND, ACTIVE, ROTATED, REVOKED)

VALIDATOR_CLASSES = ("DATA_CONTROLLER", "COUNSEL_OR_RIGHTS_AUTHORITY")

_APPOINTMENT_REQUIRED = (
    "validator_appointment_id",
    "validator_id",
    "subject_identity",
    "organization",
    "jurisdiction",
    "appointment_authority",
    "effective_from",
    "revocation_conditions",
)


class AppointmentError(ValueError):
    """The appointment fails the onboarding contract — refuse, do not register."""


def appointment_binding(appointment: dict[str, Any]) -> str:
    """Digest over the identity-bearing appointment content: who is appointed,
    by whom, for what, for when, evidenced by which artifact bytes, bound to
    which key. Any change to these facts is a different appointment."""
    evidence = appointment.get("appointment_evidence") or []
    kb = appointment.get("key_binding") or {}
    return hash_obj(
        {
            "validator_appointment_id": appointment.get("validator_appointment_id"),
            "validator_id": appointment.get("validator_id"),
            "subject_identity": appointment.get("subject_identity"),
            "organization": appointment.get("organization"),
            "authorized_classes": sorted(appointment.get("authorized_classes") or []),
            "jurisdiction": appointment.get("jurisdiction"),
            "appointment_authority": appointment.get("appointment_authority"),
            "effective_from": appointment.get("effective_from"),
            "effective_until": appointment.get("effective_until"),
            "revocation_conditions": appointment.get("revocation_conditions"),
            "evidence_digests": sorted(
                e.get("source_digest") for e in evidence if isinstance(e, dict)
            ),
            "key_id": kb.get("key_id"),
            "key_algorithm": kb.get("key_algorithm"),
            "key_fingerprint": kb.get("key_fingerprint"),
        }
    )


def _is_hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def validate_appointment(appointment: dict[str, Any]) -> None:
    """Structural onboarding gates. Raises AppointmentError with the failed
    gate. Does NOT assert the underlying appointment is legally real — that
    fact lives in the evidenced artifacts and their human origin."""
    if not isinstance(appointment, dict):
        raise AppointmentError("appointment must be an object")
    missing = [
        f
        for f in _APPOINTMENT_REQUIRED
        if not isinstance(appointment.get(f), str) or not appointment.get(f).strip()
    ]
    if missing:
        raise AppointmentError(f"partial appointment metadata: missing {missing}")

    classes = appointment.get("authorized_classes")
    if not isinstance(classes, list) or not classes:
        raise AppointmentError("authorized_classes must be a non-empty list")
    unknown = [c for c in classes if c not in VALIDATOR_CLASSES]
    if unknown:
        raise AppointmentError(f"unknown validation classes: {unknown}")

    authority = appointment["appointment_authority"].strip()
    if authority in (
        appointment["subject_identity"].strip(),
        appointment["validator_id"].strip(),
        appointment["organization"].strip(),
    ):
        raise AppointmentError(
            "self-appointed validator: appointment_authority must be a distinct "
            "external authority, not the appointee or their organization"
        )

    if _parse_z(appointment["effective_from"]) is None:
        raise AppointmentError("effective_from must be an ISO-8601 Z instant")
    until = appointment.get("effective_until")
    if until is not None:
        u = _parse_z(until)
        if u is None:
            raise AppointmentError("effective_until must be an ISO-8601 Z instant or null")
        if u <= _parse_z(appointment["effective_from"]):
            raise AppointmentError("effective_until must be after effective_from")

    evidence = appointment.get("appointment_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AppointmentError("appointment_evidence must list at least one real artifact")
    for i, e in enumerate(evidence):
        if not isinstance(e, dict):
            raise AppointmentError(f"appointment_evidence[{i}] must be an object")
        for f in ("source_type", "source_reference"):
            if not isinstance(e.get(f), str) or not e[f].strip():
                raise AppointmentError(f"appointment_evidence[{i}].{f} missing")
        if not _is_hex64(e.get("source_digest")):
            raise AppointmentError(f"appointment_evidence[{i}].source_digest must be sha256 hex")

    kb = appointment.get("key_binding")
    if not isinstance(kb, dict):
        raise AppointmentError("key_binding missing")
    if kb.get("key_algorithm") not in KEY_ALGORITHMS:
        raise AppointmentError(f"key_binding.key_algorithm must be one of {KEY_ALGORITHMS}")
    if not isinstance(kb.get("key_id"), str) or not kb["key_id"].strip():
        raise AppointmentError("key_binding.key_id missing")
    if not _is_hex64(kb.get("key_fingerprint")):
        raise AppointmentError("key_binding.key_fingerprint must be sha256 hex")
    if not isinstance(kb.get("key_ownership_proof"), str) or not kb["key_ownership_proof"]:
        raise AppointmentError("key_binding.key_ownership_proof missing")
    if kb["key_algorithm"] == ED25519 and not _is_hex64(kb.get("public_key")):
        raise AppointmentError("ed25519 key_binding requires public_key (raw hex)")


def key_ownership_payload(appointment: dict[str, Any]) -> str:
    """What the bound key must have signed to prove ownership. Binds the key to
    THIS appointment's content — a proof cannot be replayed onto a different
    appointment (the binding changes)."""
    return canonical_json(
        {
            "appointment_binding": appointment_binding(appointment),
            "key_id": (appointment.get("key_binding") or {}).get("key_id"),
            "purpose": "acgs_validator_key_ownership/v1",
        }
    )


def verify_key_ownership(appointment: dict[str, Any], *, keystore_dir: Path) -> tuple[bool, str]:
    """Verify the key_ownership_proof against the bound key. Fail closed."""
    kb = appointment.get("key_binding") or {}
    proof = kb.get("key_ownership_proof", "")
    payload = key_ownership_payload(appointment)
    if kb.get("key_algorithm") == ED25519:
        try:
            pub = bytes.fromhex(kb.get("public_key") or "")
        except ValueError:
            return False, "public_key_malformed"
        if sha256_hex(pub) != kb.get("key_fingerprint"):
            return False, "key_fingerprint_mismatch"
        if not _ed25519.verify(pub, payload, proof):
            return False, "key_ownership_proof_invalid"
        return True, "owned"
    key = _load_key(keystore_dir, kb.get("key_id", ""))
    if key is None:
        return False, "key_unavailable"
    if sha256_hex(key) != kb.get("key_fingerprint"):
        return False, "key_fingerprint_mismatch"
    if not hmac_verify(key, payload, proof):
        return False, "key_ownership_proof_invalid"
    return True, "owned"


def registration_provenance_ok(
    appointment: dict[str, Any], register_event: dict[str, Any]
) -> tuple[bool, str]:
    """Does a REGISTER event legitimately claim this appointment? Refuses
    copied identities, scope expansion, key swaps, and validity-period drift
    between appointment and registration.

    The validity period matters as much as identity and keys: verification
    trusts the REGISTER event's effective_from/effective_until (see
    validator_trust.authority_valid_at), so a REGISTER carrying a legitimate
    appointment's binding but different period values would let a registry
    writer make an expired appointment perpetual. Every authorization-bearing
    field the event claims must match the retained appointment exactly."""
    if register_event.get("validator_id") != appointment.get("validator_id"):
        return False, "copied_validator_identity"
    if register_event.get("appointment_binding") != appointment_binding(appointment):
        return False, "appointment_binding_mismatch"
    reg_classes = set(register_event.get("authorized_classes") or [])
    app_classes = set(appointment.get("authorized_classes") or [])
    if not reg_classes or not reg_classes.issubset(app_classes):
        return False, "unauthorized_scope_expansion"
    if register_event.get("effective_from") != appointment.get("effective_from"):
        return False, "validity_period_mismatch"
    if register_event.get("effective_until") != appointment.get("effective_until"):
        return False, "validity_period_mismatch"
    if register_event.get("appointment_authority") != appointment.get("appointment_authority"):
        return False, "appointment_authority_mismatch"
    kb = appointment.get("key_binding") or {}
    if register_event.get("key_id") != kb.get("key_id"):
        return False, "key_substitution"
    if register_event.get("key_fingerprint") != kb.get("key_fingerprint"):
        return False, "key_substitution"
    return True, "provenant"


def derive_ceremony_state(
    appointment: dict[str, Any],
    *,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    instant: str | None,
) -> str:
    """Derived key-ceremony state. Precedence is fail-closed: any inconsistency
    drops to the lowest state it can justify; a broken/tainted registry can
    never yield ACTIVE/ROTATED (registration is then unprovable)."""
    try:
        validate_appointment(appointment)
    except AppointmentError:
        return DISCOVERED
    owned, _reason = verify_key_ownership(appointment, keystore_dir=keystore_dir)
    if not owned:
        return APPOINTMENT_PENDING

    if events is None or not chain_intact(events):
        return KEY_BOUND  # registry tainted: registration unprovable, never ACTIVE
    vid = appointment["validator_id"]
    mine = [e for e in events if e.get("validator_id") == vid]
    reg = next((e for e in mine if e.get("event") == "REGISTER"), None)
    if reg is None or not registration_provenance_ok(appointment, reg)[0]:
        return KEY_BOUND

    # Temporal / revocation dominate registration. A revocation applies only
    # from its effective instant (consistent with authority_valid_at: rev <=
    # at), so a REVOKE scheduled for the future must not report REVOKED at an
    # earlier evaluation instant. An unparseable revocation instant — or no
    # evaluation instant to place it against — fails closed as REVOKED.
    now = _parse_z(instant) if instant else None
    until = appointment.get("effective_until")
    revs = [_parse_z(e.get("instant")) for e in mine if e.get("event") == "REVOKE"]
    if revs and (now is None or any(r is None or r <= now for r in revs)):
        return REVOKED
    if now is not None:
        frm = _parse_z(appointment["effective_from"])
        if frm is None or now < frm:
            return KEY_BOUND  # not yet in effect: registered but not active
        if until is not None:
            u = _parse_z(until)
            if u is None or now >= u:
                return REVOKED  # appointment period ended
    if any(e.get("event") == "ROTATE" for e in mine):
        return ROTATED
    return ACTIVE
