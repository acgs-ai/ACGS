"""VALIDATOR_TRUST_GOVERNANCE_V1 — who may validate, and whether that trust holds.

The onboarding layer (REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1) made a human
validation attestation the gate between DISCOVERED and routable. This layer
governs the validator behind that attestation:

  * a validator must be REGISTERED (identity, authorized evidence classes,
    appointment authority, effective period, signing key fingerprint);
  * the attestation must be SIGNED with the validator's key that was current
    at `validated_at`, and the validator's authority must have been valid at
    that instant;
  * registry events are tamper-evident (`event_binding`), keys live in a
    local keystore (gitignored) and are checked against the registered
    fingerprint;
  * conflicting or doubted validations derive CONFLICTED / INVALIDATED /
    REQUIRES_REVIEW — derived states, never stored, never manually writable.

Fail-closed root: an EMPTY validator registry trusts nobody, so an attested
record with no establishable validator authorization derives INVALIDATED and
never routes. Production ships with an empty registry and no validator keys —
no validator identity is ever invented by software.

Trust-domain note (threat model §): signatures are HMAC-SHA256 with locally
held keys, so verification requires keystore access — this binds the *local
operator* trust domain, like the receipt keystore. Third-party verifiability
would need asymmetric keys (Ed25519); recorded as a known blocker, not
papered over.
"""

from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import _ed25519
from _canonical import canonical_json, hash_obj, hmac_verify, sha256_hex
from authority_lifecycle import (
    ACTIVE,
    DISCOVERED,
    INGESTED,
    LIFECYCLE_STATES,
    REVOKED,
    SUPERSEDED,
    VALIDATED,
    OnboardingError,
    attestation_binding,
    has_valid_attestation,
    superseded_ids_of,
    validate_onboarding_record,
)
from authority_receipt import POLICY_VERSION
from authority_receipt import verify_receipt as _verify_transition_receipt
from authority_router import in_effect, source_artifact_intact

# Onboarding provenance a REGISTER event must carry (EXTERNAL_VALIDATOR_
# ONBOARDING_V1). A REGISTER without evidence-backed appointment provenance is
# an unonboarded validator and trusts nothing it signs.
ONBOARDING_PROTOCOL = "EXTERNAL_VALIDATOR_ONBOARDING_V1"

# Governed states added on top of the onboarding lifecycle. Derived only.
INVALIDATED = "INVALIDATED"
CONFLICTED = "CONFLICTED"
REQUIRES_REVIEW = "REQUIRES_REVIEW"
GOVERNED_STATES = (*LIFECYCLE_STATES, INVALIDATED, CONFLICTED, REQUIRES_REVIEW)

VALIDATOR_REGISTRY_NAME = "validator_registry.jsonl"
VALIDATOR_KEYSTORE_NAME = ".validator_keystore"
POLICY_NAME = "revalidation_policy.json"
# Appointment material retained by the onboarding ceremony, keyed by the
# appointment_binding digest. Lives with the keystore (same privilege tier,
# outside the registry file an attacker may be able to append to).
APPOINTMENTS_DIR_NAME = ".appointments"
# Immutable appointment-artifact BYTES retained by the onboarding ceremony,
# keyed by sha256 digest. Trust evaluation re-hashes these on every read —
# an appointment whose evidence artifacts are deleted, replaced, or no longer
# match their digests stops being trusted (same defense as authority-evidence
# source artifacts).
APPOINTMENT_ARTIFACTS_DIR_NAME = ".appointment_artifacts"

EVENT_SCHEMA = "acgs_validator_registry_event/v1"
EVENTS = ("REGISTER", "ROTATE", "REVOKE")
DISPOSITIONS = ("APPROVED", "REJECTED")
GENESIS = "GENESIS"

# Signature algorithms (ASYMMETRIC_VALIDATOR_KEYS_V1 dual mode). HMAC is the
# compatibility mode (keystore-bound, local trust domain); Ed25519 uses the
# public key recorded in the registry event, so third parties can verify.
HMAC_SHA256 = "hmac-sha256"
ED25519 = "ed25519"
KEY_ALGORITHMS = (HMAC_SHA256, ED25519)

# Attestation fields the trust layer requires beyond the onboarding base set.
_TRUST_FIELDS = ("validator_id", "key_id", "attestation_signature")

DEFAULT_POLICY: dict[str, Any] = {
    "max_age_days": None,  # no age constraint unless the operator sets one
    "minimum_epoch": 0,
    "require_freshness_fields": False,
}


class ValidatorTrustError(ValueError):
    """Validator registry / trust material invalid — fail closed."""


@contextmanager
def registry_write_lock(registry: Path):
    """Exclusive cross-process lock shared by EVERY validator-registry writer
    (onboarding AND admin) for the whole read-validate-append sequence.

    Two writers racing on the same registry would otherwise both read the same
    tail, both compute the same `prev_event_binding`, and the second append
    would fork the hash chain — invalidating the entire validator history at
    the next verification. The lock lives in a sidecar file (never the
    registry itself, so locking cannot create or truncate it), is keyed only
    by the registry path so admin/admin, admin/onboarding, and
    onboarding/onboarding races all serialize on the same file, and releases
    on close (and on process death)."""
    registry.parent.mkdir(parents=True, exist_ok=True)
    lock_path = registry.with_name(registry.name + ".lock")
    with lock_path.open("a", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield


# --------------------------------------------------------------------------- #
# Instants
# --------------------------------------------------------------------------- #


def _parse_z(instant: Any) -> datetime | None:
    """Strict UTC instant (…Z). Anything else is not comparable — fail closed."""
    if not isinstance(instant, str):
        return None
    try:
        return datetime.strptime(instant, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Validator registry (append-only JSONL, tamper-evident events)
# --------------------------------------------------------------------------- #


def event_binding(event: dict[str, Any]) -> str:
    """Digest over the event content (everything but the binding itself).
    `prev_event_binding` is part of the content, so the chain link is signed."""
    return hash_obj({k: v for k, v in event.items() if k != "event_binding"})


def chain_intact(events: list[dict[str, Any]]) -> bool:
    """The registry is a hash chain: each event's `prev_event_binding` must
    equal the previous event's binding (GENESIS for the first) and each
    binding must match its own content. Detects in-place edits, insertion,
    deletion, and reordering anywhere in recorded history (registry rollback
    by mid-history excision). Tail truncation is NOT detectable from the file
    alone — external anchoring is a custody control (see
    VALIDATOR_REGISTRY_CUSTODY_THREAT_MODEL_V1.md)."""
    prev = GENESIS
    for e in events:
        if e.get("prev_event_binding") != prev:
            return False
        if e.get("event_binding") != event_binding(e):
            return False
        prev = e["event_binding"]
    return True


def load_validator_events(path: Path) -> list[dict[str, Any]] | None:
    """Load the registry. Missing file -> [] (nobody trusted). A malformed
    line -> None (registry tainted; every trust check must fail)."""
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        events.append(obj)
    return events


def _events_for(events: list[dict[str, Any]], validator_id: str) -> list[dict[str, Any]]:
    return [e for e in events if e.get("validator_id") == validator_id]


def _events_intact(evts: list[dict[str, Any]]) -> bool:
    """Every event for this validator must carry an intact binding — a tampered
    registry line makes the validator unverifiable (fail closed)."""
    for e in evts:
        if e.get("event") not in EVENTS:
            return False
        if e.get("event_binding") != event_binding(e):
            return False
    return True


def _register_event(evts: list[dict[str, Any]]) -> dict[str, Any] | None:
    for e in evts:
        if e.get("event") == "REGISTER":
            return e
    return None


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _load_retained_appointment(keystore_dir: Path, binding: str) -> dict[str, Any] | None:
    """The appointment record the onboarding ceremony retained for this
    binding, or None. `binding` is validated 64-hex before this is called, so
    it cannot traverse out of the appointments directory."""
    p = keystore_dir / APPOINTMENTS_DIR_NAME / f"{binding}.json"
    if not p.is_file():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _register_has_onboarding_provenance(reg: dict[str, Any], keystore_dir: Path) -> bool:
    """A REGISTER event must carry evidence-backed onboarding provenance:
    the onboarding protocol marker, the appointment binding digest, and the
    digests of the appointment evidence reviewed during the key ceremony —
    AND the binding must correspond to appointment material the onboarding
    ceremony independently retained. Digest-shaped strings alone prove
    nothing: a hand-appended REGISTER with plausible 64-hex values must not
    pass. A bare or unprovenanced REGISTER authorizes nothing — fail closed."""
    if reg.get("onboarding") != ONBOARDING_PROTOCOL:
        return False
    binding = reg.get("appointment_binding")
    if not _hex64(binding):
        return False
    digests = reg.get("appointment_evidence_digests")
    if not isinstance(digests, list) or not digests or not all(_hex64(d) for d in digests):
        return False

    appointment = _load_retained_appointment(keystore_dir, binding)
    if appointment is None:
        return False
    # Lazy import: validator_onboarding imports this module at load time.
    import validator_onboarding as _vo

    try:
        _vo.validate_appointment(appointment)
    except _vo.AppointmentError:
        return False
    if _vo.appointment_binding(appointment) != binding:
        return False
    if not _vo.registration_provenance_ok(appointment, reg)[0]:
        return False
    if reg.get("validator_identity") != appointment.get("subject_identity"):
        return False
    app_digests = sorted(
        e.get("source_digest")
        for e in appointment.get("appointment_evidence") or []
        if isinstance(e, dict)
    )
    if sorted(digests) != app_digests:
        return False
    # The appointment artifacts themselves must remain verifiable: the
    # ceremony retained their bytes by digest, and a validator whose
    # appointment evidence is deleted, replaced, or found not to match must
    # not stay trusted on the strength of digest strings alone.
    artifacts = keystore_dir / APPOINTMENT_ARTIFACTS_DIR_NAME
    for d in app_digests:
        p = artifacts / d
        if not p.is_file():
            return False
        try:
            data = p.read_bytes()
        except OSError:
            return False
        if sha256_hex(data) != d:
            return False
    return True


def authority_valid_at(evts: list[dict[str, Any]], at: str) -> bool:
    """Was the validator's authority valid at instant `at`? Registered, inside
    the registered effective period, and not revoked at or before `at`."""
    at_dt = _parse_z(at)
    reg = _register_event(evts)
    if at_dt is None or reg is None:
        return False
    frm = _parse_z(reg.get("effective_from"))
    if frm is None or at_dt < frm:
        return False
    until = reg.get("effective_until")
    if until is not None:
        until_dt = _parse_z(until)
        if until_dt is None or at_dt >= until_dt:
            return False
    for e in evts:
        if e.get("event") == "REVOKE":
            rev = _parse_z(e.get("instant"))
            if rev is None or rev <= at_dt:
                return False
    return True


def _key_windows(evts: list[dict[str, Any]]) -> list[tuple[str, datetime, datetime | None]]:
    """(key_id, start, end) signing windows. REGISTER's key starts at
    effective_from; each ROTATE starts its key at the rotation instant and ends
    the previous key's window. A REVOKE ends the final window."""
    keyed = []
    for e in evts:
        if e.get("event") == "REGISTER":
            start = _parse_z(e.get("effective_from"))
        elif e.get("event") == "ROTATE":
            start = _parse_z(e.get("instant"))
        else:
            continue
        if start is None or not e.get("key_id"):
            return []  # malformed chronology — no key is ever current
        keyed.append((e["key_id"], start, e))
    keyed.sort(key=lambda t: t[1])
    windows: list[tuple[str, datetime, datetime | None]] = []
    for i, (kid, start, _e) in enumerate(keyed):
        end = keyed[i + 1][1] if i + 1 < len(keyed) else None
        windows.append((kid, start, end))
    revoke = min(
        (d for e in evts if e.get("event") == "REVOKE" if (d := _parse_z(e.get("instant")))),
        default=None,
    )
    if revoke is not None:
        windows = [
            (kid, start, min(end, revoke) if end else revoke)
            for kid, start, end in windows
            if start < revoke
        ]
    return windows


def key_valid_at(evts: list[dict[str, Any]], key_id: str, at: str) -> bool:
    at_dt = _parse_z(at)
    if at_dt is None:
        return False
    for kid, start, end in _key_windows(evts):
        if kid == key_id and start <= at_dt and (end is None or at_dt < end):
            return True
    return False


def key_retired(evts: list[dict[str, Any]], key_id: Any, at: Any = None) -> bool:
    """True when this key's signing window has ENDED at instant `at` (rotated
    away or the validator revoked). validated_at is signer-supplied, so a
    holder of a retired — possibly compromised — key could backdate new
    attestations into the key's old window; records resting on a retired key
    must not stay silently ACTIVE.

    A ROTATE scheduled for a FUTURE instant gives the current key a future
    window end: that key is still current and must not be treated as retired
    until the rotation actually takes effect. No usable evaluation instant ->
    any non-null end counts as retired; unknown key -> retired (fail closed)."""
    at_dt = _parse_z(at)
    for kid, _start, end in _key_windows(evts):
        if kid == key_id:
            if end is None:
                return False
            if at_dt is None:
                return True  # cannot place the instant — fail closed
            return end <= at_dt
    return True


def _key_event_of(evts: list[dict[str, Any]], key_id: str) -> dict[str, Any] | None:
    for e in evts:
        if e.get("event") in ("REGISTER", "ROTATE") and e.get("key_id") == key_id:
            return e
    return None


def key_fingerprint_of(evts: list[dict[str, Any]], key_id: str) -> str | None:
    e = _key_event_of(evts, key_id)
    fp = None if e is None else e.get("key_fingerprint")
    return fp if isinstance(fp, str) else None


def key_algorithm_of(evts: list[dict[str, Any]], key_id: str) -> str:
    e = _key_event_of(evts, key_id)
    return (e or {}).get("key_algorithm", HMAC_SHA256)


def public_key_of(evts: list[dict[str, Any]], key_id: str) -> str | None:
    e = _key_event_of(evts, key_id)
    pk = None if e is None else e.get("public_key")
    return pk if isinstance(pk, str) else None


def rotation_payload(event: dict[str, Any]) -> str:
    """Canonical signed content of a ROTATE event: everything except the
    rotation authorization itself and the chain-link fields, which are
    appended after signing. The successor key id, algorithm, fingerprint,
    public key, and rotation instant are all inside the signature."""
    return canonical_json(
        {
            k: v
            for k, v in event.items()
            if k not in ("rotation_authorization", "prev_event_binding", "event_binding")
        }
    )


def rotations_authenticated(evts: list[dict[str, Any]], keystore_dir: Path) -> bool:
    """Every ROTATE event must carry a `rotation_authorization` signature made
    by the key it retires (the chronologically previous signing key). The
    registry file is append-writable, so an unauthenticated ROTATE would let
    anyone who can append a line rotate a trusted validator onto an
    attacker-held key and sign 'trusted' attestations with it. A rotation the
    predecessor key did not sign authenticates nothing — fail closed."""
    keyed: list[tuple[datetime, dict[str, Any]]] = []
    for e in evts:
        if e.get("event") == "REGISTER":
            start = _parse_z(e.get("effective_from"))
        elif e.get("event") == "ROTATE":
            start = _parse_z(e.get("instant"))
        else:
            continue
        if start is None or not e.get("key_id"):
            return False  # malformed chronology — no rotation is verifiable
        keyed.append((start, e))
    keyed.sort(key=lambda t: t[0])
    for i, (_start, e) in enumerate(keyed):
        if e.get("event") != "ROTATE":
            continue
        if i == 0:
            return False  # a rotation with no predecessor key retires nothing
        pred = keyed[i - 1][1]
        auth = e.get("rotation_authorization")
        if not isinstance(auth, str) or not auth.strip():
            return False
        payload = rotation_payload(e)
        pred_fp = pred.get("key_fingerprint")
        if pred.get("key_algorithm", HMAC_SHA256) == ED25519:
            pk = pred.get("public_key")
            try:
                pub = bytes.fromhex(pk) if isinstance(pk, str) else None
            except ValueError:
                pub = None
            if pub is None or sha256_hex(pub) != pred_fp:
                return False
            if not _ed25519.verify(pub, payload, auth):
                return False
        else:
            key = _load_key(keystore_dir, pred.get("key_id") or "")
            if key is None or sha256_hex(key) != pred_fp:
                return False
            if not hmac_verify(key, payload, auth):
                return False
    return True


def revoked_after(evts: list[dict[str, Any]], validated_at: str) -> bool:
    """True if the validator was revoked AFTER this attestation was made — the
    attestation was valid when issued, but the trust behind it is now in doubt
    (derives REQUIRES_REVIEW, not silent continuation)."""
    v_dt = _parse_z(validated_at)
    if v_dt is None:
        return True
    for e in evts:
        if e.get("event") == "REVOKE":
            rev = _parse_z(e.get("instant"))
            if rev is None or rev > v_dt:
                return True
    return False


# --------------------------------------------------------------------------- #
# Attestation signature
# --------------------------------------------------------------------------- #


def attestation_payload(att: dict[str, Any]) -> str:
    """Canonical signed content of an attestation. Every semantic field is
    inside the signature, so altering ANY of them after signing invalidates it."""
    return canonical_json(
        {
            "confirmed_period": att.get("confirmed_period"),
            "confirmed_scope_digest": att.get("confirmed_scope_digest"),
            "disposition": att.get("disposition", "APPROVED"),
            "key_id": att.get("key_id"),
            "record_binding": att.get("record_binding"),
            "validated_at": att.get("validated_at"),
            "validation_method": att.get("validation_method"),
            "validator_id": att.get("validator_id"),
            "validator_identity": att.get("validator_identity"),
        }
    )


def attestation_payload_v2(record: dict[str, Any], att: dict[str, Any]) -> str:
    """Ed25519 signed content (ASYMMETRIC_VALIDATOR_KEYS_V1): the complete
    semantic attestation payload plus explicit bindings to the evidence
    identity, its source-document digest, the validation class, and the key
    fingerprint. Altering any bound element invalidates the signature."""
    return canonical_json(
        {
            "authority_evidence_id": record.get("authority_evidence_id"),
            "confirmed_period": att.get("confirmed_period"),
            "confirmed_scope_digest": att.get("confirmed_scope_digest"),
            "disposition": att.get("disposition", "APPROVED"),
            "evidence_source_digest": record.get("source_digest"),
            "key_fingerprint": att.get("key_fingerprint"),
            "key_id": att.get("key_id"),
            "record_binding": att.get("record_binding"),
            "signature_algorithm": ED25519,
            "validated_at": att.get("validated_at"),
            "validation_class": record.get("authority_type"),
            "validation_method": att.get("validation_method"),
            "validator_id": att.get("validator_id"),
            "validator_identity": att.get("validator_identity"),
        }
    )


def _load_key(keystore_dir: Path, key_id: str) -> bytes | None:
    """Key bytes for key_id, or None. key_id is used as a file name — reject
    anything that could traverse out of the keystore."""
    if not key_id or "/" in key_id or "\\" in key_id or ".." in key_id:
        return None
    p = keystore_dir / key_id
    if not p.is_file():
        return None
    data = p.read_bytes()
    return data if len(data) >= 16 else None


def verify_attestation_trust(
    record: dict[str, Any],
    att: dict[str, Any],
    *,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    instant: str | None = None,
) -> tuple[bool, str]:
    """Full trust verification of one attestation. Every check fails closed.

    Order: metadata completeness -> record binding -> registry integrity ->
    registration + class authorization -> rotation authentication ->
    authority valid at validated_at -> key current at validated_at ->
    key fingerprint -> signature.

    When an evaluation `instant` is supplied, an attestation whose
    `validated_at` lies in the future of that instant is rejected:
    validated_at is signer-supplied, and a forward-dated attestation would
    pre-authorize trust for a moment that has not happened yet (e.g. dodging
    an upcoming revocation or rotation window).
    """
    if events is None:
        return False, "validator_registry_unreadable"
    if not chain_intact(events):
        return False, "validator_registry_chain_broken"
    if not isinstance(att, dict):
        return False, "attestation_not_an_object"
    base = ("validator_identity", "validation_method", "validated_at", "record_binding")
    for f in (*base, *_TRUST_FIELDS):
        v = att.get(f)
        if not isinstance(v, str) or not v.strip():
            return False, f"partial_validator_metadata:{f}"
    if att.get("disposition", "APPROVED") not in DISPOSITIONS:
        return False, "unknown_disposition"
    if att["record_binding"] != attestation_binding(record):
        return False, "record_binding_mismatch"
    v_dt = _parse_z(att["validated_at"])
    if v_dt is None:
        return False, "validated_at_not_utc"
    if instant is not None:
        now_dt = _parse_z(instant)
        if now_dt is None:
            return False, "evaluation_instant_not_utc"
        if v_dt > now_dt:
            return False, "attestation_future_dated"

    evts = _events_for(events, att["validator_id"])
    if not evts:
        return False, "unknown_validator"
    if not _events_intact(evts):
        return False, "validator_registry_tampered"
    reg = _register_event(evts)
    if reg is None:
        return False, "validator_never_registered"
    if not _register_has_onboarding_provenance(reg, keystore_dir):
        return False, "register_missing_onboarding_provenance"
    # Every rotation in this validator's history must have been authorized by
    # the key it retired — otherwise an appended ROTATE would swap in an
    # attacker-held key and every later signature check would bless it.
    if not rotations_authenticated(evts, keystore_dir):
        return False, "unauthenticated_rotation"
    # The attestation's human identity must be the registered one: a trusted
    # key must not lend its signature to a different claimed validator.
    if att["validator_identity"] != reg.get("validator_identity"):
        return False, "validator_identity_mismatch"
    classes = reg.get("authorized_classes")
    if not isinstance(classes, list) or record.get("authority_type") not in classes:
        return False, "unauthorized_validator_class"
    if not authority_valid_at(evts, att["validated_at"]):
        return False, "validator_authority_invalid_at_attestation"
    if not key_valid_at(evts, att["key_id"], att["validated_at"]):
        return False, "key_not_current_at_attestation"

    fp = key_fingerprint_of(evts, att["key_id"])
    if fp is None:
        return False, "validator_key_unavailable"
    alg = key_algorithm_of(evts, att["key_id"])
    if att.get("signature_algorithm", HMAC_SHA256) != alg:
        return False, "signature_algorithm_mismatch"

    if alg == ED25519:
        pub_hex = public_key_of(evts, att["key_id"])
        try:
            pub = bytes.fromhex(pub_hex) if pub_hex else None
        except ValueError:
            pub = None
        if pub is None:
            return False, "validator_key_unavailable"
        if sha256_hex(pub) != fp:
            return False, "key_fingerprint_mismatch"
        if att.get("key_fingerprint") != fp:
            return False, "key_fingerprint_unbound"
        if not _ed25519.verify(
            pub, attestation_payload_v2(record, att), att["attestation_signature"]
        ):
            return False, "attestation_signature_invalid"
        return True, "trusted"

    # HMAC compatibility mode (legacy): keystore-bound, local trust domain.
    key = _load_key(keystore_dir, att["key_id"])
    if key is None:
        return False, "validator_key_unavailable"
    if sha256_hex(key) != fp:
        return False, "key_fingerprint_mismatch"
    if not hmac_verify(key, attestation_payload(att), att["attestation_signature"]):
        return False, "attestation_signature_invalid"
    return True, "trusted"


# --------------------------------------------------------------------------- #
# Freshness / revalidation policy
# --------------------------------------------------------------------------- #


def load_policy(path: Path) -> dict[str, Any] | None:
    """Load the revalidation policy. Missing file -> defaults (freshness is an
    operator opt-in). Malformed file -> None (every record REQUIRES_REVIEW)."""
    if not path.is_file():
        return dict(DEFAULT_POLICY)
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(obj, dict):
        return None
    policy = dict(DEFAULT_POLICY)
    policy.update({k: obj[k] for k in DEFAULT_POLICY if k in obj})
    if policy["max_age_days"] is not None and not isinstance(policy["max_age_days"], int):
        return None
    if not isinstance(policy["minimum_epoch"], int):
        return None
    return policy


def is_stale(
    record: dict[str, Any],
    atts: list[dict[str, Any]],
    instant: str | None,
    policy: dict[str, Any] | None,
) -> bool:
    """ACTIVE-eligible record demoted to REQUIRES_REVIEW when its verification
    is no longer fresh under the policy. Evidence is never deleted — staleness
    is a derived doubt, cured by revalidation, not by data loss."""
    if policy is None:
        return True  # malformed policy: nothing counts as fresh
    epoch = record.get("verification_epoch")
    last = record.get("last_verified_at")
    if policy["require_freshness_fields"] and (epoch is None or last is None):
        return True
    if policy["minimum_epoch"] > 0:
        if not isinstance(epoch, int) or epoch < policy["minimum_epoch"]:
            return True
    max_age = policy["max_age_days"]
    if max_age is not None and instant is not None:
        now = _parse_z(instant)
        basis = last
        if basis is None:
            # fall back to the newest attestation instant
            stamps = sorted(a.get("validated_at", "") for a in atts)
            basis = stamps[-1] if stamps else None
        basis_dt = _parse_z(basis)
        if now is None or basis_dt is None:
            return True
        if basis_dt > now:
            # A freshness basis dated in the future is not evidence of a past
            # verification: a typo or forward-dated revalidation would make
            # the negative age below count as "fresh" until that future
            # instant plus max_age. Not comparable — fail closed.
            return True
        if (now - basis_dt).days > max_age:
            return True
    return False


# --------------------------------------------------------------------------- #
# Governed lifecycle derivation
# --------------------------------------------------------------------------- #


def ingestion_receipt_verified(
    record: dict[str, Any],
    receipt_key: bytes | None,
    *,
    substrate_identity: str,
    substrate_digest: str,
) -> bool:
    """Verify exact record, decision, policy, state, and current-substrate binding."""
    if (
        not isinstance(substrate_identity, str)
        or not substrate_identity.strip()
        or not isinstance(substrate_digest, str)
        or not substrate_digest.strip()
    ):
        return False
    rid = record.get("ingestion_receipt")
    if not isinstance(rid, str) or not rid.strip():
        return False
    receipt = record.get("ingestion_receipt_record")
    if receipt_key is None or not isinstance(receipt, dict):
        return False
    if not _verify_transition_receipt(receipt_key, receipt):
        return False
    ev_id = record.get("authority_evidence_id")
    return (
        receipt.get("receipt_id") == rid
        and receipt.get("prior_state") == "ABSENT"
        and receipt.get("new_state") == "INGESTED"
        and receipt.get("decision") == "INGEST"
        and receipt.get("policy_version") == POLICY_VERSION
        and receipt.get("request_id") == f"INGEST::{ev_id}"
        and receipt.get("authority_subject") == record.get("subject_identity")
        and receipt.get("authority_evidence_id") == ev_id
        and receipt.get("evidence_digest") == record.get("source_digest")
        and hash_obj(receipt.get("authority_scope")) == hash_obj(record.get("authority_scope"))
        and receipt.get("substrate_identity") == substrate_identity
        and receipt.get("substrate_critical_set_digest") == substrate_digest
    )


def _attestations(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The primary `validation` block plus any `co_validations`. The primary is
    required (intrinsic gate); co-validations enable multi-validator review."""
    atts = [record.get("validation")]
    co = record.get("co_validations")
    if isinstance(co, list):
        atts.extend(co)
    return [a for a in atts if a is not None]


def derive_governed_state(
    record: dict[str, Any],
    *,
    instant: str | None,
    superseded_ids: set[str],
    in_registry: bool,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    policy: dict[str, Any] | None,
    substrate_identity: str,
    substrate_digest: str,
    receipt_key: bytes | None = None,
) -> str:
    """Trust-governed lifecycle state. Extends (never bypasses) the onboarding
    derivation: everything the intrinsic layer refuses, this layer refuses too,
    and it additionally derives INVALIDATED / CONFLICTED / REQUIRES_REVIEW.

    Precedence (fail-closed): REVOKED > SUPERSEDED > DISCOVERED (no/broken
    primary attestation) > INVALIDATED (untrustworthy attestation) >
    CONFLICTED > registry/temporal gates > REQUIRES_REVIEW > ACTIVE.
    """
    if record.get("revoked_at"):
        return REVOKED
    if record.get("authority_evidence_id") in superseded_ids:
        return SUPERSEDED
    if not has_valid_attestation(record):
        return DISCOVERED  # missing/malformed/binding-broken primary attestation

    atts = _attestations(record)
    for att in atts:
        ok, _reason = verify_attestation_trust(
            record, att, events=events, keystore_dir=keystore_dir, instant=instant
        )
        if not ok:
            return INVALIDATED

    dispositions = {a.get("disposition", "APPROVED") for a in atts}
    if dispositions == {"REJECTED"}:
        return INVALIDATED  # validators affirmatively rejected the evidence
    if len(dispositions) > 1:
        return CONFLICTED
    scope_digest = hash_obj(record.get("authority_scope"))
    for a in atts:
        confirmed = a.get("confirmed_scope_digest")
        if confirmed is not None and confirmed != scope_digest:
            return CONFLICTED  # validator confirmed a different scope
        period = a.get("confirmed_period")
        if period is not None and period != {
            "from": record.get("effective_from"),
            "until": record.get("effective_until"),
        }:
            return CONFLICTED  # validator confirmed a different validity period

    if not in_registry or not ingestion_receipt_verified(
        record,
        receipt_key,
        substrate_identity=substrate_identity,
        substrate_digest=substrate_digest,
    ):
        return VALIDATED
    if not in_effect(record, instant):
        return INGESTED
    if any(
        revoked_after(_events_for(events or [], a["validator_id"]), a["validated_at"]) for a in atts
    ):
        return REQUIRES_REVIEW
    # An attestation resting on a since-retired key (rotated away / revoked)
    # is doubt, not proof: validated_at is signer-supplied, so a retired-key
    # holder could backdate fresh attestations into the old window. Demote to
    # review until revalidated under a current key. Retirement is evaluated
    # at `instant`: a rotation scheduled for the future does not retire the
    # still-current key today.
    if any(
        key_retired(_events_for(events or [], a["validator_id"]), a.get("key_id"), instant)
        for a in atts
    ):
        return REQUIRES_REVIEW
    if is_stale(record, atts, instant, policy):
        return REQUIRES_REVIEW
    return ACTIVE


def _trusted_superseded_ids(
    records: list[dict[str, Any]],
    instant: str | None,
    *,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    substrate_identity: str,
    substrate_digest: str,
    receipt_key: bytes | None = None,
) -> set[str]:
    """Ids displaced by a successor whose attestations are all trust-verified.
    `supersedes` is attacker-writable, so only a successor that would itself
    stand under full validator-trust verification may deactivate a record.
    The successor's ingestion receipt is verified CRYPTOGRAPHICALLY against
    the authority receipt key — the base layer's structural check accepts any
    non-empty receipt string, which a registry writer can invent."""

    def successor_trusted(r: dict[str, Any]) -> bool:
        atts = _attestations(r)
        if not atts:
            return False
        if not ingestion_receipt_verified(
            r,
            receipt_key,
            substrate_identity=substrate_identity,
            substrate_digest=substrate_digest,
        ):
            return False
        return all(
            verify_attestation_trust(
                r, a, events=events, keystore_dir=keystore_dir, instant=instant
            )[0]
            for a in atts
        )

    return superseded_ids_of(records, instant, successor_trusted=successor_trusted)


def governed_active_records(
    records: list[dict[str, Any]],
    instant: str | None,
    *,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    policy: dict[str, Any] | None,
    substrate_identity: str,
    substrate_digest: str,
    artifact_dir: Path | None = None,
    receipt_key: bytes | None = None,
) -> list[dict[str, Any]]:
    """Routing-eligible subset under validator trust governance: governed-ACTIVE
    only. INVALIDATED, CONFLICTED, and REQUIRES_REVIEW never route. When
    `artifact_dir` is given, the retained source artifact must still hash to
    the record's source_digest — an unverifiable source document never routes."""
    sids = _trusted_superseded_ids(
        records,
        instant,
        events=events,
        keystore_dir=keystore_dir,
        substrate_identity=substrate_identity,
        substrate_digest=substrate_digest,
        receipt_key=receipt_key,
    )
    out = []
    for r in records:
        try:
            validate_onboarding_record(r)
        except OnboardingError:
            continue
        state = derive_governed_state(
            r,
            instant=instant,
            superseded_ids=sids,
            in_registry=True,
            events=events,
            keystore_dir=keystore_dir,
            policy=policy,
            receipt_key=receipt_key,
            substrate_identity=substrate_identity,
            substrate_digest=substrate_digest,
        )
        if state == ACTIVE and (artifact_dir is None or source_artifact_intact(r, artifact_dir)):
            out.append(r)
    return out


def governed_lifecycle_distribution(
    records: list[dict[str, Any]],
    instant: str | None,
    *,
    events: list[dict[str, Any]] | None,
    keystore_dir: Path,
    policy: dict[str, Any] | None,
    substrate_identity: str,
    substrate_digest: str,
    receipt_key: bytes | None = None,
) -> dict[str, int]:
    sids = _trusted_superseded_ids(
        records,
        instant,
        events=events,
        keystore_dir=keystore_dir,
        substrate_identity=substrate_identity,
        substrate_digest=substrate_digest,
        receipt_key=receipt_key,
    )
    dist = dict.fromkeys(GOVERNED_STATES, 0)
    for r in records:
        try:
            validate_onboarding_record(r)
        except OnboardingError:
            continue
        state = derive_governed_state(
            r,
            instant=instant,
            superseded_ids=sids,
            in_registry=True,
            events=events,
            keystore_dir=keystore_dir,
            policy=policy,
            receipt_key=receipt_key,
            substrate_identity=substrate_identity,
            substrate_digest=substrate_digest,
        )
        dist[state] += 1
    return dist
