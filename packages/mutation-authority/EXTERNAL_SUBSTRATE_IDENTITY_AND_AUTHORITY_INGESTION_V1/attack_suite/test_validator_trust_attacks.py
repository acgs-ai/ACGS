"""Adversarial suite for VALIDATOR_TRUST_GOVERNANCE_V1.

Attacks the trust layer behind validation attestations: forged validator
identities, revoked/expired validator credentials, unauthorized classes,
post-signing alteration, conflicting validators, attestation replay, registry
tampering and key drift, partial metadata, fabricated commercial-rights
inference, and staleness. Every attack must fail closed: the record derives
INVALIDATED / CONFLICTED / REQUIRES_REVIEW / DISCOVERED and never routes.

Hermetic: fixture substrate + tmp registries/keystores only. All validators
here are [FIXTURE]-marked and exist only inside each test's tmp directory.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _canonical import hash_obj, hmac_sign, sha256_hex  # noqa: E402
from authority_lifecycle import (  # noqa: E402
    ACTIVE,
    DISCOVERED,
    REVOKED,
    SUPERSEDED,
    VALIDATED,
    OnboardingError,
    attestation_binding,
    validate_onboarding_record,
)
from test_attacks import INSTANT, _evidence, build_fixture_substrate  # noqa: E402
from test_onboarding_attacks import (  # noqa: E402
    FIX_AUTH_KEY,
    FIX_KEY,
    FIX_KEY_ID,
    FIX_VALIDATOR,
    _attested,
    _compute,
    _sign_att,
    fixture_trust,
)
from validator_trust import (  # noqa: E402
    CONFLICTED,
    DEFAULT_POLICY,
    EVENT_SCHEMA,
    GENESIS,
    INVALIDATED,
    REQUIRES_REVIEW,
    attestation_payload,
    chain_intact,
    derive_governed_state,
    event_binding,
    governed_active_records,
    governed_lifecycle_distribution,
    ingestion_receipt_verified,
    load_validator_events,
    rotation_payload,
    verify_attestation_trust,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _append_event(trust, event: dict) -> None:
    events = load_validator_events(trust["registry"]) or []
    event = dict(event)
    event["prev_event_binding"] = events[-1]["event_binding"] if events else GENESIS
    event["event_binding"] = event_binding(event)
    with trust["registry"].open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


def _authorized_rotation(event: dict, predecessor_key: bytes = FIX_KEY) -> dict:
    """A ROTATE event carrying the predecessor-key signature verification now
    demands: unauthorized rotations derive `unauthenticated_rotation`."""
    event = dict(event)
    event["rotation_authorization"] = hmac_sign(predecessor_key, rotation_payload(event))
    return event


def _with_co_validation(ev: dict, co: dict) -> dict:
    """Attach a co-validation and re-bind/re-sign EVERY attestation over the
    complete validation set: attestation_binding commits to `co_validations`,
    so changing the set demands re-validation by all attesters."""
    ev = dict(ev)
    co = dict(co, validator_id=FIX_VALIDATOR, key_id=FIX_KEY_ID)
    ev["co_validations"] = [co]
    binding = attestation_binding(ev)  # excludes binding-derived fields
    co["record_binding"] = binding
    ev["co_validations"] = [_sign_att(co)]
    primary = {
        k: v
        for k, v in ev["validation"].items()
        if k not in ("record_binding", "attestation_signature")
    }
    primary["record_binding"] = binding
    ev["validation"] = _sign_att(primary)
    return ev


_DEFAULT = object()  # sentinel so policy=None (malformed) can be passed through


def _gstate(rec, trust, *, instant=INSTANT, policy=_DEFAULT, events=None):
    if events is None:
        events = load_validator_events(trust["registry"])
    return derive_governed_state(
        rec,
        instant=instant,
        superseded_ids=set(),
        in_registry=True,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY) if policy is _DEFAULT else policy,
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        receipt_key=FIX_AUTH_KEY,
    )


@pytest.fixture
def substrate(tmp_path):
    return build_fixture_substrate(tmp_path)


# --------------------------------------------------------------------------- #
# The required validator-trust attacks
# --------------------------------------------------------------------------- #


def test_vt1_forged_validator_identity_invalidated(substrate, tmp_path):
    # Attestation names a validator that was never registered. Even with a
    # bit-perfect signature under some key, no registration = no trust.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    ev["validation"]["validator_id"] = "[FORGED] vld-ghost"
    ev["validation"]["attestation_signature"] = hmac_sign(
        FIX_KEY, attestation_payload(ev["validation"])
    )
    assert _gstate(ev, trust) == INVALIDATED
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["routable_authority_records"] == 0
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][INVALIDATED] == 1


def test_vt2_revoked_validator_signing_new_evidence_invalidated(tmp_path):
    # Validator revoked 2026-08-01; attestation claims validated_at 2026-08-10.
    trust = fixture_trust(tmp_path)
    _append_event(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "REVOKE",
            "validator_id": FIX_VALIDATOR,
            "instant": "2026-08-01T00:00:00Z",
        },
    )
    ev = _attested(_evidence())  # validated_at 2026-08-10T11:00:00Z
    assert _gstate(ev, trust) == INVALIDATED


def test_vt3_expired_validator_credentials_invalidated(tmp_path):
    # Registered authority window ended before the attestation instant.
    trust = fixture_trust(tmp_path)
    reg = {
        "schema": EVENT_SCHEMA,
        "event": "REGISTER",
        "validator_id": "[FIXTURE] vld-expired",
        "validator_identity": "[FIXTURE] Former Validator",
        "authorized_classes": ["DATA_CONTROLLER"],
        "appointment_authority": "[FIXTURE] General Counsel",
        "key_id": FIX_KEY_ID,
        "key_fingerprint": sha256_hex(FIX_KEY),
        "effective_from": "2025-01-01T00:00:00Z",
        "effective_until": "2026-06-01T00:00:00Z",  # before validated_at
        "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
        "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
        "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
    }
    _append_event(trust, reg)
    ev = _attested(_evidence())
    ev["validation"]["validator_id"] = "[FIXTURE] vld-expired"
    ev["validation"]["attestation_signature"] = hmac_sign(
        FIX_KEY, attestation_payload(ev["validation"])
    )
    assert _gstate(ev, trust) == INVALIDATED


def test_vt4_unauthorized_validator_class_invalidated(tmp_path):
    # Validator authorized only for counsel evidence attests controller evidence.
    trust = fixture_trust(tmp_path / "t", classes=("COUNSEL_OR_RIGHTS_AUTHORITY",))
    ev = _attested(_evidence(authority_type="DATA_CONTROLLER"))
    assert _gstate(ev, trust) == INVALIDATED
    ok, reason = verify_attestation_trust(
        ev,
        ev["validation"],
        events=load_validator_events(trust["registry"]),
        keystore_dir=trust["keystore"],
    )
    assert not ok and reason == "unauthorized_validator_class"


def test_vt5_altered_validation_after_signing_invalidated(tmp_path):
    # Any post-signing change to any attestation field breaks the signature.
    trust = fixture_trust(tmp_path)
    for field, value in (
        ("validation_method", "[TAMPERED] different method"),
        ("validated_at", "2026-08-09T11:00:00Z"),
        ("validator_identity", "[TAMPERED] Other Person"),
        ("disposition", "REJECTED"),
    ):
        ev = _attested(_evidence())
        ev["validation"][field] = value
        assert _gstate(ev, trust) == INVALIDATED, field


def test_vt6_conflicting_validators_conflicted(substrate, tmp_path):
    # Two trust-valid attestations with contradictory dispositions.
    trust = fixture_trust(tmp_path)
    ev = _with_co_validation(
        _attested(_evidence()),
        {
            "validator_identity": "[FIXTURE] Legal Validator",
            "validation_method": "[FIXTURE] independent second review",
            "validated_at": "2026-08-10T11:30:00Z",
            "disposition": "REJECTED",
        },
    )
    assert _gstate(ev, trust) == CONFLICTED
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][CONFLICTED] == 1


def test_vt6b_contradictory_scope_or_period_conflicted(tmp_path):
    trust = fixture_trust(tmp_path)
    # Validator confirmed a DIFFERENT scope than the record carries.
    ev = _attested(_evidence())
    att = dict(ev["validation"])
    att["confirmed_scope_digest"] = hash_obj({"asset_ids": ["asset:other"]})
    ev["validation"] = _sign_att(att)
    assert _gstate(ev, trust) == CONFLICTED
    # Validator confirmed a DIFFERENT validity period than the record carries.
    ev2 = _attested(_evidence())
    att2 = dict(ev2["validation"])
    att2["confirmed_period"] = {"from": "2020-01-01T00:00:00Z", "until": None}
    ev2["validation"] = _sign_att(att2)
    assert _gstate(ev2, trust) == CONFLICTED


def test_vt7_replayed_attestation_fails_closed(tmp_path):
    trust = fixture_trust(tmp_path)
    # (a) Attestation copied from record A onto record B: binding mismatch.
    a = _attested(_evidence(ev_id="AE-A"))
    b = dict(_evidence(ev_id="AE-B"))
    b["issuer_or_appointing_party"] = "[FIXTURE] Board"
    b["validation"] = dict(a["validation"])  # replay
    b["ingestion_receipt"] = "r-fixture"
    assert _gstate(b, trust) == DISCOVERED  # binding refuses foreign attestations
    # (b) Old attestation signed with a rotated-out key at a post-rotation
    # instant: the key window closed at rotation, so trust fails.
    _append_event(
        trust,
        _authorized_rotation(
            {
                "schema": EVENT_SCHEMA,
                "event": "ROTATE",
                "validator_id": FIX_VALIDATOR,
                "key_id": "vk-2",
                "key_fingerprint": sha256_hex(b"w" * 32),
                "instant": "2026-07-01T00:00:00Z",
            }
        ),
    )
    (trust["keystore"] / "vk-2").write_bytes(b"w" * 32)
    stale = _attested(_evidence())  # validated_at 2026-08-10, signed with vk-1
    assert _gstate(stale, trust) == INVALIDATED


def test_vt7c_retired_key_attestation_requires_review(tmp_path):
    # An attestation whose key was rotated away AFTER validated_at: the
    # signature verified inside its window, but validated_at is signer-
    # supplied, so a retired (possibly compromised) key holder could backdate
    # fresh attestations into the old window. The record must not stay
    # silently ACTIVE — it demotes to REQUIRES_REVIEW until revalidated.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())  # validated_at 2026-08-10, signed with vk-1
    assert _gstate(ev, trust) == ACTIVE
    _append_event(
        trust,
        _authorized_rotation(
            {
                "schema": EVENT_SCHEMA,
                "event": "ROTATE",
                "validator_id": FIX_VALIDATOR,
                "key_id": "vk-2",
                "key_fingerprint": sha256_hex(b"w" * 32),
                "instant": "2026-08-11T00:00:00Z",  # AFTER validated_at
            }
        ),
    )
    (trust["keystore"] / "vk-2").write_bytes(b"w" * 32)
    assert _gstate(ev, trust, instant="2026-08-12T00:00:00Z") == REQUIRES_REVIEW


def test_vt8_registry_tamper_or_key_drift_invalidated(tmp_path):
    # (a) Registry event edited in place (privilege escalation attempt):
    # event_binding no longer matches -> validator unverifiable.
    trust = fixture_trust(tmp_path, classes=("COUNSEL_OR_RIGHTS_AUTHORITY",))
    lines = trust["registry"].read_text(encoding="utf-8").splitlines()
    ev_obj = json.loads(lines[0])
    ev_obj["authorized_classes"] = ["COUNSEL_OR_RIGHTS_AUTHORITY", "DATA_CONTROLLER"]
    trust["registry"].write_text(json.dumps(ev_obj, sort_keys=True) + "\n", encoding="utf-8")
    ev = _attested(_evidence(authority_type="DATA_CONTROLLER"))
    assert _gstate(ev, trust) == INVALIDATED
    # (b) Keystore key replaced: fingerprint mismatch -> fail closed.
    trust2 = fixture_trust(tmp_path / "b")
    (trust2["keystore"] / FIX_KEY_ID).write_bytes(b"x" * 32)
    ev2 = _attested(_evidence())
    assert _gstate(ev2, trust2) == INVALIDATED
    # (c) Malformed registry line: the whole registry is tainted; nobody trusted.
    trust3 = fixture_trust(tmp_path / "c")
    with trust3["registry"].open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    ev3 = _attested(_evidence())
    assert load_validator_events(trust3["registry"]) is None
    assert _gstate(ev3, trust3, events=load_validator_events(trust3["registry"])) == INVALIDATED


def test_vt9_partial_validator_metadata_invalidated(tmp_path):
    trust = fixture_trust(tmp_path)
    for missing in ("validator_id", "key_id", "attestation_signature"):
        ev = _attested(_evidence())
        del ev["validation"][missing]
        assert _gstate(ev, trust) == INVALIDATED, missing


def test_vt10_fabricated_commercial_rights_inference_rejected(substrate, tmp_path):
    # (a) An evidence record carrying any commercial-claim field is rejected
    # outright — authority qualification is not rights ownership.
    for field in ("rights_assertion", "commercial_rights", "licensing_permission"):
        fab = _attested(_evidence())
        fab[field] = "[FABRICATED] full commercial rights"
        with pytest.raises(OnboardingError):
            validate_onboarding_record(fab)
    # (b) Even a fully trust-verified ACTIVE record creates no commercial claim:
    # requests carry no rights_assertion and routing mints none (I6/I7).
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 2  # routing happened...
    assert st["report"]["rights_assertions"] == 0  # ...and asserted no right
    assert st["invariants"]["I6_ready_does_not_imply_rights_cleared"]
    assert st["invariants"]["I7_routing_creates_no_rights_assertion"]


def test_vt11_unauthenticated_rotation_fails_closed(tmp_path):
    # An attacker who can APPEND registry lines (chain-valid tail extension)
    # rotates the trusted validator onto a key they hold, then signs a
    # perfect attestation with it. Without a signature by the key the
    # rotation retires, the whole validator history is untrustworthy.
    trust = fixture_trust(tmp_path)
    attacker_key = b"z" * 32
    _append_event(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": FIX_VALIDATOR,
            "key_id": "vk-evil",
            "key_fingerprint": sha256_hex(attacker_key),
            "instant": "2026-08-01T00:00:00Z",
            # no rotation_authorization — the attacker cannot produce one
        },
    )
    ev = _attested(_evidence())
    att = dict(ev["validation"], key_id="vk-evil")
    att["attestation_signature"] = hmac_sign(attacker_key, attestation_payload(att))
    ev["validation"] = att
    ok, reason = verify_attestation_trust(
        ev,
        att,
        events=load_validator_events(trust["registry"]),
        keystore_dir=trust["keystore"],
    )
    assert not ok and reason == "unauthenticated_rotation"
    assert _gstate(ev, trust) == INVALIDATED
    # A garbage authorization string is just as dead as a missing one.
    trust2 = fixture_trust(tmp_path / "b")
    _append_event(
        trust2,
        {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": FIX_VALIDATOR,
            "key_id": "vk-evil",
            "key_fingerprint": sha256_hex(attacker_key),
            "instant": "2026-08-01T00:00:00Z",
            "rotation_authorization": hmac_sign(attacker_key, "self-signed"),
        },
    )
    ok2, reason2 = verify_attestation_trust(
        ev,
        att,
        events=load_validator_events(trust2["registry"]),
        keystore_dir=trust2["keystore"],
    )
    assert not ok2 and reason2 == "unauthenticated_rotation"


def test_vt12_future_dated_attestation_fails_closed(tmp_path):
    # validated_at is signer-supplied: an attestation dated in the FUTURE of
    # the evaluation instant pre-authorizes trust for a moment that has not
    # happened yet and must not verify at that instant.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    att = dict(ev["validation"])
    att["validated_at"] = "2026-08-10T13:00:00Z"  # one hour after INSTANT
    ev["validation"] = _sign_att(att)
    ok, reason = verify_attestation_trust(
        ev,
        ev["validation"],
        events=load_validator_events(trust["registry"]),
        keystore_dir=trust["keystore"],
        instant=INSTANT,
    )
    assert not ok and reason == "attestation_future_dated"
    assert _gstate(ev, trust) == INVALIDATED  # derivation evaluates at INSTANT
    # Once the claimed instant has actually passed, the same record stands.
    assert _gstate(ev, trust, instant="2026-08-10T14:00:00Z") == ACTIVE


def test_vt13_supersession_requires_verified_ingestion_receipt(tmp_path):
    # `supersedes` + a receipt-SHAPED string must not deactivate an
    # established record: the successor's ingestion receipt is verified
    # cryptographically against the authority receipt key, not by truthiness.
    trust = fixture_trust(tmp_path)
    events = load_validator_events(trust["registry"])
    old = _attested(_evidence(ev_id="AE-OLD"))
    pretender = _attested(
        dict(_evidence(ev_id="AE-NEW"), supersedes="AE-OLD"), receipt="r-invented"
    )
    dist = governed_lifecycle_distribution(
        [old, pretender],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        receipt_key=FIX_AUTH_KEY,
    )
    assert dist[SUPERSEDED] == 0  # the established record stands
    assert dist[ACTIVE] == 1
    assert dist[VALIDATED] == 1  # the pretender never rose past VALIDATED
    # A successor whose receipt genuinely verifies DOES supersede.
    real = _attested(dict(_evidence(ev_id="AE-NEW2"), supersedes="AE-OLD"))
    dist2 = governed_lifecycle_distribution(
        [old, real],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        receipt_key=FIX_AUTH_KEY,
    )
    assert dist2[SUPERSEDED] == 1
    assert dist2[ACTIVE] == 1


def test_vt14_rejected_successor_cannot_supersede(tmp_path):
    # A receipted successor carrying a validly SIGNED but REJECTED attestation
    # must not deactivate the established predecessor: signature trust alone
    # is not standing. The successor must itself derive governed-ACTIVE
    # before its `supersedes` claim counts — otherwise appending a rejected
    # successor would leave BOTH records unroutable (predecessor SUPERSEDED,
    # successor INVALIDATED): a denial-of-authority primitive.
    trust = fixture_trust(tmp_path)
    events = load_validator_events(trust["registry"])
    old = _attested(_evidence(ev_id="AE-OLD"))
    rejected = _attested(dict(_evidence(ev_id="AE-NEW"), supersedes="AE-OLD"))
    att = {
        k: v
        for k, v in dict(rejected["validation"], disposition="REJECTED").items()
        if k != "attestation_signature"
    }
    rejected["validation"] = _sign_att(att)  # validly signed, affirmatively REJECTED
    dist = governed_lifecycle_distribution(
        [old, rejected],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        receipt_key=FIX_AUTH_KEY,
    )
    assert dist[SUPERSEDED] == 0  # the established record stands
    assert dist[ACTIVE] == 1
    assert dist[INVALIDATED] == 1  # the rejected successor never stands
    # An out-of-effect successor (not yet in its validity period) must not
    # supersede either: full ACTIVE eligibility, not just signature trust.
    future = _attested(
        dict(
            _evidence(ev_id="AE-NEW3", effective_from="2027-01-01T00:00:00Z"),
            supersedes="AE-OLD",
        )
    )
    dist2 = governed_lifecycle_distribution(
        [old, future],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        receipt_key=FIX_AUTH_KEY,
    )
    assert dist2[SUPERSEDED] == 0
    assert dist2[ACTIVE] == 1


@pytest.mark.parametrize("artifact_state", ["missing", "tampered"])
def test_vt15_unverifiable_successor_source_cannot_supersede(tmp_path, artifact_state):
    """A successor excluded by source verification cannot displace a routable predecessor."""
    trust = fixture_trust(tmp_path)
    events = load_validator_events(trust["registry"])
    old = _attested(_evidence(ev_id="AE-OLD"))
    successor_source = b"[FIXTURE] successor appointment deed"
    successor = _attested(
        dict(
            _evidence(
                ev_id="AE-NEW-SOURCE",
                source_digest=sha256_hex(successor_source),
            ),
            supersedes="AE-OLD",
        )
    )
    assert ingestion_receipt_verified(
        successor,
        FIX_AUTH_KEY,
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
    )
    assert _gstate(successor, trust) == ACTIVE
    artifact_dir = tmp_path / "authority-artifacts"
    artifact_dir.mkdir()
    (artifact_dir / old["source_digest"]).write_bytes(b"[FIXTURE] appointment deed")
    if artifact_state == "tampered":
        (artifact_dir / successor["source_digest"]).write_bytes(b"tampered")

    routable = governed_active_records(
        [old, successor],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        artifact_dir=artifact_dir,
        receipt_key=FIX_AUTH_KEY,
    )
    assert [record["authority_evidence_id"] for record in routable] == ["AE-OLD"]

    dist = governed_lifecycle_distribution(
        [old, successor],
        INSTANT,
        events=events,
        keystore_dir=trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
        artifact_dir=artifact_dir,
        receipt_key=FIX_AUTH_KEY,
    )
    assert dist[SUPERSEDED] == 0
    assert dist[ACTIVE] == 2


def test_duplicate_register_bypasses_nothing(tmp_path):
    # An attacker who can APPEND a chain-linked registry line publishes a
    # SECOND REGISTER for the existing validator carrying their own key, then
    # signs a perfect attestation with it. Registration happens exactly once
    # (onboarding ceremony); a later REGISTER must not open a key window the
    # rotation-authentication chain never vouched for.
    trust = fixture_trust(tmp_path)
    attacker_key = b"q" * 32
    _append_event(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "REGISTER",
            "validator_id": FIX_VALIDATOR,
            "validator_identity": "[FIXTURE] Legal Validator",
            "authorized_classes": ["DATA_CONTROLLER", "COUNSEL_OR_RIGHTS_AUTHORITY"],
            "appointment_authority": "[FIXTURE] General Counsel",
            "key_id": "vk-dup",
            "key_fingerprint": sha256_hex(attacker_key),
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
            "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
            "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
        },
    )
    (trust["keystore"] / "vk-dup").write_bytes(attacker_key)
    events = load_validator_events(trust["registry"])
    assert events is not None and chain_intact(events)  # the append IS chain-valid
    ev = _attested(_evidence())
    att = dict(ev["validation"], key_id="vk-dup")
    att["attestation_signature"] = hmac_sign(attacker_key, attestation_payload(att))
    ev["validation"] = att
    ok, reason = verify_attestation_trust(ev, att, events=events, keystore_dir=trust["keystore"])
    assert not ok and reason == "duplicate_validator_registration"
    assert _gstate(ev, trust) == INVALIDATED
    # The duplicate poisons the WHOLE history: even the original validator's
    # untouched attestation no longer verifies until the registry is repaired.
    legit = _attested(_evidence())
    ok2, reason2 = verify_attestation_trust(
        legit, legit["validation"], events=events, keystore_dir=trust["keystore"]
    )
    assert not ok2 and reason2 == "duplicate_validator_registration"
    assert _gstate(legit, trust) == INVALIDATED


def test_lifecycle_override_registry_edits_fail_closed(substrate, tmp_path):
    # (a) Stripping the rejecting co-validation must not flip CONFLICTED ->
    # ACTIVE: the attestation binding commits to the complete validation set,
    # so the surviving attestations stop verifying once the set changes.
    trust = fixture_trust(tmp_path)
    ev = _with_co_validation(
        _attested(_evidence()),
        {
            "validator_identity": "[FIXTURE] Legal Validator",
            "validation_method": "[FIXTURE] independent second review",
            "validated_at": "2026-08-10T11:30:00Z",
            "disposition": "REJECTED",
        },
    )
    assert _gstate(ev, trust) == CONFLICTED
    stripped = dict(ev)
    del stripped["co_validations"]
    assert _gstate(stripped, trust) == DISCOVERED  # never ACTIVE, never routes
    st = _compute(substrate, tmp_path, [stripped], trust=trust)
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["routable_authority_records"] == 0
    # (b) Deleting an ATTESTED revocation must not resurrect the record:
    # revoked_at is inside the attestation binding, so the pre-edit
    # attestation stops verifying the moment the revocation is stripped.
    revoked = _attested(_evidence(revoked_at="2026-08-09T00:00:00Z"))
    assert _gstate(revoked, trust) == REVOKED
    resurrected = dict(revoked)
    resurrected["revoked_at"] = None
    assert _gstate(resurrected, trust) == DISCOVERED  # never ACTIVE


# --------------------------------------------------------------------------- #
# Revocation-after-issuance, freshness, and empty-registry root
# --------------------------------------------------------------------------- #


def test_validator_revoked_after_issuance_requires_review(substrate, tmp_path):
    # Attestation was valid when made; the validator was revoked later. The
    # evidence is not silently kept ACTIVE and not destroyed — it derives
    # REQUIRES_REVIEW and stops routing until revalidated.
    trust = fixture_trust(tmp_path)
    _append_event(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "REVOKE",
            "validator_id": FIX_VALIDATOR,
            # AFTER validated_at 2026-08-10T11:00 and effective by INSTANT
            "instant": "2026-08-10T11:30:00Z",
        },
    )
    ev = _attested(_evidence())
    assert _gstate(ev, trust) == REQUIRES_REVIEW
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][REQUIRES_REVIEW] == 1


def test_future_scheduled_revocation_defers_until_effective(substrate, tmp_path):
    # A REVOKE scheduled AFTER the current evaluation instant is not yet
    # effective: it must not prematurely demote otherwise valid routing
    # (consistent with authority_valid_at and key_retired, which both defer
    # the same future revocation) — but it applies from its instant onward.
    trust = fixture_trust(tmp_path)
    _append_event(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "REVOKE",
            "validator_id": FIX_VALIDATOR,
            "instant": "2026-08-15T00:00:00Z",  # AFTER the evaluation INSTANT
        },
    )
    ev = _attested(_evidence())
    assert _gstate(ev, trust) == ACTIVE  # evaluated at INSTANT (2026-08-10)
    assert _gstate(ev, trust, instant="2026-08-15T00:00:00Z") == REQUIRES_REVIEW
    assert _gstate(ev, trust, instant="2026-09-01T00:00:00Z") == REQUIRES_REVIEW
    st = _compute(substrate, tmp_path, [ev], trust=trust)  # evaluates at INSTANT
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 1
    assert st["report"]["lifecycle_distribution"][REQUIRES_REVIEW] == 0


def test_freshness_age_demotes_to_requires_review(tmp_path):
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, max_age_days=30)
    ev = _attested(_evidence())  # validated_at 2026-08-10
    assert _gstate(ev, trust, instant=INSTANT, policy=policy) == ACTIVE  # 0 days old
    assert _gstate(ev, trust, instant="2026-10-10T12:00:00Z", policy=policy) == REQUIRES_REVIEW
    # Revalidation is a re-attestation: last_verified_at is attestation-bound,
    # so refreshing the basis means attesting a record that carries it.
    ev2 = _attested(dict(_evidence(), last_verified_at="2026-10-01T00:00:00Z"))
    assert _gstate(ev2, trust, instant="2026-10-10T12:00:00Z", policy=policy) == ACTIVE


def test_future_dated_freshness_basis_fails_closed(tmp_path):
    # A freshness basis dated in the FUTURE is not evidence of a past
    # verification: a forward-dated last_verified_at would otherwise stay
    # "fresh" until that future instant plus max_age. Not comparable ->
    # REQUIRES_REVIEW.
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, max_age_days=30)
    ev = _attested(dict(_evidence(), last_verified_at="2027-01-01T00:00:00Z"))
    assert _gstate(ev, trust, instant="2026-10-10T12:00:00Z", policy=policy) == REQUIRES_REVIEW


def test_freshness_epoch_demotes_to_requires_review(tmp_path):
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, minimum_epoch=2)
    ev = _attested(_evidence())
    assert _gstate(ev, trust, policy=policy) == REQUIRES_REVIEW  # no epoch recorded
    # verification_epoch is attestation-bound: recording a new epoch is a
    # re-attestation, not a post-hoc edit of the record.
    ev1 = _attested(dict(_evidence(), verification_epoch=1))
    assert _gstate(ev1, trust, policy=policy) == REQUIRES_REVIEW
    ev2 = _attested(dict(_evidence(), verification_epoch=2))
    assert _gstate(ev2, trust, policy=policy) == ACTIVE


def test_malformed_policy_fails_closed(tmp_path):
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    assert _gstate(ev, trust, policy=None) == REQUIRES_REVIEW  # malformed policy: no freshness


def test_empty_validator_registry_trusts_nobody(substrate, tmp_path):
    # The fail-closed root: no registered validators -> a perfectly attested
    # record is INVALIDATED and nothing routes. This is production's state.
    empty = {"registry": tmp_path / "none.jsonl", "keystore": tmp_path / "none_ks"}
    ev = _attested(_evidence())
    assert _gstate(ev, empty, events=load_validator_events(empty["registry"])) == INVALIDATED
    st = _compute(substrate, tmp_path, [ev], trust=empty)
    assert st["report"]["registered_validators"] == 0
    assert st["report"]["ready_to_send"] == 0
    assert st["verdict"] == "AUTHORITY_LAYER_READY"


# --------------------------------------------------------------------------- #
# Positive control + admin CLI + determinism
# --------------------------------------------------------------------------- #


def test_positive_control_full_trust_chain_routes(substrate, tmp_path):
    # All five clauses of the success condition satisfied -> and ONLY then ->
    # the evidence routes: identity verified, authorized human validation,
    # validator valid at validation time, binding intact, lifecycle ACTIVE.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    assert _gstate(ev, trust) == ACTIVE
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 2
    assert st["report"]["routable_authority_records"] == 1
    assert st["verdict"] == "AUTHORITY_PARTIALLY_ACTIVATED"
    assert all(st["invariants"].values())


def test_validator_admin_lifecycle_and_bindings(tmp_path):
    import validator_admin as VA

    reg = tmp_path / "vreg.jsonl"
    ks = tmp_path / "vks"
    base = ["--registry", str(reg), "--keystore", str(ks)]
    # Self-asserted registration is no longer a CLI path: enrolling a validator
    # requires the evidence-backed onboarding ceremony (onboard_validator.py).
    with pytest.raises(SystemExit):
        VA.main([*base, "register", "--validator-id", "[FIXTURE] vld-cli"])
    # rotate/revoke against an unregistered validator are refused.
    rotate = ["rotate", "--validator-id", "[FIXTURE] vld-cli", "--key-id", "cli-k2"]
    assert VA.main([*base, *rotate, "--instant", "2026-06-01T00:00:00Z"]) == 3
    # Seed a REGISTER event the way the onboarding ceremony does (chain-linked
    # append with onboarding provenance + keystore-backed key).
    fingerprint = VA._write_key(ks, "cli-k1")
    VA._append(
        reg,
        {
            "schema": EVENT_SCHEMA,
            "event": "REGISTER",
            "validator_id": "[FIXTURE] vld-cli",
            "validator_identity": "[FIXTURE] CLI Validator",
            "authorized_classes": ["DATA_CONTROLLER"],
            "appointment_authority": "[FIXTURE] General Counsel",
            "key_id": "cli-k1",
            "key_fingerprint": fingerprint,
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
            "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
            "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
        },
    )
    assert VA.main([*base, *rotate, "--instant", "2026-06-01T00:00:00Z"]) == 0
    # A SUPPLIED authorization is verified against the predecessor key BEFORE
    # append: garbage is refused at write time, never laundered into the
    # registry to derive `unauthenticated_rotation` at every later read.
    bad_rotate = ["rotate", "--validator-id", "[FIXTURE] vld-cli", "--key-id", "cli-k3-bad"]
    assert (
        VA.main(
            [
                *base,
                *bad_rotate,
                "--instant",
                "2026-06-15T00:00:00Z",
                "--rotation-authorization",
                "not-a-predecessor-signature",
            ]
        )
        == 3
    )
    revoke = ["revoke", "--validator-id", "[FIXTURE] vld-cli"]
    assert VA.main([*base, *revoke, "--instant", "2026-07-01T00:00:00Z"]) == 0
    events = load_validator_events(reg)
    assert events is not None and len(events) == 3
    assert all(e["event_binding"] == event_binding(e) for e in events)
    # Keys exist and match their registered fingerprints.
    for e in events:
        if e.get("key_id"):
            assert sha256_hex((ks / e["key_id"]).read_bytes()) == e["key_fingerprint"]


def test_symlinked_registry_refuses_lifecycle_append(tmp_path):
    import validator_admin as VA

    # The configured registry swapped for a symlink to an external, VALID
    # registry JSONL must never be appended through: the lifecycle event
    # would land in the external file (corrupting a privileged target) while
    # the configured trust store stays unchanged and the command reports
    # success. The no-follow append must refuse with an operational error
    # and leave the external file byte-identical.
    ks = tmp_path / "vks"
    fingerprint = VA._write_key(ks, "cli-k1")
    external = tmp_path / "external.jsonl"
    VA._append(
        external,
        {
            "schema": EVENT_SCHEMA,
            "event": "REGISTER",
            "validator_id": "[FIXTURE] vld-sym",
            "validator_identity": "[FIXTURE] CLI Validator",
            "authorized_classes": ["DATA_CONTROLLER"],
            "appointment_authority": "[FIXTURE] General Counsel",
            "key_id": "cli-k1",
            "key_fingerprint": fingerprint,
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
            "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
            "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
        },
    )
    before = external.read_bytes()
    reg = tmp_path / "vreg.jsonl"
    reg.symlink_to(external)
    base = ["--registry", str(reg), "--keystore", str(ks)]
    revoke = ["revoke", "--validator-id", "[FIXTURE] vld-sym"]
    assert VA.main([*base, *revoke, "--instant", "2026-07-01T00:00:00Z"]) == 2
    assert external.read_bytes() == before  # nothing appended through the link
    # Positive control: a real regular file at the configured path works.
    reg.unlink()
    reg.write_bytes(before)
    assert VA.main([*base, *revoke, "--instant", "2026-07-01T00:00:00Z"]) == 0
    events = load_validator_events(reg)
    assert events is not None and events[-1]["event"] == "REVOKE"
    assert external.read_bytes() == before


def test_current_substrate_binding_is_mandatory_at_every_ingestion_api(tmp_path):
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    events = load_validator_events(trust["registry"])
    common = {
        "instant": INSTANT,
        "superseded_ids": set(),
        "in_registry": True,
        "events": events,
        "keystore_dir": trust["keystore"],
        "policy": dict(DEFAULT_POLICY),
        "receipt_key": FIX_AUTH_KEY,
    }

    with pytest.raises(TypeError):
        ingestion_receipt_verified(ev, FIX_AUTH_KEY)
    assert not ingestion_receipt_verified(
        ev, FIX_AUTH_KEY, substrate_identity="", substrate_digest="d" * 64
    )
    assert not ingestion_receipt_verified(
        ev, FIX_AUTH_KEY, substrate_identity="fixture-substrate", substrate_digest=""
    )

    with pytest.raises(TypeError):
        derive_governed_state(ev, **common)
    assert (
        derive_governed_state(ev, substrate_identity="", substrate_digest="d" * 64, **common)
        != ACTIVE
    )

    active_common = {
        "events": events,
        "keystore_dir": trust["keystore"],
        "policy": dict(DEFAULT_POLICY),
        "receipt_key": FIX_AUTH_KEY,
    }
    with pytest.raises(TypeError):
        governed_active_records([ev], INSTANT, **active_common)
    assert (
        governed_active_records(
            [ev],
            INSTANT,
            substrate_identity="fixture-substrate",
            substrate_digest="",
            **active_common,
        )
        == []
    )


def test_non_monotonic_rotation_instant_refused(tmp_path):
    # The rotation CLI signs with the LAST APPENDED key event as predecessor;
    # an out-of-order instant would make it sign with a key that is not the
    # key current at that instant, producing a ROTATE that
    # rotations_authenticated() (which sorts by instant) rejects at read
    # time. Refused loudly at write time instead.
    import validator_admin as VA

    reg = tmp_path / "vreg.jsonl"
    ks = tmp_path / "vks"
    base = ["--registry", str(reg), "--keystore", str(ks)]
    fingerprint = VA._write_key(ks, "mono-k1")
    VA._append(
        reg,
        {
            "schema": EVENT_SCHEMA,
            "event": "REGISTER",
            "validator_id": "[FIXTURE] vld-mono",
            "validator_identity": "[FIXTURE] Monotonic Validator",
            "authorized_classes": ["DATA_CONTROLLER"],
            "appointment_authority": "[FIXTURE] General Counsel",
            "key_id": "mono-k1",
            "key_fingerprint": fingerprint,
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
            "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
            "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
        },
    )

    def _rotate(key_id, instant):
        cmd = ["rotate", "--validator-id", "[FIXTURE] vld-mono", "--key-id", key_id]
        return VA.main([*base, *cmd, "--instant", instant])

    # Not later than the REGISTER effective_from -> refused.
    assert _rotate("mono-k2", "2025-12-01T00:00:00Z") == 3
    assert _rotate("mono-k2", "2026-01-01T00:00:00Z") == 3
    # Strictly later -> accepted.
    assert _rotate("mono-k2", "2026-06-01T00:00:00Z") == 0
    # Equal to or before the accepted rotation -> refused.
    assert _rotate("mono-k3", "2026-06-01T00:00:00Z") == 3
    assert _rotate("mono-k3", "2026-03-01T00:00:00Z") == 3
    events = load_validator_events(reg)
    assert events is not None and [e["event"] for e in events] == ["REGISTER", "ROTATE"]


def test_rotation_at_or_after_revocation_refused(tmp_path):
    # authority_valid_at() treats the earliest REVOKE as terminal and
    # _key_windows() discards windows beginning at or after it, so a ROTATE
    # scheduled at or after that instant would be appended, print ROTATED,
    # and hand back a key that can never validate an attestation. Refused
    # loudly at write time instead; rotations strictly BEFORE the revocation
    # stay legal (their window is trimmed at the revocation instant).
    import validator_admin as VA

    reg = tmp_path / "vreg.jsonl"
    ks = tmp_path / "vks"
    base = ["--registry", str(reg), "--keystore", str(ks)]
    fingerprint = VA._write_key(ks, "rev-k1")
    VA._append(
        reg,
        {
            "schema": EVENT_SCHEMA,
            "event": "REGISTER",
            "validator_id": "[FIXTURE] vld-rev",
            "validator_identity": "[FIXTURE] Revoked Validator",
            "authorized_classes": ["DATA_CONTROLLER"],
            "appointment_authority": "[FIXTURE] General Counsel",
            "key_id": "rev-k1",
            "key_fingerprint": fingerprint,
            "effective_from": "2026-01-01T00:00:00Z",
            "effective_until": None,
            "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
            "appointment_binding": sha256_hex(b"[FIXTURE] appointment binding"),
            "appointment_evidence_digests": [sha256_hex(b"[FIXTURE] appointment deed")],
        },
    )
    revoke = ["revoke", "--validator-id", "[FIXTURE] vld-rev"]
    assert VA.main([*base, *revoke, "--instant", "2026-06-01T00:00:00Z"]) == 0

    def _rotate(key_id, instant):
        cmd = ["rotate", "--validator-id", "[FIXTURE] vld-rev", "--key-id", key_id]
        return VA.main([*base, *cmd, "--instant", instant])

    # At the revocation instant -> refused; after it -> refused. Neither
    # attempt may persist an event or a successor key.
    assert _rotate("rev-k2", "2026-06-01T00:00:00Z") == 3
    assert _rotate("rev-k2", "2026-07-01T00:00:00Z") == 3
    assert not (ks / "rev-k2").exists()
    # Strictly before the revocation -> still a legal (window-trimmed) key.
    assert _rotate("rev-k2", "2026-03-01T00:00:00Z") == 0
    events = load_validator_events(reg)
    assert events is not None and [e["event"] for e in events] == [
        "REGISTER",
        "REVOKE",
        "ROTATE",
    ]


def test_governed_derivation_is_deterministic(tmp_path):
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    events = load_validator_events(trust["registry"])
    states = {_gstate(dict(ev), trust, events=events) for _ in range(5)}
    assert states == {ACTIVE}


# --------------------------------------------------------------------------- #
# Regressions: terminal revocation by logical id, freshness boundary, and a
# verifiable trust root behind every READY verdict.
# --------------------------------------------------------------------------- #


def test_revocation_is_terminal_for_the_logical_id(substrate, tmp_path):
    # The registry is append-only: revoking evidence appends a COPY of the
    # record carrying revoked_at. Lifecycle is derived per row, so without a
    # registry-wide revoked-id set the ORIGINAL row (no revoked_at) keeps
    # deriving ACTIVE and keeps routing — a fully revoked authority that
    # still transitions requests. Revocation must be terminal for the id.
    from authority_lifecycle import active_records, lifecycle_distribution

    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    assert _gstate(ev, trust) == ACTIVE  # positive control: the row alone routes
    revoked_copy = dict(ev, revoked_at="2026-08-10T11:30:00Z")
    # Intrinsic lifecycle layer: every representation of the id is REVOKED.
    assert active_records([ev, revoked_copy], INSTANT) == []
    dist = lifecycle_distribution([ev, revoked_copy], INSTANT)
    assert dist[REVOKED] == 2
    assert dist[ACTIVE] == 0
    # Governed layer + verifier: nothing routes, nothing transitions.
    st = _compute(substrate, tmp_path, [ev, revoked_copy], trust=trust)
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][REVOKED] == 2
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 0


def test_junk_revocation_row_cannot_revoke_an_established_id(tmp_path):
    # Only rows satisfying the onboarding contract count toward the revoked-id
    # set: a bare junk line naming an established id must not become a
    # denial-of-authority primitive.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    junk = {
        "authority_evidence_id": ev["authority_evidence_id"],
        "revoked_at": "2026-08-10T11:30:00Z",
    }
    from authority_lifecycle import revoked_ids_of

    assert revoked_ids_of([ev, junk]) == set()
    assert _gstate(ev, trust) == ACTIVE


def test_freshness_expires_at_the_exact_day_boundary(tmp_path):
    # `.days` truncation discarded up to 23:59:59 of age: at 30 days + 12
    # hours the truncated age is still "30 days", so a 30-day policy kept the
    # evidence routable for almost a full 31st day. Staleness must compare
    # the complete duration.
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, max_age_days=30)
    ev = _attested(_evidence())  # freshness basis: validated_at 2026-08-10T11:00:00Z
    # Exactly 30 days old — at the boundary, not yet past it.
    assert _gstate(ev, trust, instant="2026-09-09T11:00:00Z", policy=policy) == ACTIVE
    # 30 days + 12 hours — past the boundary; must demote, not stay "fresh".
    assert _gstate(ev, trust, instant="2026-09-09T23:00:00Z", policy=policy) == REQUIRES_REVIEW


def test_malformed_validator_registry_blocks_integration(substrate, tmp_path):
    # A validator registry that cannot be parsed correctly makes every record
    # non-routable — but "nothing routes" must not read as a HEALTHY
    # AUTHORITY_LAYER_READY. An unverifiable trust root is INTEGRATION_BLOCKED.
    bad = tmp_path / "vreg_bad.jsonl"
    bad.write_text("{ not json\n", encoding="utf-8")
    trust = {"registry": bad, "keystore": tmp_path / "vks_bad"}
    st = _compute(substrate, tmp_path, [_attested(_evidence())], trust=trust)
    assert st["report"]["validator_trust_root_intact"] is False
    assert st["report"]["ready_to_send"] == 0
    assert st["verdict"] == "INTEGRATION_BLOCKED"


def test_broken_validator_chain_blocks_integration(substrate, tmp_path):
    # A bound field edited post-hoc breaks the GENESIS-rooted hash chain: the
    # trust root is tainted, so the verdict must be INTEGRATION_BLOCKED —
    # never READY-because-nothing-routes.
    trust = fixture_trust(tmp_path)
    lines = trust["registry"].read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["validator_id"] = "[FIXTURE] vld-hijacked"
    lines[0] = json.dumps(first, sort_keys=True)
    trust["registry"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = load_validator_events(trust["registry"])
    assert events is not None and not chain_intact(events)
    st = _compute(substrate, tmp_path, [_attested(_evidence())], trust=trust)
    assert st["report"]["validator_trust_root_intact"] is False
    assert st["report"]["ready_to_send"] == 0
    assert st["verdict"] == "INTEGRATION_BLOCKED"
