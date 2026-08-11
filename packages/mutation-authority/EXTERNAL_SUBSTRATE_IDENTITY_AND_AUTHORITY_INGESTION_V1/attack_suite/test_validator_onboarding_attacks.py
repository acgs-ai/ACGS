"""Adversarial suite for EXTERNAL_VALIDATOR_ONBOARDING_V1.

Attacks the validator onboarding protocol: self-appointment, copied
identities, scope expansion, expired/revoked appointments, key substitution,
registry rollback, forged onboarding evidence, partial metadata, conflicting
appointments. Every attack must fail closed; the ceremony lifecycle
(DISCOVERED → APPOINTMENT_PENDING → KEY_BOUND → ACTIVE → ROTATED → REVOKED)
is derived, never stored.

Hermetic: tmp registries/keystores only; every identity is [FIXTURE]-marked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import onboard_validator as OV  # noqa: E402
from _canonical import hmac_sign, sha256_hex  # noqa: E402
from validator_onboarding import (  # noqa: E402
    ACTIVE,
    APPOINTMENT_PENDING,
    DISCOVERED,
    KEY_BOUND,
    REVOKED,
    ROTATED,
    AppointmentError,
    appointment_binding,
    derive_ceremony_state,
    key_ownership_payload,
    registration_provenance_ok,
    validate_appointment,
)
from validator_trust import (  # noqa: E402
    EVENT_SCHEMA,
    chain_intact,
    event_binding,
    load_validator_events,
    verify_attestation_trust,
)

INSTANT = "2026-08-10T12:00:00Z"
EXT_KEY = b"e" * 32
EXT_VALIDATOR = "[FIXTURE] vld-ext"
EXT_KEY_ID = "ext-k1"

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def fixture_appointment(tmp_path, **overrides):
    """A [FIXTURE] evidence-backed appointment with a provably owned HMAC key.
    Returns (appointment, deed_path). Isolated to tmp; nothing touches
    production registries."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    deed = tmp_path / "appointment_deed"
    if not deed.exists():
        deed.write_text("[FIXTURE] board resolution appointing external validator")
    ks = tmp_path / "vks"
    ks.mkdir(exist_ok=True)
    (ks / EXT_KEY_ID).write_bytes(EXT_KEY)
    app = {
        "validator_appointment_id": "VA-FIX-1",
        "validator_id": EXT_VALIDATOR,
        "subject_identity": "[FIXTURE] Jane Counsel",
        "organization": "[FIXTURE] Firm LLP",
        "authorized_classes": ["DATA_CONTROLLER"],
        "jurisdiction": "[FIXTURE] Jurisdiction X",
        "appointment_authority": "[FIXTURE] Client Board",
        "effective_from": "2026-01-01T00:00:00Z",
        "effective_until": None,
        "revocation_conditions": "[FIXTURE] termination of the engagement",
        "appointment_evidence": [
            {
                "source_type": "SIGNED_APPOINTMENT",
                "source_reference": str(deed),
                "source_digest": sha256_hex(deed.read_bytes()),
            }
        ],
        "key_binding": {
            "key_id": EXT_KEY_ID,
            "key_algorithm": "hmac-sha256",
            "key_fingerprint": sha256_hex(EXT_KEY),
            "key_ownership_proof": "",
        },
    }
    app.update(overrides)
    app["key_binding"]["key_ownership_proof"] = hmac_sign(EXT_KEY, key_ownership_payload(app))
    return app, deed


def _onboard(tmp_path, app, deed, *, instant=INSTANT, evidence=None):
    rec = tmp_path / "appointment.json"
    rec.write_text(json.dumps(app), encoding="utf-8")
    return OV.main(
        [
            "--appointment",
            str(rec),
            *[a for p in (evidence or [deed]) for a in ("--evidence", str(p))],
            "--registry",
            str(tmp_path / "vreg.jsonl"),
            "--keystore",
            str(tmp_path / "vks"),
            "--instant",
            instant,
        ]
    )


def _ceremony(app, tmp_path, *, instant=INSTANT):
    return derive_ceremony_state(
        app,
        events=load_validator_events(tmp_path / "vreg.jsonl"),
        keystore_dir=tmp_path / "vks",
        instant=instant,
    )


# --------------------------------------------------------------------------- #
# The required onboarding attacks
# --------------------------------------------------------------------------- #


def test_ova1_self_appointed_validator_refused(tmp_path):
    app, deed = fixture_appointment(tmp_path)
    app["appointment_authority"] = app["subject_identity"]  # appoints themself
    with pytest.raises(AppointmentError, match="self-appointed"):
        validate_appointment(app)
    assert _onboard(tmp_path, app, deed) == 3
    assert not (tmp_path / "vreg.jsonl").exists()


def test_ova2_copied_validator_identity_refused(tmp_path):
    # The same appointment evidence cannot back a second, different validator.
    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    thief, _ = fixture_appointment(tmp_path, validator_id="[FORGED] vld-thief")
    assert _onboard(tmp_path, thief, deed) == 3  # evidence already consumed
    events = load_validator_events(tmp_path / "vreg.jsonl")
    assert len([e for e in events if e["event"] == "REGISTER"]) == 1


def test_onboarding_serializes_on_the_registry_lock(tmp_path):
    # The conflict checks (gate 5) and the append (gate 6) run under ONE
    # exclusive registry lock: while another process holds it, onboarding
    # blocks instead of racing the read-check-append sequence and
    # double-registering against the same registry snapshot.
    import fcntl
    import threading

    app, deed = fixture_appointment(tmp_path)
    lock_path = tmp_path / "vreg.jsonl.lock"
    fh = lock_path.open("a", encoding="utf-8")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    done = threading.Event()
    rc: list[int] = []

    def run():
        rc.append(_onboard(tmp_path, app, deed))
        done.set()

    t = threading.Thread(target=run)
    t.start()
    try:
        assert not done.wait(1.0)  # onboarding is blocked on the held lock
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()
    t.join(10)
    assert done.is_set() and rc == [0]  # proceeds once the lock releases
    events = load_validator_events(tmp_path / "vreg.jsonl")
    assert len([e for e in events if e["event"] == "REGISTER"]) == 1


def test_ova3_unauthorized_scope_expansion_detected(tmp_path):
    # A forged REGISTER event claiming MORE classes than the appointment
    # grants fails provenance and can never derive ACTIVE.
    app, deed = fixture_appointment(tmp_path)  # grants DATA_CONTROLLER only
    assert _onboard(tmp_path, app, deed) == 0
    events = load_validator_events(tmp_path / "vreg.jsonl")
    reg = events[0]
    ok, _ = registration_provenance_ok(app, reg)
    assert ok  # honest registration is provenant
    forged = dict(reg)
    forged["authorized_classes"] = ["DATA_CONTROLLER", "COUNSEL_OR_RIGHTS_AUTHORITY"]
    ok, reason = registration_provenance_ok(app, forged)
    assert not ok and reason == "unauthorized_scope_expansion"
    # Written into the registry, the forgery also breaks the hash chain.
    (tmp_path / "vreg.jsonl").write_text(json.dumps(forged) + "\n", encoding="utf-8")
    assert not chain_intact(load_validator_events(tmp_path / "vreg.jsonl"))
    assert _ceremony(app, tmp_path) == KEY_BOUND  # tainted registry: never ACTIVE


def test_ova4_expired_appointment_refused(tmp_path):
    app, deed = fixture_appointment(tmp_path, effective_until="2026-06-01T00:00:00Z")
    assert _onboard(tmp_path, app, deed) == 3  # INSTANT is past the period
    assert not (tmp_path / "vreg.jsonl").exists()


def test_ova5_revoked_appointment_derives_revoked(tmp_path):
    import validator_admin as VA

    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    assert _ceremony(app, tmp_path) == ACTIVE
    base = ["--registry", str(tmp_path / "vreg.jsonl"), "--keystore", str(tmp_path / "vks")]
    assert (
        VA.main(
            [
                *base,
                "revoke",
                "--validator-id",
                EXT_VALIDATOR,
                "--instant",
                "2026-08-11T00:00:00Z",
            ]
        )
        == 0
    )
    # The revocation is scheduled for Aug 11: at the earlier evaluation
    # instant (Aug 10) it has not taken effect yet (consistent with
    # authority_valid_at: rev <= at), so the ceremony is still ACTIVE.
    assert _ceremony(app, tmp_path) == ACTIVE
    # From its effective instant onward it derives REVOKED.
    assert _ceremony(app, tmp_path, instant="2026-08-11T00:00:00Z") == REVOKED
    assert _ceremony(app, tmp_path, instant="2026-08-12T00:00:00Z") == REVOKED
    # No evaluation instant to place the revocation against -> fail closed.
    assert _ceremony(app, tmp_path, instant=None) == REVOKED
    # And the appointment period ending derives REVOKED too (no event needed).
    app2, _ = fixture_appointment(tmp_path)
    assert (
        derive_ceremony_state(
            dict(app2, effective_until="2026-08-01T00:00:00Z"),
            events=[],
            keystore_dir=tmp_path / "vks",
            instant=INSTANT,
        )
        != ACTIVE
    )


def test_ova6_key_substitution_fails_closed(tmp_path):
    app, deed = fixture_appointment(tmp_path)
    (tmp_path / "vks" / EXT_KEY_ID).write_bytes(b"z" * 32)  # substituted key
    assert _ceremony(app, tmp_path) == APPOINTMENT_PENDING  # ownership unprovable
    assert _onboard(tmp_path, app, deed) == 4
    assert not (tmp_path / "vreg.jsonl").exists()


def test_ova7_registry_rollback_detected(tmp_path):
    import validator_admin as VA

    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    base = ["--registry", str(tmp_path / "vreg.jsonl"), "--keystore", str(tmp_path / "vks")]
    assert (
        VA.main(
            [
                *base,
                "rotate",
                "--validator-id",
                EXT_VALIDATOR,
                "--key-id",
                "ext-k2",
                "--instant",
                "2026-08-11T00:00:00Z",
            ]
        )
        == 0
    )
    assert (
        VA.main(
            [*base, "revoke", "--validator-id", EXT_VALIDATOR, "--instant", "2026-08-12T00:00:00Z"]
        )
        == 0
    )
    lines = (tmp_path / "vreg.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    # Excise the ROTATE event (mid-history rollback): the chain breaks.
    (tmp_path / "vreg.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    events = load_validator_events(tmp_path / "vreg.jsonl")
    assert not chain_intact(events)
    assert _ceremony(app, tmp_path) == KEY_BOUND  # never ACTIVE on a tainted registry
    # And no attestation can be trusted against a broken chain.
    ok, reason = verify_attestation_trust(
        {"authority_type": "DATA_CONTROLLER"},
        {"validator_id": EXT_VALIDATOR},
        events=events,
        keystore_dir=tmp_path / "vks",
    )
    assert not ok and reason == "validator_registry_chain_broken"


def test_rotate_refuses_corrupted_predecessor_keystore_key(tmp_path):
    # The auto-sign rotate path must verify the keystore bytes against the
    # predecessor's REGISTERED fingerprint before signing: signing with
    # corrupted/replaced key bytes would append a ROTATE that
    # rotations_authenticated() rejects at read time — the command would
    # report success while silently untrusting the validator's whole history.
    import validator_admin as VA

    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    (tmp_path / "vks" / EXT_KEY_ID).write_bytes(b"z" * 32)  # corrupted key file
    base = ["--registry", str(tmp_path / "vreg.jsonl"), "--keystore", str(tmp_path / "vks")]
    assert (
        VA.main(
            [
                *base,
                "rotate",
                "--validator-id",
                EXT_VALIDATOR,
                "--key-id",
                "ext-k2",
                "--instant",
                "2026-08-11T00:00:00Z",
            ]
        )
        == 3
    )
    # Nothing appended: the registry still holds only the REGISTER event.
    events = load_validator_events(tmp_path / "vreg.jsonl")
    assert [e["event"] for e in events] == ["REGISTER"]
    # No stray successor key was left behind either.
    assert not (tmp_path / "vks" / "ext-k2").exists()


def test_ova8_forged_onboarding_evidence_refused(tmp_path):
    app, deed = fixture_appointment(tmp_path)
    deed.write_text("[TAMPERED] different content than was appointed")
    assert _onboard(tmp_path, app, deed) == 3  # digest mismatch = forged evidence
    assert not (tmp_path / "vreg.jsonl").exists()


def test_ova9_partial_metadata_refused(tmp_path):
    for missing in (
        "subject_identity",
        "organization",
        "jurisdiction",
        "appointment_authority",
        "revocation_conditions",
    ):
        app, _ = fixture_appointment(tmp_path / missing.replace("_", "-"))
        del app[missing]
        with pytest.raises(AppointmentError, match="partial appointment metadata"):
            validate_appointment(app)
        assert (
            derive_ceremony_state(app, events=[], keystore_dir=tmp_path / "vks", instant=INSTANT)
            == DISCOVERED
        )
    # Evidence-free and key-free appointments are equally refused.
    app, _ = fixture_appointment(tmp_path / "noev")
    app["appointment_evidence"] = []
    with pytest.raises(AppointmentError):
        validate_appointment(app)


def test_ova10_conflicting_appointments_refused(tmp_path):
    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    # A second appointment for the SAME validator with a different scope and
    # its own evidence: registration is refused — supersession is an explicit
    # rotate/revoke ceremony, never a silent overwrite.
    deed2 = tmp_path / "deed2"
    deed2.write_text("[FIXTURE] conflicting second appointment")
    conflicting, _ = fixture_appointment(tmp_path)
    conflicting["validator_appointment_id"] = "VA-FIX-2"
    conflicting["authorized_classes"] = ["COUNSEL_OR_RIGHTS_AUTHORITY"]
    conflicting["appointment_evidence"] = [
        {
            "source_type": "SIGNED_APPOINTMENT",
            "source_reference": str(deed2),
            "source_digest": sha256_hex(deed2.read_bytes()),
        }
    ]
    conflicting["key_binding"]["key_ownership_proof"] = hmac_sign(
        EXT_KEY, key_ownership_payload(conflicting)
    )
    assert _onboard(tmp_path, conflicting, deed2, evidence=[deed2]) == 3
    events = load_validator_events(tmp_path / "vreg.jsonl")
    assert len([e for e in events if e["event"] == "REGISTER"]) == 1


# --------------------------------------------------------------------------- #
# Ceremony ladder (derived, never stored) + end-to-end trust
# --------------------------------------------------------------------------- #


def test_ceremony_ladder_derives_each_state(tmp_path):
    import validator_admin as VA

    # DISCOVERED: no valid evidence digests.
    app, deed = fixture_appointment(tmp_path)
    broken = dict(app, appointment_evidence=[])
    assert _ceremony(broken, tmp_path) == DISCOVERED
    # APPOINTMENT_PENDING: evidence-backed, ownership not provable.
    pending = json.loads(json.dumps(app))
    pending["key_binding"]["key_ownership_proof"] = "0" * 64
    assert _ceremony(pending, tmp_path) == APPOINTMENT_PENDING
    # KEY_BOUND: provably owned key, not yet registered.
    assert _ceremony(app, tmp_path) == KEY_BOUND
    # ACTIVE: registered against this appointment, inside the period.
    assert _onboard(tmp_path, app, deed) == 0
    assert _ceremony(app, tmp_path) == ACTIVE
    # ROTATED: successor key issued; still trusted, history auditable.
    base = ["--registry", str(tmp_path / "vreg.jsonl"), "--keystore", str(tmp_path / "vks")]
    assert (
        VA.main(
            [
                *base,
                "rotate",
                "--validator-id",
                EXT_VALIDATOR,
                "--key-id",
                "ext-k2",
                "--instant",
                "2026-08-11T00:00:00Z",
            ]
        )
        == 0
    )
    assert _ceremony(app, tmp_path) == ROTATED
    # REVOKED: terminal from its effective instant onward. Before that
    # instant the scheduled revocation has not taken effect (consistent
    # with authority_valid_at), so the ceremony is still ROTATED.
    assert (
        VA.main(
            [*base, "revoke", "--validator-id", EXT_VALIDATOR, "--instant", "2026-08-12T00:00:00Z"]
        )
        == 0
    )
    assert _ceremony(app, tmp_path) == ROTATED
    assert _ceremony(app, tmp_path, instant="2026-08-12T00:00:00Z") == REVOKED


def test_onboarded_validator_attestations_are_trusted(tmp_path):
    # The whole point: a validator onboarded through the evidence-backed
    # protocol can produce attestations the trust layer accepts.
    from authority_lifecycle import attestation_binding as rec_binding
    from test_attacks import _evidence
    from validator_trust import attestation_payload

    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    rec = dict(_evidence(authority_type="DATA_CONTROLLER"))
    rec["issuer_or_appointing_party"] = "[FIXTURE] Board"
    att = {
        "validator_identity": app["subject_identity"],
        "validation_method": "[FIXTURE] reviewed artifact",
        "validated_at": INSTANT,
        "record_binding": rec_binding(rec),
        "validator_id": EXT_VALIDATOR,
        "key_id": EXT_KEY_ID,
    }
    att["attestation_signature"] = hmac_sign(EXT_KEY, attestation_payload(att))
    rec["validation"] = att
    ok, reason = verify_attestation_trust(
        rec,
        att,
        events=load_validator_events(tmp_path / "vreg.jsonl"),
        keystore_dir=tmp_path / "vks",
    )
    assert ok, reason


def test_appointment_binding_content_sensitive(tmp_path):
    app, _ = fixture_appointment(tmp_path)
    b = appointment_binding(app)
    assert b == appointment_binding(json.loads(json.dumps(app)))  # deterministic
    assert b != appointment_binding(dict(app, subject_identity="other"))
    assert b != appointment_binding(dict(app, authorized_classes=[]))


def test_preexisting_corrupt_artifact_replaced_before_registration(tmp_path):
    # A digest-named artifact planted in the retention directory BEFORE
    # onboarding must never poison the registration: the retained bytes are
    # verified against the digest, and a mismatching regular file is replaced
    # atomically with the verified supplied bytes so the ceremony derives
    # ACTIVE with provenance that keeps verifying.
    app, deed = fixture_appointment(tmp_path)
    digest = sha256_hex(deed.read_bytes())
    artifact_dir = tmp_path / "vks" / ".appointment_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / digest).write_text("[POISON] wrong bytes under the right name")
    assert _onboard(tmp_path, app, deed) == 0
    assert sha256_hex((artifact_dir / digest).read_bytes()) == digest
    assert _ceremony(app, tmp_path) == ACTIVE


def test_preexisting_non_regular_artifact_refuses_registration(tmp_path):
    # A non-regular path (directory/symlink) squatting on the digest name is
    # never followed or overwritten: onboarding fails closed with nothing
    # appended to the registry.
    app, deed = fixture_appointment(tmp_path)
    digest = sha256_hex(deed.read_bytes())
    artifact_dir = tmp_path / "vks" / ".appointment_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / digest).mkdir()
    assert _onboard(tmp_path, app, deed) == 2
    assert not (tmp_path / "vreg.jsonl").exists()


def test_unauthenticated_rotation_never_derives_rotated(tmp_path):
    # A chain-linked ROTATE forged WITHOUT a predecessor-signed
    # rotation_authorization must not derive ROTATED: the ceremony falls back
    # to KEY_BOUND (never a trusted state) instead of reporting a successful
    # key ceremony for a rotation the trust layer rejects.
    app, deed = fixture_appointment(tmp_path)
    assert _onboard(tmp_path, app, deed) == 0
    assert _ceremony(app, tmp_path) == ACTIVE
    events = load_validator_events(tmp_path / "vreg.jsonl")
    forged = {
        "schema": EVENT_SCHEMA,
        "event": "ROTATE",
        "validator_id": EXT_VALIDATOR,
        "key_id": "ext-k-attacker",
        "key_fingerprint": sha256_hex(b"a" * 32),
        "instant": "2026-08-01T00:00:00Z",
        "prev_event_binding": events[-1]["event_binding"],
    }
    forged["event_binding"] = event_binding(forged)
    with (tmp_path / "vreg.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged, sort_keys=True) + "\n")
    assert _ceremony(app, tmp_path) == KEY_BOUND
