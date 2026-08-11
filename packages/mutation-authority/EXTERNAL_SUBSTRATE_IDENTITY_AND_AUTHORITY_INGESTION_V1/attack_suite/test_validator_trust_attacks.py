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
    derive_governed_state,
    event_binding,
    load_validator_events,
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
    ev = _attested(_evidence())
    rejecting = _sign_att(
        {
            "validator_identity": "[FIXTURE] Legal Validator",
            "validation_method": "[FIXTURE] independent second review",
            "validated_at": "2026-08-10T11:30:00Z",
            "record_binding": attestation_binding(ev),
            "disposition": "REJECTED",
        }
    )
    ev["co_validations"] = [rejecting]
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
        {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": FIX_VALIDATOR,
            "key_id": "vk-2",
            "key_fingerprint": sha256_hex(b"w" * 32),
            "instant": "2026-07-01T00:00:00Z",
        },
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
        {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": FIX_VALIDATOR,
            "key_id": "vk-2",
            "key_fingerprint": sha256_hex(b"w" * 32),
            "instant": "2026-08-11T00:00:00Z",  # AFTER validated_at
        },
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
            "instant": "2026-08-15T00:00:00Z",  # AFTER validated_at 2026-08-10
        },
    )
    ev = _attested(_evidence())
    assert _gstate(ev, trust) == REQUIRES_REVIEW
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][REQUIRES_REVIEW] == 1


def test_freshness_age_demotes_to_requires_review(tmp_path):
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, max_age_days=30)
    ev = _attested(_evidence())  # validated_at 2026-08-10
    assert _gstate(ev, trust, instant=INSTANT, policy=policy) == ACTIVE  # 0 days old
    assert _gstate(ev, trust, instant="2026-10-10T12:00:00Z", policy=policy) == REQUIRES_REVIEW
    # last_verified_at refreshes the basis without touching the attestation.
    ev2 = dict(ev, last_verified_at="2026-10-01T00:00:00Z")
    assert _gstate(ev2, trust, instant="2026-10-10T12:00:00Z", policy=policy) == ACTIVE


def test_freshness_epoch_demotes_to_requires_review(tmp_path):
    trust = fixture_trust(tmp_path)
    policy = dict(DEFAULT_POLICY, minimum_epoch=2)
    ev = _attested(_evidence())
    assert _gstate(ev, trust, policy=policy) == REQUIRES_REVIEW  # no epoch recorded
    assert _gstate(dict(ev, verification_epoch=1), trust, policy=policy) == REQUIRES_REVIEW
    assert _gstate(dict(ev, verification_epoch=2), trust, policy=policy) == ACTIVE


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
    revoke = ["revoke", "--validator-id", "[FIXTURE] vld-cli"]
    assert VA.main([*base, *revoke, "--instant", "2026-07-01T00:00:00Z"]) == 0
    events = load_validator_events(reg)
    assert events is not None and len(events) == 3
    assert all(e["event_binding"] == event_binding(e) for e in events)
    # Keys exist and match their registered fingerprints.
    for e in events:
        if e.get("key_id"):
            assert sha256_hex((ks / e["key_id"]).read_bytes()) == e["key_fingerprint"]


def test_governed_derivation_is_deterministic(tmp_path):
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    events = load_validator_events(trust["registry"])
    states = {_gstate(dict(ev), trust, events=events) for _ in range(5)}
    assert states == {ACTIVE}
