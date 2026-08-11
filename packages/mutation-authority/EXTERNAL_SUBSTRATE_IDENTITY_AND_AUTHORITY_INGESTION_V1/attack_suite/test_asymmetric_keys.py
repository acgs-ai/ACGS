"""ASYMMETRIC_VALIDATOR_KEYS_V1 — Ed25519 dual-mode verification suite.

HMAC compatibility remains (the entire existing suite runs in HMAC mode);
this suite proves the Ed25519 lane: valid signatures route, wrong keys /
altered payloads / wrong validator ids / revoked keys fail closed, rotated
key history stays auditable, and mode confusion (HMAC key, Ed25519 claim)
is refused.

Skips cleanly when the optional `cryptography` backend is absent — in which
case every Ed25519 verification in the package fails closed by construction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _ed25519  # noqa: E402
from _canonical import sha256_hex  # noqa: E402
from authority_lifecycle import ACTIVE, attestation_binding  # noqa: E402
from test_attacks import FIXTURE_DOC, INSTANT, _evidence, build_fixture_substrate  # noqa: E402
from test_onboarding_attacks import _compute, _fixture_receipt  # noqa: E402
from validator_onboarding import (  # noqa: E402
    appointment_binding,
    key_ownership_payload,
)
from validator_trust import (  # noqa: E402
    APPOINTMENT_ARTIFACTS_DIR_NAME,
    APPOINTMENTS_DIR_NAME,
    ED25519,
    EVENT_SCHEMA,
    GENESIS,
    INVALIDATED,
    attestation_payload_v2,
    event_binding,
    load_validator_events,
    rotation_payload,
    verify_attestation_trust,
)

pytestmark = pytest.mark.skipif(
    not _ed25519.AVAILABLE, reason="optional cryptography backend not installed"
)

ED_VALIDATOR = "[FIXTURE] vld-ed"
ED_KEY_ID = "ed-k1"

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def ed_trust(tmp_path):
    """Registry with one Ed25519 validator; public key IN the registry event,
    so verification needs no keystore access (third-party verifiable)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    priv, pub = _ed25519.generate()
    ks = tmp_path / "edks"
    ks.mkdir(exist_ok=True)  # keystore unused for ed25519 signature verify
    # Real retained appointment material (as the onboarding ceremony retains
    # it): REGISTER provenance must resolve to it, not to a digest-shaped
    # placeholder.
    appointment = {
        "validator_appointment_id": "[FIXTURE] app-ed",
        "validator_id": ED_VALIDATOR,
        "subject_identity": "[FIXTURE] Ed Validator",
        "organization": "[FIXTURE] Org",
        "jurisdiction": "[FIXTURE] Jurisdiction X",
        "appointment_authority": "[FIXTURE] General Counsel",
        "authorized_classes": ["COUNSEL_OR_RIGHTS_AUTHORITY", "DATA_CONTROLLER"],
        "effective_from": "2026-01-01T00:00:00Z",
        "effective_until": None,
        "revocation_conditions": "[FIXTURE] resignation or dismissal",
        "appointment_evidence": [
            {
                "source_type": "appointment_deed",
                "source_reference": "[FIXTURE] deed",
                "source_digest": sha256_hex(FIXTURE_DOC),
            }
        ],
        "key_binding": {
            "key_id": ED_KEY_ID,
            "key_algorithm": ED25519,
            "key_fingerprint": sha256_hex(pub),
            "public_key": pub.hex(),
        },
    }
    appointment["key_binding"]["key_ownership_proof"] = _ed25519.sign(
        priv, key_ownership_payload(appointment)
    )
    binding = appointment_binding(appointment)
    app_dir = ks / APPOINTMENTS_DIR_NAME
    app_dir.mkdir(exist_ok=True)
    (app_dir / f"{binding}.json").write_text(
        json.dumps(appointment, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Retain the appointment artifact bytes by digest, as the ceremony does:
    # provenance digests must re-verify against retained bytes.
    art_dir = ks / APPOINTMENT_ARTIFACTS_DIR_NAME
    art_dir.mkdir(exist_ok=True)
    (art_dir / sha256_hex(FIXTURE_DOC)).write_bytes(FIXTURE_DOC)
    ev = {
        "schema": EVENT_SCHEMA,
        "event": "REGISTER",
        "validator_id": ED_VALIDATOR,
        "validator_identity": "[FIXTURE] Ed Validator",
        "authorized_classes": ["COUNSEL_OR_RIGHTS_AUTHORITY", "DATA_CONTROLLER"],
        "appointment_authority": "[FIXTURE] General Counsel",
        "key_id": ED_KEY_ID,
        "key_algorithm": ED25519,
        "key_fingerprint": sha256_hex(pub),
        "public_key": pub.hex(),
        "effective_from": "2026-01-01T00:00:00Z",
        "effective_until": None,
        "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
        "appointment_binding": binding,
        "appointment_evidence_digests": [sha256_hex(FIXTURE_DOC)],
        "prev_event_binding": GENESIS,
    }
    ev["event_binding"] = event_binding(ev)
    reg = tmp_path / "ed_vreg.jsonl"
    reg.write_text(json.dumps(ev, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "registry": reg,
        "keystore": ks,
        "priv": priv,
        "pub": pub,
        "validator_id": ED_VALIDATOR,
    }


def _ed_evidence(trust, *, validated_at="2026-08-10T11:00:00Z", key_id=ED_KEY_ID, priv=None):
    """A controller evidence record attested with an Ed25519 signature over the
    complete v2 payload (validator id, key fingerprint, attestation content,
    evidence identity, timestamp, validation class)."""
    ev = dict(_evidence(authority_type="DATA_CONTROLLER"))
    ev["issuer_or_appointing_party"] = "[FIXTURE] Board"
    att = {
        "validator_identity": "[FIXTURE] Ed Validator",
        "validation_method": "[FIXTURE] reviewed artifact",
        "validated_at": validated_at,
        "record_binding": attestation_binding(ev),
        "validator_id": trust["validator_id"],
        "key_id": key_id,
        "signature_algorithm": ED25519,
        "key_fingerprint": sha256_hex(trust["pub"]),
    }
    att["attestation_signature"] = _ed25519.sign(
        priv or trust["priv"], attestation_payload_v2(ev, att)
    )
    ev["validation"] = att
    rec = _fixture_receipt(ev)
    ev["ingestion_receipt"] = rec["receipt_id"]
    ev["ingestion_receipt_record"] = rec
    return ev


def _trusted(ev, trust):
    return verify_attestation_trust(
        ev,
        ev["validation"],
        events=load_validator_events(trust["registry"]),
        keystore_dir=trust["keystore"],
    )


def _append(trust, event):
    events = load_validator_events(trust["registry"])
    event = dict(event)
    event["prev_event_binding"] = events[-1]["event_binding"]
    event["event_binding"] = event_binding(event)
    with trust["registry"].open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


@pytest.fixture
def substrate(tmp_path):
    return build_fixture_substrate(tmp_path)


# --------------------------------------------------------------------------- #
# Required Ed25519 tests
# --------------------------------------------------------------------------- #


def test_valid_ed25519_signature_routes(substrate, tmp_path):
    trust = ed_trust(tmp_path)
    ev = _ed_evidence(trust)
    ok, reason = _trusted(ev, trust)
    assert ok, reason
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 1
    assert st["report"]["ready_to_send"] == 2  # fixture controller pair
    assert all(st["invariants"].values())


def test_wrong_key_fails(tmp_path):
    trust = ed_trust(tmp_path)
    other_priv, _other_pub = _ed25519.generate()
    ev = _ed_evidence(trust, priv=other_priv)  # signed by the wrong key
    ok, reason = _trusted(ev, trust)
    assert not ok and reason == "attestation_signature_invalid"


def test_altered_payload_fails(substrate, tmp_path):
    trust = ed_trust(tmp_path)
    for field, value in (
        ("validation_method", "[TAMPERED] other method"),
        ("validated_at", "2026-08-09T11:00:00Z"),
        ("disposition", "REJECTED"),
        ("key_fingerprint", "0" * 64),
    ):
        ev = _ed_evidence(trust)
        ev["validation"][field] = value
        ok, _reason = _trusted(ev, trust)
        assert not ok, field
    # And the evidence side of the binding: a record altered after signing
    # (evidence identity is inside the v2 payload) never routes.
    ev = _ed_evidence(trust)
    ev["source_digest"] = "b" * 64
    st = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st["report"]["ready_to_send"] == 0


def test_wrong_validator_id_fails(tmp_path):
    trust = ed_trust(tmp_path)
    ev = _ed_evidence(trust)
    ev["validation"]["validator_id"] = "[FORGED] someone-else"
    ok, reason = _trusted(ev, trust)
    assert not ok and reason in ("unknown_validator", "attestation_signature_invalid")


def test_revoked_key_fails(tmp_path):
    trust = ed_trust(tmp_path)
    _append(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "REVOKE",
            "validator_id": ED_VALIDATOR,
            "instant": "2026-08-01T00:00:00Z",
        },
    )
    ev = _ed_evidence(trust)  # validated_at 2026-08-10, after revocation
    ok, reason = _trusted(ev, trust)
    assert not ok and reason == "validator_authority_invalid_at_attestation"


def test_rotated_key_history_remains_auditable(tmp_path):
    trust = ed_trust(tmp_path)
    priv2, pub2 = _ed25519.generate()
    rot = {
        "schema": EVENT_SCHEMA,
        "event": "ROTATE",
        "validator_id": ED_VALIDATOR,
        "key_id": "ed-k2",
        "key_algorithm": ED25519,
        "key_fingerprint": sha256_hex(pub2),
        "public_key": pub2.hex(),
        "instant": "2026-09-01T00:00:00Z",
    }
    # The predecessor key (ed-k1) authorizes its own retirement.
    rot["rotation_authorization"] = _ed25519.sign(trust["priv"], rotation_payload(rot))
    _append(trust, rot)
    # An attestation signed with ed-k1 INSIDE its window stays verifiable
    # forever — rotation does not orphan history.
    old = _ed_evidence(trust, validated_at="2026-08-10T11:00:00Z")
    ok, reason = _trusted(old, trust)
    assert ok, reason
    # The same old key AFTER rotation is refused.
    stale = _ed_evidence(trust, validated_at="2026-09-15T00:00:00Z")
    ok, reason = _trusted(stale, trust)
    assert not ok and reason == "key_not_current_at_attestation"
    # The successor key signs post-rotation attestations.
    trust2 = dict(trust, priv=priv2, pub=pub2)
    fresh = _ed_evidence(trust2, validated_at="2026-09-15T00:00:00Z", key_id="ed-k2")
    ok, reason = _trusted(fresh, trust2)
    assert ok, reason


def test_algorithm_mode_confusion_refused(tmp_path):
    # An attestation claiming ed25519 against an HMAC-registered key (or vice
    # versa) is refused before any signature math runs.
    from test_onboarding_attacks import _attested, fixture_trust

    hmac_trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    ev["validation"]["signature_algorithm"] = ED25519
    ok, reason = verify_attestation_trust(
        ev,
        ev["validation"],
        events=load_validator_events(hmac_trust["registry"]),
        keystore_dir=hmac_trust["keystore"],
    )
    assert not ok and reason == "signature_algorithm_mismatch"
    from validator_trust import DEFAULT_POLICY, derive_governed_state

    state = derive_governed_state(
        ev,
        instant=INSTANT,
        superseded_ids=set(),
        in_registry=True,
        events=load_validator_events(hmac_trust["registry"]),
        keystore_dir=hmac_trust["keystore"],
        policy=dict(DEFAULT_POLICY),
        substrate_identity="fixture-substrate",
        substrate_digest="d" * 64,
    )
    assert state == INVALIDATED


def test_cli_rotation_preserves_ed25519_algorithm(tmp_path):
    # Rotating an Ed25519 validator must not silently downgrade it to a
    # locally minted HMAC key: without an explicit successor public key the
    # rotation is refused; with one, the ROTATE event stays Ed25519 — and it
    # must carry the predecessor key's rotation authorization, which the CLI
    # cannot synthesize because the private key never leaves the validator.
    import validator_admin as VA

    trust = ed_trust(tmp_path)
    base = ["--registry", str(trust["registry"]), "--keystore", str(trust["keystore"])]
    rotate = ["rotate", "--validator-id", ED_VALIDATOR, "--key-id", "ed-k2"]
    assert VA.main([*base, *rotate, "--instant", "2026-09-01T00:00:00Z"]) == 3
    priv2, pub2 = _ed25519.generate()
    with_pub = [
        *base,
        *rotate,
        "--instant",
        "2026-09-01T00:00:00Z",
        "--public-key",
        pub2.hex(),
    ]
    # Without the predecessor's signature the rotation is refused.
    assert VA.main(with_pub) == 3
    # The validator signs the exact rotation payload the CLI will append.
    expected_event = {
        "schema": EVENT_SCHEMA,
        "event": "ROTATE",
        "validator_id": ED_VALIDATOR,
        "key_id": "ed-k2",
        "key_algorithm": ED25519,
        "instant": "2026-09-01T00:00:00Z",
        "public_key": pub2.hex(),
        "key_fingerprint": sha256_hex(pub2),
    }
    # A garbage authorization is refused at write time (verified against the
    # predecessor public key before append), not laundered into the registry.
    assert VA.main([*with_pub, "--rotation-authorization", "deadbeef"]) == 3
    authorization = _ed25519.sign(trust["priv"], rotation_payload(expected_event))
    assert VA.main([*with_pub, "--rotation-authorization", authorization]) == 0
    events = load_validator_events(trust["registry"])
    rot = events[-1]
    assert rot["event"] == "ROTATE"
    assert rot["key_algorithm"] == ED25519
    assert rot["public_key"] == pub2.hex()
    assert rot["key_fingerprint"] == sha256_hex(pub2)
    assert rot["rotation_authorization"] == authorization
    # No HMAC key material was minted for the ed25519 successor.
    assert not (trust["keystore"] / "ed-k2").exists()
    # The rotated registry verifies end to end: post-rotation attestations
    # under the new key are trusted (the rotation authenticates).
    trust2 = dict(trust, priv=priv2, pub=pub2)
    fresh = _ed_evidence(trust2, validated_at="2026-09-15T00:00:00Z", key_id="ed-k2")
    ok, reason = _trusted(fresh, trust2)
    assert ok, reason


def test_cli_rotation_rejects_reused_key_id(tmp_path):
    # An Ed25519 rotation that reuses an existing key_id with a NEW public
    # key must be refused at write time: if appended, _key_windows() would
    # treat the later event as current while _key_event_of() resolves the
    # FIRST event with that id, so post-rotation attestations verify against
    # the retired key and the "successfully rotated" validator is unusable.
    import validator_admin as VA

    trust = ed_trust(tmp_path)
    _priv2, pub2 = _ed25519.generate()
    reused = {
        "schema": EVENT_SCHEMA,
        "event": "ROTATE",
        "validator_id": ED_VALIDATOR,
        "key_id": ED_KEY_ID,  # already the REGISTER key id
        "key_algorithm": ED25519,
        "instant": "2026-09-01T00:00:00Z",
        "public_key": pub2.hex(),
        "key_fingerprint": sha256_hex(pub2),
    }
    authorization = _ed25519.sign(trust["priv"], rotation_payload(reused))
    rc = VA.main(
        [
            "--registry",
            str(trust["registry"]),
            "--keystore",
            str(trust["keystore"]),
            "rotate",
            "--validator-id",
            ED_VALIDATOR,
            "--key-id",
            ED_KEY_ID,
            "--instant",
            "2026-09-01T00:00:00Z",
            "--public-key",
            pub2.hex(),
            "--rotation-authorization",
            authorization,
        ]
    )
    assert rc == 3  # refused despite an otherwise-valid predecessor authorization
    events = load_validator_events(trust["registry"])
    assert len(events) == 1 and events[0]["event"] == "REGISTER"  # nothing appended
    # The validator remains fully usable under its original key.
    ok, reason = _trusted(_ed_evidence(trust), trust)
    assert ok, reason


def test_unauthorized_ed25519_rotation_fails_closed(tmp_path):
    # Attacker appends a chain-valid ROTATE naming a keypair they generated:
    # no signature by the retired key -> nothing the validator "signs" after
    # that rotation is trusted, including attacker attestations under the
    # planted key.
    trust = ed_trust(tmp_path)
    evil_priv, evil_pub = _ed25519.generate()
    _append(
        trust,
        {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": ED_VALIDATOR,
            "key_id": "ed-evil",
            "key_algorithm": ED25519,
            "key_fingerprint": sha256_hex(evil_pub),
            "public_key": evil_pub.hex(),
            "instant": "2026-08-01T00:00:00Z",
        },
    )
    evil_trust = dict(trust, priv=evil_priv, pub=evil_pub)
    forged = _ed_evidence(evil_trust, key_id="ed-evil")
    ok, reason = _trusted(forged, evil_trust)
    assert not ok and reason == "unauthenticated_rotation"
    # And even legitimate old-key attestations demand review of the tainted
    # history — the whole validator fails closed, not just the planted key.
    legit = _ed_evidence(trust, validated_at="2026-07-01T00:00:00Z")
    ok2, reason2 = _trusted(legit, trust)
    assert not ok2 and reason2 == "unauthenticated_rotation"
