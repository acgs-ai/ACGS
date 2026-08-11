"""Adversarial suite for REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1.

Covers the eight required onboarding attacks — unsigned evidence, expired
appointment, superseded controller, scope mismatch, identity drift, evidence
replay, fabricated authority records, path relocation with changed content —
plus deterministic-verification checks and pipeline exit-code contracts.

Since VALIDATOR_TRUST_GOVERNANCE_V1, routing additionally requires the
attestation's validator to be registered and authorized, so these tests build
an isolated fixture validator trust context (registry + keystore in tmp).

Hermetic: synthetic substrate + tmp registries only. All synthetic evidence and
all fixture validators live in isolated test fixtures; nothing here touches the
production registries or the real external substrate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_authority_state as V  # noqa: E402
from _canonical import hmac_sign, sha256_hex  # noqa: E402
from _identity import build_manifest  # noqa: E402
from _registry import append_record, read_registry  # noqa: E402
from authority_lifecycle import (  # noqa: E402
    ACTIVE,
    DISCOVERED,
    INGESTED,
    LIFECYCLE_STATES,
    REVOKED,
    SUPERSEDED,
    VALIDATED,
    OnboardingError,
    active_records,
    attestation_binding,
    derive_lifecycle_state,
    lifecycle_distribution,
    validate_onboarding_record,
)
from authority_receipt import ReceiptError, mint_receipt  # noqa: E402
from test_attacks import (  # noqa: E402
    FIXTURE_DOC,
    INSTANT,
    _evidence,
    build_fixture_substrate,
)
from validator_onboarding import (  # noqa: E402
    appointment_binding,
    key_ownership_payload,
)
from validator_trust import (  # noqa: E402
    APPOINTMENT_ARTIFACTS_DIR_NAME,
    APPOINTMENTS_DIR_NAME,
    EVENT_SCHEMA,
    GENESIS,
    attestation_payload,
    event_binding,
    ingestion_receipt_verified,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

FIX_KEY = b"v" * 32
FIX_VALIDATOR = "[FIXTURE] vld-1"
FIX_KEY_ID = "vk-1"
# Authority-receipt key: seeds the test keystores so fixture ingestion
# receipts minted here verify inside compute_state / derive_governed_state.
FIX_AUTH_KEY = b"a" * 32


def _fixture_appointment(classes):
    """A real, schema-valid appointment for the fixture validator, with an
    HMAC key-ownership proof. Retained by fixture_trust the same way the
    onboarding ceremony retains it."""
    app = {
        "validator_appointment_id": "[FIXTURE] app-1",
        "validator_id": FIX_VALIDATOR,
        "subject_identity": "[FIXTURE] Legal Validator",
        "organization": "[FIXTURE] Org",
        "jurisdiction": "[FIXTURE] Jurisdiction X",
        "appointment_authority": "[FIXTURE] General Counsel",
        "authorized_classes": sorted(classes),
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
            "key_id": FIX_KEY_ID,
            "key_algorithm": "hmac-sha256",
            "key_fingerprint": sha256_hex(FIX_KEY),
        },
    }
    app["key_binding"]["key_ownership_proof"] = hmac_sign(FIX_KEY, key_ownership_payload(app))
    return app


def fixture_trust(tmp_path, *, classes=("COUNSEL_OR_RIGHTS_AUTHORITY", "DATA_CONTROLLER")):
    """Isolated fixture validator: registry + keystore in tmp, [FIXTURE]-marked.

    Never touches the production validator registry; every test builds its own.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    ks = tmp_path / "vks"
    ks.mkdir(exist_ok=True)
    (ks / FIX_KEY_ID).write_bytes(FIX_KEY)
    # Retain the appointment material the way the onboarding ceremony does:
    # REGISTER provenance must resolve to independently retained appointment
    # facts, not just digest-shaped strings.
    appointment = _fixture_appointment(classes)
    binding = appointment_binding(appointment)
    app_dir = ks / APPOINTMENTS_DIR_NAME
    app_dir.mkdir(exist_ok=True)
    (app_dir / f"{binding}.json").write_text(
        json.dumps(appointment, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Retain the underlying appointment artifact bytes by digest, the way the
    # onboarding ceremony does: provenance digests must re-verify against
    # retained bytes, not merely look digest-shaped.
    art_dir = ks / APPOINTMENT_ARTIFACTS_DIR_NAME
    art_dir.mkdir(exist_ok=True)
    (art_dir / sha256_hex(FIXTURE_DOC)).write_bytes(FIXTURE_DOC)
    ev = {
        "schema": EVENT_SCHEMA,
        "event": "REGISTER",
        "validator_id": FIX_VALIDATOR,
        "validator_identity": "[FIXTURE] Legal Validator",
        "authorized_classes": sorted(classes),
        "appointment_authority": "[FIXTURE] General Counsel",
        "key_id": FIX_KEY_ID,
        "key_fingerprint": sha256_hex(FIX_KEY),
        "effective_from": "2026-01-01T00:00:00Z",
        "effective_until": None,
        # Onboarding provenance (EXTERNAL_VALIDATOR_ONBOARDING_V1): a REGISTER
        # without evidence-backed appointment provenance is refused at trust
        # verification time.
        "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
        "appointment_binding": binding,
        "appointment_evidence_digests": [sha256_hex(FIXTURE_DOC)],
        "prev_event_binding": GENESIS,
    }
    ev["event_binding"] = event_binding(ev)
    reg = tmp_path / "vreg.jsonl"
    with reg.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(ev, sort_keys=True) + "\n")
    return {"registry": reg, "keystore": ks, "validator_id": FIX_VALIDATOR, "key_id": FIX_KEY_ID}


def _sign_att(att: dict) -> dict:
    att = dict(att)
    att["validator_id"] = FIX_VALIDATOR
    att["key_id"] = FIX_KEY_ID
    att["attestation_signature"] = hmac_sign(FIX_KEY, attestation_payload(att))
    return att


def _fixture_receipt(
    ev: dict,
    *,
    substrate_identity: str = "fixture-substrate",
    substrate_digest: str = "d" * 64,
) -> dict:
    """Mint a REAL ingestion receipt for this record under the fixture
    authority key — a bare receipt-id string no longer counts as ingested."""
    return mint_receipt(
        FIX_AUTH_KEY,
        request_id=f"INGEST::{ev['authority_evidence_id']}",
        prior_state="ABSENT",
        new_state="INGESTED",
        authority_subject=ev["subject_identity"],
        authority_evidence_id=ev["authority_evidence_id"],
        evidence_digest=ev["source_digest"],
        authority_scope=ev["authority_scope"],
        substrate_identity=substrate_identity,
        substrate_critical_set_digest=substrate_digest,
        decision="INGEST",
        decision_reason="[FIXTURE] ingested",
        created_at="2026-08-10T11:30:00Z",
    )


def _attested(ev: dict, *, receipt: str | None = None, signed: bool = True) -> dict:
    """Attach a well-formed fixture attestation (isolated test fixture only).

    signed=True adds the VALIDATOR_TRUST_GOVERNANCE_V1 trust fields signed with
    the fixture validator key (pairs with fixture_trust). By default a real
    ingestion receipt is minted and attached; pass `receipt` to force a bare
    (unverifiable) receipt-id string instead."""
    ev = dict(ev)
    ev.setdefault("issuer_or_appointing_party", "[FIXTURE] Board")
    if ev.get("authority_type") == "COUNSEL_OR_RIGHTS_AUTHORITY":
        ev.setdefault("jurisdiction", "[FIXTURE] Jurisdiction X")
        ev.setdefault("appointment_authority", "[FIXTURE] Engaging Entity")
        ev.setdefault("verification_metadata", {"method": "[FIXTURE] registry lookup"})
    att = {
        "validator_identity": "[FIXTURE] Legal Validator",
        "validation_method": "[FIXTURE] reviewed artifact",
        "validated_at": "2026-08-10T11:00:00Z",
        "record_binding": attestation_binding(ev),
    }
    ev["validation"] = _sign_att(att) if signed else att
    if receipt is None:
        rec = _fixture_receipt(ev)
        ev["ingestion_receipt"] = rec["receipt_id"]
        ev["ingestion_receipt_record"] = rec
    else:
        ev["ingestion_receipt"] = receipt
    return ev


def _state(rec: dict, *, sids: set | None = None) -> str:
    return derive_lifecycle_state(
        rec, instant=INSTANT, superseded_ids=sids or set(), in_registry=True
    )


def _compute(substrate, tmp_path, registry_records, trust=None):
    trust = trust or fixture_trust(tmp_path)
    mpath = tmp_path / "m.json"
    if not mpath.exists():
        mpath.write_text(json.dumps(build_manifest(substrate, "TEST_SUBSTRATE")), encoding="utf-8")
    # Seed the authority-receipt keystore with the fixture key so ingestion
    # receipts minted by _attested verify inside compute_state.
    ob_ks = tmp_path / "ob_ks"
    if not ob_ks.exists():
        ob_ks.write_bytes(FIX_AUTH_KEY)
        ob_ks.chmod(0o600)
    reg = tmp_path / "ob_reg.jsonl"
    # Retain the fixture source artifact so source_artifact_intact can
    # re-verify the default fixture digest at routing time.
    artifact_dir = reg.parent / ".authority_artifacts"
    artifact_dir.mkdir(exist_ok=True)
    (artifact_dir / sha256_hex(FIXTURE_DOC)).write_bytes(FIXTURE_DOC)
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    for original in registry_records:
        r = dict(original)
        if isinstance(r.get("ingestion_receipt_record"), dict):
            receipt = _fixture_receipt(
                r,
                substrate_identity=manifest["substrate_id"],
                substrate_digest=manifest["critical_set_digest"],
            )
            r["ingestion_receipt"] = receipt["receipt_id"]
            r["ingestion_receipt_record"] = receipt
        append_record(reg, r)
    return V.compute_state(
        substrate,
        reg,
        tmp_path / "ob_ks",
        INSTANT,
        manifest_path=mpath,
        validator_registry_path=trust["registry"],
        validator_keystore=trust["keystore"],
        policy_path=tmp_path / "no_policy.json",  # absent -> defaults
    )


@pytest.fixture
def substrate(tmp_path):
    return build_fixture_substrate(tmp_path)


# --------------------------------------------------------------------------- #
# The eight required onboarding attacks
# --------------------------------------------------------------------------- #


def test_ob1_unsigned_evidence_never_routes(substrate, tmp_path):
    # AUTHORITY_EVIDENCED, in effect, schema-valid — but no validation
    # attestation. Lifecycle = DISCOVERED; compute_state must not route it.
    ev = dict(_evidence(authority_type="DATA_CONTROLLER"))
    ev["issuer_or_appointing_party"] = "[FIXTURE] Board"
    assert _state(ev) == DISCOVERED
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["routable_authority_records"] == 0
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][DISCOVERED] == 1


def test_ob2_expired_appointment_never_routes(substrate, tmp_path):
    ev = _attested(_evidence(effective_until="2026-06-01T00:00:00Z"))  # before INSTANT
    assert _state(ev) == INGESTED  # on file, outside its effective period
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["routable_authority_records"] == 0
    assert st["report"]["ready_to_send"] == 0


def test_ob3_superseded_controller_never_routes(substrate, tmp_path):
    old = _attested(_evidence(ev_id="AE-OLD"))
    # supersedes is attestation-bound: it must be present when the validator
    # attests, not spliced in afterwards.
    newer = _attested(dict(_evidence(ev_id="AE-NEW"), supersedes="AE-OLD"))
    assert _state(old, sids={"AE-OLD"}) == SUPERSEDED
    st = _compute(substrate, tmp_path, [old, newer])
    # AE-OLD superseded; AE-NEW is ACTIVE and routes the controller pair only.
    assert st["report"]["lifecycle_distribution"][SUPERSEDED] == 1
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 1
    assert st["report"]["ready_to_send"] == 2  # R1, R2 via AE-NEW — not 4


def test_ob4_scope_mismatch_never_routes(substrate, tmp_path):
    ev = _attested(_evidence(assets=["asset:does-not-exist"]))
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 1  # active, but out of scope
    assert st["report"]["ready_to_send"] == 0  # I3: active != covering


def test_ob5_identity_drift_never_routes(substrate, tmp_path):
    ev = _attested(_evidence())
    ev["subject_identity"] = "[DRIFTED] Someone Else"  # changed AFTER attestation
    assert _state(ev) == DISCOVERED  # binding broken -> back to DISCOVERED
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["routable_authority_records"] == 0
    assert st["report"]["ready_to_send"] == 0


def test_ob6_evidence_replay_is_single_fact(substrate, tmp_path):
    # The same logical evidence appended twice must not double-route or mint
    # extra receipts: transitions are keyed per request, and the ReplayLedger
    # would refuse a second identical receipt.
    ev = _attested(_evidence())
    st = _compute(substrate, tmp_path, [ev, dict(ev)])
    assert st["report"]["ready_to_send"] == 2  # controller pair once, not twice
    assert st["report"]["authority_receipts"] == 4  # 2 per resolved request, exactly
    assert st["report"]["receipt_verification_failures"] == 0


def test_ob6b_bare_receipt_id_never_activates(substrate, tmp_path):
    # A receipt-shaped string without a verifiable receipt record proves
    # nothing — anyone able to write the registry could invent one. The
    # record stays VALIDATED (never ACTIVE) and never routes.
    ev = _attested(_evidence(), receipt="r-invented")
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["routable_authority_records"] == 0
    assert st["report"]["lifecycle_distribution"][VALIDATED] == 1


@pytest.mark.parametrize(
    "override",
    [
        {"authority_subject": "other-subject"},
        {"authority_evidence_id": "AE-OTHER"},
        {"evidence_digest": "b" * 64},
        {"authority_scope": {"asset_ids": ["other"], "requirement_ids": "ALL"}},
        {"substrate_identity": "other-substrate"},
        {"substrate_critical_set_digest": "e" * 64},
        {"prior_state": "VALIDATED"},
        {"new_state": "ACTIVE"},
        {"decision": "ALLOW"},
    ],
)
def test_ingestion_receipt_replay_rejected_across_exact_bindings(override):
    ev = _evidence()
    kwargs = {
        "request_id": f"INGEST::{ev['authority_evidence_id']}",
        "prior_state": "ABSENT",
        "new_state": "INGESTED",
        "authority_subject": ev["subject_identity"],
        "authority_evidence_id": ev["authority_evidence_id"],
        "evidence_digest": ev["source_digest"],
        "authority_scope": ev["authority_scope"],
        "substrate_identity": "35d071b427513b4a",
        "substrate_critical_set_digest": (
            "35d071b427513b4a85d5f5660436651787cb9f43fc6cf0163f3d66c620511c8f"
        ),
        "decision": "INGEST",
        "decision_reason": "[FIXTURE] ingested",
        "created_at": "2026-08-10T11:30:00Z",
    }
    kwargs.update(override)
    receipt = mint_receipt(FIX_AUTH_KEY, **kwargs)
    record = dict(ev, ingestion_receipt=receipt["receipt_id"], ingestion_receipt_record=receipt)
    assert not ingestion_receipt_verified(
        record,
        FIX_AUTH_KEY,
        substrate_identity="35d071b427513b4a",
        substrate_digest=("35d071b427513b4a85d5f5660436651787cb9f43fc6cf0163f3d66c620511c8f"),
    )


def test_ob7_fabricated_authority_records_rejected():
    # A counsel record without the real-artifact fields (jurisdiction,
    # appointment authority, verification metadata) is a fabrication shape and
    # is rejected outright — it cannot even enter the lifecycle.
    fab = dict(_evidence(authority_type="COUNSEL_OR_RIGHTS_AUTHORITY"))
    with pytest.raises(OnboardingError):
        validate_onboarding_record(fab)
    # And it is not counted as any lifecycle state, nor ever routable.
    assert lifecycle_distribution([fab], INSTANT) == dict.fromkeys(LIFECYCLE_STATES, 0)
    assert active_records([fab], INSTANT) == []


def test_ob8_relocation_with_changed_content_blocks(substrate, tmp_path):
    # Relocating the substrate is allowed (byte-identity), but relocation WITH a
    # changed critical object must fail identity AND mint zero transitions,
    # even with ACTIVE evidence on file.
    import shutil

    trust = fixture_trust(tmp_path)
    mpath = tmp_path / "m.json"
    mpath.write_text(json.dumps(build_manifest(substrate, "TEST_SUBSTRATE")), encoding="utf-8")
    moved = tmp_path / "relocated" / "COMMERCIAL_BUYER_READINESS_V1"
    shutil.copytree(substrate, moved)
    (moved / "README.md").write_text("# changed during relocation\n")
    reg = tmp_path / "reg8.jsonl"
    append_record(reg, _attested(_evidence()))
    # The record carries an ingestion receipt, so verification demands the
    # real trust root on file (it never mints one).
    keystore = tmp_path / "ks8"
    keystore.write_bytes(FIX_AUTH_KEY)
    keystore.chmod(0o600)
    st = V.compute_state(
        moved,
        reg,
        tmp_path / "ks8",
        INSTANT,
        manifest_path=mpath,
        validator_registry_path=trust["registry"],
        validator_keystore=trust["keystore"],
    )
    assert st["verdict"] == V.SUBSTRATE_DIVERGED
    assert st["report"]["authority_receipts"] == 0
    assert len(st["transitions"]) == 0


def test_verification_never_mints_the_receipt_key(substrate, tmp_path):
    # A registry whose records claim ingestion receipts, verified against a
    # MISSING keystore, must hard-block: minting a fresh key during
    # verification would silently invalidate every receipt on file while
    # presenting as a healthy trust root.
    trust = fixture_trust(tmp_path)
    mpath = tmp_path / "m.json"
    mpath.write_text(json.dumps(build_manifest(substrate, "TEST_SUBSTRATE")), encoding="utf-8")
    reg = tmp_path / "reg_nokey.jsonl"
    append_record(reg, _attested(_evidence()))
    missing_ks = tmp_path / "no_such_ks"
    with pytest.raises(ReceiptError):
        V.compute_state(
            substrate,
            reg,
            missing_ks,
            INSTANT,
            manifest_path=mpath,
            validator_registry_path=trust["registry"],
            validator_keystore=trust["keystore"],
        )
    assert not missing_ks.exists()  # verification created no key material
    # Receipt-free records still verify: an absent trust root is tolerable
    # only while nothing claims an ingestion receipt — and still no key is
    # minted as a side effect.
    reg2 = tmp_path / "reg_bare.jsonl"
    append_record(reg2, _evidence())
    st = V.compute_state(
        substrate,
        reg2,
        missing_ks,
        INSTANT,
        manifest_path=mpath,
        validator_registry_path=trust["registry"],
        validator_keystore=trust["keystore"],
    )
    assert st["report"]["ready_to_send"] == 0
    assert not missing_ks.exists()


# --------------------------------------------------------------------------- #
# Counsel-class contract + deterministic verification
# --------------------------------------------------------------------------- #


def test_counsel_with_required_fields_routes_in_scope_only(substrate, tmp_path):
    ev = _attested(
        _evidence(
            ev_id="AE-COUNSEL",
            authority_type="COUNSEL_OR_RIGHTS_AUTHORITY",
            assets=["asset:1"],
            requirements=["CR-B"],
        )
    )
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["lifecycle_distribution"][ACTIVE] == 1
    assert st["report"]["ready_to_send"] == 1  # R3 only (asset:1 counsel)
    assert st["report"]["no_appointed_controller"] == 2  # controller pair untouched


def test_revoked_after_activation_fails_closed(substrate, tmp_path):
    ev = _attested(_evidence())
    ev["revoked_at"] = "2026-08-01T00:00:00Z"
    assert _state(ev) == REVOKED
    st = _compute(substrate, tmp_path, [ev])
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["lifecycle_distribution"][REVOKED] == 1


def test_deterministic_verification(substrate, tmp_path):
    # Same inputs -> byte-identical report and identical receipt ids. No
    # wall-clock enters the computation.
    trust = fixture_trust(tmp_path)
    ev = _attested(_evidence())
    st1 = _compute(substrate, tmp_path, [ev], trust=trust)
    assert st1["report"]["ready_to_send"] == 2  # trust chain is live, not vacuous
    reg = tmp_path / "ob_reg.jsonl"  # _compute appended once; reuse as-is
    st2 = V.compute_state(
        substrate,
        reg,
        tmp_path / "ob_ks",
        INSTANT,
        manifest_path=tmp_path / "m.json",
        validator_registry_path=trust["registry"],
        validator_keystore=trust["keystore"],
        policy_path=tmp_path / "no_policy.json",
    )
    assert st1["report"] == st2["report"]
    assert [t["receipt_id"] for t in st1["transitions"]] == [
        t["receipt_id"] for t in st2["transitions"]
    ]


def test_attestation_binding_is_deterministic_and_content_sensitive():
    ev = dict(_evidence())
    ev["issuer_or_appointing_party"] = "[FIXTURE] Board"
    b1 = attestation_binding(ev)
    assert b1 == attestation_binding(dict(ev))  # deterministic
    assert b1 != attestation_binding(dict(ev, subject_identity="other"))  # content-bound
    assert b1 != attestation_binding(dict(ev, source_digest="b" * 64))


# --------------------------------------------------------------------------- #
# Pipeline exit-code contract (onboard_authority_evidence.py)
# --------------------------------------------------------------------------- #


def _write_record(tmp_path, rec):
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(rec), encoding="utf-8")
    return p


def _pipeline_args(tmp_path, rec, doc, trust):
    return [
        "--record",
        str(_write_record(tmp_path, rec)),
        "--document",
        str(doc),
        "--registry",
        str(tmp_path / "reg.jsonl"),
        "--keystore",
        str(tmp_path / "ks"),
        "--validator-registry",
        str(trust["registry"]),
        "--validator-keystore",
        str(trust["keystore"]),
        "--instant",
        INSTANT,
    ]


def test_pipeline_unattested_exits_4_and_writes_nothing(tmp_path):
    import onboard_authority_evidence as OB

    trust = fixture_trust(tmp_path)
    doc = tmp_path / "deed"
    doc.write_text("[FIXTURE] appointment deed")
    rec = dict(_evidence(source_digest=""))
    rec["issuer_or_appointing_party"] = "[FIXTURE] Board"
    rc = OB.main(_pipeline_args(tmp_path, rec, doc, trust))
    assert rc == 4
    assert not (tmp_path / "reg.jsonl").exists()  # DISCOVERED never touches the registry


def test_pipeline_attested_onboards_active(tmp_path):
    import onboard_authority_evidence as OB

    trust = fixture_trust(tmp_path)
    doc = tmp_path / "deed"
    doc.write_text("[FIXTURE] appointment deed")
    rec = dict(_evidence(source_digest=sha256_hex(doc.read_bytes())))
    rec["issuer_or_appointing_party"] = "[FIXTURE] Board"
    rec["validation"] = _sign_att(
        {
            "validator_identity": "[FIXTURE] Legal Validator",
            "validation_method": "[FIXTURE] reviewed deed",
            "validated_at": "2026-08-10T11:00:00Z",
            "record_binding": attestation_binding(rec),
        }
    )
    rc = OB.main(_pipeline_args(tmp_path, rec, doc, trust))
    assert rc == 0
    stored = read_registry(tmp_path / "reg.jsonl")
    assert len(stored) == 1
    assert _state(stored[0]) == ACTIVE


def test_pipeline_untrusted_validator_exits_5(tmp_path):
    # Attested, binding intact — but the validator is not in the registry
    # (empty trust context). Gate 3b refuses; the registry is untouched.
    import onboard_authority_evidence as OB

    empty_trust = {
        "registry": tmp_path / "empty_vreg.jsonl",  # never created -> trusts nobody
        "keystore": tmp_path / "empty_vks",
    }
    doc = tmp_path / "deed"
    doc.write_text("[FIXTURE] appointment deed")
    rec = dict(_evidence(source_digest=sha256_hex(doc.read_bytes())))
    rec["issuer_or_appointing_party"] = "[FIXTURE] Board"
    rec["validation"] = _sign_att(
        {
            "validator_identity": "[FIXTURE] Legal Validator",
            "validation_method": "[FIXTURE] reviewed deed",
            "validated_at": "2026-08-10T11:00:00Z",
            "record_binding": attestation_binding(rec),
        }
    )
    rc = OB.main(_pipeline_args(tmp_path, rec, doc, empty_trust))
    assert rc == 5
    assert not (tmp_path / "reg.jsonl").exists()


def test_pipeline_tampered_document_exits_3(tmp_path):
    import onboard_authority_evidence as OB

    trust = fixture_trust(tmp_path)
    doc = tmp_path / "deed"
    doc.write_text("[FIXTURE] original")
    rec = dict(_evidence(source_digest="a" * 64))  # names a different document
    rec["issuer_or_appointing_party"] = "[FIXTURE] Board"
    args = _pipeline_args(tmp_path, rec, doc, trust)
    rc = OB.main(args[:-2])  # no --instant needed for the digest gate
    assert rc == 3
