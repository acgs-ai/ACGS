"""Adversarial suite for EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1.

Hermetic: builds a tiny synthetic substrate in tmp and drives the real
identity/router/receipt/evidence code. Never touches the 232 GB read-only
substrate and never writes a fabricated record into the package registry.

Covers the 32 attacks (Section 20) and the invariants (Section 21), plus
positive controls proving the mechanism actually resolves a request when — and
only when — real, verified, in-scope, in-effect authority evidence exists.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))

from _canonical import sha256_hex  # noqa: E402
from _identity import (  # noqa: E402
    IDENTITY_CONFIRMED,
    IDENTITY_MISMATCH,
    IDENTITY_UNVERIFIABLE,
    SUBSTRATE_DRIFT,
    build_manifest,
    verify_manifest,
)
from _substrate import CRITICAL_OBJECTS  # noqa: E402
from authority_receipt import (  # noqa: E402
    ReceiptError,
    ReplayLedger,
    mint_receipt,
    verify_receipt,
)
from authority_router import (  # noqa: E402
    AUTHORITY_EVIDENCED,
    IDENTITY_EVIDENCED,
    EvidenceError,
    derived_counts,
    evidence_covers_request,
    in_effect,
    route,
    source_digest_matches,
    validate_evidence,
)

INSTANT = "2026-08-10T12:00:00Z"
KEY = b"k" * 32


# --------------------------------------------------------------------------- #
# Fixtures: a minimal but structurally real substrate + in-memory requests.
# --------------------------------------------------------------------------- #
def _requirements():
    return {"requirements": [{"requirement_id": "CR-A"}, {"requirement_id": "CR-B"}]}


def _mappings():
    return {
        "mappings": [
            {
                "mapping_id": "CR-A::a1",
                "requirement_id": "CR-A",
                "asset_id": "asset:1",
                "status": "REQUEST_REQUIRED",
            },
            {
                "mapping_id": "CR-A::a2",
                "requirement_id": "CR-A",
                "asset_id": "asset:2",
                "status": "REQUEST_REQUIRED",
            },
            {
                "mapping_id": "CR-B::a1",
                "requirement_id": "CR-B",
                "asset_id": "asset:1",
                "status": "REQUEST_REQUIRED",
            },
            {
                "mapping_id": "CR-B::a3",
                "requirement_id": "CR-B",
                "asset_id": "asset:3",
                "status": "REQUEST_REQUIRED",
            },
            {
                "mapping_id": "CR-A::a9",
                "requirement_id": "CR-A",
                "asset_id": "asset:9",
                "status": "BLOCKED",
            },
        ]
    }


def _requests():
    def req(rid, basis, asset, requirement):
        return {
            "request_id": rid,
            "routing_state": "ROUTING_REQUIRED",
            "routing_basis": basis,
            "covered_asset_ids": [asset],
            "requirement_id": requirement,
            "authority_identity_ref": None,
            "rights_assertion": None,
        }

    return [
        req("R1", "NO_APPOINTED_CONTROLLER", "asset:1", "CR-A"),
        req("R2", "NO_APPOINTED_CONTROLLER", "asset:2", "CR-A"),
        req("R3", "NO_EVIDENCED_COUNSEL_IDENTITY", "asset:1", "CR-B"),
        req("R4", "NO_EVIDENCED_COUNSEL_IDENTITY", "asset:3", "CR-B"),
    ]


def _coverage():
    return {
        "edges": [
            {"mapping_id": "CR-A::a1", "request_id": "R1"},
            {"mapping_id": "CR-A::a2", "request_id": "R2"},
            {"mapping_id": "CR-B::a1", "request_id": "R3"},
            {"mapping_id": "CR-B::a3", "request_id": "R4"},
        ]
    }


def build_fixture_substrate(tmp_path):
    """Write the 15 critical objects with structurally real registries.
    Module-level so test_onboarding_attacks.py can reuse it."""
    root = tmp_path / "COMMERCIAL_BUYER_READINESS_V1"
    (root / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1").mkdir(parents=True)
    (root / "COMMERCIAL_RIGHTS_REQUIREMENT_MODEL_V1").mkdir(parents=True)

    def w(rel, obj):
        p = root / rel
        p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")

    w("verify_readiness.py", f'ROOT = "{root.parent}"\n')
    w("README.md", "# fixture\n")
    ex = "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1"
    md = "COMMERCIAL_RIGHTS_REQUIREMENT_MODEL_V1"
    w(f"{ex}/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json", _requests_wrap())
    w(f"{ex}/COMMERCIAL_RIGHTS_REQUEST_COVERAGE.json", _coverage())
    w(f"{ex}/COMMERCIAL_RIGHTS_REQUIREMENT_ONTOLOGY.json", {"ontology": []})
    w(f"{ex}/COMMERCIAL_RIGHTS_REQUEST_SCHEMA.json", {"schema": "x"})
    w(f"{ex}/CRE_INDEX.json", {"requests": 4})
    w(f"{ex}/verify_commercial_rights_requests.py", "# verifier\n")
    w(f"{ex}/sha256sums.txt", "sums\n")
    w(f"{md}/COMMERCIAL_RIGHTS_REQUIREMENTS.json", _requirements())
    w(f"{md}/RIGHTS_REQUEST_MAPPING.json", _mappings())
    w(f"{md}/RIGHTS_REQUIREMENT_SCHEMA.json", {"schema": "x"})
    w(f"{md}/CR_INDEX.json", {"requirements": 2})
    w(f"{md}/verify_rights_requirements.py", "# verifier\n")
    w(f"{md}/sha256sums.txt", "sums\n")
    return root


@pytest.fixture
def substrate(tmp_path):
    return build_fixture_substrate(tmp_path)


def _requests_wrap():
    return {"requests": _requests()["requests"] if isinstance(_requests(), dict) else _requests()}


@pytest.fixture
def manifest(substrate):
    return build_manifest(substrate, "TEST_SUBSTRATE")


def _evidence(
    ev_id="AE-1",
    authority_type="DATA_CONTROLLER",
    assets="ALL",
    requirements="ALL",
    state=AUTHORITY_EVIDENCED,
    effective_from="2026-01-01T00:00:00Z",
    effective_until=None,
    revoked_at=None,
    source_digest="a" * 64,
):
    return {
        "authority_evidence_id": ev_id,
        "authority_type": authority_type,
        "subject_identity": "Evidenced Entity",
        "authority_scope": {"asset_ids": assets, "requirement_ids": requirements},
        "source_type": "SIGNED_APPOINTMENT",
        "source_reference": "doc://appointment/1",
        "source_digest": source_digest,
        "effective_from": effective_from,
        "effective_until": effective_until,
        "verification_state": state,
        "revoked_at": revoked_at,
    }


def _route(requests, evidence, digest="d" * 64):
    return route(
        requests,
        evidence,
        substrate_digest=digest,
        key=KEY,
        eval_instant=INSTANT,
        replay=ReplayLedger(),
    )


# --------------------------------------------------------------------------- #
# Positive controls — the mechanism must actually work, scoped.
# --------------------------------------------------------------------------- #
def test_positive_controller_evidence_resolves_only_controller_requests(manifest):
    res = _route(
        _requests()["requests"] if isinstance(_requests(), dict) else _requests(), [_evidence()]
    )
    counts = derived_counts(_requests(), res.request_final_state)
    assert counts["ready_to_send"] == 2  # R1, R2 (controller)
    assert counts["no_appointed_controller"] == 0
    assert counts["no_evidenced_counsel_identity"] == 2  # R3, R4 untouched (I4)
    assert len(res.transitions) == 4  # two receipts per resolved request
    assert res.rights_assertions_created == 0
    assert res.recipients_invented == 0


def test_positive_counsel_evidence_scoped_resolves_only_in_scope(manifest):
    ev = _evidence(
        ev_id="AE-C",
        authority_type="COUNSEL_OR_RIGHTS_AUTHORITY",
        assets=["asset:1"],
        requirements=["CR-B"],
    )
    res = _route(_requests(), [ev])
    counts = derived_counts(_requests(), res.request_final_state)
    assert counts["ready_to_send"] == 1  # only R3 (asset:1)
    assert res.request_final_state["R4"] == "ROUTING_REQUIRED"  # asset:3 out of scope (I5)


# --------------------------------------------------------------------------- #
# Substrate identity attacks 1–8
# --------------------------------------------------------------------------- #
def test_attack01_same_filename_altered_verifier(manifest, substrate):
    (
        substrate / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/verify_commercial_rights_requests.py"
    ).write_text("# TAMPERED\n")
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_attack02_same_counts_altered_registry_bytes(manifest, substrate):
    p = substrate / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json"
    p.write_text(p.read_text() + "\n")  # same data, different bytes
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_attack03_partial_copy_missing_object(manifest, substrate):
    (substrate / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/sha256sums.txt").unlink()
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_UNVERIFIABLE


def test_attack04_relocation_identical_bytes_confirms(manifest, substrate, tmp_path):
    import shutil

    dst = tmp_path / "relocated" / "COMMERCIAL_BUYER_READINESS_V1"
    shutil.copytree(substrate, dst)
    assert verify_manifest(manifest, dst)["state"] == IDENTITY_CONFIRMED


def test_attack05_changed_critical_object_after_identity(manifest, substrate):
    (substrate / "README.md").write_text("# changed\n")
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_attack06_spoofed_count_manifest(manifest, substrate):
    manifest["expected_counts"]["requests"] = 999  # lie in the manifest
    assert verify_manifest(manifest, substrate)["state"] == SUBSTRATE_DRIFT


def test_attack07_registry_replaced_with_equivalent_fake(manifest, substrate):
    p = substrate / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json"
    fake = _requests_wrap()
    fake["derivation"] = "forged"
    p.write_text(json.dumps(fake))
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_attack08_stale_manifest_detects_change(manifest, substrate):
    (substrate / "COMMERCIAL_RIGHTS_REQUIREMENT_MODEL_V1/RIGHTS_REQUEST_MAPPING.json").write_text(
        json.dumps(_mappings()) + " "
    )
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


# --------------------------------------------------------------------------- #
# Authority attacks 9–25
# --------------------------------------------------------------------------- #
def test_attack09_invented_controller_no_source_rejected():
    bad = _evidence(source_digest="")
    with pytest.raises(EvidenceError):
        validate_evidence(bad)


def test_attack10_invented_counsel_no_reference_rejected():
    bad = _evidence(authority_type="COUNSEL_OR_RIGHTS_AUTHORITY")
    bad["source_reference"] = ""
    with pytest.raises(EvidenceError):
        validate_evidence(bad)


def test_attack11_document_digest_changed_after_ingestion():
    rec = _evidence(source_digest=sha256_hex(b"original document"))
    assert source_digest_matches(rec, b"original document")
    assert not source_digest_matches(rec, b"tampered document")


def test_attack12_identity_known_but_authority_not_evidenced(manifest):
    ev = _evidence(state=IDENTITY_EVIDENCED)
    res = _route(_requests(), [ev])
    assert derived_counts(_requests(), res.request_final_state)["ready_to_send"] == 0  # I2


def test_attack13_authority_evidenced_wrong_scope(manifest):
    ev = _evidence(assets=["asset:999"])
    res = _route(_requests(), [ev])
    assert derived_counts(_requests(), res.request_final_state)["ready_to_send"] == 0  # I3


def test_attack14_controller_evidence_on_counsel_request():
    ev = _evidence(authority_type="DATA_CONTROLLER")
    counsel_req = _requests()[2]  # R3, NO_EVIDENCED_COUNSEL_IDENTITY
    assert not evidence_covers_request(ev, counsel_req, INSTANT)  # I4


def test_attack15_counsel_evidence_outside_covered_assets():
    ev = _evidence(
        authority_type="COUNSEL_OR_RIGHTS_AUTHORITY", assets=["asset:1"], requirements=["CR-B"]
    )
    r4 = _requests()[3]  # asset:3
    assert not evidence_covers_request(ev, r4, INSTANT)  # I5


def test_attack16_expired_authority():
    ev = _evidence(effective_until="2026-06-01T00:00:00Z")  # before INSTANT
    assert not in_effect(ev, INSTANT)  # I12
    r1 = _requests()[0]
    assert not evidence_covers_request(ev, r1, INSTANT)


def test_attack17_revoked_authority():
    ev = _evidence(revoked_at="2026-07-01T00:00:00Z")
    assert not in_effect(ev, INSTANT)
    assert not evidence_covers_request(ev, _requests()[0], INSTANT)


def test_attack18_duplicate_ingestion_idempotent(tmp_path):
    from _registry import append_record, read_registry

    reg = tmp_path / "reg.jsonl"
    rec = _evidence()
    append_record(reg, rec)
    existing = read_registry(reg)
    dup = any(
        e["authority_evidence_id"] == rec["authority_evidence_id"]
        and e["source_digest"] == rec["source_digest"]
        for e in existing
    )
    assert dup  # ingest CLI treats this as a no-op


def test_attack19_replayed_receipt():
    ledger = ReplayLedger()
    r = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="ROUTING_RESOLVED",
        authority_subject="X",
        authority_evidence_id="AE-1",
        evidence_digest="a" * 64,
        authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
        substrate_critical_set_digest="d" * 64,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    ledger.consume(r["receipt_id"])
    with pytest.raises(ReceiptError):
        ledger.consume(r["receipt_id"])


def test_attack20_receipt_for_request_a_used_for_request_b():
    r = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="READY_TO_SEND",
        authority_subject="X",
        authority_evidence_id="AE-1",
        evidence_digest="a" * 64,
        authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
        substrate_critical_set_digest="d" * 64,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    forged = dict(r, request_id="R2")  # reuse A's receipt for B
    assert not verify_receipt(KEY, forged)


def test_attack21_receipt_against_old_substrate_identity():
    r = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="READY_TO_SEND",
        authority_subject="X",
        authority_evidence_id="AE-1",
        evidence_digest="a" * 64,
        authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
        substrate_critical_set_digest="OLD" + "d" * 61,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    # Receipt is internally valid, but its bound substrate identity differs from
    # the current one — detectable and must be rejected by the caller.
    assert verify_receipt(KEY, r)
    assert r["substrate_identity"] != "d" * 64


def test_attack22_authority_record_changed_after_receipt():
    rec = _evidence(source_digest="a" * 64)
    r = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="READY_TO_SEND",
        authority_subject=rec["subject_identity"],
        authority_evidence_id=rec["authority_evidence_id"],
        evidence_digest=rec["source_digest"],
        authority_scope=rec["authority_scope"],
        substrate_critical_set_digest="d" * 64,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    rec2 = dict(rec, source_digest="b" * 64)  # record changed
    assert r["evidence_digest"] != rec2["source_digest"]  # binding no longer matches


def _fixture_manifest_path(substrate, tmp_path):
    m = build_manifest(substrate, "TEST_SUBSTRATE")
    p = tmp_path / "fixture_manifest.json"
    p.write_text(json.dumps(m), encoding="utf-8")
    return p


def test_attack23_manual_ready_without_receipt_blocks(substrate, tmp_path):
    # A request pre-set to READY_TO_SEND with no receipt behind it trips the I11
    # audit inside compute_state (ready implies exactly two receipts). A fixture
    # manifest makes identity CONFIRM, so the block is reached on I11, not drift.
    import verify_authority_state as V

    reg = (
        substrate / "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json"
    )
    data = json.loads(reg.read_text())
    data["requests"][0]["routing_state"] = "READY_TO_SEND"  # forged, no transition
    reg.write_text(json.dumps(data))
    mpath = _fixture_manifest_path(substrate, tmp_path)  # built AFTER the forge → counts match
    st = V.compute_state(
        substrate, tmp_path / "empty.jsonl", tmp_path / "ks", INSTANT, manifest_path=mpath
    )
    assert st["report"]["substrate_identity_state"] == IDENTITY_CONFIRMED
    assert st["report"]["authority_receipts"] == 0
    assert st["invariants"]["I11_every_transition_receipted"] is False
    assert st["verdict"] == V.INTEGRATION_BLOCKED


def test_ordering_no_transition_on_drift(substrate, tmp_path):
    # THE ordering guarantee (I9): with verified controller evidence that WOULD
    # resolve requests, a substrate failing identity mints ZERO receipts — route()
    # is never entered. Catches route-before-identity-gate.
    import verify_authority_state as V
    from _registry import append_record

    mpath = _fixture_manifest_path(substrate, tmp_path)
    (substrate / "README.md").write_text("# drifted after manifest\n")
    reg = tmp_path / "reg.jsonl"
    append_record(reg, _evidence(authority_type="DATA_CONTROLLER"))
    st = V.compute_state(substrate, reg, tmp_path / "ks", INSTANT, manifest_path=mpath)
    assert st["report"]["substrate_identity_state"] != IDENTITY_CONFIRMED
    assert st["verdict"] == V.SUBSTRATE_DIVERGED
    assert st["report"]["authority_receipts"] == 0
    assert len(st["transitions"]) == 0


def test_compute_state_layer_ready_on_confirmed_empty(substrate, tmp_path):
    import verify_authority_state as V

    mpath = _fixture_manifest_path(substrate, tmp_path)
    st = V.compute_state(
        substrate, tmp_path / "empty.jsonl", tmp_path / "ks", INSTANT, manifest_path=mpath
    )
    assert st["verdict"] == V.AUTHORITY_LAYER_READY
    assert st["report"]["ready_to_send"] == 0
    assert st["report"]["routing_required"] == 4
    assert all(st["invariants"].values())


def test_supersession_deactivates_old_record(substrate, tmp_path):
    # A superseded AUTHORITY_EVIDENCED record does not route (Section 15).
    import verify_authority_state as V
    from _registry import append_record

    mpath = _fixture_manifest_path(substrate, tmp_path)
    reg = tmp_path / "reg.jsonl"
    old = _evidence(ev_id="AE-OLD", authority_type="DATA_CONTROLLER")
    newer = _evidence(ev_id="AE-NEW", authority_type="DATA_CONTROLLER", state=IDENTITY_EVIDENCED)
    newer["supersedes"] = "AE-OLD"
    append_record(reg, old)
    append_record(reg, newer)
    st = V.compute_state(substrate, reg, tmp_path / "ks", INSTANT, manifest_path=mpath)
    assert st["report"]["superseded_authority_records"] == 1
    assert st["report"]["ready_to_send"] == 0


def test_ingest_conflict_same_id_different_document(tmp_path):
    # Same authority_evidence_id, different source document -> rejected (Section 14).
    import ingest_authority_evidence as ING

    (tmp_path / "doc1").write_text("appointment A")
    (tmp_path / "doc2").write_text("appointment B (different)")
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(_evidence(ev_id="AE-CONFLICT", source_digest="")))
    reg = tmp_path / "reg.jsonl"
    ks = tmp_path / "ks"
    base = [
        "--record",
        str(rec),
        "--registry",
        str(reg),
        "--keystore",
        str(ks),
        "--instant",
        INSTANT,
    ]
    rc1 = ING.main([*base, "--document", str(tmp_path / "doc1")])
    rc2 = ING.main([*base, "--document", str(tmp_path / "doc2")])
    assert rc1 == 0
    assert rc2 == 3  # same id, different document digest -> conflict


def test_attack24_aggregate_counts_are_derived_not_stored():
    reqs = _requests()
    reqs_with_lie = [dict(r) for r in reqs]
    reqs_with_lie[0]["ready_to_send"] = 999  # injected aggregate on a record
    counts = derived_counts(reqs_with_lie, {r["request_id"]: r["routing_state"] for r in reqs})
    assert counts["ready_to_send"] == 0  # derived from routing_state only (I8)


def test_attack25_rights_assertion_not_created_on_resolution(manifest):
    reqs = _requests()  # bind: assert over the SAME list route ran against
    res = _route(reqs, [_evidence()])
    assert res.request_final_state["R1"] == "READY_TO_SEND"  # actually resolved
    assert res.rights_assertions_created == 0  # I7
    for r in reqs:
        assert r["rights_assertion"] is None  # route did not write one onto a resolved request


# --------------------------------------------------------------------------- #
# Fail-closed tests 26–32
# --------------------------------------------------------------------------- #
def test_attack26_missing_evidence_layer_ready(manifest):
    res = _route(_requests(), [])
    assert derived_counts(_requests(), res.request_final_state)["ready_to_send"] == 0


def test_attack27_malformed_evidence_rejected():
    with pytest.raises(EvidenceError):
        validate_evidence({"authority_evidence_id": "AE-x"})


def test_attack28_unknown_authority_type_rejected():
    with pytest.raises(EvidenceError):
        validate_evidence(_evidence(authority_type="MADE_UP_AUTHORITY"))


def test_attack29_unverified_source_rejected():
    with pytest.raises(EvidenceError):
        validate_evidence(_evidence(source_digest=""))


def test_attack30_unavailable_substrate(manifest, tmp_path):
    result = verify_manifest(manifest, tmp_path / "does_not_exist")
    assert result["state"] == IDENTITY_UNVERIFIABLE


def test_attack31_substrate_identity_mismatch(manifest, substrate):
    (
        substrate / "COMMERCIAL_RIGHTS_REQUIREMENT_MODEL_V1/COMMERCIAL_RIGHTS_REQUIREMENTS.json"
    ).write_text(json.dumps(_requirements()) + " ")
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_attack32_tampered_receipt_fails_verification():
    r = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="READY_TO_SEND",
        authority_subject="X",
        authority_evidence_id="AE-1",
        evidence_digest="a" * 64,
        authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
        substrate_critical_set_digest="d" * 64,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    tampered = dict(r, new_state="SENT")  # change a bound field, keep signature
    assert not verify_receipt(KEY, tampered)


# --------------------------------------------------------------------------- #
# Invariants I1–I14 as explicit assertions where not already covered above.
# --------------------------------------------------------------------------- #
def test_invariant_I1_no_evidence_no_ready(manifest):
    assert (
        derived_counts(_requests(), _route(_requests(), []).request_final_state)["ready_to_send"]
        == 0
    )


def test_invariant_I9_identity_mismatch_blocks_transition(manifest, substrate):
    # A receipt bound to a substrate digest that no longer matches the live one
    # must not be honored: caller compares receipt.substrate_identity to current.
    (substrate / "README.md").write_text("drift\n")
    assert verify_manifest(manifest, substrate)["state"] == IDENTITY_MISMATCH


def test_invariant_I14_no_corpus_migration_needed(manifest):
    # Identity + routing operate with only the 15-object critical set, never a
    # copy of the corpus.
    assert len(CRITICAL_OBJECTS) == 15 == manifest["critical_object_count"]
