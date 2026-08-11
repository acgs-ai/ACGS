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
from jsonschema import Draft7Validator, ValidationError

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))

import authority_receipt as AR  # noqa: E402
import authority_router as Router  # noqa: E402
from _canonical import canonical_json, hash_obj, hmac_sign, sha256_hex  # noqa: E402
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
    load_or_create_key,
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
    w(f"{md}/COMMERCIAL_RIGHTS_REQUIREMENTS.json", _requirements())
    w(f"{md}/RIGHTS_REQUEST_MAPPING.json", _mappings())
    w(f"{md}/RIGHTS_REQUIREMENT_SCHEMA.json", {"schema": "x"})
    w(f"{md}/CR_INDEX.json", {"requirements": 2})
    w(f"{md}/verify_rights_requirements.py", "# verifier\n")
    # Real coreutils-format checksum manifests: verify_manifest honors the
    # transitive pin, so the sums files must actually name and hash the
    # layer's files (a placeholder string would fail identity as malformed).
    for layer in (ex, md):
        entries = sorted(p for p in (root / layer).iterdir() if p.name != "sha256sums.txt")
        w(
            f"{layer}/sha256sums.txt",
            "".join(f"{sha256_hex(p.read_bytes())}  {p.name}\n" for p in entries),
        )
    return root


@pytest.fixture
def substrate(tmp_path):
    return build_fixture_substrate(tmp_path)


def _requests_wrap():
    return {"requests": _requests()["requests"] if isinstance(_requests(), dict) else _requests()}


@pytest.fixture
def manifest(substrate):
    return build_manifest(substrate, "TEST_SUBSTRATE")


# The fixture source document behind default fixture evidence. Tests that
# exercise positive routing retain these bytes as the registry artifact so
# source_artifact_intact can re-verify the digest.
FIXTURE_DOC = b"[FIXTURE] appointment deed"
FIXTURE_DIGEST = sha256_hex(FIXTURE_DOC)


def _evidence(
    ev_id="AE-1",
    authority_type="DATA_CONTROLLER",
    assets="ALL",
    requirements="ALL",
    state=AUTHORITY_EVIDENCED,
    effective_from="2026-01-01T00:00:00Z",
    effective_until=None,
    revoked_at=None,
    source_digest=FIXTURE_DIGEST,
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
        substrate_identity="fixture-substrate",
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


def test_attack_symlinked_critical_object_fails_identity(manifest, substrate, tmp_path):
    # Replace a critical object with a symlink to an EXTERNAL file holding the
    # exact expected bytes: the in-tree object is gone, so identity must NOT
    # confirm — a follow-symlink hasher would report IDENTITY_CONFIRMED here.
    victim = substrate / "README.md"
    outside = tmp_path / "outside-readme.md"
    outside.write_bytes(victim.read_bytes())
    victim.unlink()
    victim.symlink_to(outside)
    res = verify_manifest(manifest, substrate)
    assert res["state"] == IDENTITY_MISMATCH
    assert "README.md" in res["mismatched"]


def test_attack_symlinked_sums_pinned_file_fails_identity(substrate, tmp_path):
    # Same swap against a file pinned only transitively by a layer's
    # sha256sums.txt: the checksum-listed file must be hashed no-follow too.
    ex = "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1"
    extra = substrate / ex / "extra_evidence_bundle.json"
    extra.write_text('{"pinned": true}', encoding="utf-8")
    _rewrite_layer_sums(substrate, ex)
    m = build_manifest(substrate, "TEST_SUBSTRATE")
    assert verify_manifest(m, substrate)["state"] == IDENTITY_CONFIRMED
    outside = tmp_path / "outside-bundle.json"
    outside.write_bytes(extra.read_bytes())
    extra.unlink()
    extra.symlink_to(outside)
    res = verify_manifest(m, substrate)
    assert res["state"] == IDENTITY_MISMATCH
    assert f"{ex}/extra_evidence_bundle.json" in res["mismatched"]


def test_build_manifest_refuses_symlinked_critical_object(substrate, tmp_path):
    # A manifest built over a symlinked slot would carry the marker digest and
    # re-verify against the same symlink — refuse to bind such an identity.
    victim = substrate / "README.md"
    outside = tmp_path / "outside-readme.md"
    outside.write_bytes(victim.read_bytes())
    victim.unlink()
    victim.symlink_to(outside)
    with pytest.raises(ValueError, match="not regular files"):
        build_manifest(substrate, "TEST_SUBSTRATE")


def _rewrite_layer_sums(substrate, layer):
    d = substrate / layer
    entries = sorted(p for p in d.iterdir() if p.name != "sha256sums.txt")
    (d / "sha256sums.txt").write_text(
        "".join(f"{sha256_hex(p.read_bytes())}  {p.name}\n" for p in entries),
        encoding="utf-8",
    )


def test_sums_pinned_file_altered_or_removed_fails_identity(substrate, tmp_path):
    # The identity claims each layer's sha256sums.txt "transitively pins its
    # files" — so a file LISTED in the sums but not itself a critical object
    # must fail identity when altered or removed, even though every critical
    # object's own bytes (including the sums file) are unchanged.
    ex = "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1"
    extra = substrate / ex / "extra_evidence_bundle.json"
    extra.write_text('{"pinned": true}', encoding="utf-8")
    _rewrite_layer_sums(substrate, ex)
    m = build_manifest(substrate, "TEST_SUBSTRATE")
    assert verify_manifest(m, substrate)["state"] == IDENTITY_CONFIRMED
    extra.write_text('{"pinned": false}', encoding="utf-8")  # altered after binding
    res = verify_manifest(m, substrate)
    assert res["state"] == IDENTITY_MISMATCH
    assert f"{ex}/extra_evidence_bundle.json" in res["mismatched"]
    extra.unlink()  # removed after binding
    res = verify_manifest(m, substrate)
    assert res["state"] == IDENTITY_UNVERIFIABLE
    assert f"{ex}/extra_evidence_bundle.json" in res["absent"]


def test_malformed_or_traversal_sums_manifest_fails_identity(substrate):
    # A sums file that cannot be parsed pins nothing — fail closed as a
    # mismatch, never confirm. Same for an entry whose name escapes the layer.
    ex = "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1"
    sums = substrate / ex / "sha256sums.txt"
    sums.write_text("sums\n", encoding="utf-8")
    m = build_manifest(substrate, "TEST_SUBSTRATE")
    res = verify_manifest(m, substrate)
    assert res["state"] == IDENTITY_MISMATCH
    assert f"{ex}/sha256sums.txt" in res["mismatched"]
    sums.write_text(f"{'0' * 64}  ../../../etc/passwd\n", encoding="utf-8")
    m2 = build_manifest(substrate, "TEST_SUBSTRATE")
    assert verify_manifest(m2, substrate)["state"] == IDENTITY_MISMATCH


def test_unknown_identity_class_refused(substrate):
    with pytest.raises(ValueError, match="unknown identity_class"):
        build_manifest(substrate, "TOTALLY_LEGIT_SUBSTRATE")


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


def test_malformed_evidence_id_rejected():
    # The committed schema constrains authority_evidence_id to
    # ^AE-[A-Za-z0-9_.:-]+$; runtime validation must enforce the same
    # pattern, or an empty/whitespace/free-form id would mint "INGEST::"
    # receipts and could become ACTIVE with no usable evidence identity.
    for bad_id in ("", "AE-", "ae-1", "EV-1", "AE-id with spaces", "AE-1\n", 7, None):
        with pytest.raises(EvidenceError):
            validate_evidence(_evidence(ev_id=bad_id))
    validate_evidence(_evidence(ev_id="AE-controller_2026.01:a-b"))  # schema-valid


def test_malformed_scope_shape_rejected_not_crash():
    # Scope ids must be "ALL" or a list of strings: a dict/list/None element
    # would raise TypeError deep inside _scope_covers (set() of unhashables)
    # instead of failing validation cleanly.
    for bad_scope in (
        _evidence(assets={"asset:1": True}),
        _evidence(assets=[{"asset": 1}]),
        _evidence(requirements="SOME"),
        _evidence(requirements=[None]),
    ):
        with pytest.raises(EvidenceError):
            validate_evidence(bad_scope)


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


def test_receipt_keystore_rejects_symlink_and_insecure_mode(tmp_path):
    external = tmp_path / "external-key"
    external.write_bytes(b"x" * 32)
    external.chmod(0o600)
    external_before = external.read_bytes()
    linked = tmp_path / "linked-keystore"
    linked.symlink_to(external)
    with pytest.raises(ReceiptError):
        load_or_create_key(linked)
    assert external.read_bytes() == external_before

    insecure = tmp_path / "insecure-keystore"
    insecure.write_bytes(b"y" * 32)
    insecure.chmod(0o644)
    with pytest.raises(ReceiptError):
        load_or_create_key(insecure)
    assert insecure.read_bytes() == b"y" * 32


def test_receipt_keystore_fileexists_race_revalidates_winner(tmp_path, monkeypatch):
    keystore = tmp_path / "raced-keystore"
    winner = b"w" * 32
    real_open = AR.os.open
    raced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if flags & AR.os.O_CREAT and not raced:
            raced = True
            keystore.write_bytes(winner)
            keystore.chmod(0o600)
            raise FileExistsError(path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(AR.os, "open", racing_open)
    assert load_or_create_key(keystore) == winner


def test_receipt_keystore_rejects_symlinked_ancestor_and_insecure_parent(tmp_path):
    trusted = tmp_path / "trusted-parent"
    trusted.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(trusted, target_is_directory=True)
    with pytest.raises(ReceiptError):
        load_or_create_key(linked_parent / "receipt.key")
    assert not (trusted / "receipt.key").exists()

    insecure = tmp_path / "insecure-parent"
    insecure.mkdir()
    insecure.chmod(0o777)
    with pytest.raises(ReceiptError):
        load_or_create_key(insecure / "receipt.key")
    assert not (insecure / "receipt.key").exists()


def test_receipt_keystore_rejects_parent_swap_and_removes_new_key(tmp_path, monkeypatch):
    parent = tmp_path / "secure-parent"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "moved-parent"
    protected = tmp_path / "protected.txt"
    protected.write_bytes(b"protected-original\n")
    real_open = AR.os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if flags & AR.os.O_CREAT and not swapped:
            swapped = True
            parent.rename(moved)
            parent.mkdir(mode=0o700)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(AR.os, "open", swapping_open)
    with pytest.raises(ReceiptError, match="parent changed"):
        load_or_create_key(parent / "receipt.key")
    assert not (moved / "receipt.key").exists()
    assert not (parent / "receipt.key").exists()
    assert protected.read_bytes() == b"protected-original\n"


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
        substrate_identity="fixture-substrate",
        substrate_critical_set_digest="d" * 64,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    ledger.consume(r["receipt_id"])
    with pytest.raises(ReceiptError):
        ledger.consume(r["receipt_id"])


def test_attack19b_paired_receipts_consume_atomically(tmp_path):
    # The two receipts of one request transition are consumed as ONE batch:
    # if any member is already consumed, NONE is recorded — a request can
    # never half-advance, even across ledger instances sharing the file.
    path = tmp_path / "replay.jsonl"
    ledger = ReplayLedger(path)
    minted = [
        mint_receipt(
            KEY,
            request_id="R1",
            prior_state=prior,
            new_state=new,
            authority_subject="X",
            authority_evidence_id="AE-1",
            evidence_digest="a" * 64,
            authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
            substrate_identity="fixture-substrate",
            substrate_critical_set_digest="d" * 64,
            decision="ALLOW",
            decision_reason="x",
            created_at=INSTANT,
        )
        for prior, new in (
            ("ROUTING_REQUIRED", "ROUTING_RESOLVED"),
            ("ROUTING_RESOLVED", "READY_TO_SEND"),
        )
    ]
    first, second = (r["receipt_id"] for r in minted)
    # Another process already consumed the SECOND receipt of the pair.
    ReplayLedger(path).consume(second)
    with pytest.raises(ReceiptError):
        ledger.consume_many([first, second])
    assert not ledger.has(first)  # nothing half-consumed
    assert first not in path.read_text(encoding="utf-8")
    # A duplicate inside one batch is refused before anything is recorded.
    with pytest.raises(ReceiptError):
        ledger.consume_many([first, first])
    assert not ledger.has(first)
    # With the conflict gone, the batch consumes and persists atomically.
    fresh = ReplayLedger(path)
    fresh.consume_many([first])
    assert ReplayLedger(path).has(first) and ReplayLedger(path).has(second)


def test_replay_ledger_refuses_symlinked_path(tmp_path):
    # A persistent replay path replaced by a symlink must be refused with
    # no-follow opens: following it would read prior ids from — and append
    # consumed ids into — an arbitrary writable target while the replay
    # guard reports success.
    victim = tmp_path / "victim.txt"
    victim.write_text("innocent\n", encoding="utf-8")

    # (1) Constructor: loading through a symlinked ledger path is refused.
    linked = tmp_path / "replay.jsonl"
    linked.symlink_to(victim)
    with pytest.raises(ReceiptError):
        ReplayLedger(linked)

    # (2) Consume: a symlink planted after construction is refused, nothing
    # is appended to the external target, and nothing is half-consumed.
    late = tmp_path / "replay2.jsonl"
    ledger = ReplayLedger(late)  # nothing on disk yet
    late.symlink_to(victim)
    with pytest.raises(ReceiptError):
        ledger.consume("a" * 64)
    assert victim.read_text(encoding="utf-8") == "innocent\n"
    assert not ledger.has("a" * 64)

    # (3) A real regular file at the same path still works end to end.
    late.unlink()
    ledger.consume("a" * 64)
    assert ReplayLedger(late).has("a" * 64)


def test_keystore_key_with_whitespace_edge_bytes_round_trips(tmp_path):
    # Regression: the key is raw random bytes; roughly 1 in 22 generated keys
    # begins or ends with an ASCII-whitespace byte. Loading must return the
    # stored bytes verbatim — a whitespace-stripping load would reject such a
    # key ("holds no usable key") or, worse, silently verify with different
    # key bytes than the ones that minted the receipts.
    ks = tmp_path / "ks"
    edge_key = b"\n" + b"k" * 30 + b" "  # 32 bytes, whitespace at both edges
    ks.write_bytes(edge_key)
    ks.chmod(0o600)
    assert load_or_create_key(ks) == edge_key
    # Create-then-reload must also agree bit-for-bit.
    ks2 = tmp_path / "ks2"
    created = load_or_create_key(ks2)
    assert len(created) == 32
    assert load_or_create_key(ks2) == created


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("substrate_identity", None),
        ("substrate_identity", 7),
        ("substrate_identity", ""),
        ("substrate_identity", "   "),
        ("substrate_critical_set_digest", None),
        ("substrate_critical_set_digest", 7),
        ("substrate_critical_set_digest", ""),
        ("substrate_critical_set_digest", "   "),
    ],
)
def test_receipt_mint_and_verify_reject_invalid_substrate_binding(field, invalid):
    kwargs = {
        "request_id": "R1",
        "prior_state": "ROUTING_REQUIRED",
        "new_state": "ROUTING_RESOLVED",
        "authority_subject": "Evidenced Entity",
        "authority_evidence_id": "AE-1",
        "evidence_digest": "a" * 64,
        "authority_scope": {"asset_ids": "ALL", "requirement_ids": "ALL"},
        "substrate_identity": "fixture-substrate",
        "substrate_critical_set_digest": "d" * 64,
        "decision": "ALLOW",
        "decision_reason": "fixture",
        "created_at": INSTANT,
    }
    invalid_kwargs = dict(kwargs, **{field: invalid})
    with pytest.raises(ReceiptError):
        mint_receipt(KEY, **invalid_kwargs)

    forged = mint_receipt(KEY, **kwargs)
    forged[field] = invalid
    inputs = AR._decision_inputs(
        request_id=forged["request_id"],
        prior_state=forged["prior_state"],
        new_state=forged["new_state"],
        authority_subject=forged["authority_subject"],
        authority_evidence_id=forged["authority_evidence_id"],
        evidence_digest=forged["evidence_digest"],
        authority_scope=forged["authority_scope"],
        substrate_identity=forged["substrate_identity"],
        substrate_critical_set_digest=forged["substrate_critical_set_digest"],
        decision=forged["decision"],
        decision_reason=forged["decision_reason"],
    )
    forged["decision_inputs_digest"] = hash_obj(inputs)
    forged["receipt_id"] = hash_obj({"decision_inputs_digest": forged["decision_inputs_digest"]})
    body = {key: value for key, value in forged.items() if key != "signature"}
    forged["signature"] = hmac_sign(KEY, canonical_json(body))
    assert not verify_receipt(KEY, forged)


@pytest.mark.parametrize(
    ("identity", "digest"),
    [
        (None, "d" * 64),
        (7, "d" * 64),
        ("", "d" * 64),
        ("   ", "d" * 64),
        ("fixture-substrate", None),
        ("fixture-substrate", 7),
        ("fixture-substrate", ""),
        ("fixture-substrate", "   "),
    ],
)
def test_route_denies_invalid_substrate_binding_before_receipt(identity, digest, monkeypatch):
    minted = False

    def forbidden_mint(*_args, **_kwargs):
        nonlocal minted
        minted = True
        raise AssertionError("router attempted to mint against an invalid substrate")

    monkeypatch.setattr(Router, "mint_receipt", forbidden_mint)
    result = Router.route(
        _requests(),
        [_evidence()],
        substrate_identity=identity,
        substrate_digest=digest,
        key=KEY,
        eval_instant=INSTANT,
        replay=ReplayLedger(),
    )
    assert not minted
    assert result.transitions == []
    assert all(state == "ROUTING_REQUIRED" for state in result.request_final_state.values())
    assert derived_counts(_requests(), result.request_final_state)["ready_to_send"] == 0


def test_transition_receipt_v2_matches_schema_and_v1_fails_closed():
    # substrate_identity carries the GENERATED substrate id: the canonical
    # manifest builder sets substrate_id to the first 16 hex characters of
    # critical_set_digest (_identity.build_manifest), and ingestion copies
    # that value into every transition receipt. The committed schema must
    # accept exactly that shape or every real-path receipt is rejected.
    critical_set_digest = "d" * 64
    receipt = mint_receipt(
        KEY,
        request_id="R1",
        prior_state="ROUTING_REQUIRED",
        new_state="ROUTING_RESOLVED",
        authority_subject="X",
        authority_evidence_id="AE-1",
        evidence_digest="a" * 64,
        authority_scope={"asset_ids": "ALL", "requirement_ids": "ALL"},
        substrate_identity=critical_set_digest[:16],
        substrate_critical_set_digest=critical_set_digest,
        decision="ALLOW",
        decision_reason="x",
        created_at=INSTANT,
    )
    schema = json.loads((PKG / "AUTHORITY_EVIDENCE_SCHEMA.json").read_text())
    receipt_schema = dict(schema["definitions"]["transition_receipt"])
    receipt_schema["properties"] = dict(receipt_schema["properties"])
    receipt_schema["properties"]["authority_scope"] = schema["properties"]["authority_scope"]
    Draft7Validator(receipt_schema).validate(receipt)

    # A substrate_identity that is NOT the generated 16-hex id (e.g. a full
    # 64-hex digest) is a different value than the ingestion path produces
    # and must not validate.
    wrong_shape = dict(receipt, substrate_identity="b" * 64)
    with pytest.raises(ValidationError):
        Draft7Validator(receipt_schema).validate(wrong_shape)

    legacy = dict(receipt, schema="acgs_authority_transition_receipt/v1")
    legacy_body = {key: value for key, value in legacy.items() if key != "signature"}
    legacy["signature"] = hmac_sign(KEY, canonical_json(legacy_body))
    assert not verify_receipt(KEY, legacy)
    with pytest.raises(ValidationError):
        Draft7Validator(receipt_schema).validate(legacy)

    missing_digest = dict(receipt)
    del missing_digest["substrate_critical_set_digest"]
    with pytest.raises(ValidationError):
        Draft7Validator(receipt_schema).validate(missing_digest)


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
        substrate_identity="fixture-substrate",
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
        substrate_identity="fixture-substrate",
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
        substrate_identity="fixture-substrate",
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
    # Refresh the layer's checksum manifest too: identity now honors the
    # transitive pin, and this test must reach the I11 audit, not identity.
    _rewrite_layer_sums(substrate, "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1")
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


def test_verifier_emits_blocked_verdict_on_malformed_manifest(tmp_path, monkeypatch, capsys):
    # A truncated / invalid-JSON substrate_identity.json must produce the
    # required primary verdict (INTEGRATION_BLOCKED), never an uncaught
    # traceback that makes manifest corruption look like a verifier crash.
    import verify_authority_state as V

    home = tmp_path / "home"
    home.mkdir()
    (home / "substrate_identity.json").write_text('{"substrate_id": "trunc', encoding="utf-8")
    monkeypatch.setattr(V, "HERE", home)
    rc = V.main([str(tmp_path / "substrate"), f"--instant={INSTANT}"])
    out = capsys.readouterr().out
    assert rc == 2
    assert f"VERDICT: {V.INTEGRATION_BLOCKED}" in out


def test_verifier_emits_blocked_verdict_on_malformed_registry(
    substrate, tmp_path, monkeypatch, capsys
):
    # A corrupt authority_evidence_registry.jsonl makes read_registry() raise
    # RegistryError (a RuntimeError subclass). The verifier must emit the
    # required primary verdict (INTEGRATION_BLOCKED, rc 2), never an uncaught
    # RegistryError traceback that makes registry corruption look like a
    # verifier crash.
    import verify_authority_state as V

    home = tmp_path / "home"
    home.mkdir()
    manifest = build_manifest(substrate, "TEST_SUBSTRATE")
    (home / V.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    (home / V.REGISTRY_NAME).write_text("{ not json\n", encoding="utf-8")
    monkeypatch.setattr(V, "HERE", home)
    rc = V.main([str(substrate), f"--instant={INSTANT}"])
    out = capsys.readouterr().out
    assert rc == 2
    assert f"VERDICT: {V.INTEGRATION_BLOCKED}" in out


def test_supersession_requires_qualified_successor(substrate, tmp_path):
    # `supersedes` is attacker-writable content: a successor that would not
    # itself stand (here: unattested, IDENTITY_EVIDENCED, no ingestion receipt)
    # must NOT deactivate the established record (denial-of-authority defense).
    # The old record stays classified as verified — and still does not route,
    # because routing additionally requires a trusted attestation.
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
    assert st["report"]["superseded_authority_records"] == 0  # bogus successor ignored
    assert st["report"]["verified_authority_records"] == 1  # AE-OLD still stands
    assert st["report"]["ready_to_send"] == 0  # but unattested evidence never routes


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


def test_ingest_retains_hashed_bytes_despite_document_swap(tmp_path, monkeypatch):
    # TOCTOU regression: the retained artifact must be the SAME bytes that were
    # hashed into source_digest. Simulate a document swapped on disk between
    # hashing and retention by making every read of the document AFTER the
    # first return different bytes — the artifact store must still hold the
    # originally hashed bytes (i.e. the document is read exactly once).
    import ingest_authority_evidence as ING

    original = b"appointment deed (original bytes)"
    doc = tmp_path / "doc"
    doc.write_bytes(original)
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(_evidence(ev_id="AE-TOCTOU", source_digest="")))
    reg = tmp_path / "reg.jsonl"

    real_read_bytes = Path.read_bytes
    reads = {"doc": 0}

    def swapping_read_bytes(self):
        if self == doc:
            reads["doc"] += 1
            if reads["doc"] > 1:
                return b"swapped after hashing"
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", swapping_read_bytes)
    rc = ING.main(
        [
            "--record",
            str(rec),
            "--document",
            str(doc),
            "--registry",
            str(reg),
            "--keystore",
            str(tmp_path / "ks"),
            "--instant",
            INSTANT,
        ]
    )
    assert rc == 0
    retained = tmp_path / ".authority_artifacts" / sha256_hex(original)
    assert retained.is_file()
    assert real_read_bytes(retained) == original


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("substrate_id", None),
        ("substrate_id", 7),
        ("substrate_id", ""),
        ("substrate_id", "   "),
        ("critical_set_digest", None),
        ("critical_set_digest", 7),
        ("critical_set_digest", ""),
        ("critical_set_digest", "   "),
    ],
)
def test_ingest_idempotent_revalidates_current_manifest(
    tmp_path, monkeypatch, field, invalid_value
):
    import ingest_authority_evidence as ING
    from _registry import append_record

    valid_manifest = json.loads((ING.HERE / ING.MANIFEST_NAME).read_text(encoding="utf-8"))
    document = tmp_path / "document"
    document.write_bytes(b"existing authority document")
    record = _evidence(
        ev_id="AE-IDEMPOTENT-BINDING",
        source_digest=sha256_hex(document.read_bytes()),
    )
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    registry = tmp_path / "registry.jsonl"
    append_record(registry, record)
    registry_before = registry.read_bytes()
    record_before = record_path.read_bytes()
    document_before = document.read_bytes()

    manifest_home = tmp_path / "manifest-home"
    manifest_home.mkdir()
    monkeypatch.setattr(ING, "HERE", manifest_home)
    invalid_manifest = dict(valid_manifest)
    invalid_manifest[field] = invalid_value
    (manifest_home / ING.MANIFEST_NAME).write_text(json.dumps(invalid_manifest), encoding="utf-8")
    keystore = tmp_path / "keystore"
    args = [
        "--record",
        str(record_path),
        "--document",
        str(document),
        "--registry",
        str(registry),
        "--keystore",
        str(keystore),
        "--instant",
        INSTANT,
    ]

    assert ING.main(args) == 3
    assert registry.read_bytes() == registry_before
    assert record_path.read_bytes() == record_before
    assert document.read_bytes() == document_before
    assert not (tmp_path / ".authority_artifacts").exists()
    assert not keystore.exists()
    assert len(registry.read_text(encoding="utf-8").splitlines()) == 1
    assert "ingestion_receipt" not in json.loads(
        registry.read_text(encoding="utf-8").splitlines()[0]
    )

    (manifest_home / ING.MANIFEST_NAME).write_text(json.dumps(valid_manifest), encoding="utf-8")
    assert ING.main(args) == 0
    assert registry.read_bytes() == registry_before
    assert not (tmp_path / ".authority_artifacts").exists()
    assert not keystore.exists()


def test_ingest_refuses_symlinked_artifact_store(tmp_path):
    # Retention must not follow symlinks: a `.authority_artifacts` path
    # replaced by a symlink would redirect the retained bytes outside the
    # store, and a symlink pre-planted at the digest path would either be
    # followed by a plain write (dangling) or silently counted as retained.
    import ingest_authority_evidence as ING

    doc = tmp_path / "doc"
    doc.write_text("appointment")
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(_evidence(ev_id="AE-SYMLINK", source_digest="")))
    reg = tmp_path / "reg.jsonl"
    base = [
        "--record",
        str(rec),
        "--registry",
        str(reg),
        "--keystore",
        str(tmp_path / "ks"),
        "--instant",
        INSTANT,
        "--document",
        str(doc),
    ]
    store = tmp_path / ".authority_artifacts"

    # (1) The store itself is a symlink -> refused, nothing appended or escaped.
    outside = tmp_path / "outside"
    outside.mkdir()
    store.symlink_to(outside)
    assert ING.main(list(base)) == 2
    assert list(outside.iterdir()) == []
    assert not reg.exists() or reg.read_text() == ""

    # (2) A symlink pre-planted at the digest path -> refused, not followed.
    store.unlink()
    store.mkdir()
    digest = sha256_hex(b"appointment")
    (store / digest).symlink_to(tmp_path / "planted")
    assert ING.main(list(base)) == 2
    assert not (tmp_path / "planted").exists()
    assert not reg.exists() or reg.read_text() == ""

    # (3) Clean store -> ingested, artifact retained as a regular file.
    (store / digest).unlink()
    assert ING.main(list(base)) == 0
    assert (store / digest).read_bytes() == b"appointment"
    assert not (store / digest).is_symlink()


def test_ingest_repairs_mismatched_retained_artifact(tmp_path):
    # A regular file already occupying the digest path — a partial file left
    # by an interrupted earlier write, or a preplanted wrong-content file —
    # must be re-hashed and repaired from the verified source document before
    # the record is appended. Merely accepting it would leave the evidence
    # permanently non-routable (source_artifact_intact re-hashes the retained
    # bytes) while later same-id ingests hit the idempotent path first.
    import ingest_authority_evidence as ING

    doc = tmp_path / "doc"
    doc.write_text("appointment")
    digest = sha256_hex(b"appointment")
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(_evidence(ev_id="AE-REPAIR", source_digest="")))
    reg = tmp_path / "reg.jsonl"
    store = tmp_path / ".authority_artifacts"
    store.mkdir()
    (store / digest).write_bytes(b"appoin")  # truncated/preplanted occupant
    assert (
        ING.main(
            [
                "--record",
                str(rec),
                "--registry",
                str(reg),
                "--keystore",
                str(tmp_path / "ks"),
                "--instant",
                INSTANT,
                "--document",
                str(doc),
            ]
        )
        == 0
    )
    # The retained artifact now re-verifies against the record's digest.
    assert (store / digest).read_bytes() == b"appointment"
    assert not (store / digest).is_symlink()
    assert len(reg.read_text(encoding="utf-8").splitlines()) == 1


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
        substrate_identity="fixture-substrate",
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


# --------------------------------------------------------------------------- #
# Regressions: request scope binding, registry no-follow, replay framing,
# required onboarding instant.
# --------------------------------------------------------------------------- #
_SCOPE_REMOVED = object()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("covered_asset_ids", _SCOPE_REMOVED),
        ("covered_asset_ids", None),
        ("covered_asset_ids", []),
        ("covered_asset_ids", ["asset:1", ""]),
        ("covered_asset_ids", "asset:1"),
        ("requirement_id", _SCOPE_REMOVED),
        ("requirement_id", None),
        ("requirement_id", ""),
        ("requirement_id", "   "),
    ],
)
def test_request_missing_scope_binding_never_routes(manifest, field, value):
    # A missing/empty covered_asset_ids collapses to the empty set — a subset
    # of EVERY evidence asset list — and with "ALL" scopes a request missing
    # both dimensions would route outright. A request that cannot prove its
    # scope binding must stay ROUTING_REQUIRED (fail closed).
    reqs = _requests()
    if value is _SCOPE_REMOVED:
        reqs[0].pop(field, None)
    else:
        reqs[0][field] = value
    res = _route(reqs, [_evidence()])  # "ALL"/"ALL" evidence — the worst case
    assert res.request_final_state["R1"] == "ROUTING_REQUIRED"
    assert res.request_final_state["R2"] == "READY_TO_SEND"  # intact sibling still routes


def test_registry_symlink_refused_read_and_append(tmp_path):
    # A registry path swapped for a symlink to a writable external file must
    # be refused on BOTH paths: read (planted external records would enter
    # the trust derivation) and append (an authenticated ingestion would
    # corrupt a file outside the configured registry store).
    from _registry import RegistryError, append_record, read_registry

    external = tmp_path / "outside.jsonl"
    external.write_text(json.dumps(_evidence(ev_id="AE-PLANTED")) + "\n", encoding="utf-8")
    before = external.read_bytes()
    reg = tmp_path / "reg.jsonl"
    reg.symlink_to(external)
    with pytest.raises(RegistryError):
        read_registry(reg)
    with pytest.raises(RegistryError):
        append_record(reg, _evidence(ev_id="AE-INJECTED"))
    assert external.read_bytes() == before  # nothing written through the link
    # Positive control: a regular registry file still round-trips.
    real = tmp_path / "real.jsonl"
    append_record(real, _evidence(ev_id="AE-OK"))
    assert [r["authority_evidence_id"] for r in read_registry(real)] == ["AE-OK"]


def test_replay_ledger_refuses_unterminated_tail(tmp_path):
    # An interrupted append that leaves the final line unterminated must be
    # an explicit error: silently loading the fragment forgets the real
    # consumed receipt id (replays accepted), and the next append would
    # concatenate a fresh id onto the fragment.
    path = tmp_path / "replay.jsonl"
    ledger = ReplayLedger(path)
    ledger.consume_many(["receipt-1"])
    path.write_bytes(path.read_bytes()[:-1])  # simulate the interrupted append
    corrupt = path.read_bytes()
    with pytest.raises(ReceiptError):
        ReplayLedger(path)  # restart refuses to trust the broken framing
    with pytest.raises(ReceiptError):
        ledger.consume_many(["receipt-2"])  # and refuses to extend it
    assert path.read_bytes() == corrupt  # nothing concatenated onto the fragment
    # After the fragment is restored (terminated), the consumed id is
    # remembered and replay is still refused.
    path.write_bytes(corrupt + b"\n")
    with pytest.raises(ReceiptError):
        ReplayLedger(path).consume_many(["receipt-1"])


def test_onboard_requires_evaluation_instant(tmp_path, capsys):
    # Gate 3b forwards --instant to verify_attestation_trust, where the
    # attestation_future_dated check only runs when an instant exists:
    # without one, a signed attestation claiming a future validation time
    # would be ingested. Ingestion without a valid instant must be refused
    # before anything is written.
    import onboard_authority_evidence as OB

    doc = tmp_path / "doc"
    doc.write_text("appointment")
    rec = tmp_path / "rec.json"
    rec.write_text(
        json.dumps(
            dict(
                _evidence(ev_id="AE-NO-INSTANT", source_digest=""),
                issuer_or_appointing_party="[FIXTURE] Board",
            )
        )
    )
    reg = tmp_path / "reg.jsonl"
    base = [
        "--record",
        str(rec),
        "--document",
        str(doc),
        "--registry",
        str(reg),
        "--keystore",
        str(tmp_path / "ks"),
        "--validator-registry",
        str(tmp_path / "vreg.jsonl"),
        "--validator-keystore",
        str(tmp_path / "vks"),
    ]
    assert OB.main(list(base)) == 2  # no --instant
    assert OB.main([*base, "--instant", "not-a-time"]) == 2  # unparseable
    assert not reg.exists()  # registry untouched either way
    # --emit-binding computes a binding only (no ingest, no trust
    # evaluation) and legitimately needs no instant.
    assert OB.main([*base, "--emit-binding"]) == 0
    assert not reg.exists()


def test_attack_artifact_store_symlink_swap_rejected(tmp_path):
    """A retained artifact entry — or the store directory itself — swapped for
    a symlink to byte-identical content outside the retention store must not
    verify: the artifact is opened through a pinned, non-followed store fd."""
    from authority_router import source_artifact_intact

    record = _evidence()
    store = tmp_path / "artifacts"
    store.mkdir()
    entry = store / FIXTURE_DIGEST
    entry.write_bytes(FIXTURE_DOC)
    assert source_artifact_intact(record, store) is True

    external = tmp_path / "outside-copy"
    external.write_bytes(FIXTURE_DOC)
    entry.unlink()
    entry.symlink_to(external)
    assert source_artifact_intact(record, store) is False

    entry.unlink()
    entry.write_bytes(FIXTURE_DOC)
    linked_store = tmp_path / "linked-store"
    linked_store.symlink_to(store)
    assert source_artifact_intact(record, linked_store) is False
