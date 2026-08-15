from __future__ import annotations

import json
from pathlib import Path

import pytest
from acgs_canary import signing as sig
from acgs_canary.canonical import canonical_bytes
from acgs_canary.errors import KeyPolicyError, LedgerError, LedgerStateError
from acgs_canary.ledger import AcceptanceLedger
from acgs_canary.protocol import protocol_hash

T = "2026-08-15T00:00:00Z"
H = "11" * 32


def _mk(tmp_path: Path, name: str = "ledger.jsonl") -> AcceptanceLedger:
    return AcceptanceLedger.create(
        tmp_path / name, protocol_sha256=protocol_hash(), operator="t", timestamp=T
    )


def _prepare(ledger: AcceptanceLedger, vid: str = "vt_" + "cc" * 16, tier: str = "T1"):
    return ledger.append_prepared(
        variant_id=vid,
        tier=tier,
        variant_tree_sha256=H,
        source_tree_sha256=H,
        canary_commitment_hex=H,
        allocation_manifest_sha256=H,
        licensee_ref="lref_" + "ab" * 32 if tier == "T1" else None,
        acceptance_ref={"kind": "contract", "doc_hash": "22" * 32},
        delivery={"channel": "test", "ref": "local"},
        timestamp=T,
    )


class TestChainBasics:
    def test_create_and_verify(self, tmp_path):
        ledger = _mk(tmp_path)
        report = ledger.verify()
        assert report.entries == 1 and not report.torn_tail

    def test_no_overwrite(self, tmp_path):
        _mk(tmp_path)
        with pytest.raises(LedgerError):
            _mk(tmp_path)

    def test_duplicate_variant_issuance_rejected(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        with pytest.raises(LedgerError):
            _prepare(ledger)

    def test_t1_without_licensee_ref_rejected(self, tmp_path):
        ledger = _mk(tmp_path)
        with pytest.raises(LedgerStateError):
            ledger.append_prepared(
                variant_id="vt_" + "dd" * 16,
                tier="T1",
                variant_tree_sha256=None,
                source_tree_sha256=H,
                canary_commitment_hex=H,
                allocation_manifest_sha256=H,
                licensee_ref=None,
                acceptance_ref=None,
                delivery=None,
                timestamp=T,
            )


class TestTampering:
    def _entries(self, path: Path) -> list[bytes]:
        return path.read_bytes().split(b"\n")

    def test_body_tamper_detected(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        p = tmp_path / "ledger.jsonl"
        lines = self._entries(p)
        lines[1] = lines[1].replace(b'"tier":"T1"', b'"tier":"T0"')
        p.write_bytes(b"\n".join(lines))
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_prev_hash_substitution_detected(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        p = tmp_path / "ledger.jsonl"
        lines = self._entries(p)
        entry = json.loads(lines[1])
        entry["prev"] = "ab" * 32
        # attacker recomputes entry_hash to look self-consistent
        from acgs_canary.ledger import _entry_hash

        entry["entry_hash"] = _entry_hash(entry)
        lines[1] = canonical_bytes(entry)
        p.write_bytes(b"\n".join(lines))
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_truncation_detected(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        prepared2 = _prepare(ledger, vid="vt_" + "ee" * 16)
        assert prepared2
        p = tmp_path / "ledger.jsonl"
        lines = p.read_bytes().split(b"\n")
        # drop a MIDDLE entry: chain must break
        p.write_bytes(b"\n".join([lines[0], *lines[2:]]))
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_tail_truncation_is_silent_rollback_and_detected_by_seq(self, tmp_path):
        # Removing the newest entries yields a VALID shorter chain — that is
        # inherent to hash chains and exactly why heads must be anchored.
        # The ledger itself cannot detect it; the anchor comparison does.
        ledger = _mk(tmp_path)
        e1 = _prepare(ledger)
        p = tmp_path / "ledger.jsonl"
        head_before = ledger.verify().head_hash
        assert head_before == e1["entry_hash"]
        lines = p.read_bytes().split(b"\n")
        p.write_bytes(lines[0] + b"\n")
        report = ledger.verify()
        assert report.head_hash != head_before  # anchored head no longer present

    def test_reorder_detected(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        _prepare(ledger, vid="vt_" + "ee" * 16)
        p = tmp_path / "ledger.jsonl"
        lines = p.read_bytes().split(b"\n")
        lines[1], lines[2] = lines[2], lines[1]
        p.write_bytes(b"\n".join(lines))
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_non_canonical_encoding_rejected(self, tmp_path):
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        raw = p.read_bytes()
        entry = json.loads(raw)
        pretty = json.dumps(entry, indent=1).encode() + b"\n"
        p.write_bytes(pretty)
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_unknown_critical_field_rejected(self, tmp_path):
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        entry = json.loads(p.read_bytes())
        entry["extra_field"] = 1
        p.write_bytes(canonical_bytes(entry) + b"\n")
        with pytest.raises(LedgerError):
            ledger.verify()


class TestTornTail:
    def test_torn_tail_detected_and_blocks_append(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        p = tmp_path / "ledger.jsonl"
        p.write_bytes(p.read_bytes() + b'{"schema":"acgs_canary_ledger/v1","truncat')
        with pytest.raises(LedgerError):
            ledger.verify()
        with pytest.raises(LedgerError):
            _prepare(ledger, vid="vt_" + "ff" * 16)

    def test_torn_tail_recovery_drops_partial_line(self, tmp_path):
        ledger = _mk(tmp_path)
        _prepare(ledger)
        p = tmp_path / "ledger.jsonl"
        good = p.read_bytes()
        p.write_bytes(good + b'{"torn')
        assert ledger.recover_torn_tail() is True
        report = ledger.verify()
        assert report.entries == 2 and not report.torn_tail

    def test_missing_final_newline_resealed(self, tmp_path):
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        raw = p.read_bytes()
        p.write_bytes(raw.rstrip(b"\n"))
        assert ledger.recover_torn_tail() is True
        assert ledger.verify().entries == 1

    def test_crash_sim_append_boundary(self, tmp_path):
        # Simulate a crash at every byte boundary of an append: the ledger
        # must either verify (complete append) or be recoverable to the
        # pre-append state — never silently corrupt.
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        before = p.read_bytes()
        _prepare(ledger)
        after = p.read_bytes()
        appended = after[len(before) :]
        for cut in range(1, len(appended)):
            p.write_bytes(before + appended[:cut])
            try:
                ledger.verify()
                assert appended[:cut] == appended  # only full append verifies
            except LedgerError:
                ledger.recover_torn_tail()
                report = ledger.verify(allow_torn_tail=True)
                assert report.entries in (1, 2)
        p.write_bytes(after)
        assert ledger.verify().entries == 2


class TestSignatures:
    def test_full_signature_flow(self, tmp_path):
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        ledger.verify()
        state = ledger.issuance_state(prepared["body"]["variant_id"])
        assert state["completed_t1_issuance"] and state["state"] == "countersigned"

    def test_countersign_omission_never_completed(self, tmp_path):
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        state = ledger.issuance_state(prepared["body"]["variant_id"])
        assert not state["completed_t1_issuance"]
        assert state["evidence_label"] == "publisher-testimony"

    def test_production_policy_blocks_ephemeral(self, tmp_path):
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        with pytest.raises(KeyPolicyError):
            ledger.append_issuer_signature(
                target_entry_hash=prepared["entry_hash"],
                key=issuer,
                timestamp=T,
                production=True,
            )

    def test_role_confusion_rejected(self, tmp_path):
        # A licensee-role signature spliced into an issuer-signed entry must fail.
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        licensee = sig.ephemeral_test_key("licensee")
        # Forge an issuer-signed entry whose signature was made under the
        # licensee role/purpose.
        forged_sig = sig.sign(
            licensee,
            ledger_id=prepared["ledger_id"],
            protocol_sha256=prepared["protocol_sha256"],
            role=sig.ROLE_LICENSEE,
            purpose=sig.PURPOSE_COUNTERSIGN,
            payload=bytes.fromhex(prepared["entry_hash"]),
        )
        p = tmp_path / "ledger.jsonl"
        from acgs_canary.ledger import _make_entry

        head = json.loads(p.read_bytes().split(b"\n")[-2])
        forged = _make_entry(
            ledger_id=prepared["ledger_id"],
            protocol_sha256=prepared["protocol_sha256"],
            seq=head["seq"] + 1,
            prev=head["entry_hash"],
            kind="variant.issuer_signed",
            timestamp=T,
            body={"target_entry_hash": prepared["entry_hash"], "signature": forged_sig},
        )
        with open(p, "ab") as fh:
            fh.write(canonical_bytes(forged) + b"\n")
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_cross_ledger_replay_rejected(self, tmp_path):
        # A valid issuer signature from ledger A replayed into ledger B fails
        # because the signature binds ledger_id.
        la = _mk(tmp_path, "a.jsonl")
        lb = _mk(tmp_path, "b.jsonl")
        vid = "vt_" + "cc" * 16
        pa = _prepare(la, vid=vid)
        pb = _prepare(lb, vid=vid)
        issuer = sig.ephemeral_test_key("issuer")
        ia = la.append_issuer_signature(target_entry_hash=pa["entry_hash"], key=issuer, timestamp=T)
        # splice A's signature entry body into B
        pb_path = tmp_path / "b.jsonl"
        head_b = json.loads(pb_path.read_bytes().split(b"\n")[-2])
        from acgs_canary.ledger import _make_entry

        spliced = _make_entry(
            ledger_id=pb["ledger_id"],
            protocol_sha256=pb["protocol_sha256"],
            seq=head_b["seq"] + 1,
            prev=head_b["entry_hash"],
            kind="variant.issuer_signed",
            timestamp=T,
            body={"target_entry_hash": pb["entry_hash"], "signature": ia["body"]["signature"]},
        )
        with open(pb_path, "ab") as fh:
            fh.write(canonical_bytes(spliced) + b"\n")
        with pytest.raises(LedgerError):
            lb.verify()

    def test_signature_substitution_invalidates_countersignature(self, tmp_path):
        # Replace the issuer-signature entry after the countersignature:
        # the countersignature binds the issuer ENTRY hash, so verification
        # of the replaced chain must fail.
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer1 = sig.ephemeral_test_key("issuer1")
        issuer2 = sig.ephemeral_test_key("issuer2")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer1, timestamp=T
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        p = tmp_path / "ledger.jsonl"
        lines = p.read_bytes().split(b"\n")
        # Attacker rebuilds the issuer entry with a different key and repairs
        # the local chain hashes (full re-mint of entries 2..3).
        from acgs_canary.ledger import _make_entry

        sub_sig = sig.sign(
            issuer2,
            ledger_id=prepared["ledger_id"],
            protocol_sha256=prepared["protocol_sha256"],
            role=sig.ROLE_ISSUER,
            purpose=sig.PURPOSE_ISSUE,
            payload=bytes.fromhex(prepared["entry_hash"]),
        )
        new_issued = _make_entry(
            ledger_id=prepared["ledger_id"],
            protocol_sha256=prepared["protocol_sha256"],
            seq=2,
            prev=prepared["entry_hash"],
            kind="variant.issuer_signed",
            timestamp=T,
            body={"target_entry_hash": prepared["entry_hash"], "signature": sub_sig},
        )
        old_counter = json.loads(lines[3])
        repaired_counter = _make_entry(
            ledger_id=prepared["ledger_id"],
            protocol_sha256=prepared["protocol_sha256"],
            seq=3,
            prev=new_issued["entry_hash"],
            kind="variant.countersigned",
            timestamp=T,
            body=old_counter["body"],  # still binds the OLD issuer entry hash
        )
        p.write_bytes(
            b"\n".join(
                [lines[0], lines[1], canonical_bytes(new_issued), canonical_bytes(repaired_counter)]
            )
            + b"\n"
        )
        with pytest.raises(LedgerError):
            ledger.verify()


def _bundle_for(ledger: AcceptanceLedger):
    from acgs_canary.anchor import build_anchor_bundle

    head = ledger.verify().head_hash
    return build_anchor_bundle(
        ledger_head_hash=head,
        pool_manifest_sha256=H,
        protocol_sha256=protocol_hash(),
        commitment_roots_hex=[],
        created_at=T,
    )


def _evidence_for(bundle, *, kind="rfc3161", state=None, production=False):
    from acgs_canary.anchor import STATE_CONFIRMED, AnchorEvidence, bundle_hash

    return AnchorEvidence(
        kind=kind,
        state=state or STATE_CONFIRMED,
        bundle_sha256=bundle_hash(bundle),
        evidence_ref="fx",
        anchored_at=T,
        production=production,
    )


class TestAnchorEntries:
    def test_anchor_head_must_be_in_chain(self, tmp_path):
        from acgs_canary.anchor import build_anchor_bundle

        ledger = _mk(tmp_path)
        bogus = build_anchor_bundle(
            ledger_head_hash="ab" * 32,
            pool_manifest_sha256=H,
            protocol_sha256=protocol_hash(),
            commitment_roots_hex=[],
            created_at=T,
        )
        with pytest.raises(LedgerStateError):
            ledger.append_anchor(bundle=bogus, evidence=_evidence_for(bogus), timestamp=T)

    def test_mirror_evidence_refused_at_append(self, tmp_path):
        ledger = _mk(tmp_path)
        bundle = _bundle_for(ledger)
        with pytest.raises(LedgerStateError):
            ledger.append_anchor(
                bundle=bundle, evidence=_evidence_for(bundle, kind="mirror"), timestamp=T
            )

    def test_evidence_bundle_mismatch_refused(self, tmp_path):
        from acgs_canary.anchor import STATE_CONFIRMED, AnchorEvidence

        ledger = _mk(tmp_path)
        bundle = _bundle_for(ledger)
        mismatched = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256="44" * 32,  # not the bundle's hash
            evidence_ref="fx",
            anchored_at=T,
            production=False,
        )
        with pytest.raises(LedgerStateError):
            ledger.append_anchor(bundle=bundle, evidence=mismatched, timestamp=T)

    def test_recorded_anchor_is_never_labeled_anchored_structurally(self, tmp_path):
        # Review MAJOR-1 regression: recording an anchor entry — even a
        # legitimate one — must not surface as "anchored" from the
        # structural fold. That label needs the verified path.
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        vid = prepared["body"]["variant_id"]
        assert ledger.issuance_state(vid)["evidence_label"] == "publisher-testimony"
        bundle = _bundle_for(ledger)
        evidence = _evidence_for(bundle)
        ledger.append_anchor(bundle=bundle, evidence=evidence, timestamp=T)
        state = ledger.issuance_state(vid)
        assert state["anchor_entry_recorded"]
        assert state["evidence_label"] == "anchor-entry-recorded"
        assert "anchored" not in (state["evidence_label"],)

    def test_verified_path_labels_fixture_evidence_non_production(self, tmp_path):
        from acgs_canary.anchor import FixtureVerifier, bundle_hash

        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        vid = prepared["body"]["variant_id"]
        bundle = _bundle_for(ledger)
        evidence = _evidence_for(bundle)
        ledger.append_anchor(bundle=bundle, evidence=evidence, timestamp=T)
        fx = FixtureVerifier({"fx": {"bundle_sha256": bundle_hash(bundle), "anchored_at": T}})
        state = ledger.anchored_issuance_state(vid, bundle=bundle, evidence=evidence, verifier=fx)
        assert state["evidence_label"] == "anchored-non-production"

    def test_verified_path_falls_back_on_unverifiable_evidence(self, tmp_path):
        from acgs_canary.anchor import FixtureVerifier

        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        vid = prepared["body"]["variant_id"]
        bundle = _bundle_for(ledger)
        evidence = _evidence_for(bundle)
        ledger.append_anchor(bundle=bundle, evidence=evidence, timestamp=T)
        empty_verifier = FixtureVerifier({})  # cannot confirm anything
        state = ledger.anchored_issuance_state(
            vid, bundle=bundle, evidence=evidence, verifier=empty_verifier
        )
        assert state["evidence_label"] == "anchor-entry-recorded"


class TestIssuanceStateFailClosed:
    def test_forged_countersignature_never_reports_completion(self, tmp_path):
        # Review MAJOR-2 regression: a hand-minted countersigned entry with
        # a garbage signature must not surface as completed T1 — the fold
        # verifies the chain first and raises.
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        from acgs_canary.ledger import _make_entry

        forged_sig_meta = {
            "algorithm": "ed25519",
            "key_id": "fake",
            "key_class": "ephemeral-test",
            "public_key_hex": sig.ephemeral_test_key("x").signer.public_bytes().hex(),
            "role": "licensee",
            "purpose": "variant-countersign",
            "signature_hex": "00" * 64,
        }
        forged = _make_entry(
            ledger_id=issued["ledger_id"],
            protocol_sha256=issued["protocol_sha256"],
            seq=issued["seq"] + 1,
            prev=issued["entry_hash"],
            kind="variant.countersigned",
            timestamp=T,
            body={"issuer_entry_hash": issued["entry_hash"], "signature": forged_sig_meta},
        )
        p = tmp_path / "ledger.jsonl"
        with open(p, "ab") as fh:
            fh.write(canonical_bytes(forged) + b"\n")
        with pytest.raises(LedgerError):
            ledger.issuance_state(prepared["body"]["variant_id"])

    def test_whitespace_padded_line_rejected(self, tmp_path):
        # Review MINOR-1 regression: canonical check compares exact bytes.
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        raw = p.read_bytes()
        p.write_bytes(raw[:-1] + b"  \n")
        with pytest.raises(LedgerError):
            ledger.verify()


class TestReviewHardening:
    def test_foreign_protocol_create_rejected(self, tmp_path):
        with pytest.raises(LedgerError):
            AcceptanceLedger.create(
                tmp_path / "foreign.jsonl",
                protocol_sha256="99" * 32,
                operator="t",
                timestamp=T,
            )

    def test_foreign_genesis_protocol_rejected_at_verify(self, tmp_path):
        # A self-consistent chain minted under a DIFFERENT protocol identity
        # must not verify against this package's frozen protocol.
        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        from acgs_canary.ledger import _entry_hash

        entry = json.loads(p.read_bytes())
        entry["protocol_sha256"] = "99" * 32
        entry["entry_hash"] = _entry_hash(entry)
        p.write_bytes(canonical_bytes(entry) + b"\n")
        with pytest.raises(LedgerError):
            ledger.verify()

    def test_raw_identity_licensee_ref_rejected(self, tmp_path):
        ledger = _mk(tmp_path)
        for raw in ("alice@example.com", "lref_short", "lref_" + "AB" * 32):
            with pytest.raises(LedgerStateError):
                ledger.append_prepared(
                    variant_id="vt_" + "dd" * 16,
                    tier="T1",
                    variant_tree_sha256=H,
                    source_tree_sha256=H,
                    canary_commitment_hex=H,
                    allocation_manifest_sha256=H,
                    licensee_ref=raw,
                    acceptance_ref={"kind": "contract", "doc_hash": "22" * 32},
                    delivery={"channel": "test", "ref": "local"},
                    timestamp=T,
                )

    def test_t1_prepare_requires_acceptance_and_delivery(self, tmp_path):
        ledger = _mk(tmp_path)
        for acceptance_ref, delivery in (
            (None, {"channel": "test", "ref": "local"}),
            ({"kind": "contract", "doc_hash": "22" * 32}, None),
            # Empty or malformed bindings attest nothing and are refused:
            ({}, {"channel": "test", "ref": "local"}),
            ({"kind": "contract", "doc_hash": "22" * 32}, {}),
            ({"kind": "", "doc_hash": "22" * 32}, {"channel": "test", "ref": "local"}),
            ({"kind": "contract", "doc_hash": "bad"}, {"channel": "test", "ref": "local"}),
            ({"kind": "contract"}, {"channel": "test", "ref": "local"}),
            ({"kind": "contract", "doc_hash": "22" * 32}, {"channel": "test", "ref": " "}),
            (
                {"kind": "contract", "doc_hash": "22" * 32},
                {"channel": "test", "ref": "local", "countersign_ref": "bad"},
            ),
        ):
            with pytest.raises(LedgerStateError):
                ledger.append_prepared(
                    variant_id="vt_" + "dd" * 16,
                    tier="T1",
                    variant_tree_sha256=H,
                    source_tree_sha256=H,
                    canary_commitment_hex=H,
                    allocation_manifest_sha256=H,
                    licensee_ref="lref_" + "ab" * 32,
                    acceptance_ref=acceptance_ref,
                    delivery=delivery,
                    timestamp=T,
                )

    def test_malformed_digest_bindings_rejected(self, tmp_path):
        # Every digest binding must be a canonical SHA-256 digest; an entry
        # binding "bad" for its source, canary set, or allocation artifact
        # must never become signable.
        ledger = _mk(tmp_path)
        for field in (
            "source_tree_sha256",
            "canary_commitment_hex",
            "allocation_manifest_sha256",
        ):
            for bad in ("bad", "ZZ" * 32, "22" * 31, None):
                kwargs = dict(
                    variant_id="vt_" + "dd" * 16,
                    tier="T0",
                    variant_tree_sha256=H,
                    source_tree_sha256=H,
                    canary_commitment_hex=H,
                    allocation_manifest_sha256=H,
                    licensee_ref=None,
                    acceptance_ref=None,
                    delivery=None,
                    timestamp=T,
                )
                kwargs[field] = bad
                with pytest.raises(LedgerStateError):
                    ledger.append_prepared(**kwargs)

    def test_countersigned_with_malformed_bindings_not_completed(self, tmp_path):
        # Even if a prepared entry with empty bindings somehow existed in the
        # chain, the fold must not report completion: presence-only checks
        # are not enough. Exercised by hand-minting the prepared body.
        from acgs_canary.ledger import _make_entry

        ledger = _mk(tmp_path)
        p = tmp_path / "ledger.jsonl"
        genesis = json.loads(p.read_bytes().split(b"\n")[0])
        forged = _make_entry(
            ledger_id=genesis["ledger_id"],
            protocol_sha256=genesis["protocol_sha256"],
            seq=1,
            prev=genesis["entry_hash"],
            kind="variant.prepared",
            timestamp=T,
            body={
                "variant_id": "vt_" + "dd" * 16,
                "tier": "T1",
                "variant_tree_sha256": H,
                "source_tree_sha256": H,
                "canary_commitment_hex": H,
                "allocation_manifest_sha256": H,
                "licensee_ref": "lref_" + "ab" * 32,
                "acceptance_ref": {},
                "delivery": {},
            },
        )
        with open(p, "ab") as fh:
            fh.write(canonical_bytes(forged) + b"\n")
        issued = ledger.append_issuer_signature(
            target_entry_hash=forged["entry_hash"],
            key=sig.ephemeral_test_key("issuer"),
            timestamp=T,
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"],
            key=sig.ephemeral_test_key("licensee"),
            timestamp=T,
        )
        state = ledger.issuance_state("vt_" + "dd" * 16)
        assert state["state"] == "countersigned"
        assert not state["completed_t1_issuance"]

    def test_countersigned_without_variant_tree_not_completed(self, tmp_path):
        # A countersignature over a prepared entry with no delivered tree
        # hash must not read as a completed T1 issuance.
        ledger = _mk(tmp_path)
        prepared = ledger.append_prepared(
            variant_id="vt_" + "cc" * 16,
            tier="T1",
            variant_tree_sha256=None,
            source_tree_sha256=H,
            canary_commitment_hex=H,
            allocation_manifest_sha256=H,
            licensee_ref="lref_" + "ab" * 32,
            acceptance_ref={"kind": "contract", "doc_hash": "22" * 32},
            delivery={"channel": "test", "ref": "local"},
            timestamp=T,
        )
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"],
            key=sig.ephemeral_test_key("issuer"),
            timestamp=T,
        )
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"],
            key=sig.ephemeral_test_key("licensee"),
            timestamp=T,
        )
        state = ledger.issuance_state(prepared["body"]["variant_id"])
        assert state["state"] == "countersigned"
        assert not state["completed_t1_issuance"]

    def test_org_labeled_generated_key_refused_for_production(self):
        # key_class is caller-supplied metadata: declaring "organization"
        # on a locally generated key must not unlock production issuance.
        from gove_zone.signing import Ed25519Signer

        fake_org = sig.BoundKey(
            signer=Ed25519Signer.generate(key_id="fake-org"),
            key_class=sig.KEY_CLASS_ORGANIZATION,
        )
        with pytest.raises(KeyPolicyError):
            sig.enforce_production_policy(fake_org, production=True)

    def test_verified_anchor_predating_state_entry_not_labeled_anchored(self, tmp_path):
        # An old VERIFIABLE anchor plus a newer UNVERIFIABLE anchor must not
        # combine into an "anchored" label for a state entry that only the
        # newer anchor covers.
        from acgs_canary.anchor import FixtureVerifier, bundle_hash

        ledger = _mk(tmp_path)
        _prepare(ledger, vid="vt_" + "aa" * 16)
        bundle1 = _bundle_for(ledger)
        evidence1 = _evidence_for(bundle1)
        ledger.append_anchor(bundle=bundle1, evidence=evidence1, timestamp=T)
        p2 = _prepare(ledger, vid="vt_" + "ee" * 16)
        bundle2 = _bundle_for(ledger)
        ledger.append_anchor(bundle=bundle2, evidence=_evidence_for(bundle2), timestamp=T)
        vid2 = p2["body"]["variant_id"]
        assert ledger.issuance_state(vid2)["anchor_entry_recorded"]
        fx = FixtureVerifier({"fx": {"bundle_sha256": bundle_hash(bundle1), "anchored_at": T}})
        state = ledger.anchored_issuance_state(
            vid2, bundle=bundle1, evidence=evidence1, verifier=fx
        )
        assert state["evidence_label"] == "anchor-entry-recorded"

    def test_confirmed_evidence_without_anchor_time_never_labeled_anchored(self, tmp_path):
        # An anchor is a timestamp: confirmed evidence with anchored_at=None
        # (and a fixture that likewise records none, so the verifier agrees)
        # must not surface as anchored in either label.
        from acgs_canary.anchor import STATE_CONFIRMED, AnchorEvidence, FixtureVerifier, bundle_hash

        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        bundle = _bundle_for(ledger)
        for anchored_at in (None, "not-a-timestamp", "2026-08-15T00:00:00"):
            evidence = AnchorEvidence(
                kind="rfc3161",
                state=STATE_CONFIRMED,
                bundle_sha256=bundle_hash(bundle),
                evidence_ref=f"fx-{anchored_at}",
                anchored_at=anchored_at,
                production=False,
            )
            fx = FixtureVerifier(
                {
                    f"fx-{anchored_at}": {
                        "bundle_sha256": bundle_hash(bundle),
                        "anchored_at": anchored_at,
                    }
                }
            )
            assert fx.verify(evidence, bundle)  # the verifier alone would confirm
            ledger.append_anchor(bundle=bundle, evidence=evidence, timestamp=T)
            state = ledger.anchored_issuance_state(
                prepared["body"]["variant_id"], bundle=bundle, evidence=evidence, verifier=fx
            )
            assert state["evidence_label"] == "anchor-entry-recorded"

    def test_concurrent_duplicate_issuance_rejected(self, tmp_path):
        # Two appenders preparing the SAME variant concurrently: the
        # duplicate check runs inside the locked verify-and-append
        # transaction, so exactly one append may win.
        import multiprocessing as mp

        ledger = _mk(tmp_path)
        path = str(tmp_path / "ledger.jsonl")

        def worker(q) -> None:
            lg = AcceptanceLedger(Path(path))
            try:
                lg.append_prepared(
                    variant_id="vt_" + "aa" * 16,
                    tier="T0",
                    variant_tree_sha256=H,
                    source_tree_sha256=H,
                    canary_commitment_hex=H,
                    allocation_manifest_sha256=H,
                    licensee_ref=None,
                    acceptance_ref=None,
                    delivery=None,
                    timestamp=T,
                )
                q.put(1)
            except LedgerError:
                q.put(0)

        ctx = mp.get_context("fork")
        q = ctx.Queue()
        procs = [ctx.Process(target=worker, args=(q,)) for _ in range(5)]
        for pr in procs:
            pr.start()
        for pr in procs:
            pr.join()
        results = [q.get() for _ in range(5)]
        assert sum(results) == 1  # exactly one append won
        report = ledger.verify()
        assert report.entries == 2  # genesis + the single prepared entry

    def test_concurrent_appends_serialized_by_lock(self, tmp_path):
        # Two processes appending concurrently must produce a valid chain
        # with unique seq numbers, never a forked head.
        import multiprocessing as mp

        ledger = _mk(tmp_path)
        path = str(tmp_path / "ledger.jsonl")

        def worker(i: int) -> None:
            lg = AcceptanceLedger(Path(path))
            lg.append_prepared(
                variant_id="vt_" + f"{i:02x}" * 16,
                tier="T0",
                variant_tree_sha256=H,
                source_tree_sha256=H,
                canary_commitment_hex=H,
                allocation_manifest_sha256=H,
                licensee_ref=None,
                acceptance_ref=None,
                delivery=None,
                timestamp=T,
            )

        ctx = mp.get_context("fork")
        procs = [ctx.Process(target=worker, args=(i,)) for i in range(1, 6)]
        for pr in procs:
            pr.start()
        for pr in procs:
            pr.join()
        assert all(pr.exitcode == 0 for pr in procs)
        report = ledger.verify()
        assert report.entries == 6  # genesis + 5 appends, one chain, no forks
