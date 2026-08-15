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
        variant_tree_sha256=None,
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


class TestAnchorEntries:
    def test_anchor_must_reference_existing_entry(self, tmp_path):
        ledger = _mk(tmp_path)
        with pytest.raises(LedgerStateError):
            ledger.append_anchor(head_hash="ab" * 32, anchor_ref={"kind": "rfc3161"}, timestamp=T)

    def test_anchor_upgrades_evidence_label(self, tmp_path):
        ledger = _mk(tmp_path)
        prepared = _prepare(ledger)
        issuer = sig.ephemeral_test_key("issuer")
        licensee = sig.ephemeral_test_key("licensee")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer, timestamp=T
        )
        counter = ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee, timestamp=T
        )
        vid = prepared["body"]["variant_id"]
        assert ledger.issuance_state(vid)["evidence_label"] == "publisher-testimony"
        ledger.append_anchor(
            head_hash=counter["entry_hash"],
            anchor_ref={"kind": "rfc3161", "bundle_sha256": "33" * 32, "production": False},
            timestamp=T,
        )
        state = ledger.issuance_state(vid)
        assert state["anchored"] and state["evidence_label"] == "anchored"
