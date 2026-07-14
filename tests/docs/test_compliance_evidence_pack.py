"""Anti-rot gate for the ACGS Compliance Evidence Pack.

Keeps the committed pack under ``compliance/evidence-pack`` honest and current:

* it must be **byte-reproducible** from the mapping + the committed governed-action
  inputs with the pinned clock (any drift is a reviewable diff, not silent rot);
* its manifest must cover every file and every digest must match;
* the inner proof pack must verify offline through the public API;
* every framework sheet must carry every mapped requirement id and the
  not-certified disclaimer (guards against overclaim creep);
* the CLI entrypoint must be wired (generate then verify a fresh pack);
* a tampered pack must fail verification (negative path).

Runs in the ``tests/docs`` gate, which puts ``packages/gove-zone/src`` on
``sys.path`` in-process via ``conftest.py`` (no gove-zone install, no crypto
extra needed — the generate/verify path is pure stdlib + pure-source gove_zone).
"""

from __future__ import annotations

import filecmp
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "compliance"))

import evidence_pack as ep  # noqa: E402

COMMITTED_PACK = ROOT / "compliance" / "evidence-pack"


def _load_mapping() -> dict:
    return ep.load_mapping()


def _all_requirement_ids(fw_key: str) -> list[str]:
    fw = _load_mapping()["frameworks"][fw_key]
    return [entry["id"] for entry in fw["requirements"]]


def test_committed_pack_is_byte_reproducible(tmp_path: Path) -> None:
    """Regenerating with the pinned clock must reproduce the committed pack exactly."""
    fresh = tmp_path / "evidence-pack"
    ep.build_evidence_pack(fresh, now_iso=ep.PINNED_NOW_ISO, force=True)

    committed_files = {
        p.relative_to(COMMITTED_PACK).as_posix() for p in COMMITTED_PACK.rglob("*") if p.is_file()
    }
    fresh_files = {p.relative_to(fresh).as_posix() for p in fresh.rglob("*") if p.is_file()}
    assert committed_files == fresh_files, "committed pack file set drifted from generator"

    mismatched = [
        rel
        for rel in sorted(committed_files)
        if not filecmp.cmp(COMMITTED_PACK / rel, fresh / rel, shallow=False)
    ]
    assert not mismatched, f"committed pack out of date — regenerate: {mismatched}"


def test_committed_pack_manifest_integrity() -> None:
    result = ep.verify_evidence_pack(COMMITTED_PACK)
    assert result["valid"], result["reasons"]
    assert result["checks"]["inner_proofpack_valid"] is True
    assert result["checks"]["manifest_integrity"] is True


def test_all_three_frameworks_present_with_every_requirement_id() -> None:
    frameworks = {"eu_ai_act", "iso_42001", "soc2"}
    assert {k for k, _ in ep.PACK_FRAMEWORKS} == frameworks
    for fw_key, filename in ep.PACK_FRAMEWORKS:
        sheet = (COMMITTED_PACK / "frameworks" / filename).read_text(encoding="utf-8")
        for req_id in _all_requirement_ids(fw_key):
            assert req_id in sheet, f"{filename}: missing requirement row {req_id}"


def test_eu_ai_act_sheet_covers_article_12_record_keeping() -> None:
    sheet = (COMMITTED_PACK / "frameworks" / "eu-ai-act-article-12.md").read_text(encoding="utf-8")
    # The five Article 12 record-keeping obligations the pack is named for.
    for art in ("EU-AIA-ART12-1", "EU-AIA-ART12-2A", "EU-AIA-ART12-2B", "EU-AIA-ART12-2C"):
        assert art in sheet
    assert "Art. 12" in sheet


def test_every_pack_document_carries_the_not_certified_disclaimer() -> None:
    docs = [COMMITTED_PACK / "README.md"] + [
        COMMITTED_PACK / "frameworks" / filename for _, filename in ep.PACK_FRAMEWORKS
    ]
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        assert "Not compliance-certified" in text, f"{doc.name}: missing disclaimer"
        assert "self-assessment" in text.lower(), f"{doc.name}: missing self-assessment framing"


def test_pack_text_documents_use_lf_and_end_with_exactly_one_lf() -> None:
    """Keep generated text artifacts LF-only and free of an EOF blank line."""
    docs = (
        [COMMITTED_PACK / "README.md"]
        + [COMMITTED_PACK / "frameworks" / filename for _, filename in ep.PACK_FRAMEWORKS]
        + [COMMITTED_PACK / "manifest.json"]
    )
    for doc in docs:
        payload = doc.read_bytes()
        assert b"\r" not in payload, f"{doc.name}: unexpected CR/CRLF line ending"
        assert payload.endswith(b"\n"), f"{doc.name}: missing terminal LF"
        assert not payload.endswith(b"\n\n"), f"{doc.name}: unexpected EOF blank line"


def test_runtime_evidence_is_the_audit_export_and_receipt() -> None:
    proofpack = COMMITTED_PACK / "runtime-evidence" / "proofpack"
    # requested artifacts #4 (audit export) and #5 (decision receipt report)
    audit = json.loads((proofpack / "audit-chain.json").read_text(encoding="utf-8"))
    receipt = json.loads((proofpack / "decision-receipt.json").read_text(encoding="utf-8"))
    assert audit["event_count"] >= 1
    assert audit["events"], "audit export carries no events"
    assert receipt["receipt_hash"], "decision receipt missing receipt_hash"
    assert (proofpack / "verification-summary.md").exists()


def test_cli_generate_then_verify_is_wired(tmp_path: Path) -> None:
    """Exercise the actual argparse entrypoint, not just the library functions."""
    out = tmp_path / "cli-pack"
    assert ep.main(["generate", "--out", str(out), "--force"]) == 0
    assert (out / "manifest.json").exists()
    assert ep.main(["verify", str(out)]) == 0


def test_tampered_pack_fails_verification(tmp_path: Path) -> None:
    """A mutated member file must be caught by the manifest — negative path."""
    pack = tmp_path / "tamper-pack"
    ep.build_evidence_pack(pack, force=True)
    assert ep.verify_evidence_pack(pack)["valid"] is True

    target = pack / "frameworks" / "soc2.md"
    target.write_text(target.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")

    result = ep.verify_evidence_pack(pack)
    assert result["valid"] is False
    assert any("soc2.md" in reason for reason in result["reasons"])


def test_demonstrated_control_partition_is_pinned() -> None:
    """Freeze which controls an offline ALLOW action does / does not demonstrate.

    Guards the honesty boundary: adding a blocking/deny/signing/replay control to
    the demonstrated set (so the sheets overclaim what one ALLOW action proves)
    must break this test, not ship silently.
    """
    assert ep.DEMONSTRATED_BY_ALLOW_ACTION == frozenset(
        {
            "RECEIPT-REQUIRED",
            "HASH-INTEGRITY",
            "ACTOR-ANCHOR",
            "ARG-BIND",
            "POLICY-TENANT-BIND",
            "MACI-VALIDATOR-SEP",
            "POLICY-BEFORE-EXEC",
            "AUDIT-HASHCHAIN",
        }
    )
    # An offline pack without replay material must NOT claim to demonstrate replay,
    # any blocking/deny/escalation control, or any signing/expiry/anti-replay control.
    for excluded in ("REPLAY-VERIFY", "DECISION-GATE", "FAILCLOSED", "ESCALATE-HUMAN"):
        assert excluded not in ep.DEMONSTRATED_BY_ALLOW_ACTION
        assert excluded in ep.NOT_DEMONSTRATED_OFFLINE
    assert ep.DEMONSTRATED_BY_ALLOW_ACTION.isdisjoint(ep.NOT_DEMONSTRATED_OFFLINE)


def test_replay_is_presented_as_generation_attestation_not_offline_reverified() -> None:
    """Sheets/README must not present offline replay as independently re-derived."""
    readme = (COMMITTED_PACK / "README.md").read_text(encoding="utf-8")
    assert "generator attestation" in readme
    # REPLAY-VERIFY must never appear as an offline "Control demonstrated" row.
    for _, filename in ep.PACK_FRAMEWORKS:
        sheet = (COMMITTED_PACK / "frameworks" / filename).read_text(encoding="utf-8")
        demonstrated_section = sheet.split("Control demonstrated offline")[-1].split(
            "does **not**"
        )[0]
        assert "REPLAY-VERIFY" not in demonstrated_section, f"{filename}: replay overclaimed"


def test_smuggled_nested_manifest_json_is_caught(tmp_path: Path) -> None:
    """A file *named* manifest.json below the top level must not be invisible."""
    pack = tmp_path / "smuggle-pack"
    ep.build_evidence_pack(pack, force=True)
    (pack / "frameworks" / "manifest.json").write_text("smuggled\n", encoding="utf-8")
    result = ep.verify_evidence_pack(pack)
    assert result["valid"] is False
    assert any("frameworks/manifest.json" in r for r in result["reasons"])


def test_missing_listed_file_is_caught(tmp_path: Path) -> None:
    pack = tmp_path / "missing-pack"
    ep.build_evidence_pack(pack, force=True)
    (pack / "frameworks" / "iso-42001.md").unlink()
    result = ep.verify_evidence_pack(pack)
    assert result["valid"] is False
    assert any("iso-42001.md" in r for r in result["reasons"])


def test_blanked_proofpack_pointer_fails_closed(tmp_path: Path) -> None:
    """Tampering the unsigned manifest to skip inner verification must fail closed."""
    pack = tmp_path / "failopen-pack"
    ep.build_evidence_pack(pack, force=True)
    manifest_path = pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["runtime_evidence"]["proofpack_rel"] = ""
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = ep.verify_evidence_pack(pack)
    # inner verification still ran against the fixed location, and the pointer
    # mismatch is itself flagged — the pack is not silently reported valid.
    assert result["valid"] is False
    assert result["checks"]["inner_proofpack_valid"] is True
    assert any("proofpack_rel" in r for r in result["reasons"])
