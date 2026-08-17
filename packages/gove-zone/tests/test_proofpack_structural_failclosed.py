"""Structural fail-closed guards for ``gove_zone.verifier.verify_proof_pack``.

The committed corpus in ``fixtures/proofpacks/`` covers *semantic* tamper — a
broken hash chain, a swapped receipt, a downgraded signature. It does not cover
the envelope being structurally wrong: a truncated manifest, a chain file that
is not readable JSONL, a receipt entry pointing at nothing, replay material that
does not parse.

Those paths matter for the same reason the semantic ones do. A relying party
runs this verifier offline against a pack handed to it by the party that wants
the "accept". Every branch below must end in ``valid is False`` with a stable
reason code — never an exception escaping to the caller, and never a default-true
verdict because a section was absent rather than wrong.

Each test starts from the known-good ``valid-allow`` pack and applies exactly one
structural corruption, so a passing assertion is attributable to that edit.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")  # the corpus packs are signed

from gove_zone import Ed25519Signer  # noqa: E402
from gove_zone.verifier import (  # noqa: E402
    ProofPackRejectionReason,
    verify_proof_pack,
)

CORPUS = Path(__file__).parent / "fixtures" / "proofpacks"
VALID = CORPUS / "valid-allow"
NOW = "2026-01-01T00:00:00+00:00"

_SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
TRUSTED = Ed25519Signer.from_public_bytes(
    Ed25519Signer.from_private_bytes(_SEED, key_id="fixture-key-1").public_bytes(),
    key_id="fixture-key-1",
)


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    """A writable copy of the known-good pack."""
    dest = tmp_path / "pack"
    shutil.copytree(VALID, dest)
    return dest


def _verify(pack_dir: Path):
    return verify_proof_pack(pack_dir, verifier=TRUSTED, now_iso=NOW)


def _manifest(pack_dir: Path) -> dict:
    return json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(pack_dir: Path, manifest: dict) -> None:
    (pack_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_the_unmodified_fixture_pack_verifies(pack: Path):
    """Baseline — without this, every assertion below could pass for the wrong
    reason."""
    result = _verify(pack)

    assert result.valid is True
    assert result.reasons == []


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #
def test_a_missing_pack_directory_is_rejected(tmp_path: Path):
    result = _verify(tmp_path / "no-such-pack")

    assert result.valid is False
    assert ProofPackRejectionReason.PROOFPACK_NOT_FOUND in result.reasons


def test_a_file_where_the_pack_should_be_is_rejected(tmp_path: Path):
    not_a_dir = tmp_path / "pack"
    not_a_dir.write_text("{}", encoding="utf-8")

    result = _verify(not_a_dir)

    assert result.valid is False
    assert ProofPackRejectionReason.PROOFPACK_NOT_FOUND in result.reasons


def test_a_pack_without_a_manifest_is_rejected(pack: Path):
    (pack / "manifest.json").unlink()

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.MANIFEST_MISSING in result.reasons


def test_a_truncated_manifest_is_rejected_as_malformed(pack: Path):
    (pack / "manifest.json").write_text('{"schema_version": "gove-zone/proof', encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.MANIFEST_MALFORMED in result.reasons


def test_a_manifest_that_is_not_an_object_is_rejected(pack: Path):
    """A JSON array parses fine but has no fields to check; accepting it would
    mean verifying nothing."""
    (pack / "manifest.json").write_text("[]", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.MANIFEST_MALFORMED in result.reasons


def test_a_manifest_without_a_schema_version_is_rejected(pack: Path):
    manifest = _manifest(pack)
    del manifest["schema_version"]
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.SCHEMA_VERSION_MISSING in result.reasons


def test_an_empty_schema_version_is_rejected_rather_than_defaulted(pack: Path):
    manifest = _manifest(pack)
    manifest["schema_version"] = ""
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.SCHEMA_VERSION_MISSING in result.reasons


def test_an_unsupported_schema_version_names_the_version_it_saw(pack: Path):
    manifest = _manifest(pack)
    manifest["schema_version"] = "gove-zone/proof-pack/v99"
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.SCHEMA_VERSION_UNSUPPORTED in result.reasons
    # The offending version is reported on the result, so an operator can see
    # which schema the pack claimed without re-reading the manifest.
    assert result.schema_version == "gove-zone/proof-pack/v99"


# --------------------------------------------------------------------------- #
# Audit chain
# --------------------------------------------------------------------------- #
def test_a_missing_audit_chain_is_rejected_not_treated_as_nothing_to_check(pack: Path):
    (pack / "audit.jsonl").unlink()

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.AUDIT_CHAIN_MISSING in result.reasons
    assert result.audit_chain_verified is False


def test_a_manifest_pointing_at_a_nonexistent_chain_file_is_rejected(pack: Path):
    manifest = _manifest(pack)
    manifest["audit_chain"] = "elsewhere/audit.jsonl"
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.AUDIT_CHAIN_MISSING in result.reasons


def test_an_unparseable_audit_chain_is_rejected(pack: Path):
    (pack / "audit.jsonl").write_text("this is not jsonl\n{{{\n", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert {
        ProofPackRejectionReason.AUDIT_CHAIN_UNREADABLE,
        ProofPackRejectionReason.AUDIT_CHAIN_BROKEN,
    } & set(result.reasons)
    assert result.audit_chain_verified is False


def test_an_empty_audit_chain_cannot_anchor_a_receipt(pack: Path):
    (pack / "audit.jsonl").write_text("", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.RECEIPT_NOT_ANCHORED in result.reasons


# --------------------------------------------------------------------------- #
# Receipt entries
# --------------------------------------------------------------------------- #
def test_a_receipt_entry_without_a_file_field_is_rejected(pack: Path):
    manifest = _manifest(pack)
    del manifest["receipts"][0]["file"]
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.RECEIPT_FILE_MISSING in result.reasons


def test_a_receipt_entry_pointing_at_a_missing_file_is_rejected(pack: Path):
    (pack / "receipts" / "allow.json").unlink()

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.RECEIPT_FILE_MISSING in result.reasons


def test_an_unparseable_receipt_is_rejected_as_malformed(pack: Path):
    (pack / "receipts" / "allow.json").write_text("{not json", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.RECEIPT_MALFORMED in result.reasons


def test_a_receipt_missing_required_fields_is_rejected_as_malformed(pack: Path):
    (pack / "receipts" / "allow.json").write_text('{"unrelated": true}', encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.RECEIPT_MALFORMED in result.reasons


def test_a_pack_declaring_no_receipts_proves_no_accept(pack: Path):
    """An empty receipt list must not read as "nothing was rejected, therefore
    accept"."""
    manifest = _manifest(pack)
    manifest["receipts"] = []
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.receipts == []
    assert not any(r.declared_verdict == "accept" for r in result.receipts)


# --------------------------------------------------------------------------- #
# Consumption ledger (anti-replay)
# --------------------------------------------------------------------------- #
def test_a_declared_ledger_that_is_absent_is_unprovable_not_fresh(pack: Path):
    """Declaring anti-replay and then not shipping the ledger must not yield
    the "fresh" verdict that a pack with no ledger at all would get."""
    (pack / "consumed.jsonl").unlink()

    result = _verify(pack)

    assert result.valid is False
    assert result.anti_replay_status == "unprovable"
    assert ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE in result.reasons


def test_a_corrupt_ledger_is_unprovable(pack: Path):
    (pack / "consumed.jsonl").write_text("not-a-ledger\n", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert result.anti_replay_status == "unprovable"
    assert ProofPackRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE in result.reasons


def test_a_pack_without_a_declared_ledger_reports_not_present(pack: Path):
    manifest = _manifest(pack)
    manifest["consumption_ledger"] = None
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.anti_replay_status == "not_present"


# --------------------------------------------------------------------------- #
# Replay tier
# --------------------------------------------------------------------------- #
def test_replay_material_that_does_not_parse_is_rejected(pack: Path):
    manifest = _manifest(pack)
    manifest["replay"] = {"policy_bundle": "policy.json", "side_store": "side.jsonl"}
    _write_manifest(pack, manifest)
    (pack / "policy.json").write_text("{not json", encoding="utf-8")
    (pack / "side.jsonl").write_text("", encoding="utf-8")

    result = _verify(pack)

    assert result.valid is False
    assert result.replay_verified is False
    assert ProofPackRejectionReason.REPLAY_MATERIAL_MALFORMED in result.reasons


def test_replay_material_that_is_absent_is_rejected(pack: Path):
    manifest = _manifest(pack)
    manifest["replay"] = {"policy_bundle": "missing.json", "side_store": "missing.jsonl"}
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.REPLAY_MATERIAL_MALFORMED in result.reasons


def test_a_replay_spec_missing_its_keys_is_rejected_not_skipped(pack: Path):
    manifest = _manifest(pack)
    manifest["replay"] = {"policy_bundle": "policy.json"}  # no side_store
    _write_manifest(pack, manifest)

    result = _verify(pack)

    assert result.valid is False
    assert ProofPackRejectionReason.REPLAY_MATERIAL_MALFORMED in result.reasons


def test_no_replay_spec_leaves_the_tier_unclaimed(pack: Path):
    """Absent optional evidence is reported as absent, never as verified."""
    result = _verify(pack)

    assert result.replay_verified is None


# --------------------------------------------------------------------------- #
# Non-bypassability of the outer guard
# --------------------------------------------------------------------------- #
def test_an_exception_inside_verification_becomes_a_rejection_not_a_traceback(
    pack: Path, monkeypatch: pytest.MonkeyPatch
):
    """The outer wrapper exists so a relying party never sees an exception where
    it expected a verdict — an escaping error would be an un-handled 'neither
    accept nor reject'."""
    import gove_zone.verifier as verifier_mod

    def _boom(*args: object, **kwargs: object):
        raise RuntimeError("unexpected internal failure")

    monkeypatch.setattr(verifier_mod, "_verify_proof_pack_inner", _boom)

    result = verify_proof_pack(pack, verifier=TRUSTED, now_iso=NOW)

    assert result.valid is False
    assert ProofPackRejectionReason.VERIFIER_ERROR in result.reasons
