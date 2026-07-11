"""JSON Schema contract for the ``acgs/proof-pack/v1`` evidence bundle (G2.1).

The published schemas live as package data under ``gove_zone/schemas/`` (one
per JSON artifact of the pack) and are enforced here in four ways:

1. **Schema hygiene.** Every schema file is itself a valid draft 2020-12
   schema with a stable ``$id`` under ``https://acgs.ai/schema/proof-pack/v1/``.
2. **Fixture validation.** The committed golden pack AND freshly generated
   packs (both the replay-verified unsigned pack and the signed
   no-replay-material pack) validate artifact-by-artifact.
3. **Strictness (fail-closed mirror).** Deleting ``schema_version``, mutating
   it to another version, wrong-typing a receipt hash, and injecting an
   unknown key each FAIL validation — the schema rejects what the verifier
   would reject, instead of rubber-stamping near-misses.
4. **Canonical serialization round-trip.** Every JSON artifact written by the
   real ``generate_proof_pack`` path re-serializes byte-identically under the
   documented canonical form, so schema-validating the parsed document is
   equivalent to schema-validating the bytes on disk.

Dependency posture: gove-zone has ``dependencies = []`` by design. ``jsonschema``
is a *dev-extra-only* test dependency (``pyproject.toml`` ``[project.optional-
dependencies].dev``); nothing under ``src/`` imports it — the runtime verifier
stays stdlib-only (pinned by the AST guards in test_proofpack_corpus.py and
test_acgs_proofpack.py).
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

jsonschema = pytest.importorskip("jsonschema")

from gove_zone.proofpack import (  # noqa: E402
    ARTIFACT_FILES,
    AUDIT_CHAIN_FILE,
    EVIDENCE_FILE,
    PACK_SCHEMA_VERSION,
    RECEIPT_FILE,
    REPLAY_REPORT_FILE,
    generate_proof_pack,
)

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "acgs_proofpack" / "golden"
REPLAY_INPUTS = FIXTURES / "proofpacks" / "valid-replay"
SIGNED_INPUTS = FIXTURES / "proofpacks" / "valid-allow"
NOW_ISO = "2026-01-01T00:00:00+00:00"

SCHEMA_ID_BASE = "https://acgs.ai/schema/proof-pack/v1/"

# artifact file in the pack -> schema file shipped as package data
SCHEMA_FOR_ARTIFACT = {
    EVIDENCE_FILE: "proof-pack.v1.evidence.schema.json",
    RECEIPT_FILE: "proof-pack.v1.decision-receipt.schema.json",
    AUDIT_CHAIN_FILE: "proof-pack.v1.audit-chain.schema.json",
    REPLAY_REPORT_FILE: "proof-pack.v1.replay-report.schema.json",
}
JSON_ARTIFACTS = tuple(SCHEMA_FOR_ARTIFACT)


def _load_schema(schema_file: str) -> dict[str, Any]:
    text = resources.files("gove_zone").joinpath("schemas").joinpath(schema_file).read_text("utf-8")
    doc = json.loads(text)
    assert isinstance(doc, dict)
    return doc


def _validator(artifact: str) -> Any:
    schema = _load_schema(SCHEMA_FOR_ARTIFACT[artifact])
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _assert_valid(artifact: str, doc: Any) -> None:
    errors = sorted(_validator(artifact).iter_errors(doc), key=str)
    assert not errors, f"{artifact}: schema validation failed:\n" + "\n".join(
        f"  {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors
    )


def _assert_invalid(artifact: str, doc: Any) -> None:
    assert not _validator(artifact).is_valid(doc), (
        f"{artifact}: schema accepted a document it must reject"
    )


def _golden_doc(artifact: str) -> Any:
    return json.loads((GOLDEN / artifact).read_text(encoding="utf-8"))


def _generate_replay_pack(dest: Path) -> Path:
    """The golden inputs: unsigned receipt + replay material (status=verified)."""
    generate_proof_pack(
        dest,
        receipt_path=REPLAY_INPUTS / "receipts" / "r1.json",
        audit_path=REPLAY_INPUTS / "audit.jsonl",
        policy_bundle=REPLAY_INPUTS / "policy_bundle.json",
        side_store=REPLAY_INPUTS / "replay_side_store.jsonl",
        now_iso=NOW_ISO,
    )
    return dest


def _generate_signed_pack(dest: Path) -> Path:
    """Signed receipt, no replay material (status=not_available)."""
    generate_proof_pack(
        dest,
        receipt_path=SIGNED_INPUTS / "receipts" / "allow.json",
        audit_path=SIGNED_INPUTS / "audit.jsonl",
        now_iso=NOW_ISO,
    )
    return dest


# --- 1. schema hygiene -----------------------------------------------------------


@pytest.mark.parametrize("schema_file", sorted(SCHEMA_FOR_ARTIFACT.values()))
def test_schema_file_is_valid_draft_2020_12(schema_file: str) -> None:
    schema = _load_schema(schema_file)
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == SCHEMA_ID_BASE + schema_file.removeprefix("proof-pack.v1.")


def test_schemas_ship_as_gove_zone_package_data() -> None:
    """importlib.resources must resolve every schema through the installed
    package (the wheel path), not only through a repo-relative filesystem path."""
    schemas_dir = resources.files("gove_zone").joinpath("schemas")
    for schema_file in SCHEMA_FOR_ARTIFACT.values():
        assert schemas_dir.joinpath(schema_file).is_file(), schema_file


def test_evidence_schema_pins_the_pack_schema_version() -> None:
    schema = _load_schema(SCHEMA_FOR_ARTIFACT[EVIDENCE_FILE])
    assert schema["properties"]["schema_version"] == {"const": PACK_SCHEMA_VERSION}


# --- 2. fixture validation --------------------------------------------------------


@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_golden_pack_artifact_validates(artifact: str) -> None:
    _assert_valid(artifact, _golden_doc(artifact))


@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_freshly_generated_replay_pack_validates(artifact: str, tmp_path: Path) -> None:
    pack = _generate_replay_pack(tmp_path / "pack")
    _assert_valid(artifact, json.loads((pack / artifact).read_text(encoding="utf-8")))


@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_freshly_generated_signed_pack_validates(artifact: str, tmp_path: Path) -> None:
    pack = _generate_signed_pack(tmp_path / "pack")
    _assert_valid(artifact, json.loads((pack / artifact).read_text(encoding="utf-8")))


# --- 3. strictness: the schema mirrors the verifier's fail-closed posture ---------


def test_evidence_missing_schema_version_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    _assert_valid(EVIDENCE_FILE, doc)  # guard: the untouched doc passes
    del doc["schema_version"]
    _assert_invalid(EVIDENCE_FILE, doc)


def test_evidence_wrong_schema_version_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    doc["schema_version"] = "acgs/proof-pack/v0"
    _assert_invalid(EVIDENCE_FILE, doc)


def test_evidence_wrong_typed_receipt_hash_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    doc["receipt"]["receipt_hash"] = 12345
    _assert_invalid(EVIDENCE_FILE, doc)


def test_evidence_non_hex_receipt_hash_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    doc["receipt"]["receipt_hash"] = "Z" * 64
    _assert_invalid(EVIDENCE_FILE, doc)


def test_evidence_unknown_top_level_key_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    doc["injected"] = "unexpected"
    _assert_invalid(EVIDENCE_FILE, doc)


def test_evidence_missing_artifact_digest_fails() -> None:
    doc = _golden_doc(EVIDENCE_FILE)
    del doc["artifacts"][REPLAY_REPORT_FILE]
    _assert_invalid(EVIDENCE_FILE, doc)


def test_receipt_unknown_decision_fails() -> None:
    doc = _golden_doc(RECEIPT_FILE)
    _assert_valid(RECEIPT_FILE, doc)
    doc["decision"] = "approve"
    _assert_invalid(RECEIPT_FILE, doc)


def test_receipt_unknown_key_fails() -> None:
    doc = _golden_doc(RECEIPT_FILE)
    doc["extra_grant"] = "root"
    _assert_invalid(RECEIPT_FILE, doc)


def test_audit_chain_event_missing_event_hash_fails() -> None:
    doc = _golden_doc(AUDIT_CHAIN_FILE)
    _assert_valid(AUDIT_CHAIN_FILE, doc)
    del doc["events"][0]["event_hash"]
    _assert_invalid(AUDIT_CHAIN_FILE, doc)


def test_replay_report_unknown_status_fails() -> None:
    doc = _golden_doc(REPLAY_REPORT_FILE)
    _assert_valid(REPLAY_REPORT_FILE, doc)
    doc["status"] = "tampered"
    _assert_invalid(REPLAY_REPORT_FILE, doc)


def test_replay_report_verified_with_failed_result_fails() -> None:
    """A 'verified' report attesting a failed replay contradicts the generator's
    fail-closed refusal to mint such a pack — the schema must reject it too."""
    doc = _golden_doc(REPLAY_REPORT_FILE)
    doc["result"]["valid"] = False
    _assert_invalid(REPLAY_REPORT_FILE, doc)


# --- 4. canonical serialization round-trip ----------------------------------------


def test_generated_artifacts_round_trip_byte_identical(tmp_path: Path) -> None:
    """generate -> parse -> re-serialize is byte-identical for every JSON artifact.

    ``evidence.json`` / ``audit-chain.json`` / ``replay-report.json`` are written
    as ``json.dumps(doc, indent=2, sort_keys=True) + "\\n"``; the receipt is
    ``DecisionReceipt.to_json()`` (``sort_keys=True``, default separators) plus a
    trailing newline. This pins that the schemas describe documents whose parsed
    form loses nothing relative to the bytes the digests in evidence.json bind.
    """
    pack = _generate_replay_pack(tmp_path / "pack")
    for artifact in (EVIDENCE_FILE, AUDIT_CHAIN_FILE, REPLAY_REPORT_FILE):
        raw = (pack / artifact).read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        assert raw == (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"), artifact
    raw = (pack / RECEIPT_FILE).read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    assert raw == (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8"), RECEIPT_FILE


def test_every_json_artifact_has_a_published_schema() -> None:
    """The pack's JSON artifact set and the schema map stay in lockstep."""
    json_artifacts = {EVIDENCE_FILE, *(n for n in ARTIFACT_FILES if n.endswith(".json"))}
    assert json_artifacts == set(SCHEMA_FOR_ARTIFACT)
