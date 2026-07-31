"""JSON Schema contract for the ``acgs/proof-pack/v1`` evidence bundle (G2.1).

The published schemas live as package data under ``gove_zone/schemas/`` (one
per JSON artifact of the pack) and are enforced here in four ways:

1. **Schema hygiene.** Every schema file is itself a valid draft 2020-12
   schema with a stable ``$id`` under its version's own prefix
   (``https://acgs.ai/schema/proof-pack/v1/`` or ``.../v1.1/``). The v1
   schemas are FROZEN — external validators cache and resolve them by ``$id``
   — so a new pack schema version ships as NEW files with distinct ``$id``
   values, never as an in-place widening of the v1 contract.
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
    _SUMMARY_REVISION_FOR_SCHEMA,
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
GOLDEN_V1 = FIXTURES / "acgs_proofpack" / "golden-v1"
REPLAY_INPUTS = FIXTURES / "proofpacks" / "valid-replay"
SIGNED_INPUTS = FIXTURES / "proofpacks" / "valid-allow"
NOW_ISO = "2026-01-01T00:00:00+00:00"

# One published schema set per supported pack schema version. v1 is FROZEN:
# external validators that cache or resolve schemas by $id must never see the
# contract at an existing $id change, so v1.1 ships as distinct files under a
# distinct $id prefix instead of widening the v1 schemas in place.
SCHEMA_SETS = {
    "acgs/proof-pack/v1": {
        "id_base": "https://acgs.ai/schema/proof-pack/v1/",
        "file_prefix": "proof-pack.v1.",
    },
    "acgs/proof-pack/v1.1": {
        "id_base": "https://acgs.ai/schema/proof-pack/v1.1/",
        "file_prefix": "proof-pack.v1.1.",
    },
}

# artifact file in the pack -> schema file suffix shipped as package data
SCHEMA_SUFFIX_FOR_ARTIFACT = {
    EVIDENCE_FILE: "evidence.schema.json",
    RECEIPT_FILE: "decision-receipt.schema.json",
    AUDIT_CHAIN_FILE: "audit-chain.schema.json",
    REPLAY_REPORT_FILE: "replay-report.schema.json",
}
JSON_ARTIFACTS = tuple(SCHEMA_SUFFIX_FOR_ARTIFACT)


def _schema_file(version: str, artifact: str) -> str:
    return SCHEMA_SETS[version]["file_prefix"] + SCHEMA_SUFFIX_FOR_ARTIFACT[artifact]


def _load_schema(schema_file: str) -> dict[str, Any]:
    text = resources.files("gove_zone").joinpath("schemas").joinpath(schema_file).read_text("utf-8")
    doc = json.loads(text)
    assert isinstance(doc, dict)
    return doc


def _validator(artifact: str, version: str = PACK_SCHEMA_VERSION) -> Any:
    schema = _load_schema(_schema_file(version, artifact))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _assert_valid(artifact: str, doc: Any, version: str = PACK_SCHEMA_VERSION) -> None:
    errors = sorted(_validator(artifact, version).iter_errors(doc), key=str)
    assert not errors, f"{artifact}: schema validation failed:\n" + "\n".join(
        f"  {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors
    )


def _assert_invalid(artifact: str, doc: Any, version: str = PACK_SCHEMA_VERSION) -> None:
    assert not _validator(artifact, version).is_valid(doc), (
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


@pytest.mark.parametrize("version", sorted(SCHEMA_SETS))
@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_schema_file_is_valid_draft_2020_12(version: str, artifact: str) -> None:
    schema = _load_schema(_schema_file(version, artifact))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == SCHEMA_SETS[version]["id_base"] + SCHEMA_SUFFIX_FOR_ARTIFACT[artifact]


def test_schemas_ship_as_gove_zone_package_data() -> None:
    """importlib.resources must resolve every schema through the installed
    package (the wheel path), not only through a repo-relative filesystem path."""
    schemas_dir = resources.files("gove_zone").joinpath("schemas")
    for version in SCHEMA_SETS:
        for artifact in JSON_ARTIFACTS:
            schema_file = _schema_file(version, artifact)
            assert schemas_dir.joinpath(schema_file).is_file(), schema_file


def test_every_supported_pack_version_has_a_schema_set() -> None:
    """The published schema sets and the verifier's supported schema versions
    (each bound 1:1 to a summary-template revision) stay in lockstep, and the
    version newly generated packs declare is one of them."""
    assert set(SCHEMA_SETS) == set(_SUMMARY_REVISION_FOR_SCHEMA)
    assert PACK_SCHEMA_VERSION in SCHEMA_SETS


@pytest.mark.parametrize("version", sorted(SCHEMA_SETS))
def test_each_schema_set_pins_exactly_its_own_version(version: str) -> None:
    """Every version-declaring artifact schema accepts exactly ONE
    schema_version — its own. A consumer that resolved the v1 schemas (by $id
    or from a cache) must reject v1.1 documents rather than silently accept a
    contract change, and vice versa."""
    for artifact in (EVIDENCE_FILE, AUDIT_CHAIN_FILE, REPLAY_REPORT_FILE):
        schema = _load_schema(_schema_file(version, artifact))
        assert schema["properties"]["schema_version"] == {"const": version}, (
            f"{_schema_file(version, artifact)}: schema_version must pin {version} only"
        )


def test_cross_version_documents_are_rejected() -> None:
    """The in-place-widening regression: a v1.1 evidence document must FAIL
    the frozen v1 evidence schema, and a v1 evidence document must FAIL the
    v1.1 evidence schema — version selection is meaningful, not cosmetic."""
    v1_1_doc = _golden_doc(EVIDENCE_FILE)
    assert v1_1_doc["schema_version"] == "acgs/proof-pack/v1.1"
    _assert_valid(EVIDENCE_FILE, v1_1_doc, version="acgs/proof-pack/v1.1")
    _assert_invalid(EVIDENCE_FILE, v1_1_doc, version="acgs/proof-pack/v1")

    v1_doc = json.loads((GOLDEN_V1 / EVIDENCE_FILE).read_text(encoding="utf-8"))
    assert v1_doc["schema_version"] == "acgs/proof-pack/v1"
    _assert_valid(EVIDENCE_FILE, v1_doc, version="acgs/proof-pack/v1")
    _assert_invalid(EVIDENCE_FILE, v1_doc, version="acgs/proof-pack/v1.1")


# --- 2. fixture validation --------------------------------------------------------


@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_golden_pack_artifact_validates(artifact: str) -> None:
    _assert_valid(artifact, _golden_doc(artifact))


@pytest.mark.parametrize("artifact", JSON_ARTIFACTS)
def test_golden_v1_pack_artifact_validates_against_frozen_v1_schemas(artifact: str) -> None:
    """The historical v1 pack keeps validating against the schemas its $id
    generation pinned — freezing v1 must never orphan already-issued packs."""
    doc = json.loads((GOLDEN_V1 / artifact).read_text(encoding="utf-8"))
    _assert_valid(artifact, doc, version="acgs/proof-pack/v1")


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


# The scoped-trust receipt v2 fields DecisionReceipt.to_dict() emits all-or-none
# on top of the v1 serialization. generate_proof_pack accepts a v2 receipt and
# mints an acgs/proof-pack/v1.1 bundle, so the v1.1 receipt schema must accept
# genuine generator output carrying them — while the FROZEN v1 schema keeps
# rejecting them (no v1-era generator ever packaged a v2 receipt).
_RECEIPT_V2_FIELDS = {
    "receipt_schema_version": "gove-zone/decision-receipt/v2",
    "project_id": "proj-1",
    "environment_id": "env-1",
    "trust_epoch": 1,
}


def test_receipt_v2_scoped_trust_fields_validate_under_v1_1() -> None:
    doc = _golden_doc(RECEIPT_FILE)
    doc.update(_RECEIPT_V2_FIELDS)
    _assert_valid(RECEIPT_FILE, doc)


def test_receipt_v2_scoped_trust_fields_stay_rejected_by_frozen_v1() -> None:
    doc = json.loads((GOLDEN_V1 / RECEIPT_FILE).read_text(encoding="utf-8"))
    _assert_valid(RECEIPT_FILE, doc, version="acgs/proof-pack/v1")  # guard
    doc.update(_RECEIPT_V2_FIELDS)
    _assert_invalid(RECEIPT_FILE, doc, version="acgs/proof-pack/v1")


@pytest.mark.parametrize("dropped", sorted(_RECEIPT_V2_FIELDS))
def test_receipt_v2_partial_scoped_trust_fields_fail(dropped: str) -> None:
    """DecisionReceipt.from_dict enforces the four v2 fields all-or-none; the
    v1.1 schema mirrors that instead of accepting a half-v2 receipt."""
    doc = _golden_doc(RECEIPT_FILE)
    doc.update(_RECEIPT_V2_FIELDS)
    del doc[dropped]
    _assert_invalid(RECEIPT_FILE, doc)


def test_receipt_v2_unknown_receipt_schema_version_fails() -> None:
    doc = _golden_doc(RECEIPT_FILE)
    doc.update(_RECEIPT_V2_FIELDS)
    doc["receipt_schema_version"] = "gove-zone/decision-receipt/v3"
    _assert_invalid(RECEIPT_FILE, doc)


def test_receipt_v2_nonpositive_trust_epoch_fails() -> None:
    doc = _golden_doc(RECEIPT_FILE)
    doc.update(_RECEIPT_V2_FIELDS)
    doc["trust_epoch"] = 0
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
    assert json_artifacts == set(SCHEMA_SUFFIX_FOR_ARTIFACT)
