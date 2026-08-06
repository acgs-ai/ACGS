"""Constitution-hash stamp in the evidence bundle (G2.5 / G2.1 schema completeness).

ADDITIVE to frozen ``acgs/proof-pack/v1``: the ``constitution`` block is an
OPTIONAL property. A pack generated WITH a constitution source carries a 64-hex
``constitution.hash`` that re-derives from the canonical constitution bytes
(``sha256_json`` — no new canonicalization); a pack generated WITHOUT one omits
the key entirely and still validates against the frozen schema (v1 back-compat).
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

jsonschema = pytest.importorskip("jsonschema")

from gove_zone.decision import sha256_json  # noqa: E402
from gove_zone.proofpack import (  # noqa: E402
    EVIDENCE_FILE,
    PACK_SCHEMA_VERSION,
    generate_proof_pack,
)
from gove_zone.proofpack_cli import main as acgs_main  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
SIGNED_INPUTS = FIXTURES / "proofpacks" / "valid-allow"
NOW_ISO = "2026-01-01T00:00:00+00:00"

CONSTITUTION = {
    "constitution_id": "acgs-demo-constitution",
    "version": "1.0.0",
    "policies": ["no-side-effect-without-receipt", "fail-closed"],
}


def _evidence_schema() -> Any:
    # Freshly generated packs declare PACK_SCHEMA_VERSION; validate against
    # that version's own schema file (v1 stays frozen under its own $id).
    schema_file = f"proof-pack.{PACK_SCHEMA_VERSION.rsplit('/', 1)[1]}.evidence.schema.json"
    text = resources.files("gove_zone").joinpath("schemas").joinpath(schema_file).read_text("utf-8")
    doc = json.loads(text)
    assert isinstance(doc, dict)
    return doc


def _validator() -> Any:
    schema = _evidence_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _generate(dest: Path, *, constitution_path: Path | None) -> dict[str, Any]:
    generate_proof_pack(
        dest,
        receipt_path=SIGNED_INPUTS / "receipts" / "allow.json",
        audit_path=SIGNED_INPUTS / "audit.jsonl",
        now_iso=NOW_ISO,
        constitution_path=constitution_path,
    )
    return json.loads((dest / EVIDENCE_FILE).read_text(encoding="utf-8"))


def test_evidence_with_constitution_source_carries_valid_hash(tmp_path: Path) -> None:
    const_path = tmp_path / "constitution.json"
    const_path.write_text(json.dumps(CONSTITUTION), encoding="utf-8")

    evidence = _generate(tmp_path / "pack", constitution_path=const_path)

    assert "constitution" in evidence
    block = evidence["constitution"]
    assert isinstance(block, dict)
    digest = block["hash"]
    assert isinstance(digest, str) and len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
    # The hash re-derives from the canonical constitution bytes: reuse the
    # existing helper, never a bespoke canonicalization.
    assert digest == sha256_json(CONSTITUTION)

    # The enriched evidence bundle still validates against the frozen schema.
    errors = sorted(_validator().iter_errors(evidence), key=str)
    assert not errors, [e.message for e in errors]


def test_evidence_without_constitution_source_omits_key_and_validates(tmp_path: Path) -> None:
    evidence = _generate(tmp_path / "pack", constitution_path=None)

    # Frozen-v1 back-compat: no source -> the optional key is omitted entirely.
    assert "constitution" not in evidence
    errors = sorted(_validator().iter_errors(evidence), key=str)
    assert not errors, [e.message for e in errors]


# --- dispatcher-level wiring: `acgs proofpack generate` --------------------------
#
# A unit call to generate_proof_pack() does NOT prove the constitution stamp is
# reachable from the artifact relying parties actually run (the CLI). These tests
# drive the argparse dispatcher through proofpack_cli.main(), so a --constitution
# flag that is defined but never threaded into generate_proof_pack() fails here.


def _cli_generate(out: Path, extra: list[str]) -> int:
    return acgs_main(
        [
            "proofpack",
            "generate",
            "--receipt",
            str(SIGNED_INPUTS / "receipts" / "allow.json"),
            "--audit",
            str(SIGNED_INPUTS / "audit.jsonl"),
            "--out",
            str(out),
            "--now-iso",
            NOW_ISO,
            *extra,
        ]
    )


def test_cli_generate_stamps_constitution_hash_and_registry_id(tmp_path: Path) -> None:
    const_path = tmp_path / "constitution.json"
    const_path.write_text(json.dumps(CONSTITUTION), encoding="utf-8")
    out = tmp_path / "pack"

    rc = _cli_generate(
        out,
        ["--constitution", str(const_path), "--constitution-registry-id", "acgs-registry"],
    )
    assert rc == 0

    evidence = json.loads((out / EVIDENCE_FILE).read_text(encoding="utf-8"))
    assert evidence["constitution"] == {
        "hash": sha256_json(CONSTITUTION),
        "registry_id": "acgs-registry",
    }


def test_cli_generate_without_constitution_flag_omits_block(tmp_path: Path) -> None:
    out = tmp_path / "pack"
    rc = _cli_generate(out, [])
    assert rc == 0

    evidence = json.loads((out / EVIDENCE_FILE).read_text(encoding="utf-8"))
    assert "constitution" not in evidence
