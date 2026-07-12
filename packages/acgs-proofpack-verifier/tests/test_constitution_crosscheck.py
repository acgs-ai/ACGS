"""Fail-closed constitution-hash registry cross-check in the proof-pack verifier (G2.5).

ADDITIVE / v1-safe: the cross-check runs ONLY when the caller supplies a
registry. With no registry the (optional) ``constitution`` block is carried but
never checked — backward compatible. When a registry IS supplied, four cases
flip verification to FAIL, each with an explicit reason string; the taxonomy is
ported verbatim from the proven ``acgs_governance_eval_mvp`` reference:

  - ``constitution_hash_missing``          registry supplied, bundle has no hash
  - ``constitution_hash_not_in_registry``  bundle hash absent from the registry
  - ``constitution_registry_malformed``    registry parsed but not a JSON array
                                           of 64-hex strings
  - ``constitution_registry_unreadable``   registry path unreadable / unparseable

The pack is built from the committed golden fixture with a ``constitution`` block
injected into ``evidence.json`` — the manifest carries no digest of itself, so
the other four artifacts (and their digests) are untouched and still verify.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from acgs_proofpack_verifier import verify_pack
from acgs_proofpack_verifier.cli import main as cli_main

_TESTS = Path(__file__).parent
GOLDEN = _TESTS / "fixtures" / "golden"
NOW_ISO = "2026-01-01T00:00:00+00:00"

CONST_HASH = "a" * 64
OTHER_HASH = "b" * 64


def _pack(dest: Path, *, constitution_hash: str | None) -> Path:
    shutil.copytree(GOLDEN, dest)
    evidence_path = dest / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if constitution_hash is not None:
        evidence["constitution"] = {"hash": constitution_hash}
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return dest


def _registry(tmp_path: Path, payload: str) -> Path:
    path = tmp_path / "constitution-registry.json"
    path.write_text(payload, encoding="utf-8")
    return path


def test_valid_pack_with_matching_registry_passes(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    registry = _registry(tmp_path, json.dumps([CONST_HASH]))
    result = verify_pack(pack, now_iso=NOW_ISO, constitution_registry=registry)
    assert result.valid, result.reasons


def test_no_registry_carries_but_does_not_check(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    result = verify_pack(pack, now_iso=NOW_ISO)
    assert result.valid, result.reasons


def test_registry_supplied_but_bundle_hash_missing_fails(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=None)
    registry = _registry(tmp_path, json.dumps([CONST_HASH]))
    result = verify_pack(pack, now_iso=NOW_ISO, constitution_registry=registry)
    assert not result.valid
    assert any("constitution_hash_missing" in str(r) for r in result.reasons), result.reasons


def test_bundle_hash_not_in_registry_fails(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    registry = _registry(tmp_path, json.dumps([OTHER_HASH]))
    result = verify_pack(pack, now_iso=NOW_ISO, constitution_registry=registry)
    assert not result.valid
    assert any("constitution_hash_not_in_registry" in str(r) for r in result.reasons), (
        result.reasons
    )


def test_malformed_registry_fails_closed(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    # Parses as JSON but is not a non-empty array of 64-hex strings.
    registry = _registry(tmp_path, "[]")
    result = verify_pack(pack, now_iso=NOW_ISO, constitution_registry=registry)
    assert not result.valid
    assert any("constitution_registry_malformed" in str(r) for r in result.reasons), result.reasons


def test_unreadable_registry_fails_closed(tmp_path: Path) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    registry = _registry(tmp_path, "{not json")
    result = verify_pack(pack, now_iso=NOW_ISO, constitution_registry=registry)
    assert not result.valid
    assert any("constitution_registry_unreadable" in str(r) for r in result.reasons), result.reasons


# --- dispatcher-level wiring: `acgs proofpack verify --constitution-registry` ----
#
# Calling verify_pack() directly does NOT prove the registry cross-check is
# reachable from the CLI auditors/CI gates actually run. These tests drive the
# argparse dispatcher through cli.main(), so a --constitution-registry flag that
# is defined but never threaded into verify_pack() fails here (the pack would
# verify valid, exit 0, and the mismatch would go unreported).


def _cli_verify(pack: Path, extra: list[str], capsys) -> tuple[int, dict]:
    rc = cli_main(["proofpack", "verify", str(pack), "--now-iso", NOW_ISO, *extra])
    report = json.loads(capsys.readouterr().out)
    return rc, report


def test_cli_verify_matching_registry_exits_zero(tmp_path: Path, capsys) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    registry = _registry(tmp_path, json.dumps([CONST_HASH]))
    rc, report = _cli_verify(pack, ["--constitution-registry", str(registry)], capsys)
    assert rc == 0
    assert report["valid"] is True


def test_cli_verify_hash_not_in_registry_exits_one(tmp_path: Path, capsys) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    registry = _registry(tmp_path, json.dumps([OTHER_HASH]))
    rc, report = _cli_verify(pack, ["--constitution-registry", str(registry)], capsys)
    assert rc == 1
    assert report["valid"] is False
    assert "constitution_hash_not_in_registry" in report["reasons"]


def test_cli_verify_without_registry_flag_carries_but_does_not_check(
    tmp_path: Path, capsys
) -> None:
    pack = _pack(tmp_path / "pack", constitution_hash=CONST_HASH)
    rc, report = _cli_verify(pack, [], capsys)
    assert rc == 0
    assert report["valid"] is True
