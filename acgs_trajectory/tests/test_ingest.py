from __future__ import annotations

import json
from pathlib import Path

from acgs_trajectory.ingest import ingest_text
from acgs_trajectory.materialize import stamp_normalized_digest
from acgs_trajectory.raw_store import RawStore

CAP = "2026-08-06T00:00:00Z"


def ingest(read_fixture, name, tmp_path, **kw):
    store = RawStore(tmp_path)
    return ingest_text(read_fixture(name), store=store, captured_at=CAP, **kw), store


def test_complete_session_reaches_complete(read_fixture, tmp_path, complete_git):
    res, store = ingest(read_fixture, "complete_session.jsonl", tmp_path, repo_git=complete_git)
    assert res.status == "complete", res.reasons
    assert res.reasons == []
    # schema-valid
    assert res.record["schema_version"] == "governance_trajectory/v2"
    # derived stays null
    assert res.record["derived"] == {"scores": None, "labels": None, "tier": None, "outcome": None}
    # manifest chain intact
    ok, errors = store.verify_chain()
    assert ok, errors


def test_missing_git_head_is_incomplete_not_complete(read_fixture, tmp_path):
    # no git join -> V3 flags missing head sha -> capped below complete (fail closed)
    res, _ = ingest(read_fixture, "complete_session.jsonl", tmp_path)
    assert res.status == "incomplete"
    assert any("missing_git_head_sha" in r for r in res.reasons)


def test_secret_session_quarantined_and_not_in_shared_archive(read_fixture, tmp_path):
    res, store = ingest(read_fixture, "secret_session.jsonl", tmp_path)
    assert res.status == "quarantined"
    assert any(r.startswith("secret:") for r in res.reasons)
    # authoritative raw preserved unmodified in the RESTRICTED store, not shared raw/
    assert "quarantine" in res.raw_ref.uri
    assert not list((tmp_path / "raw").rglob("*.jsonl"))
    # raw content is byte-identical to input (never redacted)
    stored = (tmp_path / res.raw_ref.uri).read_bytes()
    assert stored == read_fixture("secret_session.jsonl").encode("utf-8")
    # incident logged
    assert (tmp_path / "incidents.log").exists()


def test_unsupported_version_quarantined(read_fixture, tmp_path):
    res, _ = ingest(read_fixture, "unsupported_version_session.jsonl", tmp_path)
    assert res.status == "quarantined"
    assert any("unsupported_version" in r for r in res.reasons)


def test_unknown_record_type_quarantined_but_retained(read_fixture, tmp_path):
    res, store = ingest(read_fixture, "unknown_type_session.jsonl", tmp_path)
    assert res.status == "quarantined"
    assert any("unknown_record_type" in r for r in res.reasons)
    # retained, not dropped
    assert store.verify_raw(res.raw_ref)


def test_broken_tool_ref_is_incomplete(read_fixture, tmp_path, complete_git):
    res, _ = ingest(read_fixture, "broken_tool_ref_session.jsonl", tmp_path, repo_git=complete_git)
    assert res.status == "incomplete"
    assert any("broken_tool_ref" in r for r in res.reasons)


def test_tamper_detection_v4(read_fixture, tmp_path, complete_git):
    res, _ = ingest(read_fixture, "complete_session.jsonl", tmp_path, repo_git=complete_git)
    rec = res.record
    # simulate a raw digest that no longer matches the bytes
    from acgs_trajectory.validate import v4_tamper

    assert v4_tamper(rec, b"different bytes") == ["V4:raw_digest_mismatch"]
    assert v4_tamper(rec, read_fixture("complete_session.jsonl").encode("utf-8")) == []


def test_determinism_identical_input_identical_output(read_fixture, tmp_path, complete_git):
    r1 = ingest_text(read_fixture("complete_session.jsonl"), store=None, captured_at=CAP, repo_git=complete_git)
    r2 = ingest_text(read_fixture("complete_session.jsonl"), store=None, captured_at=CAP, repo_git=complete_git)
    assert r1.record["trajectory_id"] == r2.record["trajectory_id"]
    assert r1.record["integrity"]["normalized_sha256"] == r2.record["integrity"]["normalized_sha256"]


def test_normalized_digest_self_excluding(read_fixture, tmp_path, complete_git):
    res, _ = ingest(read_fixture, "complete_session.jsonl", tmp_path, repo_git=complete_git)
    rec = res.record
    d1 = rec["integrity"]["normalized_sha256"]
    # recomputing must reproduce the same digest
    stamp_normalized_digest(rec)
    assert rec["integrity"]["normalized_sha256"] == d1


def test_packaged_schema_matches_docs():
    root = Path(__file__).resolve().parents[1]
    a = (root / "acgs_trajectory/schemas/governance_trajectory_v2.schema.json").read_bytes()
    b = (root / "docs/schema/governance_trajectory_v2.schema.json").read_bytes()
    assert a == b, "packaged schema drifted from docs/schema (single source of truth)"
