"""Phase 2 annotation-writer tests — acceptance P2-6/P2-7 (ADR 0003 §6, §8)."""

from __future__ import annotations

import json
from pathlib import Path

from acgs_trajectory.annotate import AnnotationStore
from acgs_trajectory.canonical import canonical_bytes
from acgs_trajectory.evaluate import evaluate
from acgs_trajectory.replay import replay

FIX = Path(__file__).parent / "fixtures"
FIXTURES = [
    "complete_session.jsonl",
    "unmitigated_edit_session.jsonl",
    "hook_prevented_session.jsonl",
]


def _records():
    return [replay(FIX / n).record for n in FIXTURES]


def test_annotation_written_to_derived_path_not_raw(tmp_path):
    store = AnnotationStore(tmp_path)
    ann = store.annotate_record(replay(FIX / "complete_session.jsonl").record)
    path = store.path_for(ann["annotation_id"])
    assert path.exists()
    # derived layout: annotations/<ab>/<id>.json ; NEVER under raw/
    rel = path.relative_to(tmp_path)
    assert rel.parts[0] == "annotations"
    assert "raw" not in rel.parts
    assert rel.parts[1] == ann["annotation_id"][:2]
    assert rel.name == f"{ann['annotation_id']}.json"


def test_written_annotation_is_canonical_bytes(tmp_path):
    store = AnnotationStore(tmp_path)
    ann = store.annotate_record(replay(FIX / "complete_session.jsonl").record)
    path = store.path_for(ann["annotation_id"])
    assert path.read_bytes() == canonical_bytes(ann)


def test_registry_chain_verifies(tmp_path):
    store = AnnotationStore(tmp_path)
    for rec in _records():
        store.annotate_record(rec)
    ok, errors = store.verify_chain()
    assert ok, errors


def test_registry_is_hash_chained(tmp_path):
    store = AnnotationStore(tmp_path)
    for rec in _records():
        store.annotate_record(rec)
    lines = [
        json.loads(l)
        for l in store.registry_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    assert len(lines) == len(FIXTURES)
    assert lines[0]["prev_entry_sha256"] is None
    for prev, cur in zip(lines, lines[1:]):
        assert cur["prev_entry_sha256"] == prev["entry_sha256"]
    # registry body must NOT carry a timestamp (rebuild determinism)
    for entry in lines:
        assert "captured_at" not in entry
        assert "timestamp" not in entry


def test_registry_tamper_is_detected(tmp_path):
    store = AnnotationStore(tmp_path)
    for rec in _records():
        store.annotate_record(rec)
    # corrupt the first entry's derived field
    lines = store.registry_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["evaluator_version"] = "9.9.9"
    lines[0] = json.dumps(first, sort_keys=True, ensure_ascii=False)
    store.registry_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, errors = store.verify_chain()
    assert not ok
    assert errors


# ---- Fix 5 (SEC-MED): tail-truncation detection via head/length anchor -------


def test_fix5_tail_truncation_is_detected(tmp_path):
    store = AnnotationStore(tmp_path)
    for rec in _records():
        store.annotate_record(rec)
    # baseline: full chain + anchor verifies.
    ok, errors = store.verify_chain()
    assert ok, errors
    # drop the NEWEST registry entry (tail-truncation). The remaining prefix is
    # still an internally-consistent hash chain, so the plain chain check passes —
    # only the head/length commitment anchor catches it.
    lines = [
        l for l in store.registry_path.read_text(encoding="utf-8").splitlines() if l.strip()
    ]
    assert len(lines) >= 2
    store.registry_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    ok, errors = store.verify_chain()
    assert not ok
    assert any("tail-truncation" in e or "head anchor" in e for e in errors), errors


def test_fix5_head_anchor_is_rebuild_deterministic(tmp_path):
    # the head anchor is written by idempotent overwrite, so delete + rebuild
    # reproduces identical anchor content (P2-7 rebuild determinism).
    records = _records()

    def build(root: Path) -> str:
        store = AnnotationStore(root)
        for rec in records:
            store.annotate_record(rec)
        return store.head_anchor_path.read_text(encoding="utf-8")

    assert build(tmp_path / "a") == build(tmp_path / "b")


# ---- P2-7: rebuild — delete derived dir, re-run -> identical files + chain ---


def test_p2_7_rebuild_reproduces_identical_files_and_chain(tmp_path):
    records = _records()

    def build(root: Path) -> tuple[dict[str, bytes], str]:
        store = AnnotationStore(root)
        for rec in records:
            store.annotate_record(rec)
        files: dict[str, bytes] = {}
        for p in sorted((root / "annotations").rglob("*.json")):
            files[str(p.relative_to(root))] = p.read_bytes()
        registry = store.registry_path.read_text(encoding="utf-8")
        return files, registry

    files_a, registry_a = build(tmp_path / "run_a")
    files_b, registry_b = build(tmp_path / "run_b")

    # identical annotation files (byte-for-byte, same relative paths)
    assert set(files_a) == set(files_b)
    for rel in files_a:
        assert files_a[rel] == files_b[rel], f"annotation {rel} differs across rebuild"
    # identical registry chain
    assert registry_a == registry_b


def test_p2_7_rebuild_after_delete_in_place(tmp_path):
    import shutil

    store = AnnotationStore(tmp_path)
    records = _records()
    for rec in records:
        store.annotate_record(rec)
    before_files = {
        str(p.relative_to(tmp_path)): p.read_bytes()
        for p in sorted((tmp_path / "annotations").rglob("*.json"))
    }
    before_registry = store.registry_path.read_text(encoding="utf-8")

    # delete the derived dir + registry entirely
    shutil.rmtree(tmp_path / "annotations")
    store.registry_path.unlink()

    # re-run from the frozen records alone
    store2 = AnnotationStore(tmp_path)
    for rec in records:
        store2.annotate_record(rec)
    after_files = {
        str(p.relative_to(tmp_path)): p.read_bytes()
        for p in sorted((tmp_path / "annotations").rglob("*.json"))
    }
    after_registry = store2.registry_path.read_text(encoding="utf-8")

    assert before_files == after_files
    assert before_registry == after_registry


def test_idempotent_rewrite_is_noop(tmp_path):
    store = AnnotationStore(tmp_path)
    rec = replay(FIX / "complete_session.jsonl").record
    ann = evaluate(rec)
    p1 = store.write_annotation(ann)
    b1 = p1.read_bytes()
    p2 = store.write_annotation(ann)  # second write, identical content
    assert p1 == p2
    assert p2.read_bytes() == b1
