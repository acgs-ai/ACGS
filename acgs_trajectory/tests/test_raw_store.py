from __future__ import annotations

import os
import stat

import pytest

from acgs_trajectory.raw_store import RawStore


def test_content_addressed_worm(tmp_path):
    store = RawStore(tmp_path)
    data = b'{"type":"user"}\n'
    ref = store.put_raw(data, record_count=1)
    assert ref.sha256 in ref.uri
    path = tmp_path / ref.uri
    # sealed read-only
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert not (mode & stat.S_IWUSR)
    # idempotent re-write of identical content is a no-op
    ref2 = store.put_raw(data, record_count=1)
    assert ref2.sha256 == ref.sha256


def test_verify_raw_detects_tamper(tmp_path):
    store = RawStore(tmp_path)
    ref = store.put_raw(b"hello\n", record_count=1)
    assert store.verify_raw(ref)
    # tamper the stored object
    path = tmp_path / ref.uri
    os.chmod(path, 0o644)
    path.write_bytes(b"tampered\n")
    assert store.verify_raw(ref) is False


def test_manifest_hash_chain(tmp_path):
    store = RawStore(tmp_path)
    e1 = store.append_manifest({"trajectory_id": "t1", "raw_sha256": "a" * 64,
                                "raw_uri": "raw/aa/x.jsonl", "normalized_sha256": "b" * 64,
                                "captured_at": "t", "status": "complete"})
    e2 = store.append_manifest({"trajectory_id": "t2", "raw_sha256": "c" * 64,
                                "raw_uri": "raw/cc/y.jsonl", "normalized_sha256": "d" * 64,
                                "captured_at": "t", "status": "incomplete"})
    assert e1["prev_entry_sha256"] is None
    assert e2["prev_entry_sha256"] == e1["entry_sha256"]
    ok, errors = store.verify_chain()
    assert ok and not errors


def test_manifest_chain_detects_modification(tmp_path):
    store = RawStore(tmp_path)
    store.append_manifest({"trajectory_id": "t1", "raw_sha256": "a" * 64, "raw_uri": "u",
                           "normalized_sha256": "b" * 64, "captured_at": "t", "status": "complete"})
    # silently modify a committed manifest entry
    text = store.manifest_path.read_text().replace('"complete"', '"quarantined"')
    store.manifest_path.write_text(text)
    ok, errors = store.verify_chain()
    assert ok is False and errors


def test_quarantine_store_is_restricted(tmp_path):
    store = RawStore(tmp_path)
    ref = store.put_raw(b"secret payload\n", record_count=1, quarantine=True)
    assert "quarantine" in ref.uri
    mode = stat.S_IMODE(os.stat(tmp_path / ref.uri).st_mode)
    # not group/other readable
    assert not (mode & (stat.S_IRGRP | stat.S_IROTH))
