"""Fail-closed constitution-hash registry cross-check (criterion G2.5).

Every scenario goes through ``verify_replay_bundle`` (the dispatcher-level
entry point) — never through the allowed-hash helper directly — so the
tests prove the cross-check is wired into the real verification path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_mcp_v0._io import sha256_json, write_constitution_registry
from governed_mcp_v0.errors import GovernanceDenied
from governed_mcp_v0.mcp_server import (
    GovernedMCPServer,
    create_fixture_environment,
    verify_replay_bundle,
)


def _server(tmp_path: Path, case_name: str) -> GovernedMCPServer:
    return GovernedMCPServer(create_fixture_environment(tmp_path / case_name))


def test_valid_bundle_without_registry_derives_hash_from_constitution(tmp_path):
    server = _server(tmp_path, "no_registry")
    server.write_file("allowed.txt", "ok")
    assert not server.targets.constitution_registry_path.exists()
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def test_valid_bundle_with_matching_registry(tmp_path):
    server = _server(tmp_path, "matching_registry")
    server.write_file("allowed.txt", "ok")
    registry_path = write_constitution_registry(server.targets)
    assert registry_path == server.targets.constitution_registry_path
    constitution = json.loads(server.targets.constitution_path.read_text(encoding="utf-8"))
    assert json.loads(registry_path.read_text(encoding="utf-8")) == [sha256_json(constitution)]
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def test_receipt_stamped_missing_fails_even_with_valid_registry(tmp_path):
    server = _server(tmp_path, "missing_stamp")
    write_constitution_registry(server.targets)
    server.targets.constitution_path.unlink()
    with pytest.raises(GovernanceDenied):
        server.write_file("blocked.txt", "no side effect")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_hash_missing" in failure for failure in replay.failures)


def test_receipt_with_unknown_hash_fails(tmp_path):
    server = _server(tmp_path, "unknown_hash")
    server.write_file("allowed.txt", "ok")
    # Mutate the live constitution after the fact: the receipt's stamped
    # hash no longer matches the (re-derived) allowed singleton set.
    constitution = json.loads(server.targets.constitution_path.read_text(encoding="utf-8"))
    constitution["policies"].append("injected-after-the-fact")
    server.targets.constitution_path.write_text(json.dumps(constitution), encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_hash_not_in_registry" in failure for failure in replay.failures)


def test_registry_omitting_live_hash_fails(tmp_path):
    server = _server(tmp_path, "registry_omits_hash")
    server.write_file("allowed.txt", "ok")
    server.targets.constitution_registry_path.write_text(json.dumps(["f" * 64]), encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_hash_not_in_registry" in failure for failure in replay.failures)


@pytest.mark.parametrize(
    "payload",
    ["[]", '"not-a-list"', "[42]", '[""]', '["missing"]', "{}"],
)
def test_malformed_registry_fails_closed(tmp_path, payload):
    server = _server(tmp_path, "malformed_registry")
    server.write_file("allowed.txt", "ok")
    server.targets.constitution_registry_path.write_text(payload, encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_registry_malformed" in failure for failure in replay.failures)


def test_unparseable_registry_fails_closed(tmp_path):
    server = _server(tmp_path, "unparseable_registry")
    server.write_file("allowed.txt", "ok")
    server.targets.constitution_registry_path.write_text("{not json", encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_registry_unreadable" in failure for failure in replay.failures)


def test_no_registry_and_unreadable_constitution_fails_closed(tmp_path):
    server = _server(tmp_path, "constitution_gone")
    server.write_file("allowed.txt", "ok")
    server.targets.constitution_path.unlink()
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("constitution_unreadable_for_hash_crosscheck" in failure for failure in replay.failures)
    # The previously stamped (real) hash can no longer be cross-checked: the
    # allowed set is empty, so the receipt is rejected too — never a silent pass.
    assert any("constitution_hash_not_in_registry" in failure for failure in replay.failures)


def test_registry_writer_requires_readable_constitution(tmp_path):
    server = _server(tmp_path, "writer_fail_closed")
    server.targets.constitution_path.unlink()
    with pytest.raises(FileNotFoundError):
        write_constitution_registry(server.targets)
    assert not server.targets.constitution_registry_path.exists()
