from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from governed_mcp_v0 import GovernedMCPServer, create_fixture_environment


def test_record_decision_serializes_receipts_and_audit_chain(tmp_path):
    targets = create_fixture_environment(tmp_path / "concurrency")
    server = GovernedMCPServer(targets)

    def record(index: int) -> int:
        decision = server._record_decision(  # noqa: SLF001 - regression covers the private persistence critical section.
            "filesystem.write_file",
            "write_file",
            {"path": f"file-{index}.txt", "content_hash": f"hash-{index}"},
            "allow",
            "concurrency regression",
            ["guard-side-effects"],
        )
        return int(decision.receipt_path.name.split("-", 1)[0])

    with ThreadPoolExecutor(max_workers=8) as executor:
        receipt_indices = list(executor.map(record, range(16)))

    receipts = sorted(targets.receipts_dir.glob("*.json"))
    assert len(receipts) == 16
    assert len({receipt.name for receipt in receipts}) == 16
    assert len(set(receipt_indices)) == 16

    events = [json.loads(line) for line in targets.audit_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(events) == 16
    for previous, current in zip(events[:-1], events[1:], strict=True):
        assert current["previous_hash"] == previous["event_hash"]


def test_next_receipt_index_skips_orphan_receipt_filenames(tmp_path):
    """If a stray receipt exists at a higher index than the audit length, the
    next admission must skip it instead of clobbering it.

    Reproduces the orphan scenario: audit has N entries but receipts_dir
    contains an index > N (e.g. external cleanup unlinked the audit row but
    left the receipt). The pre-fix line-count derivation would pick N+1
    and either FileExistsError (if N+1 still exists) or silently re-link
    against the wrong receipt; max(receipt-indices)+1 is collision-proof.
    """
    targets = create_fixture_environment(tmp_path / "orphan")
    server = GovernedMCPServer(targets)

    server._record_decision(  # noqa: SLF001
        "filesystem.write_file",
        "write_file",
        {"path": "first.txt", "content_hash": "h1"},
        "allow",
        "seed",
        ["guard-side-effects"],
    )
    orphan = targets.receipts_dir / "0099-orphan-from-external-cleanup.json"
    orphan.write_text(json.dumps({"orphan": True}), encoding="utf-8")

    decision = server._record_decision(  # noqa: SLF001
        "filesystem.write_file",
        "write_file",
        {"path": "second.txt", "content_hash": "h2"},
        "allow",
        "after orphan",
        ["guard-side-effects"],
    )
    new_index = int(decision.receipt_path.name.split("-", 1)[0])
    assert new_index == 100, f"expected index 100 (orphan+1), got {new_index}"
    assert decision.receipt_path.exists()
