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
