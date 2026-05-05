from __future__ import annotations

import json
import time

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore


def test_audit_chain_valid_for_two_events(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    base_payload = {
        "actor": {"id": "agent-legal-1", "role": "LegalOps"},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "resource": "contracts/supplier-123",
        "inputs_hash": "sha256:test",
        "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
    }

    first = adapter.validate(base_payload)
    second = adapter.validate({**base_payload, "resource": "contracts/supplier-456"})

    assert first.allow is True
    assert second.allow is True
    assert first.event_hash is not None
    assert second.previous_hash == first.event_hash
    assert store.verify_chain()["valid"] is True


def test_audit_chain_detects_tamper(tmp_path, roles_bundle, policy_bundle):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    adapter.validate(
        {
            "actor": {"id": "agent-legal-1", "role": "LegalOps"},
            "intent": "Redline supplier agreement",
            "action_type": "contract.redline",
            "resource": "contracts/supplier-123",
            "inputs_hash": "sha256:test",
            "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
        }
    )

    event = json.loads(path.read_text().splitlines()[0])
    event["allow"] = False
    path.write_text(json.dumps(event) + "\n")

    assert store.verify_chain()["valid"] is False


def test_audit_chain_handles_concurrent_appends(tmp_path, roles_bundle, policy_bundle):
    import threading

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    def submit(resource: str) -> None:
        adapter.validate(
            {
                "actor": {"id": "agent-legal-1", "role": "LegalOps"},
                "intent": "Redline supplier agreement",
                "action_type": "contract.redline",
                "resource": resource,
                "inputs_hash": "sha256:test",
                "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
            }
        )

    n_workers = 8
    threads = [
        threading.Thread(target=submit, args=(f"contracts/supplier-{i}",))
        for i in range(n_workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    verification = store.verify_chain()
    assert verification["valid"] is True, verification["failures"]
    assert verification["checked"] == n_workers
    assert verification["failures"] == []


def test_audit_append_is_amortized_O1(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    base_payload = {
        "actor": {"id": "agent-legal-1", "role": "LegalOps"},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "inputs_hash": "sha256:test",
        "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
    }

    # Warmup so the cold-cache path is not measured.
    for i in range(100):
        adapter.validate({**base_payload, "resource": f"contracts/warmup-{i}"})

    # Fill to event 900 without measuring.
    for i in range(800):
        adapter.validate({**base_payload, "resource": f"contracts/fill-{i}"})

    # Measure appends 901-1000.
    samples: list[float] = []
    for i in range(100):
        start = time.perf_counter()
        adapter.validate({**base_payload, "resource": f"contracts/measured-{i}"})
        samples.append(time.perf_counter() - start)

    samples.sort()
    p99 = samples[int(len(samples) * 0.99) - 1]
    assert p99 < 0.010, f"p99 latency {p99 * 1000:.2f}ms exceeds 10ms budget"
