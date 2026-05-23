from __future__ import annotations

import json
import time

import pytest
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


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_audit_race",
    coverage_angle="audit_concurrent_append_safety",
)
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
    threads = [threading.Thread(target=submit, args=(f"contracts/supplier-{i}",)) for i in range(n_workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    verification = store.verify_chain()
    assert verification["valid"] is True, verification["failures"]
    assert verification["checked"] == n_workers
    assert verification["failures"] == []


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_amortized_O1",
)
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
    assert p99 < 0.050, f"p99 latency {p99 * 1000:.2f}ms exceeds 50ms budget (O(1) regression threshold)"


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_tail_reads_once_per_append",
)
def test_audit_append_tail_reads_once_per_append(tmp_path, roles_bundle, policy_bundle, monkeypatch):
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

    adapter.validate({**base_payload, "resource": "contracts/warmup"})

    real_read = ChainHashAuditStore._read_last_hash_from_disk
    counter = {"n": 0}

    def counting(self):
        counter["n"] += 1
        return real_read(self)

    monkeypatch.setattr(ChainHashAuditStore, "_read_last_hash_from_disk", counting)

    for i in range(20):
        adapter.validate({**base_payload, "resource": f"contracts/hot-{i}"})

    assert counter["n"] == 20, (
        f"hot-path appends triggered {counter['n']} disk reads; expected exactly one O(1) tail read per append"
    )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_invokes_one_tail_read_per_append",
)
def test_audit_append_invokes_one_tail_read_per_append(tmp_path, roles_bundle, policy_bundle, monkeypatch):
    base_payload = {
        "actor": {"id": "agent-legal-1", "role": "LegalOps"},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "inputs_hash": "sha256:test",
        "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
    }

    chain_sizes = (10, 200, 800)
    paths: dict[int, object] = {}
    for n in chain_sizes:
        path = tmp_path / f"audit-{n}.jsonl"
        bs_store = ChainHashAuditStore(path)
        bs_adapter = GovernedToolAdapter(
            roles_bundle=roles_bundle,
            policy_bundle=policy_bundle,
            audit_store=bs_store,
        )
        for i in range(n):
            bs_adapter.validate({**base_payload, "resource": f"contracts/bs{n}-{i}"})
        paths[n] = path

    real_read = ChainHashAuditStore._read_last_hash_from_disk
    counts: dict[int, int] = {n: 0 for n in chain_sizes}
    active = {"n": 0}

    def counting(self):
        if active["n"] in counts:
            counts[active["n"]] += 1
        return real_read(self)

    monkeypatch.setattr(ChainHashAuditStore, "_read_last_hash_from_disk", counting)

    for n in chain_sizes:
        active["n"] = n
        cold_store = ChainHashAuditStore(paths[n])
        cold_adapter = GovernedToolAdapter(
            roles_bundle=roles_bundle,
            policy_bundle=policy_bundle,
            audit_store=cold_store,
        )
        cold_adapter.validate({**base_payload, "resource": f"contracts/cold{n}-first"})
        for i in range(10):
            cold_adapter.validate({**base_payload, "resource": f"contracts/hot{n}-{i}"})

    for n in chain_sizes:
        assert counts[n] == 11, (
            f"chain_size={n}: appends invoked _read_last_hash_from_disk "
            f"{counts[n]} times; expected exactly one O(1) tail read per append"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_verify_chain_one_hash_per_event",
)
def test_audit_verify_chain_one_hash_per_event(tmp_path, roles_bundle, policy_bundle, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(audit_path)
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

    n_events = 200
    for i in range(n_events):
        adapter.validate({**base_payload, "resource": f"contracts/verify-{i}"})

    import governance.audit.jsonl_chain as jc

    real_hash = jc.sha256_json
    counter = {"n": 0}

    def counting(*args, **kwargs):
        counter["n"] += 1
        return real_hash(*args, **kwargs)

    monkeypatch.setattr(jc, "sha256_json", counting)

    result = store.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == n_events
    assert counter["n"] == n_events, (
        f"verify_chain hashed {counter['n']} times for {n_events} events; "
        f"O(n^2) regression: expected exactly {n_events} hash calls"
    )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_writes_one_line_no_rewrite",
)
def test_audit_append_writes_one_line_no_rewrite(tmp_path, roles_bundle, policy_bundle):
    audit_path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(audit_path)
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

    n_appends = 50
    sizes = [0]
    for i in range(n_appends):
        adapter.validate({**base_payload, "resource": f"contracts/sz-{i}"})
        sizes.append(audit_path.stat().st_size)

    deltas = [sizes[i + 1] - sizes[i] for i in range(n_appends)]
    assert all(d > 0 for d in deltas), f"non-positive size delta detected: {deltas}; append should be strictly additive"

    content = audit_path.read_text(encoding="utf-8")
    line_count = content.count("\n")
    assert line_count == n_appends, (
        f"file has {line_count} newlines for {n_appends} appends; append produced unexpected line count"
    )

    assert sizes[-1] == sum(deltas), (
        f"final size {sizes[-1]} != sum of deltas {sum(deltas)}; append rewrote prior content"
    )
