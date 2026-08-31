from __future__ import annotations

import json
import time

import pytest

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore

_BASE_PAYLOAD = {
    "actor": {"id": "agent-legal-1", "role": "LegalOps"},
    "intent": "Redline supplier agreement",
    "action_type": "contract.redline",
    "inputs_hash": "sha256:test",
    "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
}

_CHILD_APPENDER = '''
import sys

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles

audit_path, resource = sys.argv[1], sys.argv[2]
adapter = GovernedToolAdapter(
    roles_bundle=load_roles("governance/roles.json"),
    policy_bundle=load_policy_bundle("governance/policies/2026-05"),
    audit_store=ChainHashAuditStore(audit_path),
)
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
'''


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
    assert p99 < 0.010, f"p99 latency {p99 * 1000:.2f}ms exceeds 10ms budget"


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_does_not_reread_chain_after_warmup",
)
def test_audit_append_does_not_reread_chain_after_warmup(
    tmp_path, roles_bundle, policy_bundle, monkeypatch
):
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

    assert counter["n"] == 0, (
        f"hot-path appends triggered {counter['n']} disk reads; "
        "O(n^2) regression: cached _last_hash was not reused"
    )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_append_cold_start_invokes_disk_read_exactly_once",
)
def test_audit_append_cold_start_invokes_disk_read_exactly_once(
    tmp_path, roles_bundle, policy_bundle, monkeypatch
):
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
        assert counts[n] == 1, (
            f"chain_size={n}: cold-start invoked _read_last_hash_from_disk "
            f"{counts[n]} times; O(n^2) regression: expected exactly 1"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="CRIT",
    issue="autofix_o_n2_audit_caching",
    coverage_angle="audit_verify_chain_one_hash_per_event",
)
def test_audit_verify_chain_one_hash_per_event(
    tmp_path, roles_bundle, policy_bundle, monkeypatch
):
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
def test_audit_append_writes_one_line_no_rewrite(
    tmp_path, roles_bundle, policy_bundle
):
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
    assert all(d > 0 for d in deltas), (
        f"non-positive size delta detected: {deltas}; "
        "append should be strictly additive"
    )

    content = audit_path.read_text(encoding="utf-8")
    line_count = content.count("\n")
    assert line_count == n_appends, (
        f"file has {line_count} newlines for {n_appends} appends; "
        "append produced unexpected line count"
    )

    assert sizes[-1] == sum(deltas), (
        f"final size {sizes[-1]} != sum of deltas {sum(deltas)}; "
        "append rewrote prior content"
    )


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_audit_race",
    coverage_angle="audit_chain_valid_across_two_store_instances_same_path",
)
def test_audit_chain_valid_across_two_store_instances_same_path(
    tmp_path, roles_bundle, policy_bundle
):
    audit_path = tmp_path / "audit.jsonl"
    store_a = ChainHashAuditStore(audit_path)
    store_b = ChainHashAuditStore(audit_path)
    adapter_a = GovernedToolAdapter(
        roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store_a
    )
    adapter_b = GovernedToolAdapter(
        roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store_b
    )

    first = adapter_a.validate({**_BASE_PAYLOAD, "resource": "contracts/inst-a1"})
    second = adapter_b.validate({**_BASE_PAYLOAD, "resource": "contracts/inst-b1"})
    third = adapter_a.validate({**_BASE_PAYLOAD, "resource": "contracts/inst-a2"})

    assert second.previous_hash == first.event_hash
    assert third.previous_hash == second.event_hash

    verification = store_a.verify_chain()
    assert verification["valid"] is True, verification["failures"]
    assert verification["checked"] == 3
    assert verification["failures"] == []
    assert store_a.last_hash() == third.event_hash
    assert store_b.last_hash() == third.event_hash


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_audit_race",
    coverage_angle="audit_chain_valid_across_separate_writer_processes",
)
def test_audit_chain_valid_across_separate_writer_processes(
    tmp_path, roles_bundle, policy_bundle
):
    import os
    import subprocess
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    audit_path = tmp_path / "audit.jsonl"
    script = tmp_path / "child_appender.py"
    script.write_text(_CHILD_APPENDER, encoding="utf-8")

    store = ChainHashAuditStore(audit_path)
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store
    )

    adapter.validate({**_BASE_PAYLOAD, "resource": "contracts/parent-1"})

    child = subprocess.run(
        [sys.executable, str(script), str(audit_path), "contracts/child-1"],
        cwd=str(repo_root),
        env={**os.environ, "PYTHONPATH": str(repo_root)},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert child.returncode == 0, child.stderr

    adapter.validate({**_BASE_PAYLOAD, "resource": "contracts/parent-2"})

    verification = store.verify_chain()
    assert verification["valid"] is True, verification["failures"]
    assert verification["checked"] == 3
    assert verification["failures"] == []
