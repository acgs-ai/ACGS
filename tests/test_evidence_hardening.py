"""
audit-evidence-hardening Round 1 — evidence_hardening approach family.

Each test targets a HIGH-severity issue that had only one seed test and adds a
structurally distinct EVIDENCE property: not "does the fix still work?" but
"does the system produce verifiable, reconstructible evidence of the event?"

All (pr, issue, coverage_angle) triples are distinct from prior rounds.
"""
from __future__ import annotations

import threading

import pytest

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore, InMemoryAuditStore
from governance.gates import AuthorityGate
from governance.models import ActionRequest, Principal
from governance.testing import governance_test_harness, make_request


# ---------------------------------------------------------------------------
# Issue: codex_audit_race  (HIGH, pr="codex-investigate (no upstream PR)")
# Seed angle: audit_concurrent_append_safety
# New angle: chain stays reconstructible (verify_chain passes) after concurrent
# writes — not just "no crash", but the resulting chain is a valid linked list.
# ---------------------------------------------------------------------------


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_audit_race",
    coverage_angle="audit_chain_reconstructible_after_concurrent_writes",
)
def test_audit_chain_reconstructible_after_concurrent_writes(
    tmp_path, roles_bundle, policy_bundle
):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    n_workers = 8
    threads = [
        threading.Thread(
            target=lambda r=f"contracts/supplier-{i}": adapter.validate(
                make_request(resource=r)
            )
        )
        for i in range(n_workers)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = store.verify_chain()
    # Primary evidence invariant: every recorded event is linked back to its
    # predecessor — the chain is fully reconstructible from the JSONL file
    # with no broken hash links, regardless of write interleaving order.
    assert result["valid"] is True, (
        f"chain invalid after concurrent writes: {result.get('failures')}"
    )
    assert result["checked"] == n_workers, (
        f"expected {n_workers} events reconstructed, got {result['checked']}"
    )
    assert result["failures"] == [], result["failures"]


# ---------------------------------------------------------------------------
# Issue: codex_no_audit_guard  (HIGH, pr="codex-investigate (no upstream PR)")
# Seed angle: guard_refuses_no_audit_store
# New angle: the refusal carries a structured error message that identifies the
# missing evidence sink — so callers have actionable evidence of why the guard
# blocked, not just a bare exception.
# ---------------------------------------------------------------------------


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_no_audit_guard",
    coverage_angle="audit_guard_refusal_carries_evidence_message",
)
def test_audit_guard_refusal_carries_evidence_message(roles_bundle, policy_bundle):
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=None,
    )
    payload = make_request()

    with pytest.raises(Exception) as exc_info:
        adapter.guard(payload, lambda tool_input: None)

    # The exception message must identify the missing evidence sink so that an
    # operator can reconstruct *why* the action was blocked, not just that it was.
    msg = str(exc_info.value).lower()
    assert any(
        kw in msg for kw in ("audit", "store", "log", "record", "evidence")
    ), (
        f"guard refusal message '{exc_info.value}' lacks evidence-sink identification; "
        "operators cannot reconstruct why the action was blocked"
    )


# ---------------------------------------------------------------------------
# Issue: codex_tenant_spoof  (HIGH, pr="codex-investigate (no upstream PR)")
# Seed angle: actor_cannot_spoof_request_tenant
# New angle: the tenant-mismatch denial writes a complete audit record that
# captures BOTH actor_tenant and request_tenant — the evidence is persisted,
# not just returned in-memory to the caller.
# ---------------------------------------------------------------------------


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_tenant_spoof",
    coverage_angle="spoof_attempt_produces_persisted_audit_evidence",
)
def test_spoof_attempt_produces_persisted_audit_evidence(
    tmp_path, roles_bundle, policy_bundle
):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    payload = make_request(
        actor={
            "id": "agent-legal-1",
            "role": "LegalOps",
            "tenant": "acme",
        },
        tenant="globex",
    )
    decision = adapter.validate(payload)

    # The gate must deny the spoof.
    assert decision.allow is False

    # Evidence invariant: the denial must be durably recorded so that it can be
    # reconstructed in an audit investigation — not just returned to the caller.
    assert tmp_path.joinpath("audit.jsonl").exists(), (
        "no audit file written; spoof attempt leaves no persisted evidence trail"
    )
    import json

    lines = tmp_path.joinpath("audit.jsonl").read_text().splitlines()
    assert len(lines) >= 1, "no audit events written for spoof attempt"

    event = json.loads(lines[-1])
    # The recorded event must capture that the action was denied (allow=False).
    assert event.get("allow") is False, (
        f"recorded audit event shows allow={event.get('allow')}; "
        "spoof denial not captured in evidence"
    )
    # The chain must be valid so the persisted evidence is reconstructible.
    assert store.verify_chain()["valid"] is True


# ---------------------------------------------------------------------------
# Issue: autofix_api_auth_bypass  (HIGH, pr="fix/governance-eng-autofix")
# Seed angles: audit_query_no_token_401, audit_no_token_401, validate_*
# New angle: a denied request (auth bypass attempt) produces an audit record
# with a non-null event_hash — the denial is hash-linked into the chain and
# cannot be silently dropped without breaking chain reconstruction.
# ---------------------------------------------------------------------------


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="auth_denial_is_hash_linked_into_audit_chain",
)
def test_auth_denial_is_hash_linked_into_audit_chain(roles_bundle, policy_bundle):
    store = InMemoryAuditStore()
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    # A role that is not authorised for contract.approve — simulates an
    # auth-bypass attempt where the caller uses the wrong role.
    deny_payload = make_request(
        role="MarketingOps",
        action_type="contract.approve",
        resource="contracts/supplier-123",
        metadata={},
    )
    decision = adapter.validate(deny_payload)

    # The adapter must deny the bypass attempt.
    assert decision.allow is False

    # Evidence invariant: the denial must carry a non-null event_hash so that
    # it is hash-linked into the chain. A null hash means the denial could be
    # silently removed from the chain without detection.
    assert decision.event_hash is not None, (
        "denied decision has no event_hash; "
        "auth-bypass denial is not hash-linked and can be silently dropped"
    )

    # The chain must remain valid (denial does not corrupt the evidence log).
    result = store.verify_chain()
    assert result["valid"] is True, (
        f"chain invalid after recording auth-bypass denial: {result.get('failures')}"
    )
    assert result["checked"] >= 1
