"""Adversarial and invariant coverage for the Execution Governance Layer.

Numbering follows the acceptance table in
``docs/governance/acgs-vnext-execution-governance-layer.md`` §5.

One case is specified there as **not closed**, and is asserted here as *not
closed* rather than quietly omitted. ADV-A is closed on the hook-visible path,
but the layer makes no claim about commands that never reach the hook:

* **ADV-A** — a manager invoked by absolute path fails closed when the command
  reaches this hook. This layer is not a ``PATH`` shim, so an interactive
  terminal invocation outside the hook remains out of scope.
* **ADV-E** — a truncated audit tail is invisible to an internal chain walk. The
  test asserts precisely that: undetected without an external anchor, detected
  with one.

An acceptance suite that asserted ADV-E prevention would be false.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

import pytest

from gove_zone.audit import ChainHashAuditStore
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import (
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.execution import (
    ACTION_PACKAGE_INSTALL,
    ACTION_PACKAGE_INVOKE,
    ACTION_SHELL_EXEC,
    EXECUTION_BOUNDARY,
    build_execution_policy,
    classify_command,
    make_execution_call_factory,
)
from gove_zone.executor import execute_with_receipt
from gove_zone.gateway import BypassAttemptError, UniversalGateway
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Validator


class FakeSigner:
    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"adv-key", key_id: str = "adv-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@pytest.fixture
def signer() -> FakeSigner:
    return FakeSigner()


@pytest.fixture
def ledger(tmp_path: Path) -> ReceiptConsumptionLedger:
    return ReceiptConsumptionLedger(str(tmp_path / "ledger.jsonl"))


@pytest.fixture
def gateway(
    tmp_path: Path, signer: FakeSigner, ledger: ReceiptConsumptionLedger
) -> UniversalGateway:
    return UniversalGateway(
        tenant_id="tenant-exec",
        execution_boundary=EXECUTION_BOUNDARY,
        policy=build_execution_policy(),
        profile=GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-exec"),
        authority="execution-governance",
        audit_path=tmp_path / "audit.jsonl",
        ledger=ledger,
    )


def audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# -- INV-5 — the ADV9 keystone ----------------------------------------------- #


def test_direct_call_to_a_sealed_execution_tool_is_refused_and_audited(
    gateway: UniversalGateway, tmp_path: Path
) -> None:
    """The complete-mediation keystone: holding a reference to the governed tool
    must not be enough to use it."""
    ran: list[dict[str, Any]] = []
    sealed = gateway.register_tool(ACTION_SHELL_EXEC, lambda **kw: ran.append(kw))

    with pytest.raises(BypassAttemptError):
        sealed(argv_prefix=["ls"])

    assert ran == []
    attempts = gateway.bypass_attempts()
    assert len(attempts) == 1
    assert attempts[0]["tool"] == ACTION_SHELL_EXEC
    denials = [e for e in audit_events(tmp_path) if e["decision"] == "deny"]
    assert denials, "a bypass attempt must leave an audited synthesized DENY"


def test_the_governed_path_executes_the_same_tool(
    gateway: UniversalGateway,
) -> None:
    """Positive control for INV-5. Without it, a gate that refused everything
    would score perfectly on the bypass test."""
    ran: list[dict[str, Any]] = []

    def record_execution(**kwargs: Any) -> str:
        ran.append(kwargs)
        return "ok"

    gateway.register_tool(ACTION_SHELL_EXEC, record_execution)

    outcome = gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["ls"]})

    assert outcome.executed
    assert ran == [{"argv_prefix": ["ls"]}]


# -- ADV-C — re-entrancy: a governed tool invoking another governed tool ------ #


def test_a_governed_tool_cannot_reach_a_second_sealed_tool(
    gateway: UniversalGateway,
) -> None:
    """The grant is per-tool. An install that tries to trigger a second install
    mid-execution — the shape a lifecycle script would take — is refused."""
    second_ran: list[Any] = []
    second = gateway.register_tool(ACTION_PACKAGE_INSTALL, lambda **kw: second_ran.append(kw))

    def outer(**_kwargs: Any) -> Any:
        return second(package="left-pad")

    gateway.register_tool(ACTION_SHELL_EXEC, outer)

    with pytest.raises(BypassAttemptError):
        gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["sh"]})

    assert second_ran == []


# -- INV-4 — one decision authorizes at most one side effect ----------------- #


def test_receipt_is_single_use(
    gateway: UniversalGateway, signer: FakeSigner, ledger: ReceiptConsumptionLedger
) -> None:
    calls: list[Any] = []
    gateway.register_tool(ACTION_SHELL_EXEC, lambda **kw: calls.append(kw))

    outcome = gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["ls"]})
    assert outcome.receipt is not None

    with pytest.raises(ReceiptAlreadyUsedError):
        execute_with_receipt(
            tool_fn=lambda **kw: calls.append(kw),
            args={"argv_prefix": ["ls"]},
            receipt=outcome.receipt,
            expected_tenant_id="tenant-exec",
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_action=ACTION_SHELL_EXEC,
            expected_actor="operator-a",
            expected_audit_hash=outcome.audit_hash,
            verifier=signer,
            require_signature=True,
            consumption_ledger=ledger,
        )

    assert len(calls) == 1


# -- INV-6 / ADV-B — argument and actor binding ------------------------------ #


def test_executed_arguments_must_equal_receipted_arguments(
    gateway: UniversalGateway, signer: FakeSigner
) -> None:
    gateway.register_tool(ACTION_SHELL_EXEC, lambda **kw: kw)
    outcome = gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["ls"]})

    with pytest.raises(ReceiptValidationError) as excinfo:
        execute_with_receipt(
            tool_fn=lambda **kw: kw,
            args={"argv_prefix": ["rm", "-rf"]},
            receipt=outcome.receipt,
            expected_tenant_id="tenant-exec",
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_action=ACTION_SHELL_EXEC,
            expected_actor="operator-a",
            verifier=signer,
        )

    assert excinfo.value.reason_code == ReceiptRejectionReason.ARGUMENT_MISMATCH


def test_receipt_for_one_actor_is_rejected_for_another(
    gateway: UniversalGateway, signer: FakeSigner
) -> None:
    """ADV-B. The anchor is the caller's runtime identity, not a receipt field,
    so it cannot be forged by editing the receipt."""
    gateway.register_tool(ACTION_SHELL_EXEC, lambda **kw: kw)
    outcome = gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["ls"]})

    with pytest.raises(ReceiptValidationError) as excinfo:
        execute_with_receipt(
            tool_fn=lambda **kw: kw,
            args={"argv_prefix": ["ls"]},
            receipt=outcome.receipt,
            expected_tenant_id="tenant-exec",
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_action=ACTION_SHELL_EXEC,
            expected_actor="operator-b",
            verifier=signer,
        )

    assert excinfo.value.reason_code == ReceiptRejectionReason.ACTOR_MISMATCH


def test_receipt_from_a_different_boundary_is_rejected(
    gateway: UniversalGateway, signer: FakeSigner
) -> None:
    """``execution-environment`` is not interchangeable with any other boundary:
    a receipt minted for a tool boundary cannot authorize an environment
    mutation."""
    gateway.register_tool(ACTION_SHELL_EXEC, lambda **kw: kw)
    outcome = gateway.invoke("operator-a", ACTION_SHELL_EXEC, {"argv_prefix": ["ls"]})

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=lambda **kw: kw,
            args={"argv_prefix": ["ls"]},
            receipt=outcome.receipt,
            expected_tenant_id="tenant-exec",
            expected_execution_boundary="some-other-boundary",
            expected_action=ACTION_SHELL_EXEC,
            expected_actor="operator-a",
            verifier=signer,
        )


# -- INV-3 — self-validation ------------------------------------------------- #


def test_an_actor_cannot_validate_its_own_execution_decision() -> None:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION_PACKAGE_INSTALL,
        argument_hash="0" * 64,
        policy_version="execution-governance/test",
        event_id="ev_self",
        actor="operator-a",
    )

    with pytest.raises(ReceiptValidationError) as excinfo:
        DecisionReceipt.from_record(
            record,
            audit_hash="a" * 64,
            previous_audit_hash="b" * 64,
            tenant_id="tenant-exec",
            execution_boundary=EXECUTION_BOUNDARY,
            policy_bundle_id="execution-governance/v1",
            policy_hash="c" * 64,
            request_id="req-1",
            validator=Validator(validator_id="operator-a"),
            authority="execution-governance",
        )

    assert excinfo.value.reason_code == ReceiptRejectionReason.SELF_VALIDATION


# -- INV-1 — fail-closed when the decision cannot be recorded ---------------- #


def test_hook_denies_when_the_audit_chain_cannot_be_appended(
    gateway: UniversalGateway, tmp_path: Path
) -> None:
    """An unrecordable decision is not a decision. Governance that cannot write
    its evidence must not authorize a side effect."""
    if os.geteuid() == 0:
        pytest.skip("running as root: file mode does not restrict writes")

    factory = make_execution_call_factory("pnpm")
    first = gateway.handle_claude_hook(
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        actor="operator-a",
        call_factory=factory,
    )
    assert first["hookSpecificOutput"]["permissionDecision"] == "allow"

    audit = tmp_path / "audit.jsonl"
    audit.chmod(0o444)
    try:
        blocked = gateway.handle_claude_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
            actor="operator-a",
            call_factory=factory,
        )
    finally:
        audit.chmod(0o644)

    assert blocked["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_denies_a_payload_it_cannot_govern(gateway: UniversalGateway) -> None:
    response = gateway.handle_claude_hook(
        {},
        actor="operator-a",
        call_factory=make_execution_call_factory("pnpm"),
    )

    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_requires_an_actor(gateway: UniversalGateway) -> None:
    with pytest.raises(ValueError):
        gateway.handle_claude_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            actor="",
            call_factory=make_execution_call_factory("pnpm"),
        )


# -- INV-2 — actor allowlist ------------------------------------------------- #


def test_actor_outside_the_allowlist_is_denied(
    tmp_path: Path, signer: FakeSigner, ledger: ReceiptConsumptionLedger
) -> None:
    restricted = UniversalGateway(
        tenant_id="tenant-exec",
        execution_boundary=EXECUTION_BOUNDARY,
        policy=build_execution_policy(),
        profile=GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-exec"),
        authority="execution-governance",
        audit_path=tmp_path / "audit.jsonl",
        ledger=ledger,
        allowed_actors=frozenset({"operator-a"}),
    )

    response = restricted.handle_claude_hook(
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        actor="stranger",
        call_factory=make_execution_call_factory("pnpm"),
    )

    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


# -- ADV-A — hook path closed; interactive-terminal boundary remains -------- #


def test_absolute_path_invocation_fails_closed_but_a_path_shim_is_not_claimed() -> None:
    """The hook rejects an attacker-selected executable path.

    This layer is still not a ``PATH`` shim: a command typed into an interactive
    terminal reaches no hook at all. That residual remains ADV9's and is not
    closed by this assertion.
    """
    event = classify_command("/usr/local/bin/npm install", canonical_package_manager="pnpm")

    assert event.action == ACTION_PACKAGE_INVOKE
    assert event.decidable is False
    assert event.undecidable_reasons == ("untrusted-execution-context",)
    assert event.facts["invoked_by_absolute_path"] is True
    # The recovered manager identity is preserved so the canonical-manager
    # denial still applies to the explicit-path spelling.
    assert event.facts["manager"] == "npm"
    assert event.facts["manager_is_canonical"] is False


def test_bypass_attempts_is_only_evidence_when_the_gate_is_on_the_path(
    gateway: UniversalGateway,
) -> None:
    """An empty ``bypass_attempts()`` proves nothing on its own — a gateway
    nothing was ever routed through reports zero too. Recorded so no later reader
    mistakes emptiness for coverage."""
    assert gateway.bypass_attempts() == ()


# -- ADV-E — NOT CLOSED: audit-tail truncation ------------------------------- #


def test_truncated_audit_tail_is_invisible_without_an_external_anchor(
    gateway: UniversalGateway, tmp_path: Path
) -> None:
    factory = make_execution_call_factory("pnpm")
    for _ in range(3):
        gateway.handle_claude_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
            actor="operator-a",
            call_factory=factory,
        )

    audit = tmp_path / "audit.jsonl"
    lines = [ln for ln in audit.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3
    trusted_count = len(lines)
    trusted_last_hash = json.loads(lines[-1])["event_hash"]

    audit.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    store = ChainHashAuditStore(str(audit))

    # Internal walk alone: a prefix of a valid chain is itself a valid chain.
    assert store.verify_chain()["valid"] is True

    # External anchor: now, and only now, the truncation is visible.
    anchored = store.verify_chain(
        expected_count=trusted_count, expected_last_hash=trusted_last_hash
    )
    assert anchored["valid"] is False
    assert anchored["failures"]
