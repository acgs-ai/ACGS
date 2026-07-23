"""Tests for the receipt-required executor guard (execute_with_receipt, GovernedExecutor)."""

from __future__ import annotations

import dataclasses
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from threading import Event, Lock
from types import MappingProxyType
from typing import Any

import pytest

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ProductionProfileError,
    ReceiptValidationError,
    Validator,
    adapter_artifact_digest,
    execute_with_receipt,
)
from gove_zone.audit import (
    AuditCheckpoint,
    AuditCheckpointAnchor,
    ChainHashAuditStore,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionState,
    ConsumptionStateAnchor,
    ReceiptConsumptionError,
    ReceiptConsumptionStore,
)
from gove_zone.signing import Ed25519Signer

_CONSUMPTION_KEY = b"executor-guard-consumption-key-v1!!"
_SIGNER = Ed25519Signer.generate("executor-guard-test-key")
_LIFECYCLE_SIGNER = Ed25519Signer.generate("executor-lifecycle-key")


class _AuditAnchor(AuditCheckpointAnchor):
    def __init__(self) -> None:
        self.states: dict[str, AuditCheckpoint] = {}
        self._lock = Lock()

    def read(self, namespace: str) -> AuditCheckpoint | None:
        with self._lock:
            return self.states.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        with self._lock:
            if self.states.get(namespace) != expected:
                return False
            self.states[namespace] = replacement
            return True


class _ConsumptionAnchor(ConsumptionStateAnchor):
    def __init__(self) -> None:
        self.states: dict[str, AnchoredConsumptionState] = {}
        self._lock = Lock()

    def read(self, namespace: str) -> AnchoredConsumptionState | None:
        with self._lock:
            return self.states.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool:
        with self._lock:
            if self.states.get(namespace) != expected:
                return False
            self.states[namespace] = replacement
            return True


def _strict_dependencies(tmp_path: Path, prefix: str = "fixture") -> dict[str, Any]:
    audit_anchor = _AuditAnchor()
    consumption_anchor = _ConsumptionAnchor()
    audit_path = tmp_path / f"{prefix}-audit.jsonl"
    consumption_path = tmp_path / f"{prefix}-consumption.sqlite3"
    return {
        "consumption_store": ReceiptConsumptionStore(
            consumption_path,
            hmac_key=_CONSUMPTION_KEY,
            state_anchor=consumption_anchor,
            anchor_namespace=f"executor/{prefix}/consumption",
            require_trusted_anchor=True,
        ),
        "rejection_audit": ChainHashAuditStore(
            audit_path,
            checkpoint_anchor=audit_anchor,
            checkpoint_namespace=f"executor/{prefix}/audit",
            checkpoint_signer=_SIGNER,
            checkpoint_verifier={_SIGNER.key_id: _SIGNER},
            require_trusted_checkpoint=True,
        ),
        "verifier": _SIGNER,
        "lifecycle_signer": _LIFECYCLE_SIGNER,
        "lifecycle_authority_id": "lifecycle-validator",
    }


@pytest.fixture
def replay_dependencies(tmp_path: Path) -> dict[str, Any]:
    return _strict_dependencies(tmp_path)


def _assert_last_denial(dependencies: dict[str, Any], reason_code: str) -> None:
    events = list(dependencies["rejection_audit"].iter_events())
    assert events[-1]["decision"] == Decision.DENY.value
    assert events[-1]["matched_rules"] == [reason_code]


class SideEffectTracker:
    def __init__(self) -> None:
        self.called = False
        self.called_with: dict[str, Any] | None = None

    def run_tool(self, **kwargs: Any) -> str:
        self.called = True
        self.called_with = kwargs
        return "success"


_DEFAULT_ALLOW_ARGS: dict[str, Any] = {"path": "safe.txt"}


def make_test_receipt(
    decision: str = "allow",
    transformations: list[dict[str, Any]] | None = None,
    tenant_id: str = "tenant-A",
    execution_boundary: str = "local-sandbox",
    action: str = "runtime.file.write",
    args: dict[str, Any] | None = None,
    constraints: dict[str, Any] | None = None,
) -> DecisionReceipt:
    from gove_zone.decision import sha256_json

    effective_args = args if args is not None else _DEFAULT_ALLOW_ARGS
    record = DecisionRecord(
        decision=Decision(decision),
        tool=action,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_abc",
        transformed_args={"path": "transformed.txt"} if decision == "transform" else None,
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
        constraints=constraints,
        signer=_SIGNER,
    )
    if transformations is not None:
        import dataclasses

        receipt = dataclasses.replace(receipt, transformations=transformations)
        h = receipt.compute_hash()
        receipt = dataclasses.replace(receipt, receipt_hash=h)
    return receipt


def test_executor_refuses_no_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "No receipt provided" in str(exc_info.value)
    assert not tracker.called
    _assert_last_denial(replay_dependencies, "receipt.execution.receipt_required")


def test_executor_audits_missing_actor(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    with pytest.raises(ReceiptValidationError, match="receipt.execution.actor_required"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=make_test_receipt(),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="",
            require_signature=True,
            **replay_dependencies,
        )
    assert not tracker.called
    _assert_last_denial(replay_dependencies, "receipt.execution.actor_required")


def test_executor_refuses_malformed_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Make it malformed by clearing receipt_id
    receipt = dataclasses.replace(receipt, receipt_id="")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "Missing or empty required field" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_tampered_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Tamper with tenant_id without recomputing receipt_hash
    receipt = dataclasses.replace(receipt, tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "receipt_hash mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_denied_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("deny")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "Denied receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_escalated_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("escalate")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "Escalated receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_wrong_tenant(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt(tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "Tenant mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_transform_mismatch(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args has path="transformed.txt"

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            # Pass original untransformed arg
            args={"path": "original.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=True,  # explicit dev mode: this case tests non-signing behavior
            **replay_dependencies,
        )
    assert "Transform mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_allows_valid_allowed_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("allow")

    res = execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
        tool_fn=tracker.run_tool,
        args={"path": "safe.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        require_signature=True,  # explicit dev mode: this case tests non-signing behavior
        **replay_dependencies,
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "safe.txt"}


def test_executor_allows_valid_transformed_receipt(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args must have path="transformed.txt"

    res = execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
        tool_fn=tracker.run_tool,
        args={"path": "transformed.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        require_signature=True,  # explicit dev mode: this case tests non-signing behavior
        **replay_dependencies,
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "transformed.txt"}


def test_governed_executor_workflow(replay_dependencies: dict[str, Any]) -> None:
    tracker = SideEffectTracker()
    # Explicit dev mode: this case exercises the registry/execute plumbing with an
    # unsigned receipt, not the production-signed default.
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=True,
        **replay_dependencies,
    )
    executor.register("runtime.file.write", tracker.run_tool)

    receipt = make_test_receipt("allow", args={"path": "test.txt"})
    res = executor.execute("runtime.file.write", {"path": "test.txt"}, receipt)
    assert res == "success"
    assert tracker.called


def test_executor_production_default_rejects_unsigned_no_verifier(
    replay_dependencies: dict[str, Any],
) -> None:
    """DEFAULT-FLIP PROOF: with no require_signature argument, the gate runs in the
    production profile (require_signature=True). An unsigned receipt with no verifier
    configured fails closed LOUD, naming the dev opt-out, and the side effect never runs.
    """
    from gove_zone import ProductionProfileError

    tracker = SideEffectTracker()
    receipt = make_test_receipt("allow")
    dependencies = dict(replay_dependencies)
    dependencies.pop("verifier")
    with pytest.raises(ProductionProfileError) as exc_info:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            # NOTE: no require_signature, no verifier — production profile is the default.
            **dependencies,
        )
    assert "production profile requires a signer/verifier" in str(exc_info.value)
    assert "GovernanceProfile.dev()" in str(exc_info.value)
    assert not tracker.called
    _assert_last_denial(replay_dependencies, "receipt.execution.verifier_required")


def test_governed_executor_production_default_rejects_unsigned(
    replay_dependencies: dict[str, Any],
) -> None:
    """DEFAULT-FLIP PROOF for GovernedExecutor: constructed with no require_signature,
    it defaults to the production profile and fails closed loud on an unsigned receipt
    with no verifier.
    """
    tracker = SideEffectTracker()
    dependencies = dict(replay_dependencies)
    dependencies.pop("verifier")
    with pytest.raises(ValueError, match="trusted verifier"):
        GovernedExecutor(
            tenant_id="tenant-A",
            execution_boundary="local-sandbox",
            expected_actor="anonymous",
            **dependencies,
        )
    assert not tracker.called


def test_first_use_succeeds_and_second_use_is_audited_rejection(
    replay_dependencies: dict[str, Any],
) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    kwargs = {
        "tool_fn": tracker.run_tool,
        "args": {"path": "safe.txt"},
        "receipt": receipt,
        "expected_tenant_id": "tenant-A",
        "expected_execution_boundary": "local-sandbox",
        "expected_action": "runtime.file.write",
        "expected_actor": "anonymous",
        "require_signature": True,
        **replay_dependencies,
    }
    assert (
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((kwargs)["tool_fn"]), **kwargs
        )
        == "success"
    )
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((kwargs)["tool_fn"]), **kwargs
        )
    assert tracker.called
    events = list(replay_dependencies["rejection_audit"].iter_events())
    assert events[-1]["decision"] == Decision.DENY.value
    assert "receipt.execution.replay" in events[-1]["matched_rules"]


def test_concurrent_replay_allows_exactly_one(
    replay_dependencies: dict[str, Any],
) -> None:
    receipt = make_test_receipt()
    calls = 0

    def tool(**_kwargs: Any) -> str:
        nonlocal calls
        calls += 1
        return "ok"

    def attempt(_index: int) -> str:
        try:
            return execute_with_receipt(
                tool,
                {"path": "safe.txt"},
                receipt,
                expected_adapter_artifact_digest=adapter_artifact_digest(tool),
                expected_tenant_id="tenant-A",
                expected_execution_boundary="local-sandbox",
                expected_action="runtime.file.write",
                expected_actor="anonymous",
                require_signature=True,
                **replay_dependencies,
            )
        except ReceiptValidationError as exc:
            return str(exc).split(":", 1)[0]

    with ThreadPoolExecutor(max_workers=32) as pool:
        outcomes = list(pool.map(attempt, range(32)))
    assert outcomes.count("ok") == 1
    assert outcomes.count("receipt.execution.replay") == 31
    assert calls == 1


def test_restart_and_reissued_request_id_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restart.sqlite3"
    consumption_anchor = _ConsumptionAnchor()
    audit_anchor = _AuditAnchor()
    first_store = ReceiptConsumptionStore(
        path,
        hmac_key=_CONSUMPTION_KEY,
        state_anchor=consumption_anchor,
        anchor_namespace="executor/restart/consumption",
        require_trusted_anchor=True,
    )
    audit = ChainHashAuditStore(
        tmp_path / "restart-audit.jsonl",
        checkpoint_anchor=audit_anchor,
        checkpoint_namespace="executor/restart/audit",
        checkpoint_signer=_SIGNER,
        checkpoint_verifier={_SIGNER.key_id: _SIGNER},
        require_trusted_checkpoint=True,
    )
    receipt = make_test_receipt()
    common = {
        "tool_fn": lambda **_kwargs: "ok",
        "args": {"path": "safe.txt"},
        "expected_tenant_id": "tenant-A",
        "expected_execution_boundary": "local-sandbox",
        "expected_action": "runtime.file.write",
        "expected_actor": "anonymous",
        "require_signature": True,
        "verifier": _SIGNER,
        "lifecycle_signer": _LIFECYCLE_SIGNER,
        "lifecycle_authority_id": "lifecycle-validator",
        "rejection_audit": audit,
    }
    assert (
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            receipt=receipt,
            consumption_store=first_store,
            **common,
        )
        == "ok"
    )
    restarted = ReceiptConsumptionStore(
        path,
        hmac_key=_CONSUMPTION_KEY,
        state_anchor=consumption_anchor,
        anchor_namespace="executor/restart/consumption",
        require_trusted_anchor=True,
    )
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            receipt=receipt,
            consumption_store=restarted,
            **common,
        )

    reissued = dataclasses.replace(receipt, receipt_id="ev_reissued", receipt_hash="")
    reissued = dataclasses.replace(reissued, receipt_hash=reissued.compute_hash())
    reissued = dataclasses.replace(
        reissued,
        signature=_SIGNER.sign(reissued.receipt_hash.encode("utf-8")),
    )
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            receipt=reissued,
            consumption_store=restarted,
            **common,
        )


def test_adapter_exception_marks_unknown_and_retry_is_denied(
    replay_dependencies: dict[str, Any],
) -> None:
    calls = 0
    receipt = make_test_receipt()

    def ambiguous(**_kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        raise TimeoutError("ambiguous fixture timeout")

    common = {
        "tool_fn": ambiguous,
        "args": {"path": "safe.txt"},
        "receipt": receipt,
        "expected_tenant_id": "tenant-A",
        "expected_execution_boundary": "local-sandbox",
        "expected_action": "runtime.file.write",
        "expected_actor": "anonymous",
        "require_signature": True,
        **replay_dependencies,
    }
    with pytest.raises(ReceiptValidationError, match="receipt.execution.outcome_unknown"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]), **common
        )
    status = replay_dependencies["consumption_store"].status("tenant-A", receipt.receipt_id)
    assert status is not None and status.state is ConsumptionState.UNKNOWN
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]), **common
        )
    assert calls == 1


def test_missing_tampered_and_revoked_dependencies_never_call_tool(
    tmp_path: Path,
) -> None:
    calls = 0
    receipt = make_test_receipt()

    def tool(**_kwargs: Any) -> str:
        nonlocal calls
        calls += 1
        return "bad"

    common = {
        "tool_fn": tool,
        "args": {"path": "safe.txt"},
        "receipt": receipt,
        "expected_tenant_id": "tenant-A",
        "expected_execution_boundary": "local-sandbox",
        "expected_action": "runtime.file.write",
        "expected_actor": "anonymous",
        "require_signature": True,
        "verifier": _SIGNER,
        "lifecycle_signer": _LIFECYCLE_SIGNER,
        "lifecycle_authority_id": "lifecycle-validator",
    }
    dependencies = _strict_dependencies(tmp_path, "dependency")
    audit = dependencies["rejection_audit"]
    with pytest.raises(ReceiptValidationError, match="consumption_store_required"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            rejection_audit=audit,
            **common,
        )
    with pytest.raises(ReceiptValidationError, match="audit_required"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]), **common
        )

    store = ReceiptConsumptionStore(tmp_path / "unanchored.sqlite3", hmac_key=_CONSUMPTION_KEY)
    with pytest.raises(ReceiptValidationError, match="consumption_store_failed"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            consumption_store=store,
            rejection_audit=audit,
            **common,
        )
    dependency_denial = list(audit.iter_events())[-1]
    assert dependency_denial["decision"] == Decision.DENY.value
    assert dependency_denial["matched_rules"] == ["receipt.execution.consumption_store_failed"]
    evidence = dependency_denial["execution_evidence"]
    assert evidence["phase"] == "dependency_validation"
    assert evidence["consumption_state"] == "UNAVAILABLE"
    assert "tenant-A" not in str(evidence)

    revoked_dependencies = _strict_dependencies(tmp_path, "revoked")
    revoked = revoked_dependencies["consumption_store"]
    revoked.revoke("tenant-A", receipt.receipt_id)
    with pytest.raises(ReceiptValidationError, match="receipt.execution.revoked"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            consumption_store=revoked,
            rejection_audit=revoked_dependencies["rejection_audit"],
            **common,
        )

    bad_audit = ChainHashAuditStore(tmp_path / "bad-audit.jsonl")
    clean = dependencies["consumption_store"]
    with pytest.raises(ReceiptValidationError, match="audit_failed"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]),
            consumption_store=clean,
            rejection_audit=bad_audit,
            **common,
        )
    assert calls == 0


def test_standalone_rejects_signature_opt_out_before_adapter(
    replay_dependencies: dict[str, Any],
) -> None:
    tracker = SideEffectTracker()
    dependencies = dict(replay_dependencies)
    dependencies.pop("verifier")
    with pytest.raises(ProductionProfileError, match="requires signatures"):
        execute_with_receipt(
            tracker.run_tool,
            {"path": "safe.txt"},
            make_test_receipt(),
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            verifier=_SIGNER,
            require_signature=False,
            consumption_store=dependencies["consumption_store"],
            rejection_audit=dependencies["rejection_audit"],
        )
    assert tracker.called is False


def test_reserve_then_claim_audit_failure_is_zero_call_and_non_retryable(
    replay_dependencies: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    audit = replay_dependencies["rejection_audit"]
    original_append = audit.append_committed

    def fail_claim(record: DecisionRecord) -> Any:
        if record.reason == "receipt.execution.reserved":
            raise RuntimeError("injected claim append failure")
        return original_append(record)

    monkeypatch.setattr(audit, "append_committed", fail_claim)
    common = {
        "tool_fn": tracker.run_tool,
        "args": {"path": "safe.txt"},
        "receipt": receipt,
        "expected_tenant_id": "tenant-A",
        "expected_execution_boundary": "local-sandbox",
        "expected_action": "runtime.file.write",
        "expected_actor": "anonymous",
        "require_signature": True,
        **replay_dependencies,
    }
    with pytest.raises(ReceiptValidationError, match="audit_failed"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]), **common
        )
    assert tracker.called is False
    status = replay_dependencies["consumption_store"].status("tenant-A", receipt.receipt_id)
    assert status is not None and status.state is ConsumptionState.UNKNOWN
    with pytest.raises(ReceiptValidationError, match="receipt.execution.replay"):
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((common)["tool_fn"]), **common
        )


def test_mark_succeeded_fail_before_commit_persists_unknown_and_audits(
    replay_dependencies: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    store = replay_dependencies["consumption_store"]

    def fail_before(*_args: Any, **_kwargs: Any) -> Any:
        raise ReceiptConsumptionError("injected pre-commit failure")

    monkeypatch.setattr(store, "mark_succeeded", fail_before)
    with pytest.raises(ReceiptValidationError, match="outcome_unknown"):
        execute_with_receipt(
            tracker.run_tool,
            {"path": "safe.txt"},
            receipt,
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            **replay_dependencies,
        )
    status = store.status("tenant-A", receipt.receipt_id)
    assert tracker.called is True
    assert status is not None and status.state is ConsumptionState.UNKNOWN
    events = list(replay_dependencies["rejection_audit"].iter_events())
    assert events[-1]["execution_evidence"]["consumption_state"] == "UNKNOWN"


def test_mark_succeeded_fail_after_commit_preserves_truthful_success(
    replay_dependencies: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    store = replay_dependencies["consumption_store"]
    original_mark = store.mark_succeeded

    def commit_then_fail(*args: Any, **kwargs: Any) -> Any:
        original_mark(*args, **kwargs)
        raise ReceiptConsumptionError("injected post-commit failure")

    monkeypatch.setattr(store, "mark_succeeded", commit_then_fail)
    assert (
        execute_with_receipt(
            tracker.run_tool,
            {"path": "safe.txt"},
            receipt,
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            **replay_dependencies,
        )
        == "success"
    )
    status = store.status("tenant-A", receipt.receipt_id)
    assert status is not None and status.state is ConsumptionState.SUCCEEDED


def test_execution_audit_is_hash_only_and_tamper_evident(
    replay_dependencies: dict[str, Any],
) -> None:
    receipt = make_test_receipt()

    def adapter(**_kwargs: object) -> str:
        return "ok"

    assert (
        execute_with_receipt(
            adapter,
            {"path": "safe.txt"},
            receipt,
            expected_adapter_artifact_digest=adapter_artifact_digest(adapter),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            **replay_dependencies,
        )
        == "ok"
    )
    audit = replay_dependencies["rejection_audit"]
    events = list(audit.iter_events())
    claim = events[-2]["execution_evidence"]
    assert claim["phase"] == "claim_committed"
    assert claim["consumption_state"] == "RESERVED"
    assert claim["argument_hash"] == receipt.argument_hash
    rendered = str(claim)
    assert "tenant-A" not in rendered
    assert "req-123" not in rendered
    assert not any(value.startswith("attempt_") for value in claim.values())
    audit.path.write_text("{}\n", encoding="utf-8")
    assert audit.verify_checkpointed_chain()["valid"] is False


def test_governed_executor_registry_and_trust_roots_are_frozen(
    replay_dependencies: dict[str, Any],
) -> None:
    tracker = SideEffectTracker()
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        **replay_dependencies,
    )
    executor.register("runtime.file.write", tracker.run_tool)
    assert not hasattr(executor, "__dict__")
    with pytest.raises(AttributeError, match="immutable"):
        executor._sealed = False  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        executor._tenant_id = "tenant-B"  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        executor._GovernedExecutor__registry = MappingProxyType({})  # type: ignore[attr-defined]

    registry = executor._GovernedExecutor__registry  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        registry["runtime.file.write"] = registry["runtime.file.write"]  # type: ignore[index]
    with pytest.raises(AttributeError):
        registry["runtime.file.write"].adapter = lambda **_: "swapped"

    with pytest.raises(ValueError, match="already registered"):
        executor.register("runtime.file.write", lambda **_kwargs: None)
    executor.register("runtime.file.other", tracker.run_tool)
    assert not hasattr(executor, "registry")
    with pytest.raises(AttributeError, match="immutable"):
        executor._consumption_store = object()  # type: ignore[assignment]
    with pytest.raises(ReceiptValidationError, match="cannot override"):
        executor.execute(
            "runtime.file.write",
            {"path": "safe.txt"},
            make_test_receipt(),
            require_signature=False,
        )
    assert tracker.called is False

    assert (
        executor.execute(
            "runtime.file.write",
            {"path": "safe.txt"},
            make_test_receipt(),
        )
        == "success"
    )
    assert tracker.called is True
    assert tracker.called_with == {"path": "safe.txt"}
    execution_claim = list(replay_dependencies["rejection_audit"].iter_events())[-2]
    adapter_digest = execution_claim["execution_evidence"]["adapter_artifact_digest"]
    assert len(adapter_digest) == 64
    assert adapter_digest == adapter_digest.lower()
    assert all(character in "0123456789abcdef" for character in adapter_digest)

    with pytest.raises(RuntimeError, match="frozen"):
        executor.register("runtime.file.other", lambda **_kwargs: None)


def test_governed_executor_adapter_digest_distinguishes_code_and_hides_partial_values(
    replay_dependencies: dict[str, Any],
) -> None:
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        **replay_dependencies,
    )

    def first_adapter(**_kwargs: object) -> str:
        return "first"

    def second_adapter(**_kwargs: object) -> str:
        return "second"

    executor.register_tool("runtime.first", first_adapter)
    executor.register_tool("runtime.second", second_adapter)

    registry = executor._GovernedExecutor__registry  # type: ignore[attr-defined]
    first_digest = registry["runtime.first"].adapter_artifact_digest
    second_digest = registry["runtime.second"].adapter_artifact_digest
    assert first_digest != second_digest

    secret = "fixture-secret-must-not-appear"
    with pytest.raises(ValueError) as error:
        executor.register_tool("runtime.partial", partial(first_adapter, marker=secret))
    assert secret not in str(error.value)

    # Deliberate object.__setattr__, ctypes/debugger mutation, and mutable callable
    # globals/private object state remain outside the trusted Python-process boundary.


def test_direct_executor_uses_private_nested_argument_and_constraint_snapshots(
    replay_dependencies: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = SideEffectTracker()
    arguments = {"payload": {"path": "safe.txt"}}
    constraints = {"scope": {"environment": "production"}}
    receipt = make_test_receipt(
        args=arguments,
        constraints={"scope": {"environment": "production"}},
    )
    original_verify = DecisionReceipt.verify
    snapshot_verified = Event()
    mutation_complete = Event()

    def wait_for_concurrent_mutation_then_verify(self, *args, **kwargs):
        snapshot_verified.set()
        assert mutation_complete.wait(timeout=5)
        return original_verify(self, *args, **kwargs)

    def mutate_caller_owned_objects() -> None:
        assert snapshot_verified.wait(timeout=5)
        arguments["payload"]["path"] = "tampered.txt"
        constraints["scope"]["environment"] = "staging"
        mutation_complete.set()

    monkeypatch.setattr(
        DecisionReceipt,
        "verify",
        wait_for_concurrent_mutation_then_verify,
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        mutation = pool.submit(mutate_caller_owned_objects)
        result = execute_with_receipt(
            tool_fn=tracker.run_tool,
            args=arguments,
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            expected_constraints=constraints,
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            **replay_dependencies,
        )
        mutation.result(timeout=5)

    assert result == "success"
    assert tracker.called_with == {"payload": {"path": "safe.txt"}}
    assert arguments == {"payload": {"path": "tampered.txt"}}
    assert constraints == {"scope": {"environment": "staging"}}


@pytest.mark.parametrize(
    ("expected_digest", "reason_code"),
    [
        (None, "receipt.execution.adapter_artifact_required"),
        ("0" * 64, "receipt.execution.adapter_artifact_mismatch"),
    ],
)
def test_direct_executor_denies_missing_or_wrong_adapter_digest_before_call(
    tmp_path: Path,
    expected_digest: str | None,
    reason_code: str,
) -> None:
    dependencies = _strict_dependencies(tmp_path, reason_code.rsplit(".", 1)[-1])
    tracker = SideEffectTracker()

    with pytest.raises(ReceiptValidationError, match=reason_code):
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=make_test_receipt(),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            expected_adapter_artifact_digest=expected_digest,
            **dependencies,
        )

    assert tracker.called is False
    _assert_last_denial(dependencies, reason_code)


def test_direct_executor_denies_callable_swap_before_reservation(
    replay_dependencies: dict[str, Any],
) -> None:
    expected = SideEffectTracker()
    swapped_calls: list[dict[str, Any]] = []

    def swapped_tool(**kwargs: Any) -> str:
        swapped_calls.append(kwargs)
        return "swapped"

    with pytest.raises(
        ReceiptValidationError,
        match="receipt.execution.adapter_artifact_mismatch",
    ):
        execute_with_receipt(
            tool_fn=swapped_tool,
            args={"path": "safe.txt"},
            receipt=make_test_receipt(),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            expected_adapter_artifact_digest=adapter_artifact_digest(expected.run_tool),
            **replay_dependencies,
        )

    assert expected.called is False
    assert swapped_calls == []
    assert replay_dependencies["consumption_store"].status("tenant-A", "ev_abc") is None


def test_direct_executor_audits_non_json_nested_arguments_before_call(
    replay_dependencies: dict[str, Any],
) -> None:
    tracker = SideEffectTracker()

    with pytest.raises(
        ReceiptValidationError,
        match="receipt.execution.argument_snapshot_invalid",
    ):
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"nested": {"unsupported": object()}},
            receipt=make_test_receipt(),
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            expected_adapter_artifact_digest=adapter_artifact_digest(tracker.run_tool),
            **replay_dependencies,
        )

    assert tracker.called is False
    _assert_last_denial(
        replay_dependencies,
        "receipt.execution.argument_snapshot_invalid",
    )
