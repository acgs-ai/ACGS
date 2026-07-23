"""Shared fixtures for the adversary suite (Pack II artifact B2).

These mirror the canonical governed-run idiom from
``packages/gove-zone/tests/test_receipt_signing.py`` (``_issue`` / ``_run_gate``)
so every adversary test exercises the REAL gate — ``execute_with_receipt`` —
rather than a re-implemented or mocked kernel. A test that passes for the wrong
reason (import error, mocked gate, vacuous assertion) is a BLOCKER, so a
positive control (``test_fixtures_baseline.py``) proves the fixtures produce a
genuinely valid governed run before any "attack succeeds" assertion is trusted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from gove_zone.executor import adapter_artifact_digest

# The adversary gaps here concern the receipt gate; the signing machinery needs
# `cryptography`. Skip cleanly where the optional extra is absent (same pattern
# as the rest of the security suite) so this dir never hard-fails collection.
pytest.importorskip("cryptography")

from gove_zone import (  # noqa: E402  (after importorskip by design)
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Validator,
    execute_with_receipt,
)
from gove_zone.audit import (  # noqa: E402
    AuditCheckpoint,
    AuditCheckpointAnchor,
    ChainHashAuditStore,
)
from gove_zone.consumption import (  # noqa: E402
    AnchoredConsumptionState,
    ConsumptionStateAnchor,
    ReceiptConsumptionStore,
)
from gove_zone.decision import sha256_json  # noqa: E402
from gove_zone.signing import Ed25519Signer  # noqa: E402

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}
_SIGNER = Ed25519Signer.generate("standalone-adversary-key")
_LIFECYCLE_SIGNER = Ed25519Signer.generate("standalone-adversary-lifecycle-key")


@dataclass(frozen=True)
class StrictGateDependencies:
    """Per-scenario durable dependencies required by the standalone final gate."""

    signer: Ed25519Signer
    consumption_store: ReceiptConsumptionStore
    rejection_audit: ChainHashAuditStore


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


def strict_gate_dependencies(root: Path) -> StrictGateDependencies:
    """Build one isolated strict dependency set, reusable across replay attempts."""
    return StrictGateDependencies(
        signer=_SIGNER,
        consumption_store=ReceiptConsumptionStore(
            root / "standalone-consumption.sqlite3",
            hmac_key=b"standalone-adversary-consumption-key-v1",
            state_anchor=_ConsumptionAnchor(),
            anchor_namespace="adversary/standalone/consumption",
            require_trusted_anchor=True,
        ),
        rejection_audit=ChainHashAuditStore(
            root / "standalone-rejections.jsonl",
            checkpoint_anchor=_AuditAnchor(),
            checkpoint_namespace="adversary/standalone/audit",
            checkpoint_signer=_SIGNER,
            checkpoint_verifier={_SIGNER.key_id: _SIGNER},
            require_trusted_checkpoint=True,
        ),
    )


class SideEffect:
    """A guarded side effect that records whether — and how often — it ran."""

    def __init__(self) -> None:
        self.ran = False
        self.run_count = 0
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.run_count += 1
        self.args = kwargs
        return "SIDE EFFECT EXECUTED"


def _issue_allow_receipt(
    signer: Any | None = None,
    *,
    actor: str = "agent-1",
    validator_id: str = "constitutional-council",
    policy_version: str = "v2-current",
    policy_hash: str = "policy/v2-current",
    args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    """Mint an ALLOW receipt, optionally signed, via the real receipt schema."""
    effective_args = args if args is not None else ARGS
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(effective_args),
        policy_version=policy_version,
        event_id="ev_adversary",
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash=policy_hash,
        request_id="req-123",
        validator=Validator(validator_id),
        authority="tenant-A/write-grant",
        signer=signer,
    )


def _run_gate(
    receipt: DecisionReceipt | None,
    side_effect: SideEffect,
    *,
    verifier: Any = None,
    require_signature: bool = False,
    args: dict[str, Any] | None = None,
    expected_tenant_id: str = TENANT,
    expected_execution_boundary: str = BOUNDARY,
    expected_action: str = ACTION,
    expected_actor: str = "agent-1",
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    expected_policy_version: str | None = None,
    expected_validator_id: str | None = None,
    expected_validator_role: str | None = None,
    expected_authority: str | None = None,
    consumption_store: ReceiptConsumptionStore,
    rejection_audit: ChainHashAuditStore,
) -> Any:
    """Run a receipt through the real gate. Dev posture by default
    (unsigned + require_signature=False), matching the security suite."""
    return execute_with_receipt(
        expected_adapter_artifact_digest=adapter_artifact_digest(side_effect.run),
        tool_fn=side_effect.run,
        args=args if args is not None else ARGS,
        receipt=receipt,
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
        expected_policy_version=expected_policy_version,
        expected_validator_id=expected_validator_id,
        expected_validator_role=expected_validator_role,
        expected_authority=expected_authority,
        lifecycle_signer=_LIFECYCLE_SIGNER,
        lifecycle_authority_id="adversary-lifecycle-validator",
        verifier=verifier,
        require_signature=require_signature,
        consumption_store=consumption_store,
        rejection_audit=rejection_audit,
    )


@pytest.fixture
def side_effect() -> SideEffect:
    return SideEffect()


@pytest.fixture
def issue() -> Callable[..., DecisionReceipt]:
    """Factory that mints an ALLOW receipt (see ``_issue_allow_receipt``)."""
    return _issue_allow_receipt


@pytest.fixture
def run_gate(tmp_path: Any) -> Callable[..., Any]:
    """The real governed gate (see ``_run_gate``)."""
    dependencies = strict_gate_dependencies(Path(tmp_path))

    def run(*args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("verifier", dependencies.signer)
        kwargs.setdefault("require_signature", True)
        return _run_gate(
            *args,
            **kwargs,
            consumption_store=dependencies.consumption_store,
            rejection_audit=dependencies.rejection_audit,
        )

    return run
