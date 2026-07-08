"""The governance membrane: control-plane mutations dispatch through gove-zone.

Core invariant, made literal for the platform itself:

    **No valid Decision Receipt, no side effect.**

Every mutating control-plane operation (register agent, publish policy,
activate policy, create user, generate export, ...) is registered as a kernel
tool and executed via :meth:`gove_zone.Kernel.dispatch` under the
organization's *active* policy bundle. The receipt — ALLOW, DENY, or
ESCALATE — is persisted in the same transaction as the side effect. A DENY
or ESCALATE rolls the transaction back, persists only the receipt, and maps
to HTTP 403 / 202.

The org's audit chain is a per-org ``ChainHashAuditStore`` file; its tip
(count + last hash) is anchored in the ``organizations`` row on every
dispatch so file-level truncation is detectable from the database.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    DeniedError,
    EscalateError,
    Kernel,
    Receipt,
)
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.tool import ToolCall, normalize_path_context
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.auth import Principal
from acgs_control_plane.models import Organization, PolicyBundle, ReceiptRow

BASELINE_POLICY_ID = "acp-baseline/v1"


def baseline_policy() -> RuleSetPolicy:
    """Default governance when an org has no active bundle yet.

    ``RuleSetPolicy`` is allow-by-default (rules can only deny/escalate), so
    the baseline ships one protective rule instead of a no-op: destructive
    org-level operations escalate until an explicit policy says otherwise.
    """
    return RuleSetPolicy(
        policy_id=BASELINE_POLICY_ID,
        rules=(
            PolicyRule(
                rule_id="baseline-escalate-org-destructive",
                effect=Decision.ESCALATE,
                tools=frozenset({"org.delete", "org.purge"}),
                reason="destructive org operations require explicit policy + approval",
            ),
        ),
    )


def load_active_policy(session: Session, org_id: str) -> Policy:
    row = session.execute(
        select(PolicyBundle).where(PolicyBundle.org_id == org_id, PolicyBundle.status == "active")
    ).scalar_one_or_none()
    if row is None:
        return baseline_policy()
    return RuleSetPolicy.from_dict(row.bundle)


def org_audit_store(audit_dir: Path, org_id: str) -> ChainHashAuditStore:
    audit_dir.mkdir(parents=True, exist_ok=True)
    return ChainHashAuditStore(audit_dir / f"{org_id}.audit.jsonl")


def chain_tip(store: ChainHashAuditStore) -> tuple[int, str]:
    """Single pass over the chain file: (event_count, last_event_hash)."""
    count = 0
    last = ""
    for event in store.iter_events():
        count += 1
        last = str(event.get("event_hash", ""))
    return count, last


@dataclass(frozen=True)
class GovernedOutcome:
    """What a governed mutation produced: a result (ALLOW only) + receipt row."""

    result: Any
    receipt: ReceiptRow
    decision: str


class PolicyDeniedError(Exception):
    """Mutation denied by the org's policy bundle. Receipt row is committed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


class PolicyEscalatedError(Exception):
    """Mutation requires approval. Receipt row is committed; nothing executed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


def _receipt_row_from_payload(org_id: str, payload: dict[str, Any]) -> ReceiptRow:
    return ReceiptRow(
        id=str(payload["event_id"]),
        org_id=org_id,
        tool=str(payload["tool"]),
        decision=str(payload["decision"]),
        actor=str(payload.get("actor", "")),
        goal=str(payload.get("goal", "")),
        argument_hash=str(payload.get("argument_hash", "")),
        audit_hash=str(payload.get("audit_hash", "")),
        policy_version=str(payload.get("policy_version", "")),
        result_hash=payload.get("result_hash"),
        error_class=payload.get("error_class"),
        payload=payload,
    )


def _blocked_payload(record: DecisionRecord, audit_hash: str) -> dict[str, Any]:
    return {
        **record.to_dict(),
        "audit_hash": audit_hash,
        "actor": record.actor,
        "result_hash": None,
        "error_class": None,
    }


def _anchor(session: Session, org_id: str, store: ChainHashAuditStore) -> None:
    count, last = chain_tip(store)
    org = session.get(Organization, org_id)
    if org is not None:
        org.audit_anchor_count = count
        org.audit_anchor_hash = last


class GovernanceMembrane:
    """Per-request bridge between one org's HTTP mutations and its kernel."""

    def __init__(
        self,
        session: Session,
        audit_dir: Path,
        org_id: str,
        principal: Principal,
    ) -> None:
        self.session = session
        self.org_id = org_id
        self.principal = principal
        self.store = org_audit_store(audit_dir, org_id)
        self.kernel = Kernel(
            policy=load_active_policy(session, org_id),
            audit=self.store,
            actor=principal.actor_id,
        )

    def run(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        fn: Callable[..., Any],
        *,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
    ) -> GovernedOutcome:
        """Dispatch ``fn`` as governed tool ``tool_name``; commit receipt + effect atomically.

        On ALLOW: side effect + receipt row + audit anchor commit together.
        On DENY/ESCALATE: session is rolled back first, then ONLY the receipt
        row + anchor are committed, and a typed error is raised for the HTTP
        layer to map (403 / 202).
        """
        self.kernel.registry.register(tool_name, fn)
        call_state = {"principal_role": self.principal.role.value, **dict(state or {})}
        try:
            result, receipt = self.kernel.dispatch(
                tool_name,
                dict(args),
                goal=goal,
                path=list(path),
                state=call_state,
            )
        except DeniedError as exc:
            self.session.rollback()
            row = _receipt_row_from_payload(
                self.org_id, _blocked_payload(exc.record, exc.audit_hash)
            )
            self.session.add(row)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
            raise PolicyDeniedError(row, exc.record.reason) from exc
        except EscalateError as exc:
            self.session.rollback()
            row = _receipt_row_from_payload(
                self.org_id, _blocked_payload(exc.record, exc.audit_hash)
            )
            self.session.add(row)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
            raise PolicyEscalatedError(row, exc.record.reason) from exc
        except Exception:
            # Tool execution failed after ALLOW: the kernel already appended a
            # failure event to the audit chain. No partial side effect may
            # survive.
            self.session.rollback()
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
            raise

        row = self._persist_allowed(receipt)
        return GovernedOutcome(result=result, receipt=row, decision=row.decision)

    def _persist_allowed(self, receipt: Receipt) -> ReceiptRow:
        row = _receipt_row_from_payload(self.org_id, receipt.to_dict())
        self.session.add(row)
        _anchor(self.session, self.org_id, self.store)
        self.session.commit()
        return row

    def simulate_decision(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        actor: str,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
    ) -> DecisionRecord:
        """Pure policy preview: evaluate without executing or auditing."""
        call = ToolCall(
            name=tool_name,
            args=dict(args),
            goal=goal,
            actor=actor,
            path=normalize_path_context(list(path)),
            state=dict(state or {}),
        )
        return self.kernel.policy.evaluate(call)
