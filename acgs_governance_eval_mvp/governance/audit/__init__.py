from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable

from governance.models import DecisionRecord

from .in_memory import InMemoryAuditStore
from .jsonl_chain import AuthorizationTraceIntegrityError, ChainHashAuditStore, extract_trace


@runtime_checkable
class AuditStore(Protocol):
    def append(self, decision: DecisionRecord) -> dict[str, Any]: ...

    def last_hash(self) -> str: ...

    def iter_events(self) -> Iterable[dict[str, Any]]: ...

    def query(
        self,
        *,
        event_id: str | None = None,
        rule_id: str | None = None,
        gate: str | None = None,
        allow: bool | None = None,
        risk_tag: str | None = None,
        tenant: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]: ...

    def verify_chain(self) -> dict[str, Any]: ...


__all__ = [
    "AuditStore",
    "AuthorizationTraceIntegrityError",
    "ChainHashAuditStore",
    "InMemoryAuditStore",
    "extract_trace",
]
