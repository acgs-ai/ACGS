"""Backend-neutral contracts for normalized process-event storage.

The local :class:`EventStore` remains the default implementation. This slice
exports only the event-store protocol used by ``ProcessIntelligenceService``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEvent
from agent_bus_analyzer.process_mining.storage.event_store import (
    AppendResult,
    ChainVerificationResult,
)


@runtime_checkable
class ProcessEventStore(Protocol):
    """Tenant-explicit, append-only normalized event-store contract."""

    def append(self, event: ProcessEvent) -> AppendResult: ...

    def verify_chain(self, tenant_id: str) -> ChainVerificationResult: ...

    def query_by_case(self, *, tenant_id: str, case_id: str) -> tuple[ProcessEvent, ...]: ...

    def list_events(self, *, tenant_id: str) -> tuple[ProcessEvent, ...]: ...

    def query_by_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> tuple[ProcessEvent, ...]: ...

    def get_event(self, *, tenant_id: str, event_id: str) -> ProcessEvent | None: ...
