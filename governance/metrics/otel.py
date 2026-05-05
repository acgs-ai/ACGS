from __future__ import annotations

from typing import Any

from governance.models import GateResult


class GovernanceMetrics:
    """Thin optional OTel adapter.

    Metrics are intentionally low-cardinality. Keep event_id out of metric labels.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._meter = None
        self._gate_counter = None
        self._decision_counter = None
        if enabled:
            try:
                from opentelemetry import metrics
            except Exception:
                self.enabled = False
                return

            self._meter = metrics.get_meter("acgs.governance_eval")
            self._gate_counter = self._meter.create_counter("acgs_governance_gate_decisions_total")
            self._decision_counter = self._meter.create_counter("acgs_governance_decisions_total")

    @classmethod
    def disabled(cls) -> "GovernanceMetrics":
        return cls(enabled=False)

    def record_gate(self, result: GateResult) -> None:
        if not self.enabled or self._gate_counter is None:
            return
        self._gate_counter.add(
            1,
            {
                "gate": result.gate,
                "allow": str(result.allowed).lower(),
                "reason_code": result.reason_codes[0] if result.reason_codes else "UNKNOWN",
            },
        )

    def record_decision(self, event: dict[str, Any]) -> None:
        if not self.enabled or self._decision_counter is None:
            return
        self._decision_counter.add(
            1,
            {
                "allow": str(event.get("allow")).lower(),
                "tenant": str(event.get("tenant", "unknown")),
            },
        )
