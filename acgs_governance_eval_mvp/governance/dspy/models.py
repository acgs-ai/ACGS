from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from governance.models import sha256_json, utc_now_iso

Verdict = Literal["supported", "partial", "invalidated", "undecidable"]
ProgramStatus = Literal["draft", "active", "retired"]


@dataclass(frozen=True)
class DSPyProgramRecord:
    program_id: str
    version: str
    signature_hash: str
    weights_hash: str
    maci_role: str
    status: ProgramStatus = "draft"
    eval_report_hash: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DSPyInvocationEvidence:
    program_id: str
    program_version: str
    inputs_hash: str
    outputs_hash: str
    referenced_audit_event_ids: list[str]
    latency_ms: float
    engine: str
    engine_error_msg: str | None = None

    def __post_init__(self) -> None:
        if self.outputs_hash == sha256_json({}) and self.engine_error_msg is None:
            raise ValueError("empty DSPy outputs_hash requires engine_error_msg")


@dataclass(frozen=True)
class ClaimLedgerEntry:
    event_id: str
    tenant: str
    timestamp: str
    claim_text: str
    verdict: Verdict
    evidence_refs: list[str]
    missing_evidence: list[str]
    scope_boundary: str
    invocation: DSPyInvocationEvidence
    safer_claim_text: str | None = None
    previous_hash: str | None = None
    event_hash: str | None = None
