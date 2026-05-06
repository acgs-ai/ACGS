from __future__ import annotations

import time
from typing import Any, Callable

from governance.models import sha256_json

from .models import DSPyInvocationEvidence, DSPyProgramRecord


class MACIRoleViolation(PermissionError):
    pass


class DSPyEngineError(RuntimeError):
    pass


class DSPyProgramInactiveError(RuntimeError):
    pass


class GovernedDSPyModule:
    """Governed DSPy callable wrapper.

    GovernedDSPyModule does NOT write to audit_store; callers own the single
    append so failures and successes share one ledger event shape.
    """

    def __init__(
        self,
        *,
        program_record: DSPyProgramRecord,
        engine: Callable[[dict[str, Any]], dict[str, Any]],
        maci_role: str,
        forbidden_validator_roles: tuple[str, ...] = (),
        pre_validate: Callable[[dict[str, Any]], None] | None = None,
        post_validate: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
    ) -> None:
        self.program_record = program_record
        self.engine = engine
        self.maci_role = maci_role
        self.forbidden_validator_roles = forbidden_validator_roles
        self.pre_validate = pre_validate
        self.post_validate = post_validate

    def invoke(
        self,
        inputs: dict[str, Any],
        *,
        calling_maci_role: str,
    ) -> tuple[dict[str, Any] | None, DSPyInvocationEvidence]:
        if calling_maci_role == self.maci_role and self.maci_role in self.forbidden_validator_roles:
            raise MACIRoleViolation(f"MACI role {self.maci_role} cannot self-validate")
        if self.program_record.status != "active":
            raise DSPyProgramInactiveError(
                f"DSPy program {self.program_record.program_id}@{self.program_record.version} is not active"
            )

        if self.pre_validate is not None:
            self.pre_validate(inputs)

        start = time.perf_counter()
        engine_error_msg: str | None = None
        outputs: dict[str, Any] | None
        try:
            outputs = self.engine(inputs)
            latency_ms = (time.perf_counter() - start) * 1000
        except Exception as exc:
            outputs = None
            # Scrub common secret patterns before storing in the audit chain.
            import re as _re
            _raw = f"{type(exc).__name__}: {exc}"
            engine_error_msg = _re.sub(
                r"(sk-|Bearer |password=|api[_-]?key=|token=)\S+",
                r"\1<redacted>",
                _raw,
                flags=_re.IGNORECASE,
            )[:500]
            latency_ms = (time.perf_counter() - start) * 1000

        if outputs is not None and self.post_validate is not None:
            self.post_validate(inputs, outputs)

        evidence = DSPyInvocationEvidence(
            program_id=self.program_record.program_id,
            program_version=self.program_record.version,
            inputs_hash=sha256_json(inputs),
            outputs_hash=sha256_json(outputs if outputs is not None else {}),
            referenced_audit_event_ids=list(inputs.get("audit_event_ids", [])),
            latency_ms=latency_ms,
            engine=_engine_name(self.engine),
            engine_error_msg=engine_error_msg,
        )
        return outputs, evidence


def _engine_name(engine: Callable[[dict[str, Any]], dict[str, Any]]) -> str:
    name = getattr(engine, "__qualname__", None) or getattr(engine, "__name__", None)
    if name:
        return str(name)
    return engine.__class__.__name__
