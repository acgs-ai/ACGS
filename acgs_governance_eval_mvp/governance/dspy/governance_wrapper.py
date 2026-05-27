from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

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
        if calling_maci_role in self.forbidden_validator_roles:
            raise MACIRoleViolation(f"MACI role {calling_maci_role!r} is in forbidden_validator_roles")
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
            _raw = f"{type(exc).__name__}: {exc}"
            # Pass 1: keyword-prefixed secrets — preserve label, redact value.
            _scrubbed = re.sub(
                r"(sk-|Bearer\s+|password=|api[_\-]?key=|token=)\S+",
                r"\1<redacted>",
                _raw,
                flags=re.IGNORECASE,
            )
            # Pass 2: standalone known-format secrets — redact entire token.
            engine_error_msg = re.sub(
                r"eyJ[\w\-]+\.[\w\-]+\.[\w\-]*"
                r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
                r"|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}"
                r"|github_pat_[A-Za-z0-9_]{22,}"
                r"|AIza[0-9A-Za-z\-_]{35}"
                r"|hf_[A-Za-z0-9]{34,}"
                r"|xox[baprs]-[0-9A-Za-z\-]+"
                r"|sk_live_[0-9A-Za-z]{24,}|rk_live_[0-9A-Za-z]{24,}",
                "<redacted>",
                _scrubbed,
                flags=re.IGNORECASE,
            )[:500]
            latency_ms = (time.perf_counter() - start) * 1000

        if outputs is not None and not outputs and engine_error_msg is None:
            outputs = None
            engine_error_msg = "engine returned empty output"

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
