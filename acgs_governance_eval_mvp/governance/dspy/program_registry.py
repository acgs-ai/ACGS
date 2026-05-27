from __future__ import annotations

import threading
from dataclasses import replace
from typing import Any

from governance.audit import AuditStore
from governance.models import (
    DECISION_SCHEMA_VERSION,
    ActionRequest,
    DecisionRecord,
    Principal,
    sha256_json,
)

from .models import DSPyProgramRecord

DSPY_PROGRAM_REGISTRY_ACTION_TYPE = "dspy.program_registry"


class DSPyProgramRegistry:
    def __init__(self, audit_store: AuditStore):
        if audit_store is None:
            raise TypeError("audit_store is required")
        self.audit_store = audit_store
        self._records: dict[tuple[str, str], DSPyProgramRecord] = {}
        self._active_versions: dict[str, str] = {}
        self._promoted: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def register(self, record: DSPyProgramRecord) -> None:
        key = (record.program_id, record.version)
        with self._lock:
            if key in self._records:
                raise ValueError(f"duplicate DSPy program {record.program_id}@{record.version}")
            if record.status == "active":
                raise ValueError("register draft or retired records; use promote() to activate")
            self._records[key] = record

    def promote(self, program_id: str, version: str, *, eval_report_hash: str) -> DSPyProgramRecord:
        if not eval_report_hash:
            raise ValueError("eval_report_hash is required")
        with self._lock:
            record = self._require_record(program_id, version)
            previous_active = self._active_versions.get(program_id)
            self._append_registry_event(
                op="promote",
                program_id=program_id,
                version=version,
                previous_active=previous_active,
                eval_report_hash=eval_report_hash,
            )
            if previous_active and previous_active != version:
                previous_key = (program_id, previous_active)
                self._records[previous_key] = replace(self._records[previous_key], status="retired")
            promoted = replace(record, status="active", eval_report_hash=eval_report_hash)
            self._records[(program_id, version)] = promoted
            self._active_versions[program_id] = version
            self._promoted.add((program_id, version))
            return promoted

    def retire(self, program_id: str, version: str) -> None:
        with self._lock:
            record = self._require_record(program_id, version)
            previous_active = self._active_versions.get(program_id)
            self._append_registry_event(
                op="retire",
                program_id=program_id,
                version=version,
                previous_active=previous_active,
            )
            self._records[(program_id, version)] = replace(record, status="retired")
            if previous_active == version:
                self._active_versions.pop(program_id, None)

    def rollback(self, program_id: str, *, to_version: str) -> DSPyProgramRecord:
        with self._lock:
            key = (program_id, to_version)
            record = self._require_record(program_id, to_version)
            if key not in self._promoted:
                raise ValueError(f"cannot rollback to never-promoted version {program_id}@{to_version}")
            previous_active = self._active_versions.get(program_id)
            self._append_registry_event(
                op="rollback",
                program_id=program_id,
                version=to_version,
                previous_active=previous_active,
            )
            if previous_active and previous_active != to_version:
                previous_key = (program_id, previous_active)
                self._records[previous_key] = replace(self._records[previous_key], status="retired")
            restored = replace(record, status="active")
            self._records[key] = restored
            self._active_versions[program_id] = to_version
            return restored

    def get_active(self, program_id: str) -> DSPyProgramRecord | None:
        with self._lock:
            version = self._active_versions.get(program_id)
            if version is None:
                return None
            return self._records[(program_id, version)]

    def list_programs(self, program_id: str | None = None) -> list[DSPyProgramRecord]:
        with self._lock:
            records = list(self._records.values())
        if program_id is not None:
            records = [record for record in records if record.program_id == program_id]
        return sorted(records, key=lambda record: (record.program_id, record.version))

    def _require_record(self, program_id: str, version: str) -> DSPyProgramRecord:
        try:
            return self._records[(program_id, version)]
        except KeyError as exc:
            raise ValueError(f"unknown DSPy program {program_id}@{version}") from exc

    def _append_registry_event(
        self,
        *,
        op: str,
        program_id: str,
        version: str,
        previous_active: str | None,
        eval_report_hash: str | None = None,
    ) -> None:
        tool_input: dict[str, Any] = {
            "op": op,
            "program_id": program_id,
            "version": version,
            "previous_active": previous_active,
        }
        if eval_report_hash is not None:
            tool_input["eval_report_hash"] = eval_report_hash
        request = ActionRequest(
            action_type=DSPY_PROGRAM_REGISTRY_ACTION_TYPE,
            resource=f"dspy/programs/{program_id}/{version}",
            actor=Principal(id=program_id, role="dspy_registrar", tenant="default"),
            intent=f"DSPy program registry {op}",
            inputs_hash=sha256_json(tool_input),
            metadata={"registry_op": tool_input},
            tool_input=tool_input,
        )
        decision = DecisionRecord(
            event_id=request.event_id,
            tenant=request.tenant,
            allow=True,
            reasons=[f"DSPy registry {op} allowed"],
            reason_codes=["DSPY_PROGRAM_REGISTRY_ALLOW"],
            rule_ids=[],
            checks=[],
            request=request,
            policy_version="dspy-registry-v1",
            role_version="dspy-maci-v1",
            decision_state="allow",
            effective_tool_input=tool_input,
            policy_bundle_hash="",
            role_bundle_hash="",
            decision_schema_version=DECISION_SCHEMA_VERSION,
        )
        self.audit_store.append(decision)
