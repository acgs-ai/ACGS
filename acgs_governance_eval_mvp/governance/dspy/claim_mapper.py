from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any, cast

from governance.audit import AuditStore
from governance.models import (
    DECISION_SCHEMA_VERSION,
    ActionRequest,
    DecisionRecord,
    Principal,
    sha256_json,
    utc_now_iso,
)

from .governance_wrapper import GovernedDSPyModule
from .models import ClaimLedgerEntry, DSPyProgramRecord, Verdict

DSPY_CLAIM_MAPPING_ACTION_TYPE = "dspy.claim_mapping"
KNOWN_VERDICTS: set[str] = {"supported", "partial", "invalidated", "undecidable"}


class EvidenceToClaimMapper:
    """Map audit evidence to claim verdicts without importing DSPy at module load.

    Inputs: claim_text, audit_event_ids, evidence_refs.
    Outputs: verdict, evidence_refs, missing_evidence, scope_boundary,
    safer_claim_text.
    """

    MACI_ROLE = "evidence_mapper"

    def __init__(
        self,
        *,
        program_record: DSPyProgramRecord,
        engine: Callable[[dict[str, Any]], dict[str, Any]],
        audit_store: AuditStore,
    ) -> None:
        if audit_store is None:
            raise TypeError("audit_store is required and must not be None")
        self.program_record = program_record
        self.engine = engine
        self.audit_store = audit_store

    @classmethod
    def from_dspy(
        cls,
        *,
        program_record: DSPyProgramRecord,
        audit_store: AuditStore,
        lm: Any = None,
    ) -> EvidenceToClaimMapper:
        import dspy

        class ClaimMappingSignature(dspy.Signature):  # type: ignore[misc]
            claim_text = dspy.InputField()
            audit_event_ids = dspy.InputField()
            evidence_refs = dspy.InputField()
            verdict = dspy.OutputField()
            missing_evidence = dspy.OutputField()
            scope_boundary = dspy.OutputField()
            safer_claim_text = dspy.OutputField()

        predictor = dspy.Predict(ClaimMappingSignature)

        def engine(inputs: dict[str, Any]) -> dict[str, Any]:
            if lm is not None:
                with dspy.context(lm=lm):
                    result = predictor(**inputs)
            else:
                result = predictor(**inputs)
            return {
                "verdict": getattr(result, "verdict", "undecidable"),
                "evidence_refs": getattr(result, "evidence_refs", inputs.get("evidence_refs", [])),
                "missing_evidence": getattr(result, "missing_evidence", []),
                "scope_boundary": getattr(result, "scope_boundary", "audit_events"),
                "safer_claim_text": getattr(result, "safer_claim_text", None),
            }

        return cls(program_record=program_record, engine=engine, audit_store=audit_store)

    def map_claim(
        self,
        *,
        tenant: str,
        claim_text: str,
        audit_event_ids: list[str],
        evidence_refs: list[str],
        calling_maci_role: str,
    ) -> ClaimLedgerEntry:
        missing_evidence, foreign_tenant_seen = self._pre_validate_evidence(
            tenant=tenant,
            audit_event_ids=audit_event_ids,
        )
        inputs = {
            "tenant": tenant,
            "claim_text": claim_text,
            "audit_event_ids": list(audit_event_ids),
            "evidence_refs": list(evidence_refs),
            "missing_evidence": list(missing_evidence),
        }
        wrapper = GovernedDSPyModule(
            program_record=self.program_record,
            engine=self.engine,
            maci_role=self.MACI_ROLE,
            forbidden_validator_roles=(self.MACI_ROLE,),
        )
        outputs, invocation = wrapper.invoke(inputs, calling_maci_role=calling_maci_role)
        output_data = outputs or {}
        engine_verdict = str(output_data.get("verdict", "undecidable"))
        raw_missing = output_data.get("missing_evidence", [])
        raw_refs = output_data.get("evidence_refs", evidence_refs)
        safe_missing: list[str] = [str(x) for x in raw_missing] if isinstance(raw_missing, list) else []
        safe_refs: list[str] = [str(x) for x in raw_refs] if isinstance(raw_refs, list) else list(evidence_refs)
        combined_missing = _dedupe([*missing_evidence, *safe_missing])

        verdict = self._decide_verdict(
            engine_error_msg=invocation.engine_error_msg,
            foreign_tenant_seen=foreign_tenant_seen,
            engine_verdict=engine_verdict,
            missing_evidence=combined_missing,
            audit_event_ids=audit_event_ids,
        )
        entry_before_append = ClaimLedgerEntry(
            event_id="",
            tenant=tenant,
            timestamp=utc_now_iso(),
            claim_text=claim_text,
            verdict=verdict,
            evidence_refs=safe_refs,
            missing_evidence=combined_missing,
            scope_boundary=str(output_data.get("scope_boundary", "audit_events")),
            safer_claim_text=output_data.get("safer_claim_text"),
            invocation=invocation,
            previous_hash=None,
            event_hash=None,
        )
        request = self._build_request(entry_before_append, inputs)
        entry_before_append = ClaimLedgerEntry(
            **{
                **asdict(entry_before_append),
                "event_id": request.event_id,
                "invocation": invocation,
            }
        )
        request = ActionRequest(
            action_type=request.action_type,
            resource=request.resource,
            actor=request.actor,
            intent=request.intent,
            inputs_hash=request.inputs_hash,
            tenant=request.tenant,
            event_id=request.event_id,
            metadata={"claim_ledger": asdict(entry_before_append)},
            tool_input=request.tool_input,
        )
        decision = DecisionRecord(
            event_id=request.event_id,
            tenant=tenant,
            allow=True,
            reasons=[f"DSPy claim mapping verdict: {verdict}"],
            reason_codes=[f"DSPY_CLAIM_{verdict.upper()}"],
            rule_ids=[],
            checks=[],
            request=request,
            policy_version="dspy-claim-mapper-v1",
            role_version="dspy-maci-v1",
            decision_state="allow",
            effective_tool_input=inputs,
            policy_bundle_hash="",
            role_bundle_hash="",
            decision_schema_version=DECISION_SCHEMA_VERSION,
        )
        stored = self.audit_store.append(decision)
        return ClaimLedgerEntry(
            **{
                **asdict(entry_before_append),
                "invocation": invocation,
                "previous_hash": stored["previous_hash"],
                "event_hash": stored["event_hash"],
            }
        )

    def _pre_validate_evidence(
        self,
        *,
        tenant: str,
        audit_event_ids: list[str],
    ) -> tuple[list[str], bool]:
        missing_evidence: list[str] = []
        foreign_tenant_seen = False
        for event_id in audit_event_ids:
            matches = self.audit_store.query(event_id=event_id, limit=1)
            if not matches:
                missing_evidence.append(event_id)
                continue
            event = matches[0]
            event_tenant = event.get("request", {}).get("tenant", event.get("tenant"))
            if event_tenant != tenant:
                foreign_tenant_seen = True
                missing_evidence.append(f"FOREIGN_TENANT_EVIDENCE:{event_id}")
        return missing_evidence, foreign_tenant_seen

    def _decide_verdict(
        self,
        *,
        engine_error_msg: str | None,
        foreign_tenant_seen: bool,
        engine_verdict: str,
        missing_evidence: list[str],
        audit_event_ids: list[str],
    ) -> Verdict:
        if engine_error_msg is not None:
            return "undecidable"
        if foreign_tenant_seen:
            return "invalidated"
        if engine_verdict not in KNOWN_VERDICTS:
            return "undecidable"
        if self._integrity_failed(audit_event_ids) and engine_verdict in ("supported", "partial"):
            return "invalidated"
        if missing_evidence and engine_verdict == "supported":
            return "partial"
        return cast(Verdict, engine_verdict)

    def _integrity_failed(self, audit_event_ids: list[str]) -> bool:
        for event_id in audit_event_ids:
            for event in self.audit_store.query(event_id=event_id, limit=1):
                metadata = event.get("request", {}).get("metadata", {})
                if metadata.get("integrity_status") == "fail":
                    return True
                if event.get("integrity_status") == "fail":
                    return True
        return False

    def _build_request(
        self,
        entry: ClaimLedgerEntry,
        inputs: dict[str, Any],
    ) -> ActionRequest:
        return ActionRequest(
            action_type=DSPY_CLAIM_MAPPING_ACTION_TYPE,
            resource=f"dspy/claims/{self.program_record.program_id}/{self.program_record.version}",
            actor=Principal(
                id=self.program_record.program_id,
                role=self.MACI_ROLE,
                tenant=entry.tenant,
            ),
            intent="Map evidence to claim verdict",
            inputs_hash=sha256_json(inputs),
            tenant=entry.tenant,
            metadata={"claim_ledger": asdict(entry)},
            tool_input=inputs,
        )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
