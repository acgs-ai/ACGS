"""Evidence-backed, inactive policy-gap proposals."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.errors import TenantIsolationError
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ProcessEvent,
    ProcessEventKind,
)

POLICY_GAP_ALGORITHM_VERSION = "policy-gap-1.0"


class ProposalStatus(StrEnum):
    INACTIVE = "inactive"


@dataclass(frozen=True, slots=True)
class PolicyGapProposal:
    proposal_id: str
    tenant_id: str
    status: ProposalStatus
    tool_name: str
    support: int
    evidence_event_ids: tuple[str, ...]
    candidate_control: str
    rationale: str
    algorithm_version: str
    analytical_only: bool = True
    activates_policy: bool = False


def discover_policy_gaps(events: Iterable[ProcessEvent]) -> tuple[PolicyGapProposal, ...]:
    """Propose review-only controls for executed actions lacking policy coverage."""
    event_list = list(events)
    tenants = {event.tenant_id for event in event_list}
    if len(tenants) > 1:
        raise TenantIsolationError("policy-gap analysis cannot combine tenants")
    if not event_list:
        return ()
    tenant_id = next(iter(tenants))
    gaps: dict[str, list[ProcessEvent]] = defaultdict(list)
    for event in event_list:
        governance = event.governance
        execution_observed = (
            governance.is_side_effect and event.kind is ProcessEventKind.TOOL_RESULT
        )
        if not execution_observed:
            continue
        if governance.policy_id is not None and governance.policy_version is not None:
            continue
        tool = governance.tool_name or event.activity
        gaps[tool].append(event)

    proposals = []
    for tool in sorted(gaps):
        evidence_ids = tuple(sorted(event.event_id for event in gaps[tool]))
        proposal_id = sha256_canonical(
            {
                "algorithm_version": POLICY_GAP_ALGORITHM_VERSION,
                "tenant_id": tenant_id,
                "tool_name": tool,
                "evidence_event_ids": evidence_ids,
            }
        )
        proposals.append(
            PolicyGapProposal(
                proposal_id=proposal_id,
                tenant_id=tenant_id,
                status=ProposalStatus.INACTIVE,
                tool_name=tool,
                support=len({event.case_id for event in gaps[tool]}),
                evidence_event_ids=evidence_ids,
                candidate_control=(
                    f"Require an authoritative policy decision and verified receipt for {tool}."
                ),
                rationale="observed side effect lacks complete policy coverage",
                algorithm_version=POLICY_GAP_ALGORITHM_VERSION,
            )
        )
    return tuple(proposals)
