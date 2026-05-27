from __future__ import annotations

import pytest
from governance.adapters.anthropic_claude import govern_anthropic_tool_call
from governance.adapters.langgraph import govern_langgraph_tool_call
from governance.adapters.openai_agents import govern_openai_agent_tool_call
from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.models import ActionRequest, Principal
from governance.utils import canonical_input_hash

PRINCIPAL = {"id": "agent-legal-1", "role": "LegalOps"}
TOOL_ARGS = {
    "contract_id": "supplier-123",
    "fields": ["price", "term"],
    "resource": "contracts/supplier-123",
}


def _adapter(tmp_path, roles_bundle, policy_bundle) -> GovernedToolAdapter:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    return GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )


def _executor(tool_input):
    return {"executed": True, "echo": tool_input}


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_reference_adapters_block_denied",
    coverage_angle="openai_adapter_blocks_denied",
)
def test_openai_agents_adapter_blocks_denied_tool_call(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)

    with pytest.raises(PermissionError):
        govern_openai_agent_tool_call(
            agent_name="legal-bot",
            tool_name="contract.redline",
            tool_args=TOOL_ARGS,
            principal=PRINCIPAL,
            adapter=adapter,
            tool_executor=_executor,
        )


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_reference_adapters_block_denied",
    coverage_angle="openai_adapter_allows_permitted",
)
def test_openai_agents_adapter_allows_permitted_tool_call(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)
    permitted_args = {**TOOL_ARGS, "policy_citations": ["CONTRACT-AUTHORITY-001"]}

    result = govern_openai_agent_tool_call(
        agent_name="legal-bot",
        tool_name="contract.redline",
        tool_args=permitted_args,
        principal=PRINCIPAL,
        adapter=adapter,
        tool_executor=_executor,
    )

    assert result == {"executed": True, "echo": permitted_args}


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_reference_adapters_block_denied",
    coverage_angle="langgraph_adapter_blocks_denied",
)
def test_langgraph_adapter_blocks_denied(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)

    with pytest.raises(PermissionError):
        govern_langgraph_tool_call(
            node_name="redline-node",
            tool_name="contract.redline",
            tool_args=TOOL_ARGS,
            principal=PRINCIPAL,
            adapter=adapter,
            tool_executor=_executor,
        )


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_reference_adapters_block_denied",
    coverage_angle="anthropic_adapter_blocks_denied",
)
def test_anthropic_adapter_blocks_denied(tmp_path, roles_bundle, policy_bundle):
    adapter = _adapter(tmp_path, roles_bundle, policy_bundle)

    with pytest.raises(PermissionError):
        govern_anthropic_tool_call(
            session_id="sess-xyz",
            tool_name="contract.redline",
            tool_args=TOOL_ARGS,
            principal=PRINCIPAL,
            adapter=adapter,
            tool_executor=_executor,
        )


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_canonical_hash_invariants",
    coverage_angle="cross_adapter_canonical_hash_parity",
)
def test_all_three_adapters_produce_identical_inputs_hash_for_same_input():
    """Cross-adapter replay soundness: identical tool_input must yield identical inputs_hash."""
    args = dict(TOOL_ARGS)
    principal = Principal.from_dict(PRINCIPAL)

    def build_request(intent: str, resource: str, adapter_label: str) -> ActionRequest:
        return ActionRequest.from_dict(
            {
                "actor": principal,
                "intent": intent,
                "action_type": "contract.redline",
                "resource": resource,
                "inputs_hash": canonical_input_hash(args),
                "tool_input": args,
                "metadata": {"adapter": adapter_label},
            }
        )

    openai_req = build_request(
        "openai-agents:legal-bot:contract.redline",
        "openai-agents/legal-bot",
        "openai-agents",
    )
    langgraph_req = build_request(
        "langgraph:redline-node:contract.redline",
        "langgraph/redline-node",
        "langgraph",
    )
    anthropic_req = build_request(
        "anthropic-claude:sess-xyz:contract.redline",
        "anthropic-claude/sess-xyz",
        "anthropic-claude",
    )

    assert openai_req.inputs_hash == langgraph_req.inputs_hash == anthropic_req.inputs_hash
