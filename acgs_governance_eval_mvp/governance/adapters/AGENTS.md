# AGENTS.md - acgs_governance_eval_mvp/governance/adapters

## Purpose

Vendor-specific adapters that normalize LLM and agent-framework tool-use
callbacks into the governance pipeline's internal event shape, then defer to
`GovernedToolAdapter.validate` for the actual decision. Adapters do not own
policy or audit state; they own the call shape.

## Modules

- `tools.py` - `GovernedToolAdapter` class; the canonical orchestrator that composes `AuthorityGate`, `PolicyRecallGate`, `GovernanceRecallGate`, the `ChainHashAuditStore`, and `GovernanceMetrics`. Other adapters defer to this.
- `anthropic_claude.py` - `govern_anthropic_tool_call(...)` wraps the Anthropic Claude Agent SDK tool-use callback; raises `PermissionError` (typed `GovernanceDeniedError` planned) on deny so the SDK surfaces a tool-use failure to the model.
- `langgraph.py` - `govern_langgraph_tool_call(...)` plugs into a LangGraph tool-node `before_tool_node` hook; on deny the exception becomes the node's error so the graph can route to a remediation node.
- `openai_agents.py` - `govern_openai_agent_tool_call(...)` plugs into the OpenAI Agents SDK guardrails/tool-use surface; same exception contract.

## Integration Pattern

Each vendor adapter exposes a single `govern_<vendor>_tool_call(...)` callable.
Callers pass `(session_id|node_name|agent_name, tool_name, tool_args, principal, adapter, tool_executor)`;
the adapter builds an `ActionRequest`, calls `adapter.validate(...)`, raises
on deny, and otherwise invokes `tool_executor(tool_args)`. Decisions feed
`governance/audit` and `governance/metrics` automatically via `GovernedToolAdapter`.

## Gotchas

- These adapters do not import the real vendor SDK; they depend only on the SDK's callback contract. Vendor version drift is asserted in `tests/test_reference_adapters.py` — keep that test green when SDK shapes change.
- Tool-call args MUST be canonicalized through `governance.utils.canonical_input_hash` before being placed in the request so the audit-chain hash is reproducible.
- On deny, today the adapters raise `PermissionError`; a typed `GovernanceDeniedError` is planned (Lane 2). Do not catch `Exception` blindly in your integration.
