"""MCP-governed agent demo — the ACGS MCP Governance Gateway end to end.

Flow demonstrated::

    Agent -> MCP request -> ACGS policy check -> Decision Receipt -> tool execution

Five scenarios, matching the gateway's binding guarantees:

1. **Allowed tool** — policy ALLOW mints a receipt; the tool executes and the
   MCP result carries the receipt metadata.
2. **Denied tool** — policy DENY returns a structured ``isError`` result; the
   tool never executes.
3. **Modified arguments** — a receipt minted for one argument set refuses a
   tampered argument set (canonical argument hashing).
4. **Expired receipt** — a receipt past its ``expires_at`` refuses execution.
5. **Replayed receipt** — with a consumption ledger, a spent receipt refuses
   a second execution (single use).

Local-only: no network, no MCP SDK required. The gateway is transport-neutral —
it consumes already-parsed ``tools/call`` payloads. Runs in the explicit
unsigned dev profile so the demo needs no crypto extra; production deployments
use ``GovernanceProfile.production(...)`` with a signer/verifier.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision
from gove_zone.errors import ReceiptValidationError
from gove_zone.kernel import Kernel
from gove_zone.policy import PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from mcp_gateway import MCPGovernanceGateway

AGENT = "agent://support-assistant"


def build_kernel(audit_path: Path, executed: list[str]) -> Kernel:
    policy = RuleSetPolicy(
        policy_id="mcp-governed-agent/v1",
        rules=[
            PolicyRule(
                rule_id="no-destructive-deletes",
                effect=Decision.DENY,
                tools=frozenset({"delete_customer_records"}),
            )
        ],
    )
    kernel = Kernel(policy=policy, audit=ChainHashAuditStore(str(audit_path)), actor=AGENT)

    @kernel.tool("read_customer_record")
    def read_customer_record(customer_id: str) -> dict[str, Any]:
        executed.append(f"read_customer_record:{customer_id}")
        return {"customer_id": customer_id, "plan": "enterprise"}

    @kernel.tool("delete_customer_records")
    def delete_customer_records(table: str) -> None:  # pragma: no cover - must never run
        executed.append(f"delete_customer_records:{table}")

    return kernel


def gateway_over(kernel: Kernel, **overrides: Any) -> MCPGovernanceGateway:
    config: dict[str, Any] = dict(
        tenant_id="tenant-A",
        execution_boundary="mcp-governed-agent/local",
        policy_bundle_id="mcp-governed-agent-bundle",
        authority="policy-engine",
        validator=Validator(validator_id="acgs-validator", role="validator"),
        profile=GovernanceProfile.dev(),
    )
    config.update(overrides)
    return MCPGovernanceGateway(kernel, **config)


def mcp_request(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}


def main() -> int:
    executed: list[str] = []
    workdir = Path(tempfile.mkdtemp(prefix="mcp-governed-agent-"))
    kernel = build_kernel(workdir / "audit.jsonl", executed)
    gateway = gateway_over(kernel)

    # 1. Allowed tool: request -> policy ALLOW -> receipt -> execution.
    allowed = gateway.handle_tools_call(
        mcp_request("read_customer_record", {"customer_id": "c-42"}), actor=AGENT
    )
    allowed_ok = (
        allowed["isError"] is False
        and executed == ["read_customer_record:c-42"]
        and bool(allowed["_meta"]["gove_zone"]["receipt_hash"])
    )

    # 2. Denied tool: structured rejection, no execution.
    denied = gateway.handle_tools_call(
        mcp_request("delete_customer_records", {"table": "customers"}), actor=AGENT
    )
    denied_ok = (
        denied["isError"] is True
        and denied["_meta"]["gove_zone"]["decision"] == "deny"
        and not any(e.startswith("delete_customer_records") for e in executed)
    )

    # 3. Modified arguments: the receipt is bound to the canonical argument
    # hash; executing with tampered arguments is refused.
    decision = gateway.authorize("read_customer_record", {"customer_id": "c-42"}, actor=AGENT)
    tamper_blocked = False
    try:
        gateway.execute(
            decision.receipt, "read_customer_record", {"customer_id": "c-999"}, actor=AGENT
        )
    except ReceiptValidationError:
        tamper_blocked = True

    # 4. Expired receipt: a TTL'd receipt past expires_at refuses execution.
    expiring_gateway = gateway_over(kernel, receipt_ttl_seconds=-1.0)
    stale = expiring_gateway.authorize("read_customer_record", {"customer_id": "c-42"}, actor=AGENT)
    expiry_blocked = False
    try:
        expiring_gateway.execute(
            stale.receipt, "read_customer_record", {"customer_id": "c-42"}, actor=AGENT
        )
    except ReceiptValidationError:
        expiry_blocked = True

    # 5. Replayed receipt: with a consumption ledger, a receipt is single-use —
    # the first execution burns it, the second is refused.
    ledgered_gateway = gateway_over(
        kernel, consumption_ledger=ReceiptConsumptionLedger(workdir / "consumed.jsonl")
    )
    single_use = ledgered_gateway.authorize(
        "read_customer_record", {"customer_id": "c-77"}, actor=AGENT
    )
    ledgered_gateway.execute(
        single_use.receipt, "read_customer_record", {"customer_id": "c-77"}, actor=AGENT
    )
    replay_blocked = False
    try:
        ledgered_gateway.execute(
            single_use.receipt, "read_customer_record", {"customer_id": "c-77"}, actor=AGENT
        )
    except ReceiptValidationError:
        replay_blocked = True

    checks = {
        "allowed_tool_executed_with_receipt": allowed_ok,
        "denied_tool_blocked_without_execution": denied_ok,
        "modified_arguments_blocked": tamper_blocked,
        "expired_receipt_blocked": expiry_blocked,
        "replayed_receipt_blocked": replay_blocked,
        "side_effects_observed": executed,
    }
    report = {
        "status": "pass"
        if all(v is True for k, v in checks.items() if k != "side_effects_observed")
        and executed == ["read_customer_record:c-42", "read_customer_record:c-77"]
        else "fail",
        **checks,
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
