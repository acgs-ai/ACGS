"""MCP tool gateway — govern an MCP server's ``tools/call`` with gove-zone.

This shows the INTEGRATION PATTERN, not a vendored SDK. There is **no real
``mcp`` / ``fastmcp`` import** here: this demo runs with only ``gove-zone``
installed. We model a standard MCP JSON-RPC ``tools/call`` request shape::

    {"method": "tools/call",
     "params": {"name": "write_file",
                "arguments": {"path": "/etc/passwd", "content": "..."}}}

and route it through gove-zone's real governance API. ``handle_mcp_call`` is
written so it drops straight into a real FastMCP ``@server.tool()`` handler:
parse the request, get a governed decision, and either return an MCP error
response or run the real side effect behind a signed receipt gate.

Two governance layers (defense in depth)
-----------------------------------------
1. **In-band audited policy decision** — :func:`emit_receipt_for_hook` parses
   the MCP request natively (``params.name`` + ``params.arguments``), lifts
   ``arguments.path`` into the governed ``ToolCall.path``, runs a
   :class:`PathBoundaryPolicy`, and appends a tamper-evident audit receipt. A
   write under ``/etc`` is DENIED; a write under ``/tmp`` is ALLOWED.

   Hook-adapter gotcha (load-bearing): through the hook adapter the raw tool
   *arguments* are replaced by a hash before the policy sees them, so a policy
   keyed on raw argument keywords would silently never fire. We therefore
   match on ``call.path`` (``PathBoundaryPolicy``), which the adapter preserves.

2. **Cryptographic signed execution gate** — on ALLOW, the real side effect
   runs only behind :func:`execute_with_receipt` configured from the
   **production** :class:`GovernanceProfile` (``require_signature=True`` — the
   secure default posture). We generate an Ed25519 keypair in-demo (fine and
   pedagogically correct for a self-contained example: the private key signs at
   issuance, the gate verifies with the public key only). A production gate with
   no verifier fails closed loud — we demonstrate that too.

Honest scope
------------
This is foundational / local-alpha proof. It proves the local invariant — no
allowed path executes without a verified receipt, and a denied path leaves no
side effect — against the real evaluator, hook adapter, signer, executor, and
audit chain. It is NOT a production, compliance, or regulator-ready
certification. See ``SECURITY.md``. Generating the keypair in-process is for the
self-contained demo only; real deployments must manage key custody, distribution,
and revocation externally (the signing module documents those residuals).

Run it::

    uv run --package gove-zone python \\
        packages/gove-zone/examples/mcp-tool-gateway/demo.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    Ed25519Signer,
    GovernanceProfile,
    PathBoundaryPolicy,
    ProductionProfileError,
    Receipt,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    emit_receipt_for_hook,
    evaluate_tenant_action,
    execute_with_receipt,
)
from gove_zone.integration import resolve_audit_path

# --- Trust boundary constants ------------------------------------------------
# The MCP server's logical execution boundary + the calling agent's identity.
# In a real server, ACTOR is the AUTHENTICATED session principal supplied by the
# runtime — never read from the request body, which an attacker could forge.
BOUNDARY = "mcp-local-sandbox"
TENANT = "tenant-A"
ACTOR = "mcp-agent"
# A distinct MACI validating principal — never the proposer/actor.
VALIDATOR = Validator("constitutional-council")

# Protected path prefixes. A write whose ``path`` starts with one of these is
# denied at the in-band policy gate. ``allowed_actors`` is intentionally empty:
# no actor is exempt from the /etc boundary.
PROTECTED_PREFIXES = ["/etc", "/usr", "/boot"]


def _banner(title: str) -> None:
    print(f"\n=== {title} ===")


def mcp_request(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a standard MCP JSON-RPC ``tools/call`` request payload."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }


def _mcp_error_response(message: str, audit_hash: str) -> dict[str, Any]:
    """MCP ``tools/call`` result for a governance-denied call.

    Per the MCP spec, tool-level failures are reported as a successful JSON-RPC
    result with ``isError: true`` (not a protocol-level error), so the model can
    see and reason about the denial. We attach the audit hash as evidence.
    """
    return {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "_meta": {"gove_zone": {"decision": "deny", "audit_hash": audit_hash}},
    }


def _mcp_ok_response(text: str, audit_hash: str) -> dict[str, Any]:
    """MCP ``tools/call`` result for a governance-allowed, executed call."""
    return {
        "isError": False,
        "content": [{"type": "text", "text": text}],
        "_meta": {"gove_zone": {"decision": "allow", "audit_hash": audit_hash}},
    }


def handle_mcp_call(
    request: dict[str, Any],
    *,
    audit: ChainHashAuditStore,
    profile: GovernanceProfile,
    policy_store: TenantPolicyStore,
    signer: Ed25519Signer,
    side_effect_log: list[str],
) -> dict[str, Any]:
    """Govern one MCP ``tools/call`` and return an MCP-shaped response.

    Copy-pasteable into a real FastMCP handler: the body of an
    ``@server.tool()`` would call this with the inbound request and return the
    dict. Two gates run in series:

    1. In-band audited policy decision (``emit_receipt_for_hook`` +
       ``PathBoundaryPolicy``). DENY → return an MCP ``isError`` response and
       run NO side effect.
    2. ALLOW → mint a signed Decision Receipt for the *real* arguments and run
       the side effect only behind ``execute_with_receipt`` configured from the
       production profile (signed, ``require_signature=True``).

    For demo clarity this handler is specialized to a single ``write_file`` tool
    (it always routes to ``runtime.file.write``); a real ``@server.tool()``
    handler would dispatch on ``params.name``. ``side_effect_log`` is a test
    artifact a real handler would not carry.
    """
    params = request.get("params", {})
    tool_name = params.get("name", "")
    arguments = dict(params.get("arguments", {}))

    # --- Gate 1: in-band audited policy decision -----------------------------
    # The hook adapter parses the MCP shape, hashes the raw arguments, and lifts
    # arguments["path"] into the governed ToolCall.path so PathBoundaryPolicy can
    # match it. GateMode stays at its default — now ENFORCE — and main() pins
    # GOVE_ZONE_PROFILE=dev to acknowledge that this passive gate-1 audit anchor
    # is legitimately unsigned (signing lives at gate 2).
    policy = PathBoundaryPolicy(blocked_prefixes=PROTECTED_PREFIXES)
    receipt: Receipt | None = emit_receipt_for_hook(
        request,
        action_kind="tool_call",
        actor=ACTOR,
        policy=policy,
    )
    assert receipt is not None, "gate-1 emission must produce an audit anchor"
    audit_hash = receipt.audit_hash

    if receipt.record.decision is not Decision.ALLOW:
        # Denied. Return an MCP error response; the side effect never runs.
        reason = receipt.record.reason
        rules = ", ".join(receipt.record.matched_rules) or "(none)"
        return _mcp_error_response(
            f"gove-zone DENIED {tool_name}: {reason} [rules: {rules}]",
            audit_hash,
        )

    # --- Gate 2: cryptographic signed execution gate -------------------------
    # The hook receipt bound a HASHED arg summary, not the raw args, so it cannot
    # authorize execute_with_receipt directly. Mint a fresh signed Decision
    # Receipt over the REAL arguments, then run the side effect behind the gate.
    request_id = f"mcp-{audit_hash[:12]}"
    signed_receipt = evaluate_tenant_action(
        store=policy_store,
        tenant_id=TENANT,
        requester_tenant_id=TENANT,
        action="runtime.file.write",
        args=arguments,
        execution_boundary=BOUNDARY,
        request_id=request_id,
        actor=ACTOR,
        validator=VALIDATOR,
        authority="tenant-A/mcp-write-grant",
        audit_store=audit,
        signer=signer,
    )

    def write_file(path: str, content: str) -> str:
        Path(path).write_text(content, encoding="utf-8")
        side_effect_log.append(path)
        return f"wrote {len(content)} bytes to {path}"

    # execute_with_receipt fail-closes unless the receipt verifies. Configure the
    # gate straight from the production profile bundle (signed, verifier-checked).
    result = execute_with_receipt(
        tool_fn=write_file,
        args=arguments,
        receipt=signed_receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
        expected_actor=ACTOR,
        **profile.as_gate_kwargs(),
    )
    # Surface the SIGNED gate-2 receipt's audit-event hash: that is the event
    # that actually authorized execution, so the printed evidence ties to the
    # right anchor (the deny path, by contrast, surfaces gate 1's hash because
    # gate 1 is the whole decision there).
    return _mcp_ok_response(result, signed_receipt.audit_event_hash)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gove-zone-mcp-demo-") as scratch:
        scratch_path = Path(scratch)
        # Pin every gove-zone path inside the tempdir: the hook auditor writes
        # $CLAUDE_PROJECT_DIR/.gove-zone/audit.jsonl; without this it would write
        # under cwd. GateMode stays at its default — which is now ENFORCE
        # (fail-closed). The passive gate-1 auditor emits unsigned audit-anchor
        # receipts, so under enforcement it must explicitly acknowledge that via
        # the dev profile; the EXECUTION gate below still runs the full
        # production profile with signed receipts.
        os.environ["CLAUDE_PROJECT_DIR"] = scratch
        os.environ.pop("GOVE_ZONE_AUDIT_PATH", None)
        os.environ.pop("GOVE_ZONE_GATE_MODE", None)
        os.environ["GOVE_ZONE_PROFILE"] = "dev"

        # Lead with the production profile (the secure default): signed receipts
        # required at the execution gate. Generate an Ed25519 keypair in-demo —
        # the private key signs at issuance; the gate verifies with the public
        # key only. (Self-contained demo convenience; not production key mgmt.)
        signer = Ed25519Signer.generate()
        verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
        profile = GovernanceProfile.production(signer=signer, verifier=verifier)

        audit = ChainHashAuditStore(resolve_audit_path())
        policy_store = TenantPolicyStore(scratch_path / "policies")
        # The tenant bundle the signed execution gate consults: deny shell.exec,
        # allow file writes (PathBoundaryPolicy at gate 1 owns the /etc deny).
        policy_store.store_bundle(
            TENANT,
            RuleSetPolicy.from_dict(
                {
                    "id": "policy-A",
                    "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}],
                }
            ),
        )
        side_effect_log: list[str] = []

        print("gove-zone — MCP tool gateway (integration PATTERN, not a vendored SDK)")
        print(f"profile    : {profile.name} (require_signature={profile.require_signature})")
        print(f"is_production: {profile.is_production}")
        print(f"audit path : {resolve_audit_path()}")
        print(f"protected  : {PROTECTED_PREFIXES}")

        # --- 1. DENIED: write to a protected path --------------------------------
        _banner("1. MCP tools/call → write_file /etc/passwd  (must be DENIED)")
        deny_req = mcp_request(
            "write_file",
            {"path": "/etc/passwd", "content": "root::0:0::/root:/bin/sh\n"},
        )
        print("request:")
        print(json.dumps(deny_req, indent=2, sort_keys=True))
        deny_resp = handle_mcp_call(
            deny_req,
            audit=audit,
            profile=profile,
            policy_store=policy_store,
            signer=signer,
            side_effect_log=side_effect_log,
        )
        print("MCP response:")
        print(json.dumps(deny_resp, indent=2, sort_keys=True))
        # The whole point: deny is LOUD and asserted, and NO side effect ran.
        assert deny_resp["isError"] is True, "protected-path write should be denied"
        assert deny_resp["_meta"]["gove_zone"]["decision"] == "deny"
        # No side effect ran — the demo never touches the real filesystem on DENY.
        # (side_effect_log only records writes the write_file closure performed.)
        assert side_effect_log == [], "no side effect may run on a denied call"
        print("  ASSERT OK: denied, no file written, audit anchor recorded.")

        # --- 2. ALLOWED: write to a /tmp path ------------------------------------
        _banner("2. MCP tools/call → write_file (tempdir)  (must be ALLOWED + executed)")
        target = scratch_path / "report.txt"
        allow_req = mcp_request(
            "write_file",
            {"path": str(target), "content": "governed write ok\n"},
        )
        print("request:")
        print(json.dumps(allow_req, indent=2, sort_keys=True))
        allow_resp = handle_mcp_call(
            allow_req,
            audit=audit,
            profile=profile,
            policy_store=policy_store,
            signer=signer,
            side_effect_log=side_effect_log,
        )
        print("MCP response:")
        print(json.dumps(allow_resp, indent=2, sort_keys=True))
        assert allow_resp["isError"] is False, "tempdir write should be allowed"
        assert allow_resp["_meta"]["gove_zone"]["decision"] == "allow"
        assert target.read_text() == "governed write ok\n", "allowed write must execute"
        assert side_effect_log == [str(target)], "exactly the allowed side effect ran"
        print(f"  ASSERT OK: executed behind signed gate; file = {target.read_text()!r}")

        # --- 3. Production gate with NO verifier fails closed LOUD ----------------
        _banner("3. Production profile with no verifier  (must FAIL CLOSED loud)")
        no_verifier_profile = GovernanceProfile.production(signer=signer, verifier=None)
        try:
            handle_mcp_call(
                mcp_request("write_file", {"path": str(scratch_path / "x.txt"), "content": "x"}),
                audit=audit,
                profile=no_verifier_profile,
                policy_store=policy_store,
                signer=signer,
                side_effect_log=side_effect_log,
            )
        except ProductionProfileError as exc:
            print(f"  ASSERT OK: raised {type(exc).__name__}: {str(exc)[:88]}…")
        else:
            raise SystemExit("production profile with no verifier failed to fail-closed")

        # --- 4. Audit chain is tamper-evident over every decision ----------------
        _banner("4. Verify the tamper-evident audit chain")
        verdict = audit.verify_chain()
        print(json.dumps(verdict, indent=2, sort_keys=True))
        assert verdict["valid"] is True, "audit chain must verify"
        print(f"  ASSERT OK: {verdict['checked']} tamper-evident events anchored.")

        print("\nAll MCP-gateway invariants held.")
        print("  - protected-path write DENIED, no side effect")
        print("  - tempdir write ALLOWED behind a signed production-profile gate")
        print("  - production gate with no verifier fails closed loud")
        print("  - every decision left tamper-evident audit evidence")
        print("\nScope: local-alpha proof of the gateway invariant — NOT a")
        print("production / compliance / regulator-ready certification.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
