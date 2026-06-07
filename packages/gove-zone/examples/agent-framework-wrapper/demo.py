"""Governing agent-framework tool calls with gove-zone — the integration PATTERN.

This shows the SAME gove-zone governance gate wrapping two different agent
framework tool-call shapes, WITHOUT importing the real SDKs:

  (a) a LangGraph-style tool node — a pre-execution intercept that gates a tool
      call *before* the graph node runs its side effect;
  (b) an OpenAI Agents ``@function_tool``-style wrapper — a decorator/closure
      that gates the wrapped tool function on every invocation.

Both route through gove-zone's REAL side-effect gate
(:func:`gove_zone.execute_with_receipt` via :class:`gove_zone.GovernedExecutor`)
under the **production profile** — signed Decision Receipts are required, and the
gate verifies an Ed25519 signature against a public key before any side effect
runs. A small reusable ``govern(tool_fn, ...)`` closure carries the gate; the two
framework-shaped adapters are thin wrappers around it.

We model each framework's *call shape* with a tiny in-file stub and a
representative payload, then govern it with gove-zone's real API. This is the
integration PATTERN, not a vendored SDK — there is no ``langgraph`` or
``openai-agents`` import anywhere. The demo runs with ONLY gove-zone installed.

Note on lineage: the eval-MVP adapters under
``acgs_governance_eval_mvp/governance/adapters/*`` wrap an OLDER kernel. This demo
uses **gove-zone proper** (``gove_zone.*``), the current kernel.

Honest scope: this is local Alpha proof of the wrapping invariant — "no valid
signed Decision Receipt, no side effect." It is NOT a production, compliance, or
regulator-ready certification. The Ed25519 key is generated in-process purely so
the example is self-contained; a real deployment supplies a signer at issuance
and distributes only the public verifier to the gate (mirror of SECURITY.md and
the receipt-gated-execution example).

Run it (from the monorepo root)::

    uv run --package gove-zone python \\
        packages/gove-zone/examples/agent-framework-wrapper/demo.py

Or directly with gove-zone on the path::

    python packages/gove-zone/examples/agent-framework-wrapper/demo.py

Each scenario asserts its expected outcome; any violated invariant exits non-zero.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Ed25519Signer,
    GovernanceProfile,
    GovernedExecutor,
    ProductionProfileError,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
    execute_with_receipt,
)

# --- Governance constants -------------------------------------------------
# The execution boundary and tenant the gate is scoped to.
BOUNDARY = "local-sandbox"
TENANT = "tenant-A"
# MACI role separation: the validating principal must differ from the proposer.
VALIDATOR = Validator("constitutional-council")
# The AUTHENTICATED invoking principal, supplied to the gate as expected_actor.
# In a real host this comes from the authenticated session/runtime context — NOT
# from the request body or the receipt (using a request-supplied identity would
# be circular: an attacker could set it to match a forged receipt). Modelling it
# as a separate constant makes the trust boundary explicit.
CALLER_IDENTITY = "agent-1"
PROPOSER = "agent-1"  # the agent proposing the tool call


# --- ANSI helpers ---------------------------------------------------------
def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _banner(title: str) -> None:
    print(f"\n=== {title} ===")


# --- A stand-in side-effecting tool --------------------------------------
class FileWriterTool:
    """A representative high-risk tool. Records whether it actually ran.

    This stands in for whatever real side effect an agent framework would call
    (write a file, hit an API, run a shell command). The whole point of the gate
    is that ``ran`` stays ``False`` on a denied call.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ran = False
        self.last_args: dict[str, Any] | None = None

    def write_file(self, *, path: str, content: str) -> str:
        self.ran = True
        self.last_args = {"path": path, "content": content}
        target = self.root / path
        target.write_text(content)
        return f"wrote {len(content)} bytes to {path}"


# --- The reusable governed wrapper ---------------------------------------
class GovernedToolGate:
    """Carries the real gove-zone gate so framework adapters can reuse it.

    Issuance (minting a signed receipt) and enforcement (the production gate)
    both live here. The two framework adapters below call :meth:`govern` and care
    only about their own call SHAPE — the governance is identical underneath.
    """

    def __init__(
        self,
        *,
        store: TenantPolicyStore,
        audit: ChainHashAuditStore,
        profile: GovernanceProfile,
    ) -> None:
        self._store = store
        self._audit = audit
        self._profile = profile

    def govern(
        self,
        tool_fn: Callable[..., Any],
        action: str,
        args: dict[str, Any],
        *,
        request_id: str,
    ) -> Any:
        """Issue a signed receipt for *action*/*args*, then gate *tool_fn* on it.

        This is the reusable ``govern(tool_fn)``-style wrapper: the SAME callable
        the framework would run is the one the gate executes. Returns the tool
        result on ALLOW. Raises :class:`ReceiptValidationError` if the policy
        denied the action (or any gate check fails) — and in that case ``tool_fn``
        is never called, so no side effect runs.
        """
        # 1. Issue a Decision Receipt by evaluating the action against the
        #    tenant's active policy bundle. The issuer SIGNS it with the private
        #    key from the production profile.
        receipt = evaluate_tenant_action(
            store=self._store,
            tenant_id=TENANT,
            requester_tenant_id=TENANT,
            action=action,
            args=args,
            execution_boundary=BOUNDARY,
            request_id=request_id,
            actor=PROPOSER,
            validator=VALIDATOR,
            authority="tenant-A/write-grant",
            audit_store=self._audit,
            signer=self._profile.signer,
        )
        # 2. Gate execution on the receipt. With the production profile's gate
        #    kwargs (require_signature=True + public verifier) the gate
        #    cryptographically verifies the receipt and refuses a denied one
        #    BEFORE ``tool_fn`` runs. The wrapped fn IS the governed side effect.
        return execute_with_receipt(
            tool_fn=tool_fn,
            args=args,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=action,
            expected_actor=CALLER_IDENTITY,
            **self._profile.as_gate_kwargs(),
        )


# --- Framework adapter (a): LangGraph-style tool node ---------------------
# LangGraph models a workflow as a graph of nodes; a node receives the running
# state and returns an updated state. A common governance integration point is a
# *pre-execution intercept* on the tool node: gate the proposed tool call before
# the node performs its side effect. We model a node as `state -> state` and let
# the gate decide whether the tool runs.
def make_langgraph_tool_node(
    gate: GovernedToolGate,
    action: str,
    tool_fn: Callable[..., Any],
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph-style node fn that gates *tool_fn* before executing it.

    Call shape modelled (not imported): a node ``fn(state) -> state`` reads the
    proposed tool call from ``state["tool_call"]`` and writes the outcome back
    into ``state``. Governance is a pre-execution intercept inside the node, and
    the gated callable is exactly the *tool_fn* the node would otherwise run.
    """

    def tool_node(state: dict[str, Any]) -> dict[str, Any]:
        call = state["tool_call"]
        request_id = state.get("request_id", "lg-node")
        new_state = dict(state)
        try:
            result = gate.govern(tool_fn, action, call["args"], request_id=request_id)
        except ReceiptValidationError as exc:
            # Fail closed: the node records the denial and routes onward WITHOUT
            # running the side effect. A real graph would branch to an error/halt
            # node here.
            new_state["governed"] = {"decision": "blocked", "reason": str(exc)}
            return new_state
        new_state["governed"] = {"decision": "allowed", "result": result}
        return new_state

    return tool_node


# --- Framework adapter (b): OpenAI Agents @function_tool-style wrapper -----
# OpenAI Agents exposes tools as plain Python functions decorated with
# `@function_tool`. The natural governance integration is a decorator that wraps
# the tool fn so every invocation is gated. We model the decorator's CALL SHAPE
# (a decorator returning a same-signature callable) without importing the SDK.
def function_tool_governed(
    gate: GovernedToolGate,
    action: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """A `@function_tool`-style decorator that routes the call through the gate.

    The wrapped function keeps its keyword signature, but its own body only runs
    if the gate ALLOWs the receipt. On DENY it raises ``ReceiptValidationError``
    and the wrapped body is never entered (no side effect). The decorator gates
    the SAME callable it wrapped — there is no decoy.
    """

    def decorator(tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(**kwargs: Any) -> Any:
            # The gate issues + verifies a signed receipt for THIS invocation,
            # then runs the WRAPPED tool_fn iff the receipt allows it. We never
            # call tool_fn directly — that would bypass the gate — but the gate
            # does execute the same tool_fn the decorator wrapped.
            return gate.govern(tool_fn, action, kwargs, request_id="oa-tool")

        wrapper.__name__ = getattr(tool_fn, "__name__", "governed_tool")
        wrapper.__doc__ = tool_fn.__doc__
        return wrapper

    return decorator


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-agent-fw-"))
    store = TenantPolicyStore(workdir / "policies")
    audit = ChainHashAuditStore(workdir / "audit.jsonl")
    tool = FileWriterTool(workdir / "out")
    (workdir / "out").mkdir(parents=True, exist_ok=True)

    print("\ngove-zone — governing agent-framework tool calls (integration PATTERN)")
    print("Invariant: no valid signed Decision Receipt, no side effect.")
    print("(Frameworks are modelled by in-file stubs; no SDK is imported.)\n")

    # --- Production profile: signed receipts required at the gate. ---------
    # Generate an Ed25519 keypair IN the demo so the example is self-contained.
    # Issuer signs with the private key; the gate verifies with the PUBLIC key
    # only. In production the signer lives with the issuer and only the public
    # verifier reaches the gate.
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
    profile = GovernanceProfile.production(signer=signer, verifier=verifier)
    _banner("Profile")
    print(f"  profile        = {profile.name} (is_production={profile.is_production})")
    print(f"  gate kwargs    = {profile.as_gate_kwargs()!r}")
    if not profile.is_production:
        _fail("expected the production profile to lead this demo")

    # The reusable gate carries issuance + the production enforcement check. Both
    # framework adapters pass their OWN tool_fn to gate.govern() — the gate runs
    # the exact callable the framework would otherwise run.
    gate = GovernedToolGate(store=store, audit=audit, profile=profile)

    # Sanity: a production gate with NO verifier must fail closed loud. This is
    # the secure-by-default posture — we never silently downgrade to unsigned.
    # GovernedExecutor is gove-zone's registry-style gate; here it just makes the
    # misconfiguration (require_signature=True, no verifier) easy to exhibit.
    _banner("Fail-closed check: production gate with no verifier")
    try:
        bad = GovernedExecutor(
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            expected_actor=CALLER_IDENTITY,
            # require_signature defaults True; no verifier supplied.
        )
        bad.register("runtime.file.write", tool.write_file)
        bad.execute("runtime.file.write", {"path": "x", "content": "y"}, None)
        _fail("production gate with no verifier did not fail closed")
    except ProductionProfileError as exc:
        _ok(f"production gate with no verifier fails closed loud: {exc}")

    # --- LangGraph-style node: ALLOW then DENY ----------------------------
    # Policy bundle: default ALLOW, but DENY the high-risk tool when proposing a
    # write to a forbidden path. We model "forbidden" as a dedicated tool name so
    # the deny rule fires at issuance regardless of the (hashed) args.
    allow_bundle = RuleSetPolicy.from_dict(
        {
            "id": "policy-A",
            "rules": [
                {"id": "R1", "effect": "deny", "tools": ["runtime.shell.exec"]},
            ],
        }
    )
    deny_write_bundle = RuleSetPolicy.from_dict(
        {
            "id": "policy-A",
            "rules": [
                {"id": "R1", "effect": "deny", "tools": ["runtime.file.write"]},
            ],
        }
    )
    store.store_bundle(TENANT, allow_bundle)

    _banner("Adapter (a): LangGraph-style tool node")
    # The node's tool fn is the FileWriterTool side effect. The gate runs exactly
    # this callable on ALLOW and never touches it on DENY.
    node = make_langgraph_tool_node(gate, "runtime.file.write", tool.write_file)

    # ALLOW: the node executes the side effect.
    tool.ran = False
    state = {
        "tool_call": {"args": {"path": "report.txt", "content": "ok"}},
        "request_id": "lg-allow",
    }
    out_state = node(state)
    if out_state["governed"]["decision"] != "allowed":
        _fail(f"expected node ALLOW, got {out_state['governed']}")
    if not tool.ran:
        _fail("ALLOW node did not reach the side effect")
    _ok(f"node allowed + executed → {out_state['governed']['result']!r}")

    # DENY: switch the active bundle to deny the write; the node must block it and
    # the side effect must NOT run.
    store.store_bundle(TENANT, deny_write_bundle)
    tool.ran = False
    tool.last_args = None
    state = {
        "tool_call": {"args": {"path": "report.txt", "content": "blocked"}},
        "request_id": "lg-deny",
    }
    out_state = node(state)
    if out_state["governed"]["decision"] != "blocked":
        _fail(f"expected node DENY, got {out_state['governed']}")
    if tool.ran:
        _fail("side effect ran despite node DENY")
    _ok(f"node blocked, no side effect → {out_state['governed']['reason']}")
    store.store_bundle(TENANT, allow_bundle)  # restore default ALLOW

    # --- OpenAI Agents @function_tool-style wrapper: ALLOW then DENY ------
    _banner("Adapter (b): OpenAI Agents @function_tool-style wrapper")

    # The decorated function's OWN body is the side effect. ``body_ran`` is the
    # discriminating witness: it flips True only if save_note's body executes, so
    # we can prove the gate runs the wrapped fn on ALLOW and never on DENY.
    body_ran: list[bool] = [False]
    notes_dir = workdir / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)

    @function_tool_governed(gate, "runtime.file.write")
    def save_note(*, path: str, content: str) -> str:
        """Persist a note. This body runs ONLY if the gate allows the receipt."""
        body_ran[0] = True
        (notes_dir / path).write_text(content)
        return f"saved note {path!r} ({len(content)} bytes)"

    # ALLOW: the decorated tool's own body runs through the gate and executes.
    body_ran[0] = False
    result = save_note(path="note.txt", content="hello")
    if not body_ran[0]:
        _fail("ALLOW @function_tool did not run the wrapped fn's body")
    if not (notes_dir / "note.txt").exists():
        _fail("ALLOW @function_tool produced no side effect on disk")
    _ok(f"@function_tool allowed + ran wrapped body → {result!r}")

    # DENY: deny the write; the wrapped fn's body must never run and raise instead.
    store.store_bundle(TENANT, deny_write_bundle)
    body_ran[0] = False
    try:
        save_note(path="blocked.txt", content="blocked")
        _fail("denied @function_tool reached execution")
    except ReceiptValidationError as exc:
        if body_ran[0]:
            _fail("wrapped fn body ran despite @function_tool DENY")
        if (notes_dir / "blocked.txt").exists():
            _fail("side effect hit disk despite @function_tool DENY")
        _ok(f"@function_tool blocked, wrapped body never ran → {exc}")
    store.store_bundle(TENANT, allow_bundle)

    # --- Audit evidence ----------------------------------------------------
    _banner("Audit chain")
    verdict = audit.verify_chain()
    if not verdict["valid"]:
        _fail(f"audit chain failed verification: {verdict['failures']}")
    _ok(f"audit chain verified: {verdict['checked']} tamper-evident events")

    print("\n\033[32mAll invariants held across both framework adapters.\033[0m")
    print("Same gate, two call shapes; denied calls ran no side effect.")
    print(f"(audit log: {audit.path})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
