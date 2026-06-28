# Wave 3 (Plug) — A2A Receipt-Gated Delegation: Design Spec

**Status:** DESIGN — pending adversarial review before implementation.

## Goal

Close the agent-stack map's `thin` A2A row (today: a docstring mention in
`integration.py`, no adapter) with an honest, evidence-backed `exists`: a real
**agent→agent delegation boundary** where the *remote* agent runs a delegated
action **only** through the gove-zone gate, bound to the **delegating** principal.
No valid Decision Receipt for *this* delegating actor → the remote side effect
never runs.

## Non-negotiable constraints

1. **Pure composition — no kernel surgery.** Compose the existing PUBLIC
   primitives only. Do NOT modify `receipt.py`, `executor.py`, `tenant.py`,
   `decision.py`, or `integration.py`. The adapter calls them; it does not
   reimplement gate logic. (Dangerous-zone discipline: the gate stays sealed.)
2. **Zero runtime deps.** gove-zone is `dependencies = []`. Signing uses the
   optional `crypto` extra (lazy `cryptography` import in `signing.py`); the
   adapter must import-safe without it and only require it on the signed path.
3. **No real A2A SDK.** Mirror the A2A delegation *contract* (client agent →
   AgentCard-identified remote agent → delegated task), not the `a2a` package —
   same discipline as the Wave 2 LangGraph adapter.
4. **MACI preserved.** The receipt's proposer (`actor`) = the delegating agent;
   the `validator` MUST be a distinct principal (mint fails closed otherwise,
   receipt.py:282-287). The adapter must never let proposer == validator.
5. **`expected_actor` comes from the AUTHENTICATED transport identity**, NEVER
   from the receipt (executor.py:41-49; the load-bearing anti-forgery anchor,
   proven by `test_gate_refuses_actor_rewrite_forgery`). The adapter's remote
   handler takes the authenticated caller id as a *separate argument* from the
   receipt.
6. **Cross-boundary = signed.** A2A crosses trust boundaries, so the headline
   path mints a signed receipt (`Ed25519Signer`) and the remote gate verifies
   with `require_signature=True` + a trusted verifier.
7. Claim-safety: README states mechanism, not compliance; "no real a2a dep, by
   design"; no "certified/production-ready/compliant".

## Verified gate API (from recon; file:line authoritative — re-read before coding)

- Mint (delegating side): `evaluate_tenant_action(store, tenant_id, requester_tenant_id, action, args, execution_boundary, request_id, actor, *, validator: Validator, authority: str, audit_store: ChainHashAuditStore, goal="", expires_at="", signer: ReceiptSigner | None=None) -> DecisionReceipt` (`tenant.py:106-122`). Self-validation guard at `tenant.py:136-141`.
- Gate (remote side): `execute_with_receipt(tool_fn, args, receipt, *, expected_tenant_id, expected_execution_boundary, expected_action, expected_actor, expected_audit_hash=None, expected_policy_hash=None, expected_policy_bundle_id=None, verifier=None, require_signature=False) -> Any` (`executor.py:17-31`). Runs `tool_fn(**args)` only if `receipt.verify(...)` does not raise (`executor.py:75`).
- `Validator(validator_id: str, role: str = "validator")` — empty id/role rejected (`receipt.py:69-86`).
- `Ed25519Signer.generate()` / `.from_public_bytes(...)` (`signing.py`); needs `crypto` extra.
- `ChainHashAuditStore(path)` (`audit.py`).

Fail-closed guarantees the gate already provides (the adapter must EXERCISE, not reimplement):
- missing receipt → `ReceiptValidationError("No receipt provided…")` (executor.py:55-56)
- wrong delegating actor → `"actor mismatch…"` (receipt.py:444-448)
- caller == validator → `"self-validation: validator is the invoking principal…"` (receipt.py:449-452)
- wrong action → `"Action mismatch…"` (receipt.py:514-517)
- substituted args → `"argument mismatch…"` (receipt.py:577-584)
- tampered hash → `"receipt_hash mismatch"` (receipt.py:389-393); bad signature → `"invalid signature"` (receipt.py:432-433)

## Module: `packages/gove-zone/src/gove_zone/a2a.py` (new, additive)

```python
@dataclass(frozen=True)
class AgentCard:
    """Minimal A2A-shaped identity for a remote agent (no discovery service)."""
    agent_id: str
    execution_boundary: str
    capabilities: tuple[str, ...] = ()      # action names the remote agent serves

@dataclass(frozen=True)
class DelegatedTask:
    action: str
    args: Mapping[str, Any]
    declared_goal: str = ""

class A2ADelegationError(Exception):
    """Raised when a delegated task is not admissible at the remote boundary.
    Wraps the underlying ReceiptValidationError so callers get one A2A-level type."""

def mint_delegation(
    *, store, audit_store,
    delegating_actor: str,                  # → receipt.actor (proposer)
    task: DelegatedTask,
    tenant_id: str, execution_boundary: str, request_id: str,
    validator: Validator,                   # MUST differ from delegating_actor
    authority: str,
    signer: "ReceiptSigner | None" = None,
) -> "DecisionReceipt":
    """Delegating side: mint a (optionally signed) DecisionReceipt that binds the
    delegated action+args to the delegating agent. Composes evaluate_tenant_action.
    Raises if validator == delegating_actor (MACI; surfaced from the kernel)."""

class GovernedA2AServer:
    """Remote side: accepts delegated tasks and runs them ONLY via the gate."""
    def __init__(self, *, card: AgentCard, tenant_id: str,
                 verifier=None, require_signature: bool = False): ...
    def register(self, action: str, fn: Callable[..., Any]) -> None: ...
    def accept_delegation(
        self, *, authenticated_delegator: str,   # from transport handshake, NOT the receipt
        task: DelegatedTask, receipt: "DecisionReceipt | None",
    ) -> Any:
        """Run task.action(**task.args) iff the gate admits the receipt for
        authenticated_delegator. Calls execute_with_receipt with
        expected_actor=authenticated_delegator, expected_action=task.action,
        args=task.args, expected_tenant_id/boundary from this server.
        Raises A2ADelegationError (wrapping ReceiptValidationError) on any
        fail-closed vector. The registered fn is reachable ONLY through this gate."""
```

**Critical wiring invariants (review these hardest):**
- `accept_delegation` passes `args=task.args` to BOTH the gate and (via the gate) the fn — the gate binds them; the server never calls the registered fn outside `execute_with_receipt`.
- `expected_actor=authenticated_delegator`, a parameter SEPARATE from `receipt`. A receipt whose `actor` ≠ `authenticated_delegator` is rejected by the kernel — the server must not "fix up" the mismatch.
- `require_signature` + `verifier` are the server's policy, not the receipt's — a caller cannot downgrade them.
- The server refuses actions not in `card.capabilities` BEFORE gating? No — register is the source of truth; unknown action → the gate/registry raises. Keep capabilities advisory (for the AgentCard shape), the registry authoritative.

## Example + README

- `packages/gove-zone/examples/a2a_governed_delegation/demo.py` — runnable, local-only:
  - Agent A (`planner`) delegates `contract.redline` to remote Agent B (`legal-svc`) across a simulated A2A boundary.
  - **Happy path:** mint signed receipt (Ed25519) bound to `planner` → B's `accept_delegation(authenticated_delegator="planner", ...)` runs the action → print result + persisted receipt + verify audit chain.
  - **Fail-closed scenarios**, each prints BLOCKED + the kernel reason, executor spy stays empty:
    1. No receipt.
    2. Wrong delegator (receipt minted for `planner`, transport authenticates `impostor`).
    3. Substituted args (receipt for `{fields:[price]}`, B asked to run `{fields:[price,liability]}`).
    4. Tampered receipt (mutate a field; signature/hash check rejects).
  - `sys.exit(0)`; requires `crypto` extra for the signed path (README documents it).
- README: what it proves, the A2A delegation contract it mirrors, the honest scope line (no real `a2a` dep, mechanism not compliance), run command.

## Tests: `packages/gove-zone/tests/test_a2a_delegation.py`

Drive `GovernedA2AServer.accept_delegation(...)` (NOT `execute_with_receipt` directly — handler-wiring rule). A spy executor records calls.

- `test_delegation_allows_authenticated_delegator_and_runs` — happy path (unsigned, same domain): spy called once with the bound args; result returned; receipt persisted (`audit_store` chain verifies).
- `test_delegation_no_receipt_fails_closed` — `receipt=None` → `A2ADelegationError`; spy empty.
- `test_delegation_wrong_delegator_fails_closed` — receipt minted for `agent-A`, `authenticated_delegator="agent-B"` → `A2ADelegationError` (actor mismatch); spy empty.
- `test_delegation_substituted_args_fails_closed` — receipt for args X, task carries args Y → `A2ADelegationError` (argument mismatch); spy empty.
- `test_delegation_signed_forgery_rejected` — signed path with `require_signature=True`; a tampered/re-signed-with-wrong-key receipt → `A2ADelegationError`; spy empty. (Needs `crypto` extra; the gove-zone dev install bundles it.)
- `test_mint_self_validation_forbidden` — `mint_delegation` with `validator == delegating_actor` → raises (MACI), surfaced from kernel.

All fail-closed tests assert BOTH the raise AND the spy emptiness (the un-run side effect is the real proof).

## Verification (must pass + paste literal output)

```
uv run --package gove-zone --extra dev --extra crypto python -m pytest packages/gove-zone/tests/test_a2a_delegation.py -q
uv run --package gove-zone --extra dev --extra crypto python -m pytest packages/gove-zone/tests -q      # full suite, no regression
uv run --package gove-zone --extra crypto python packages/gove-zone/examples/a2a_governed_delegation/demo.py   # exit 0
uv run --package gove-zone ruff check src/gove_zone/a2a.py examples/a2a_governed_delegation tests/test_a2a_delegation.py
uv run --package gove-zone --extra crypto mypy src/gove_zone/a2a.py     # strict; a2a.py is in the typed surface
make lint-docs                                                          # docs gate (README/example smoke)
```

## Out of scope (named, not silently dropped)

- Real `a2a` SDK transport / JSON-RPC / AgentCard discovery endpoint (contract-only here).
- Multi-hop delegation chains (A→B→C). Single hop only.
- Updating the stack-map `thin → exists` row (lives on PR #182; separate follow-up).
