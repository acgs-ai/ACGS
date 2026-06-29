# A2A Receipt-Gated Delegation

Wave 3 (Plug). An honest agent→agent delegation boundary built by **pure
composition** over the gove-zone kernel — no kernel surgery, no new gate logic.

## What it proves

A *remote* agent runs a delegated action **only** through the gove-zone gate,
bound to the **delegating** principal. The mechanism:

1. **Delegating side** (`mint_delegation`): Agent A mints a Decision Receipt that
   binds the delegated action + exact args to A's identity (the receipt's
   `actor`/proposer), under a same-tenant policy, with a distinct MACI validator.
   The receipt may be Ed25519-signed.
2. **Remote side** (`GovernedA2AServer.accept_delegation`): Agent B runs the
   registered handler **only** via `execute_with_receipt`, passing the
   transport-authenticated caller id as `expected_actor` — **never**
   `receipt.actor`. No valid receipt for *this* delegating actor → the remote
   side effect never runs.

Fail-closed vectors the demo exercises (handler stays un-run in every one):

| Scenario | Why it's blocked |
|---|---|
| No receipt | gate refuses execution with no receipt |
| Wrong delegator | receipt minted for `planner`, transport authenticates `impostor` → actor mismatch |
| Substituted args | receipt for `{fields:[price]}`, remote asked to run `{fields:[price,liability]}` → argument mismatch |
| Tampered/forged signed receipt | signature attests the original hash; a recomputed hash cannot be re-signed without the private key → invalid signature |

## The A2A contract it mirrors

It models the A2A delegation shape — a client agent delegates a task to an
AgentCard-identified remote agent — **without depending on the `a2a` SDK**, by
design. There is no transport, no JSON-RPC, and no AgentCard discovery endpoint
here. Same discipline as the kernel's other integration demos: mirror the
contract, compose the gate.

## Trust boundary (load-bearing)

`authenticated_delegator` MUST originate from a transport authentication
mechanism (mutual TLS, signed JWT, A2A handshake). This adapter **consumes** an
already-authenticated identity; it does not establish one. The gate binds the
receipt to that value but cannot itself authenticate it — supplying an
unauthenticated or caller-chosen string voids the actor-binding guarantee.

## Scope (honest)

This is a **mechanism demonstration**, not a compliance artifact. It is not
certified, not production-ready, and not regulator-ready. Same-tenant delegation
only; cross-tenant A2A, multi-hop chains, and real transport authentication are
out of scope (see the design spec).

## Run

```bash
# from the monorepo root — the signed path needs the optional crypto extra
uv run --package gove-zone --extra crypto python \
    packages/gove-zone/examples/a2a_governed_delegation/demo.py
```

Exits `0` when every invariant holds; non-zero on any violation.
