# ADR 0011: Reject Cordis lifecycle-pattern adoption; use receipt-governed immutable policy-head resolution

## Status

Accepted (2026-08-15).

## Context

A proposal (design notes, 2026-08-15) suggested adopting four lifecycle patterns from
Cordis (https://github.com/cordiverse/cordis, TypeScript meta-framework) into the Python
governance kernel and adapter layer:

1. **Revertible effects** — every registration (listeners, timers, routes, model clients,
   policy rules) pairs with a disposal function, enabling leak-free hot unload/reload.
2. **Declarative dependencies + state machine** — adapters declare service dependencies
   (identity, policy, ledger, model backend) and transition to inactive when one fails.
3. **Scoped services** — tenant, regulated domain, model provider, policy bundle as
   independent scopes instead of process-global singletons.
4. **Dependency-change-triggered reconciliation** — policy version / model backend /
   signature verifier changes trigger controlled unload/reload, not process restart.

The evaluation grounded against origin/master @ fd2d5e86f and external evidence
(dossiers preserved at `docs/adr/evidence/0011-cordis-pov/`).

## Decision

**Reject** adoption of the Cordis pattern suite. The kernel already encodes a stronger
idiom for the same goals, and the one live gap has an ACGS-native answer.

- **Disposal (pattern 1) solves a problem this kernel avoids by construction.**
  Per-call kernel construction (`tenant.py:127-160`), per-session kernels via
  `WeakKeyDictionary` (`adapters/mcp_gateway.py:341-343`), and add-only registries where
  non-replacement is a load-bearing security invariant — stale `SealedTool` handles from a
  replaced registration are treated adversarially and can never consume a grant
  (`gateway.py:424-437`, `143-147`). Revertible-effects/hot-swap semantics would invert
  that invariant.
- **Dependency state machines (pattern 2)** have no mainstream Python implementation
  (build, not import); OSGi literature identifies service dynamism as the complexity that
  hurt adoption and reliability. Fail-closed dispatch already yields the required
  semantics: broken dependency → DENY. Any future "inactive" state must mean DENY.
- **Scoped services (pattern 3)** are already the platform trajectory, in DB/registry
  form rather than DI-container form: tenant-scoped scope repository (PR #374),
  one-active-root-per-scope trust (PRs #378/#380/#425), per-environment
  `EnvironmentPolicyHead` with CAS generation (PR #395). A DI-container mechanism would
  be a second, competing idiom.
- **Reconciliation (pattern 4)**: the only verified gap is the MCP gateway freezing its
  policy bundle at `load_gateway_config` (`adapters/mcp_gateway.py:193-251`) and pinning
  session kernels at construction (line 378) — a policy change today requires process
  restart. PR #395 already established the platform's lifecycle shape: immutable signed
  versions + CAS head swap through the receipt-governed mutation path. Reload is an
  audited state transition, not an in-process subscription graph. Python module hot
  reload is disqualified by stdlib documentation itself (stale instances, thread-unsafe).

The gap is closed by existing-roadmap work, not pattern adoption: per-dispatch resolution
of the active policy head in the gateway. Scoped in
`docs/superpowers/plans/2026-08-15-gateway-per-dispatch-policy-head-resolution.md`.

## Consequences

- No plugin framework, DI container, disposable lifecycle API, replacement-capable
  registry, or filesystem/module reload machinery enters the kernel.
- The gateway gains per-dispatch policy-head resolution (see plan) with fail-closed
  resolution and one pinned `(environment, generation, digest)` tuple per operation.
- Cordis itself (MIT, TS, npm 4.0.0-rc.8, API marked unstable) remains irrelevant to the
  Python kernel; the frontend has no plugin system that would host it.

## Reversal trigger

Revisit disposables and declarative-dependency state machines if the kernel grows
genuinely long-lived in-process residents: resident model-backend clients, streaming
sessions requiring policy swap without reconnect, or third-party in-process plugins.
Hard constraint on any revisit: inactive = DENY (fail-closed preserved).

## Source trail

- Evidence dossiers (project grounding, precedent/activity, external evidence, repo
  profile): `docs/adr/evidence/0011-cordis-pov/`
- Grounded at origin/master fd2d5e86f, 2026-08-15; tracker = acgs-ai/ACGS.
