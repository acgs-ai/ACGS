# Plan: Gateway per-dispatch policy-head resolution

Date: 2026-08-15
Decision record: `docs/adr/0011-reject-cordis-lifecycle-patterns.md`
Grounding: origin/master @ fd2d5e86f (this plan cites master line numbers; implement from
a fresh branch off `origin/master`, not from a stale checkout).

## Objective

Replace process-start policy pinning in the long-lived MCP gateway with per-dispatch
resolution of the active `EnvironmentPolicyHead`, using the immutable signed-policy and
CAS-generation model established by PR #395.

This is not hot reload, module reload, a subscription graph, or a disposable lifecycle
framework. It is an audited lookup of the currently authorized immutable policy version
at a request boundary.

## Current state (verified touchpoints)

- `packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py:193-251` —
  `load_gateway_config(path)` loads and verifies the policy bundle once, freezing it into
  `GatewayConfig(policy=...)` for process lifetime.
- `adapters/mcp_gateway.py:378` — each new session's kernel is built from that frozen
  config: `kernel=Kernel(policy=self._config.policy, audit=self._audit, actor=principal)`.
  Sessions therefore pin a policy for their entire lifetime.
- `adapters/mcp_gateway.py:322-330` — constructor injection is the existing DI idiom
  (`GovernedGateway.__init__` takes a resolved config + initialised downstream session);
  the resolver injects here.
- `EnvironmentPolicyHead` + CAS generation + receipt-governed activation live in
  **acgs-control-plane** (private submodule, PR #395). Not surveyable or editable from
  the parent repo.
- Note: the kernel class is `Kernel` (`kernel.py:68-136`), not `GovernanceKernel`.

## Repo-boundary split (hard constraint)

Two lanes, two repos, committed separately:

**Lane A — `packages/gove-zone` (parent repo; zero-runtime-deps constraint applies):**
1. `ResolvedPolicy` frozen dataclass: `environment_id`, `generation`, `bundle_digest`,
   `kernel: Kernel`.
2. `ActivePolicyResolver` Protocol (async `resolve(*, environment_id) -> ResolvedPolicy`;
   fail-closed contract in docstring).
3. `StaticPolicyResolver` reference implementation wrapping today's frozen-bundle
   behavior (generation pinned at load) — preserves existing single-bundle deployments
   and gives tests an in-memory fixture.
4. Gateway rewiring: session context stores `principal` only; kernel selection moves to
   the dispatch path via the resolver. Bounded cache
   `(environment_id, generation, bundle_digest) -> Kernel`; cache never decides
   freshness — every dispatch reads the authoritative head first.
5. Streaming: pin the resolved tuple for the stream's documented authorization lifetime;
   no mid-stream policy change.

**Lane B — `acgs-control-plane` (private submodule, separate branch/PR):**
6. DB-backed `ActivePolicyResolver` implementation against `EnvironmentPolicyHead`
   (#395): read head (generation + digest) → load immutable bundle by digest → verify
   signature/scope/trust-root/digest → optionally re-read head if no consistent snapshot
   → accept only self-consistent snapshots. A concurrent CAS swap yields the complete
   old or complete new snapshot, never mixed (TOCTOU defense).

## Required semantics (acceptance contract)

1. **Resolve at the dispatch boundary** — head read + bundle resolution + validation
   before authorization for every new dispatch; kernel constructed/retrieved only after
   validation succeeds.
2. **Pin one version per operation** — exactly one
   `(environment, head generation, bundle digest)` tuple per dispatch; a CAS-head change
   during an in-flight dispatch does not alter it; new head applies to the next dispatch.
3. **Fail closed** — missing head, unknown bundle, signature failure, trust-root
   mismatch, malformed generation, or inconsistent head/bundle linkage denies. Never
   fall back to the startup bundle. No "last known good" unless a separately governed
   availability policy authorizes it explicitly.
4. **Preserve security invariants** — registries stay add-only; no replacement API;
   stale `SealedTool` handles still cannot consume grants; a head transition selects a
   different immutable kernel, it never mutates registrations inside an existing one;
   identity and tenant/environment scope stay server-derived.
5. **Mutation stays receipt-governed** — head changes only via the existing signed,
   receipt-producing CAS path. The gateway gains no `reload`/`watch`/`unregister`/
   mutable-override endpoint. Filesystem watching and Python module reload out of scope.

## Observability

Each governed dispatch emits: environment id, head generation, bundle digest, resolver
outcome, denial reason category on failure, and the mutation-receipt / head-transition
reference where the evidence model supports it. Never emit policy contents, credentials,
raw prompts, grant secrets, or sensitive tenant metadata.

## Test matrix (minimum)

Dispatcher-level (through the gateway path, not direct unit calls — handler-wiring rule):

- Same generation across successive dispatches reuses the cached immutable kernel.
- CAS head swap → next dispatch uses new bundle, no process restart.
- In-flight dispatch stays pinned to old verified version during a swap.
- Concurrent swaps never produce a mixed head/bundle snapshot.
- Denies: missing head; unknown digest; invalid signature; wrong environment/tenant
  scope; rolled-back / non-monotonic generation (per #395 contract); repository timeout
  or partial read; cached old kernel present but new head invalid (deny, don't serve
  cache).
- Stale `SealedTool` handle still cannot consume a grant after a head transition.
- Duplicate registration / replacement remain unavailable.
- Restart vs non-restart paths produce identical authorization decisions for the same
  immutable head.
- Audit evidence records the exact generation and digest used.
- Negative-path proof that the denied side effect did NOT run (security-sensitive-files
  rule).

## Gates

- Lane A: `uv run --package gove-zone python -m pytest packages/gove-zone/tests
  --import-mode=importlib -q` (sync with `--extra crypto --extra dev` first — gove-zone
  has zero runtime deps).
- Lane B: control-plane package gates inside the submodule, including the live-PG
  evidence gate (SQLite skips mask PG-only behavior).
- Docs after code verified: `docs/SECURITY_MODEL.md` (policy binding at gateway),
  `docs/CLAIMS.md` (wording stays local-proof-scoped). State explicitly: policy bundle
  binding changed at the gateway resolution point; receipt schema unchanged.
- Security-sensitive surface (`mcp_gateway.py`, `kernel.py` untouched ideally) — review
  lane separate from implementer.

## Non-goals

Cordis adoption; general-purpose plugin lifecycle APIs; DI containers; Python module hot
reload; filesystem/DB change subscriptions; mid-request policy mutation;
replacement-capable registries; third-party in-process plugins; policy editing through
the gateway.

## Completion gates

Done only when: policy changes take effect for new gateway dispatches without restart;
every dispatch attributable to one verified immutable generation + digest; all resolution
failures deny rather than fall back; existing add-only-registration and stale-handle
security tests stay green; concurrency tests show no mixed-version authorization; no
generic lifecycle framework introduced.
