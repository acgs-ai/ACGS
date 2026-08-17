# Project grounding — Cordis-style lifecycle patterns vs govern-zone kernel

All quotes from **origin/master @ fd2d5e86f** (fetched 2026-08-15) via `git show`, unless noted.
Working tree is behind master; nothing below was read from the working tree.

## Incumbent

No plugin framework, no dispose/unload/reload machinery anywhere in `gove_zone`:
grep for `dispose|unregister|teardown|reload|hot|restart|refresh|watch` across
`packages/gove-zone/src/gove_zone/*.py` returns only docstring words ("unregistered",
"watchdog") — zero lifecycle APIs. Registration is add-only and fail-closed on duplicates:

- `packages/gove-zone/src/gove_zone/tool.py:156-160`:
  "Register *fn* under *name*. Raises if *name* is already registered." — `ToolRegistry` is a plain dict, no `unregister`.
- `packages/gove-zone/src/gove_zone/gateway.py:424-437` (`UniversalGateway.register_tool`):
  "Fail-closed on duplicates … silently replacing a tool would leave stale sealed handles
  for the same name in circulation." — the *reason* there is no re-registration is a security
  invariant (stale `SealedTool` handles), not an oversight.
- `gateway.py:117-124`: one-shot grants are already scoped, not global:
  `_ACTIVE_GRANT: contextvars.ContextVar[_GateGrant | None]` — "One-shot execution grant
  bound to a specific SealedTool *instance* … a stale same-named handle — finds no usable
  grant and is detected as a bypass." Grants are identity-bound (`sealed is ...`), so replaced
  registrations are already treated adversarially (gateway.py:143-147).
- `kernel.py:68-136`: `Kernel` is instance-scoped — policy/audit/registry/actor injected via
  constructor; no module-level kernel. Per-dispatch watchdog creates and discards its own
  `ThreadPoolExecutor` (`kernel.py:459-468`, `ex.shutdown(wait=False)`) — no long-lived timer/thread state.
- `adapters/mcp_gateway.py:341-343`: session lifecycle is GC-based, not explicit disposal:
  `self._sessions: WeakKeyDictionary[ServerSession, SessionContext] = WeakKeyDictionary()` —
  "A WeakKeyDictionary keys on identity" to prevent cross-session actor bleed; entries die with the session object.
- `adapters/mcp_gateway.py:285-296` (`SessionContext`): "Keying this per session (not
  process-global) means the streamable-HTTP transport swap cannot introduce cross-session actor bleed." Each session gets its own `Kernel` (`principal: str; kernel: Kernel`).
- `packages/acgs-control-plane` exists on origin/master only as a **private submodule gitlink**
  (`.gitmodules`: url `https://github.com/acgs-ai/acgs-control-plane.git`, branch main) — contents not surveyable from this repo.

## Scoping (pattern 3 incumbent)

Tenant + policy-bundle scoping exists and is **per-call construction**, not scoped services:

- `tenant.py:127-160` (`evaluate_tenant_action`): loads the tenant's bundle from disk on every
  call (`policy = store.load_bundle(tenant_id, requester_tenant_id)`), then builds a throwaway
  kernel: `kernel = Kernel(policy=policy, audit=audit_store, actor=actor)`. Cross-tenant reads
  fail closed: `tenant.py:96-100` "Cross-tenant access blocked: tenant {requester} cannot load
  bundle for tenant {tenant_id}" (PermissionError).
- `tenant.py:55` `TenantPolicyStore` is explicitly a "Fixture store for active policy bundle
  lookups by tenant ID" — filesystem-per-tenant-dir, self-described fixture, not a service.
- Module-level mutable state sweep: grep `lru_cache|@cache|global |^_X = {` over
  `gove_zone/**` finds only immutable lookup tables (`metrics.py:51 _TRUTHY`,
  `proofpack.py:528`, `gateway.py:1328 _JSON_TYPES`). **No process-global singletons.**

## Policy-change propagation (pattern 4 incumbent)

Bundle is pinned at process start; a policy change today = process restart:

- `adapters/mcp_gateway.py:193/223/251`: `load_gateway_config(path)` →
  `policy = _load_policy_bundle(bundle_data, source=str(bundle_path))` → frozen into
  `GatewayConfig(policy=...)` once.
- `adapters/mcp_gateway.py:378`: each new session's kernel is built from that frozen config:
  `kernel=Kernel(policy=self._config.policy, audit=self._audit, actor=principal)` — no watch,
  no refresh, no re-read path anywhere (grep above).
- `adapters/mcp_gateway.py:322-330` (`GovernedGateway.__init__`): "Construct with a resolved
  GatewayConfig and an **already initialised** downstream ClientSession (injected so tests can
  wire an in-memory fixture…)" — constructor injection is the existing DI idiom.

## Convention fit

- `integration.py:1-28` declares itself "the **single canonical adapter** between agent-runtime
  hook payloads (Claude Code PreToolUse, Codex apply_patch, generic A2A/MCP tool events) and the
  gove-zone governance kernel… Hooks MUST go through this module rather than calling
  kernel/audit primitives directly. The contract here is the integration boundary; the kernel is
  implementation detail." Adapters are **stateless functions** (`emit_receipts_for_hook`,
  `make_langgraph_tool_node`), not long-lived registered objects — nothing to unload.
- `integration.py:18-24`: adapter is "fail-closed by default: with no gate mode configured it
  runs in enforce mode" — any state-machine "inactive" transition would have to preserve
  fail-closed semantics (inactive must mean DENY, not skip).
- Prior decisions: `docs/adr/` has 0001-0010 + saas-* build-vs-buy — **none** cover plugin
  architecture, DI, lifecycle, or hot reload (filename scan). grep for
  `hot.reload|plugin framework|dependency injection` across `docs/` on origin/master: zero hits.
- Zero `TODO|FIXME|HACK|XXX` in `gove_zone/**` source (grep returned nothing).

## Migration cost / compatibility

- Cordis itself (MIT, TypeScript) would only ever touch `acgi-ai/` (React 19 + Vite frontend);
  no frontend plugin system observed in this survey — the live question is Python pattern adoption only.
- The add-only registry semantics are load-bearing security behavior with dedicated wording in
  both registries (tool.py:157, gateway.py:431-433) and grant-identity checks built around the
  assumption that replacement is *illegitimate* (gateway.py:143-147: "a stale handle left over
  from a replaced registration can never consume a grant"). Revertible-effects/hot-swap would
  invert that assumption and touches security-sensitive files listed in
  `.claude/rules/security-sensitive-files.md` (kernel.py, policy.py, tenant.py, integration.py) —
  negative-path tests + docs updates are mandatory per that rule.
- Per-call construction (tenant.py) and per-session construction (mcp_gateway.py) mean there is
  little long-lived state to leak today; the disposal problem Cordis solves barely exists yet.

## Incumbent pain

- Thin. No TODO/FIXME markers, no open reload complaints found in-repo. The one concrete gap:
  a policy-bundle version change in the MCP gateway pilot requires process restart
  (bundle frozen in `GatewayConfig` at `load_gateway_config`, mcp_gateway.py:193-251), and
  existing sessions would keep their constructed-at-session-start kernels (line 378) even
  across a restart-free reload — that is the only real touchpoint for pattern 4.
- `TenantPolicyStore` self-labels as a fixture (tenant.py:55) — per-tenant scoped services
  (pattern 3) have no production-grade incumbent, only this filesystem fixture.
- Note: control-plane submodule contents (sessions/Alembic/policy_bundles per memory index)
  were NOT surveyable from this repo; any lifecycle machinery there is unverified.
