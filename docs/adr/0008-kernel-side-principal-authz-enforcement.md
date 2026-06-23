# ADR-0008: Kernel-side principal AUTHZ enforcement (first slice)

- Status: Accepted
- Date: 2026-06-23
- Relates to: ADR-0005 (AUTHZ propagation, Accepted), `AUTHZ-ROADMAP.md` (R1, R3)
- Distinct from: ADR-0007 (AUTHZ trace cryptographic core — targets
  `acgs_governance_eval_mvp/governance/crypto/`, a different codebase and a
  different concern: signed `AuthorizationTrace` hops, not a kernel actor check)

## Context

The gove-zone kernel **records** the acting identity on every decision
(`Kernel.actor` → `ToolCall.actor` → `DecisionRecord.actor`) but never **asks
whether that actor is allowed to act**. Policy evaluates the call's content; it
does not authorize the principal. This is the gap B13 (roadmap) and requirement
**R1** ("agent principals must be first-class authorization subjects with
explicit, bounded permissions") name. `AUTHZ-ROADMAP.md` also names the
enforcement seam **R3** and its kill-switch **`AUTHZ_ENFORCE`**.

The full R1–R7 program (delegation R2, aggregation R4, workflow/temporal/recovery
traces R5–R7, a per-data-boundary capability taxonomy) is large and partly
harness-level. We need a first slice that closes the most basic gap —
"unauthorized principal acted" — without boiling the ocean, and without changing
default behavior for the existing API.

## Decision

Add a stdlib-only `gove_zone.authz` module (`PrincipalRegistry`,
`PrincipalEntry`, `AuthzReason`, `authz_enforce_from_env`) and two new,
default-safe `Kernel` constructor params: `authz_enforce: bool = False` and
`principal_registry: PrincipalRegistry | None = None`.

- **Off by default.** When `authz_enforce` is `False`, the kernel never consults
  the registry and behaves byte-for-byte as before (the 588-test baseline is
  unchanged).
- **Fail-closed when on.** The check sits at the top of `_evaluate_only` (shared
  by `dispatch` and `simulate`), *before* policy evaluation. An actor that is not
  a registered, tool-authorized principal yields a synthesized
  `fail-closed/authz` DENY with `matched_rules=("AUTHZ_DENY:<reason>",)`; the
  DENY is attached and audited like any other decision and flows through the
  existing `DeniedError` path (already handled by `mcp_tools_call`).
- **Misconfiguration fails closed at construction:** `authz_enforce=True` with no
  registry raises; an unreadable/malformed registry raises at `from_json`.
- **Scope:** authorizes the integrator-set `Kernel.actor` (a per-kernel
  identity), **not** a per-call claim — a request must never assert its own
  identity (spoofing vector).
- **No `DecisionRecord` schema change** — reuses `matched_rules` + `reason`.

## Consequences

- **+** Closes the recorded-but-not-enforced actor gap (R1) with a fail-closed,
  opt-in switch; no behavior change for existing callers; wired in the real
  dispatch path with a dispatcher-level negative-path test.
- **−** Coarse: one identity per kernel instance, not per-request principals.
- **Deferred (explicitly NOT delivered here, so AUTHZ is not "done"):**
  - the `executor.py` receipt-gate path (a separate downstream surface);
  - per-call principal identity from the MCP request;
  - R2 delegation, R4 aggregation, R5–R7 traces, full R3 capability taxonomy;
  - a CI guard that fails if `AUTHZ_ENFORCE` is left off in an enforcing
    deployment (`AUTHZ-ROADMAP.md` open question 3).
