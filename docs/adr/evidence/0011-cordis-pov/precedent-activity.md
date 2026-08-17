# Precedent & Activity Dossier — Cordis-style plugin lifecycle patterns

Scouted 2026-08-15. Method notes:
- Canonical tracker is **acgs-ai/ACGS** (git remote origin). The `dislovelhl/ACGS` handle in
  the brief resolves to a stale private repo with 1 PR total — searched there first, near-empty;
  re-ran everything against acgs-ai/ACGS.
- Local checkout is behind origin/master (ADRs 0008–0010 and saas-* docs absent locally);
  doc pass done via `git grep`/`git show` against origin/master.

## Precedent

- **No prior stance on Cordis or any plugin-lifecycle framework.** Zero hits across issues,
  PRs, ADRs, CONCEPTS.md, PLAN-MONOREPO.md, ROADMAP docs for: "cordis", "plugin" (as a
  framework topic), "hot reload", "dependency injection" (as a topic), "adapter registry",
  "scoped service". The term "plugin" appears in ROADMAP-ENFORCEMENT-SUBSTRATE.md only as
  "the advisory plugin" (the removable LLM advisory layer, lines 154, 413) — a falsifiability
  device, not a plugin system.
- **ADR corpus has no lifecycle/DI/plugin decision.** origin/master ADRs 0001–0010 cover
  kernel-of-record (0009), execution-governance layer (0010), authz, monorepo topology.
  However six `docs/adr/saas-*-build-vs-buy.md` files (billing, identity OIDC/SAML/SCIM, KMS,
  independent witness, object retention) show the team's established **build-vs-buy ADR
  pattern** — the natural vehicle if a Cordis-pattern adoption verdict is recorded.
- **PR #240 (merged 2026-07-09) — Universal Agent Gateway** is the incumbent adapter-layer
  architecture: framework-neutral chokepoint; `register_tool` returns a `SealedTool` (raw
  callable held in closure); execution needs a one-shot instance-bound gate grant; bypass
  attempts synthesized as DENY + `BypassAttemptError`. Registration is static/append-only —
  no unload, no revert-on-dispose, no reload story in the description.
- **PR #395 (merged 2026-07-30) — "govern signed policy lifecycle" (G013/P3-POLICY-001).**
  The team's chosen shape for policy-bundle lifecycle: immutable signed `PolicyVersion`
  records bound to org/project/environment; **exactly-one active `EnvironmentPolicyHead` with
  compare-and-swap generation**; publish/activate through the receipt-governed mutation path;
  registration fail-closed when the head is missing/stale/corrupt/unverifiable. i.e. lifecycle
  = DB-backed immutable versions + CAS head swap, not in-process hot reload.
- **PR #274 (merged 2026-07-11)** — roadmap refresh marking Policy PARTIAL: "versioning +
  tenant-binding shipped; signing + lifecycle missing" (state at that date; #395 later closed
  much of it).
- **Scoped services precedent is DB/registry-shaped, not DI-container-shaped:** PR #374
  (merged 2026-07-25) tenant-scoped scope repository; PR #378/#380 (merged 2026-07-25) scoped
  receipt-v2 trust with one-active-root-per-scope partial unique index
  (`0004_managed_trust_v2`); PR #425 (merged 2026-07-31) wires scoped trust into the HTTP
  request path. PR #235 (merged 2026-07-07) enterprise IAM: IdP adapters + RBAC.
- **PR #265 (CLOSED 2026-07-11)** — Wave 3 A2A receipt-gated delegation adapter; closed
  unmerged (part of a batch sweep), the only adapter-registry-flavored PR that didn't land.
- docs/ROADMAP.md (origin/master, row "Policy: signed bundles and versioned policy registry",
  🟡 PARTIAL [6]): wants "active/stale/revoked states, tenant binding tests"; risk column:
  "Receipts may bind hashes but **operators lack lifecycle controls**."

## Incumbent pain & exposure

- **Adapter-bypass gap, named in PR #240's own body (2026-07-09):** "gove_zone.mcp and
  adapters/{langgraph,autogen} route through the unsigned `Kernel.dispatch` loop (the known
  adapter-bypass gap)". Per-framework adapters were duplicate live paths beside the strong
  gate — the team's recorded adapter-layer pain is *bypass/duplicate-path*, not reload/leaks.
- **Issue #392 (opened → closed 2026-08-04 via PR #425):** scoped-trust primitives existed
  and were fail-closed, but the HTTP integration was intentionally disabled
  (`canonical_path_enabled = False`); `execute_with_receipt` had exactly one in-package call
  site and `ManagedMutationUnitOfWork` had **zero non-test callers** — a documented
  built-but-not-wired lifecycle gap on the request path (since closed).
- **No tracker evidence of hot-reload/restart-required/resource-leak/duplicate-registration
  pain.** Searches for "reload", "hot reload", "reconcil", "adapter registry", "lifecycle"
  (issues) return no such complaints, open or closed.
- **Tracker is currently near-empty:** 1 open issue (#167, GCP WIF production-deploy setup,
  2026-07-07), 0 open PRs. Any live pain is not being tracked in GitHub issues.

## Gaps / caveats

- Read PR/issue descriptions only (no diffs, per brief); "no reload story" claims reflect
  descriptions, not code.
- dislovelhl/acgs (stale repo) contains one open PR "Multi tenant enterprise security"
  (2025-10-12) — predates the canonical repo's IAM work; ignored as stale.
