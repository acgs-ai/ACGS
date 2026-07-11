# Governed-MCP Gateway — Gap Analysis (SWOT Recommendation 3)

> Status: analysis only. Product stage is **alpha**; nothing here claims production-readiness,
> certification, or compliance approval (see `docs/CLAIMS.md`, `AGENTS.md`).
> Date: 2026-07-03. Companion to [swot-gove-zone.md](swot-gove-zone.md) (Recommendation 3:
> "Ship the governed-MCP gateway as the flagship integration") and
> [startup-canvas-gove-zone.md](startup-canvas-gove-zone.md).

Every claim below maps to a file:line actually inspected on the current working tree
(branch `feat/governed-vulnclaw-pentest`, dirty tree owned by other sessions — line
numbers are as-read on 2026-07-03).

---

## 1. Current-state map

Two distinct MCP-adjacent artifacts exist today. **Neither is a gateway** in the sense a
design partner could put in front of an arbitrary MCP server.

### 1.1 `acgs_governance_eval_mvp/governed_mcp_v0/` — a governed *fixture MCP server*

What it is: a self-contained MCP **server** whose own ten tools are governed. It is an
eval harness, not a proxy for someone else's server.

| Capability | Evidence |
|---|---|
| Admission gate on every guarded tool: tool→action mapping, deny raises `GovernanceDenied` | `server.py:50-107` (`GovernedMCPServer.admit`) |
| Fail-closed on malformed args, unknown tool, tool/action mismatch, and policy-engine exceptions | `server.py:53-94` (`except Exception → decision="deny", "fail closed: …"`) |
| Per-decision receipt + hash-chained audit JSONL, fail-closed on persistence errors; exclusive receipt write treated as corruption signal | `server.py:109-182` (`_record_decision`, `GovernanceStorageError` at `server.py:160-169`) |
| Denials are recorded too (deny receipts + audit events) | `server.py:95-107` |
| Deterministic policy engine — **hardcoded fixture allowlists** (sandbox paths, `@example.test` email, `sandbox-api`/`sandbox` deploy, two-command shell allowlist) | `policy.py:17-101` |
| Offline replay verification: re-derives chain hashes, receipt hashes, and checks each ALLOW left the exact recorded side effect (file hash, outbox row, deploy state, github mutation) | `verify.py:125-188`, effect checks `verify.py:42-122` |
| FastMCP stdio binding (optional import; returns `None` when the `mcp`/`fastmcp` runtime is absent) registering 10 fixture tools | `mcp_server.py:34-57`, `__main__` stdio loop `mcp_server.py:62-66` |
| Executable eval scenarios incl. tamper detection (receipt tamper, chain tamper, missing receipt, effect tamper) and fail-closed policy explosion | `eval_gate.py:29-284` |
| Escalation *signal* exists only as an `approval_required` flag surfaced through the graph loop | `eval_gate.py:236` (`approval_request.approval_required is True`); no pending/approve/resume mechanism |

What it is **not** (verified absences):

- **Not a proxy.** There is no code path that forwards `tools/call` to a downstream MCP
  server; the facade's tools *are* the side effects (`server.py:184-264`).
- **Receipts are unsigned.** No signature field, no signer anywhere in the package
  (`server.py:136-146` receipt core: hashes only). The gove-zone Ed25519 signed-receipt
  machinery is not used here.
- **Two receipt formats.** `governed_mcp_v0` receipt fields (`server.py:136-146`) are a
  different schema from gove-zone's `DecisionReceipt` (`packages/gove-zone/src/gove_zone/receipt.py`)
  — the repo's own spec (`docs/DECISION_RECEIPT_SPEC.md`).
- **No escalate decision.** Policy returns only `allow`/`deny` (`policy.py:26-101`).
- **No tenant / actor / boundary binding.** `AdmissionDecision` (`models.py:26-42`) carries
  no actor, tenant, or execution-boundary fields.
- **FastMCP path untested.** The import is `pragma: no cover` optional
  (`mcp_server.py:35-43`); no test exercises a real MCP runtime over stdio.

### 1.2 `packages/gove-zone/` — kernel with an MCP *payload shape parser* and an in-process *pattern demo*

The kernel has the strongest primitives, but its MCP surface is a parse branch plus two
demos, not a deployable component.

| Capability | Evidence |
|---|---|
| Runtime-neutral payload parse incl. MCP JSON-RPC `{method:"tools/call", params:{name, arguments}}` | `src/gove_zone/integration.py:305-334` (`_tool_name_and_input_from_payload`); MCP branch `integration.py:327-334` |
| Observe-by-default / enforce gate mode; enforce fails closed on emission failure | `integration.py:64-104` (`GateMode`, `current_gate_mode`), module docstring `integration.py:18-23` |
| Signed-receipt execution gate: `execute_with_receipt` refuses without a valid receipt; `require_signature=True` is the default; binds expected tenant / boundary / action / actor (actor from runtime context, never the receipt) | `src/gove_zone/executor.py:25-50` |
| Full decision vocabulary incl. ESCALATE and TRANSFORM | `src/gove_zone/decision.py:24` |
| Escalation lifecycle primitives: `approve_escalation` (distinct human validator), `resume_with_receipt` | `src/gove_zone/escalation.py:87,206` |
| Structured rejection payloads (machine-readable deny) | `src/gove_zone/rejection.py:58` (`rejection_dict`) |
| Production posture fails closed loud when the gate has no verifier | demo assertion `packages/gove-zone/examples/mcp-tool-gateway/demo.py:323-338` (`ProductionProfileError`) |
| Tamper-evident audit chain + offline verification CLI (`gove-zone replay`), plus `gate`, `policy`, `eval`, `smoke`, `proofpack` subcommands | `src/gove_zone/cli.py:622-800` (subparser registrations) |
| In-process MCP gateway **pattern** demo: `handle_mcp_call` — two gates (audited policy decision → signed execution gate), MCP-shaped `isError` responses carrying `_meta.gove_zone.{decision, audit_hash}`, deny leaves no side effect, chain verifies | `packages/gove-zone/examples/mcp-tool-gateway/demo.py:132-229` (handler), assertions `demo.py:272-345` |
| Minimal root-repo MCP gate example (dev mode, `require_signature=False`) | `/home/martin/Documents/ACGS/examples/mcp_tool_gate/demo.py:65-104` |
| Framework adapters directory contains langgraph + autogen only — **no `mcp` adapter module** | `src/gove_zone/adapters/` (`__init__.py`, `autogen.py`, `langgraph.py`) |

Honest-scope statements already in the repo (the docs are ahead of the code here, in the
right direction):

- "The current `gove-zone` integration code supports MCP-style payload normalization.
  That is **not the same** as claiming a complete governed MCP gateway is
  production-deployed." — `docs/mcp/overview.md`
- "This shows the INTEGRATION PATTERN, not a vendored SDK. There is **no real
  `mcp`/`fastmcp` import** here" — `mcp-tool-gateway/demo.py:3-5`
- `docs/INTEGRATION_MATRIX.md:23` tiers "MCP `tools/call`" as **Shipped + tested**, backed
  by `integration.py`, `examples/mcp_tool_gate/`, `docs/mcp/` — accurate for the *payload
  parse + in-process gate*, and only for that. A gateway would need a new row with new
  evidence (matrix tier rule at `INTEGRATION_MATRIX.md:40`).

Known design wart with gateway consequences: through the hook adapter, raw tool arguments
are hashed before the policy sees them, so argument-keyed policies silently never fire;
the demo works around it via `PathBoundaryPolicy` on the lifted `call.path`
(`mcp-tool-gateway/demo.py:24-27` and README "Hook-adapter gotcha").

### 1.3 Summary verdict

Today the repo can prove, locally and honestly: *an MCP-shaped request routed through
gove-zone in-process is receipt-gated, fail-closed, deny leaves no side effect, and the
evidence chain verifies offline.* What no artifact provides: a **process a design partner
can run in front of an MCP server they did not modify.** Every existing path requires
either writing Python against gove-zone's API (pattern demo) or adopting the fixture
server (governed_mcp_v0).

---

## 2. The flagship-gateway bar

A design partner points their MCP host (Claude Desktop / Claude Code / any MCP client) at
the gateway; the gateway fronts an **arbitrary, unmodified** downstream MCP server.

1. **Transport-real.** Speaks actual MCP on both sides — stdio (subprocess downstream)
   first, streamable HTTP second — against the current MCP spec. Passes through
   `initialize`, `tools/list`, resources/prompts/notifications untouched.
2. **Receipt gate on every `tools/call`.** Parse → policy evaluate → mint receipt →
   forward downstream only on ALLOW with a validated (signed, in production posture)
   receipt. No bypass path; unknown/unparseable methods that can cause side effects are
   denied, not forwarded.
3. **Fail-closed everywhere.** Policy exception, evidence-persistence failure, missing
   signer/verifier in production posture, malformed request → deny with structured
   rejection; never forward on error.
4. **DENY / ESCALATE are enforced and usable.** Deny returns an MCP `isError` result with
   the structured rejection payload + audit hash (so the model can reason about it).
   Escalate returns a pending-approval payload with an event id; a human approves out of
   band (`approve_escalation`) and the call resumes via receipt (`resume_with_receipt`).
5. **Evidence emitted per call, including denials:** one receipt format (the gove-zone
   `DecisionReceipt` spec), hash-chained audit store, tenant/actor/boundary bound, actor
   derived from the authenticated session — never from the request body.
6. **Offline-verifiable:** gateway evidence dir exports a proof pack a third party checks
   with `gove-zone replay` / the offline verifier, with no network and no policy re-run.
7. **Config, not code:** downstream server command/URL, tenant, boundary, policy bundle,
   signer/verifier material in a config file. Target: time-to-first-governed-call < 1h
   (canvas riskiest-assumption #3).
8. **Conformance-tested at the dispatcher level** (per the repo's own tier rules and the
   handler-wiring rubric): a real MCP SDK client → gateway → real MCP SDK server test that
   asserts deny leaves no downstream side effect, allow executes exactly once, and the
   chain verifies.
9. **Claim-safe:** new INTEGRATION_MATRIX row + CLAIMS.md evidence rows; alpha status
   stated; no certification language.

---

## 3. Gap list (ranked by impact vs. effort)

| # | Gap | Evidence of absence | Impact | Effort | Pilot-blocking? |
|---|---|---|---|---|---|
| G1 | **No transport-level proxy exists.** Nothing accepts MCP traffic and forwards to a downstream server; only in-process patterns and the fixture server | §1.1/§1.2 verified absences; `adapters/` has no mcp module | Critical — this *is* the product of Rec 3 | High (largest single work item) | **Yes** |
| G2 | **No real MCP SDK anywhere in the tested path.** Optional import falls back to `None` (`mcp_server.py:35-43`); demos deliberately avoid the SDK; current-spec behaviors (streamable HTTP, notifications, pagination, progress) unverified | `mcp_server.py:35-43`; `mcp-tool-gateway/demo.py:3-5` | Critical — "works with the current MCP spec" is currently unclaimable | Medium (SDK as optional extra + conformance harness) | **Yes** |
| G3 | **Policy not partner-configurable on the MCP path.** governed_mcp_v0 policies are hardcoded fixtures (`policy.py:17-101`); the demo wires `PathBoundaryPolicy`/`RuleSetPolicy` in code | `policy.py:17-101`; `demo.py:169,255-263` | Critical — a partner cannot express *their* scope | Medium (`yaml_policy.py` + `TenantPolicyStore` exist, need gateway wiring) | **Yes** |
| G4 | **Actor identity is hardcoded, not session-derived.** Demos use constants and warn a real server must use the authenticated principal | `demo.py:80-85` (comment), `demo.py:83-86` (constants); `examples/mcp_tool_gate/demo.py:19` | Critical — receipts that bind a made-up actor are weak evidence | Medium | **Yes** |
| G5 | **Escalate not wired into any MCP flow.** Kernel primitives exist (`escalation.py:87,206`; `decision.py:24`) but no MCP response shape, no pending queue, no resume path; governed_mcp_v0 has only an `approval_required` flag (`eval_gate.py:236`) | as cited | High — deny-only gateways get disabled by users the first time they need an exception; SWOT bar names deny/escalate | Medium | **Yes** (if partner policies use escalate — assume they will) |
| G6 | **Argument-hash gotcha blocks arg-keyed policies through the hook adapter** — gateway must evaluate policy on raw MCP `params.arguments`, not the hashed hook summary | `mcp-tool-gateway/README.md` "Hook-adapter gotcha"; `demo.py:24-27` | High — silent no-fire policies are a governance hazard | Low-Medium (gateway calls evaluator directly, as gate 2 already does) | **Yes** (safety-relevant) |
| G7 | **Two receipt formats in-repo.** governed_mcp_v0's unsigned receipt schema vs. gove-zone signed `DecisionReceipt` | `server.py:136-146` vs. `receipt.py` / `docs/DECISION_RECEIPT_SPEC.md` | Medium — flagship must emit exactly one, the spec'd one | Low (choose gove-zone format; leave governed_mcp_v0 as eval harness) | No (decision now, migration later) |
| G8 | **Proof-pack export not wired to gateway evidence.** `gove-zone replay` + `proofpack` CLI exist (`cli.py:622,790`) but no "export this gateway session as a verifiable pack" flow/doc | `cli.py:622-800` | Medium — auditor story (SWOT Rec 1 synergy) | Low | No |
| G9 | **No overhead numbers for the gated call path** (SWOT W6 / Rec 4) | no benchmark artifact for MCP path found | Medium — removes integration-tax objection | Low (harness exists: `benchmark_adapters.py`) | No |
| G10 | **Docs/claims for a gateway don't exist yet** (correctly — nothing to claim). New matrix row, CLAIMS.md rows, quickstart | `INTEGRATION_MATRIX.md:23,40`; `docs/mcp/*` | Medium — matrix tier rules require example + conformance test before claiming | Low (after G1-G2) | No (but gates the *announcement*) |

---

## 4. Implementation plan (ordered work items)

Analysis-stage plan; no code written in this stage. Each item names target files and its
exit evidence. Items 1–7 constitute the pilot-blocking core (G1–G6); 8–11 are polish.

1. **Gateway skeleton (G1).** New `packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`
   (+ export in `adapters/__init__.py`): stdio↔stdio proxy first — spawn the downstream
   MCP server as a subprocess, pass through `initialize`/`tools/list`/resources/prompts,
   intercept `tools/call`. Uses the official `mcp` SDK behind an optional extra
   (`gove-zone[mcp]`) consistent with the zero-runtime-deps posture
   (`gove-zone-zero-runtime-deps` memory; `pyproject.toml` extras).
2. **Gateway config (G3).** `GatewayConfig` loader (same module or
   `adapters/mcp_gateway_config.py`): downstream command/URL, tenant id, execution
   boundary, policy-bundle path (reuse `yaml_policy.py` + `tenant.py::TenantPolicyStore`),
   signer/verifier key paths, profile selection (`profile.py::GovernanceProfile` —
   production default, dev explicit).
3. **Raw-argument policy evaluation (G6).** Inside the intercept, call
   `evaluation.py::evaluate_tenant_action` (as gate 2 of the demo does at
   `demo.py:193-206`) on the **raw** `params.arguments`; keep `emit_receipt_for_hook` only
   as the audit anchor. This kills the hash-summary no-fire hazard by construction.
4. **Session actor binding (G4).** Derive actor from the MCP session (`initialize`
   `clientInfo` + gateway-config principal mapping); assert in code and docs that actor is
   never read from `tools/call` bodies. Target: `mcp_gateway.py`; test forging an actor in
   the body and asserting the receipt binds the session principal.
5. **Deny path (G5-adjacent).** DENY → MCP result `isError: true` with
   `rejection.py::rejection_dict` payload + audit hash in `_meta.gove_zone` (pattern
   already proven at `demo.py:109-129`). Never a protocol-level error, so the model can
   reason about the denial.
6. **Escalate path (G5).** ESCALATE → `isError` pending-approval response carrying the
   escalation event id; new CLI verb (extend `cli.py`) wrapping
   `escalation.py::approve_escalation`; retry of the same call after approval resumes via
   `escalation.py::resume_with_receipt`. Negative test: unapproved retry stays blocked.
7. **Conformance tests (G2 + wiring proof).** New
   `packages/gove-zone/tests/test_mcp_gateway_conformance.py`: real MCP SDK client →
   gateway → real MCP SDK fixture server (temp-dir side effects). Asserts: allowed call
   executes exactly once downstream; denied call leaves zero downstream side effect;
   gateway with production profile and no verifier refuses to start (fail-closed); audit
   chain verifies. This is the dispatcher-level test the handler-wiring rubric requires —
   unit tests on `handle`-style functions do not count.
8. **Proof-pack export (G8).** Wire gateway evidence dir into the existing `proofpack` /
   `replay` CLI (`cli.py:622,790`); doc: "hand this directory + verifier to a third
   party."
9. **Receipt-format convergence note (G7).** ADR in `docs/adr/`: gateway emits gove-zone
   `DecisionReceipt` only; `governed_mcp_v0` is re-scoped in docs as the *eval fixture
   harness* (its `eval_gate.py` scenarios remain valuable as behavioral spec), not a
   product artifact.
10. **Benchmarks (G9).** Extend `benchmark_adapters.py` with a gateway lane; publish
    p50/p99 added latency per governed call in docs (SWOT Rec 4).
11. **Claim-safe docs (G10).** `docs/mcp/quickstart.md` rewrite around the gateway
    (<1h target, measured); new `INTEGRATION_MATRIX.md` row ("MCP gateway (transport
    proxy)") entering at the tier the evidence supports; matching `docs/CLAIMS.md` rows.
    No row flips before the conformance test in item 7 is green.

## 5. Pilot-blocking vs. polish

**Blocks a design-partner pilot:** G1 (proxy), G2 (real-SDK conformance), G3 (partner
policy config), G4 (session actor binding), G5 (escalate flow), G6 (raw-arg policy) —
i.e., plan items 1–7. Without these, a partner cannot govern a server they didn't write,
cannot express their own scope, and the receipts bind fictional actors.

**Polish (can land during/after pilot):** G7 (format convergence ADR), G8 (proof-pack
export ergonomics — needed before the *auditor* sprint, not the first pilot), G9
(benchmarks), G10 (matrix/claims/docs — required before public announcement, not before a
hands-on pilot with a partner who can read the honest-scope notes).

**What already meets the bar (do not rebuild):** fail-closed admission + evidence
persistence semantics (`server.py:109-182` as behavioral reference), signed execution gate
with production default (`executor.py:25-39`), escalation/rejection primitives
(`escalation.py`, `rejection.py`), offline chain verification (`verify.py`, `cli.py`
replay), and the MCP response-shape pattern (`demo.py:109-129`). The flagship gateway is
predominantly an **assembly-and-transport** project, not new governance machinery.
