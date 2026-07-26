# ACGS Runtime Governance Integration Research Appendix v2.2

Status: research appendix only.

This appendix preserves ecosystem analysis from the Agent Runtime Governance
Integration Report while aligning it with the current ACGS / gove-zone security
model and claim ledger. It does **not** replace the v2.1/W0 execution roadmap,
does **not** authorize implementation work, and does **not** propose a new core
platform namespace.

The operating boundary is:

> **gove-zone kernel remains authoritative.**

External components may request, observe, translate, or route governance inputs.
They do not own execution authority.

## Executive Summary

ACGS is best positioned as an agent runtime governance kernel: it sits below
agent reasoning and above side-effectful execution. The current local kernel
already provides the authoritative receipt-gated execution boundary for governed
paths. For configured strict governed side-effect paths, missing strict
prerequisites refuse rather than degrade:

> **No valid Decision Receipt, no side effect.**

The integration opportunity is not to create a parallel `acgs/gateway`,
`acgs/receipt`, or `acgs/audit` platform. The opportunity is to expose the
existing gove-zone kernel through narrowly scoped adapters:

- MCP gateway adapter;
- OPA policy adapter;
- OpenTelemetry telemetry adapter;
- ReBAC query adapter;
- agent framework integration adapter.

Hook/middleware/plugin are request interception surfaces only.
Final authorization boundary is executor PEP. On configured strict governed
side-effect paths, the executor must independently verify actor, action,
arguments, resource scope as expressed by route-bound execution-boundary and
argument bindings, policy version, receipt validity, and atomic consumption
before any side effect is attempted.

This appendix keeps partner and investor language claim-safe: ACGS has a
receipt-gated local kernel and reference integration surfaces. Control plane,
registry, broad framework support, ReBAC, OPA rollout, and managed deployment
operations are future or deferred work unless the v2.1/W0 gates say otherwise.

## Scope Boundary

This document is an integration research appendix. It is not:

- an execution roadmap;
- a production-readiness claim;
- an approval to build greenfield core services;
- a substitute for `docs/SECURITY_MODEL.md`, `docs/CLAIMS.md`, or
  `docs/DECISION_RECEIPT_SPEC.md`;
- a compliance, certification, or regulator-approval claim.

The only current execution roadmap is the W0-aligned sequence in
[W0 Dependency Alignment](#w0-dependency-alignment).

### Authoritative Kernel Boundary

The gove-zone kernel remains the authority for admission, receipt issuance,
audit evidence, replay support, and final side-effect gating. External
components can integrate only as adapters. They may not bypass or replace:

- `packages/gove-zone/src/gove_zone/receipt.py`;
- `packages/gove-zone/src/gove_zone/executor.py`;
- `packages/gove-zone/src/gove_zone/kernel.py`;
- `packages/gove-zone/src/gove_zone/audit.py`;
- `packages/gove-zone/src/gove_zone/replay.py`;
- `packages/gove-zone/src/gove_zone/replay_store.py`;
- `packages/gove-zone/src/gove_zone/policy.py`;
- `packages/gove-zone/src/gove_zone/gateway.py`;
- `packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`;
- `packages/gove-zone/src/gove_zone/integration.py`.

### Adapter Decision Template

Any proposed integration must answer this before implementation:

| Field | Required answer |
|---|---|
| Existing implementation | Which current gove-zone surface owns the behavior? |
| Target interface | Which narrow interface will the adapter call or implement? |
| Decision | `Reuse`, `Extend`, `Adapter`, or `Deferred` |

If no existing implementation can be named, the proposal is deferred by default.

## Current Kernel Mapping

| Research concept | Existing implementation | Decision |
|---|---|---|
| Agent Action Gateway | `kernel.py`, `gateway.py`, `executor.py`, `integration.py` | **Reuse / Extend**. Route new action shapes into the existing kernel. Do not create `acgs/gateway/*`. |
| MCP Gateway | `adapters/mcp_gateway.py`, `mcp.py`, `gateway.py`, `integration.py` | **Reuse / Extend**. MCP work extends the existing adapter and gateway controls. Current evidence is reference/fixture/local, not production-topology evidence. |
| Decision Receipt | `receipt.py`, `signing.py`, `DECISION_RECEIPT_SPEC.md` | **Reuse / Extend**. Schema changes must follow W0-M0/M1 and claim-ledger discipline. Do not create `acgs/receipt/*`. |
| Audit trail | `audit.py`, `decision.py`, `SECURITY_MODEL.md`, `CLAIMS.md` | **Reuse / Extend**. Audit remains append-only, hash-chained, and tamper-evident. Do not create `acgs/audit/*`. |
| Replay diff / regression gate | `replay.py`, `replay_store.py`, future W0-M0 capture/privacy profile | **Extend after W0-M0**. Full replay depends on complete captured policy inputs, not audit-only hashes. |
| Policy engine | `policy.py`, `authz.py`, `PolicyArtifactSnapshot`, `PolicyArtifactAttestation` | **Reuse / Adapter**. OPA can be a future policy adapter behind the existing policy interface. It never owns execution authority. |
| Executor PEP | `executor.py`, `kernel.py`, `gateway.py` | **Reuse**. This is the final authorization boundary. |
| Consumption / atomicity | `consumption.py`, strict standalone and managed execution paths | **Reuse / Extend**. Atomic consumption remains part of final execution gating. |
| MCP proof evidence | `proofpack.py`, `proofpack_cli.py`, MCP adapter tests | **Reuse**. Product proof packs add semantic verification over the generic structural codec. |
| Agent framework integration | `integration.py`, `adapters/langgraph.py`, `adapters/autogen.py`, reference example `examples/agent_framework_gate`, `INTEGRATION_GUIDE.md`, `INTEGRATION_MATRIX.md` | **Adapter**. Framework adapters normalize requests into the governed executor boundary; current examples are reference/local evidence, not broad production support. |
| OpenTelemetry mapping | No stable core dependency; optional future mapping only | **Adapter**. Telemetry must be versioned and redacted. It cannot define receipt semantics. |
| OpenFGA / SpiceDB / ReBAC | No current kernel dependency | **Deferred**. Introduce only for a design partner with a real relationship-authorization requirement. |
| Control plane / registry platform | No managed production control plane exists or is claimed in this appendix | **Deferred** until W0 and qualified corpus gates pass. |
| Paseo plugin | No checked-in authoritative adapter in this repo | **Deferred adapter**. Any Paseo work must run in Paseo's own repo scope and call the gove-zone executor PEP. |
| all-agentic integration | No checked-in authoritative adapter in this repo | **Deferred adapter**. Any PR must be scoped to that repo and keep gove-zone as the execution boundary. |

## Adapter Opportunities

### MCP Gateway Adapter

Existing implementation:

- `adapters/mcp_gateway.py` (reference/local evidence);
- `mcp.py` (MCP-facing shapes);
- `gateway.py` (gateway-facing control surface);
- `integration.py` (adapter integration surface);
- `INTEGRATION_GUIDE.md`;
- `CLAIMS.md`.

Target interface:

- Normalize MCP `tools/list` and `tools/call` into the existing gove-zone
  managed authorization kernel.
- Keep downstream credentials gateway-held.
- Preserve no direct fallback to the raw downstream tool.
- Keep the raw downstream unreachable except through the governed path.

Decision:

- **Reuse / Extend**.

Constraints:

- MCP adapters do not own final authorization.
- MCP host/broker/sidecar placement is an interception surface only.
- Per-call authorization should be described as a host/client security best
  practice and implementation responsibility, not a universal MCP protocol
  `MUST`.
- If the governed route is unavailable, the adapter must refuse rather than
  silently call the downstream tool.
- Existing MCP evidence is reference/fixture/local evidence only. It is not
  production-topology evidence.

### OPA Policy Adapter

Existing implementation:

- `policy.py`;
- `authz.py`;
- `PolicyArtifactSnapshot`;
- `PolicyArtifactAttestation`;
- strict managed execution final revalidation.

Target interface:

- A future adapter may translate a `ToolCall` or managed request into OPA input
  and translate OPA output back into the existing gove-zone policy decision
  shape.
- OPA bundle metadata can be content-addressed and bound into the existing
  policy artifact snapshot.

Decision:

- **Adapter, future optional**.

Rules:

- OPA never owns execution authority.
- OPA decision logs are diagnostic data only.
- OPA logs are not Decision Receipts.
- OPA bundle distribution is not a substitute for gove-zone receipt signing,
  executor verification, audit anchoring, or atomic consumption.
- OPA rollout is not part of the current execution path.

External note:

- OPA is a general-purpose policy engine with bundles and decision logs. Those
  capabilities are useful for policy adapter research, but the gove-zone kernel
  remains authoritative.

### OpenTelemetry Telemetry Adapter

Existing implementation:

- no current receipt-schema dependency on OpenTelemetry GenAI conventions;
- current evidence flows live in receipts, audit records, replay, and proof
  packs.

Target interface:

- A versioned, redacted telemetry adapter may emit spans/events that reference
  receipt ids, audit event ids, policy versions, adapter ids, and outcome
  classes.

Decision:

- **Adapter only**.

Rules:

- Telemetry must not redefine receipt or audit semantics.
- Schema mapping must be versioned.
- Sensitive fields and tool arguments must be redacted, tokenized, or omitted by
  default.
- Telemetry failures must not cause an ungoverned side effect.
- OpenTelemetry rollout is not part of the current execution path.

### ReBAC Query Adapter

Existing implementation:

- no current OpenFGA or SpiceDB kernel dependency;
- current policy/evidence binding lives in `policy.py`, `authz.py`, and
  strict execution.

Target interface:

- A future relationship-authorization adapter may answer relationship queries
  for a policy evaluator.
- Its answer may become policy input, but not execution authority.

Decision:

- **Deferred**.

Rules:

- Introduce OpenFGA or SpiceDB only when a design partner has a real ReBAC
  requirement.
- Relationship checks do not mint receipts.
- Relationship checks do not replace actor/action/argument/resource/policy
  binding at the executor.

### Agent Framework Integration Adapter

Existing implementation:

- `integration.py`;
- `adapters/langgraph.py`;
- `adapters/autogen.py`;
- `executor.py`;
- `gateway.py`;
- reference example `examples/agent_framework_gate`;
- `INTEGRATION_GUIDE.md`;
- `INTEGRATION_MATRIX.md`.

Target interface:

- Normalize framework tool-call payloads into the existing governed executor
  path.
- Keep model/planner approval separate from execution authorization.

Decision:

- **Adapter**.

Rules:

- Hook, middleware, plugin, and graph-node adapters are request interception
  surfaces only.
- Final authorization boundary is executor PEP.
- If an interception surface cannot reach the governed executor PEP, the request
  is not executable.
- TypeScript is allowed for console and Paseo adapter surfaces only; it must not
  rewrite the Python core kernel.
- Paseo and all-agentic integrations are deferred until they have their own
  repo-local scope, version pin, conformance plan, and negative tests.

## Deferred Integrations

The following items are useful research directions but are not on the current
execution path:

| Integration | Status | Reason for deferral |
|---|---|---|
| OPA rollout | Future optional adapter | W0 capture/signing/locking and qualified corpus come first. OPA cannot own execution authority. |
| OpenFGA / SpiceDB | Deferred | No confirmed design-partner ReBAC requirement yet. |
| Paseo plugin | Deferred adapter | Requires Paseo repo scope, local instructions, and conformance tests. |
| all-agentic hook PR | Deferred adapter | Requires external repo scope and must not imply framework-wide production support. |
| Registry platform | Deferred | Agent registry and relationship lifecycle are not W0 blockers. |
| Managed control plane | Deferred | Control plane/meta governance comes after W3 replay diff and W2 mining. |
| Cross-runtime standard receipt validators | Roadmap | Current receipt schema is project-defined and vendor-neutral, not a cross-vendor standard. |

## Security Claims Boundary

This section is binding for public or investor-facing reuse of this appendix.

### Invariant

> **No valid Decision Receipt, no side effect.**

This claim applies only to paths wired through the governed executor or managed
kernel, and only when required strict prerequisites are configured for that
path. Missing strict prerequisites refuse rather than degrade. A raw tool
exposed outside the governed topology remains a bypass.

### Final Authorization Boundary

Hook/middleware/plugin are request interception surfaces only.
Final authorization boundary is executor PEP.

Before side-effect execution on configured strict governed side-effect paths,
the executor independently verifies:

- actor binding;
- action binding;
- argument binding;
- resource scope as expressed by route-bound execution-boundary and argument
  bindings;
- policy bundle, version, hash, and artifact binding where required;
- receipt validity;
- expiry and signature where required;
- audit anchor where required;
- tenant boundary;
- decision executability;
- atomic consumption / single-use state where required.

The current Decision Receipt has no universal standalone resource field.
Resource scope is represented through execution boundary, action, arguments,
constraints, tenant, and policy artifact bindings.

### Decision Receipt

For receipts issued and verified in signed strict mode, Decision Receipt
claim-safe wording is:

> "cryptographically verifiable authorization decision integrity under
> key-management assumptions"

The Decision Receipt is an authorization artifact. It binds the decision and the
inputs used for authorization. It is not a proof that an external effect
occurred.

Unsigned local/dev receipt mode exists for compatibility and local proof paths.
It is not production signing evidence. Production-profile default signing remains
Phase 1 / W0-M1.

Do not claim:

- legal non-repudiation beyond the configured key assumptions;
- WORM-like permanence unless a verified WORM or off-host durable backend is
  supplied;
- downstream effects occur exactly once;
- admission-time hashes of downstream outputs.

### Audit

Audit claim-safe wording:

> "append-only hash-chained tamper-evident audit trail"

The local JSONL audit chain is not WORM storage. Bare hash chains detect in-chain
edits, reorders, and malformed tails, but they do not detect a trusted full
rewrite or truncation to a shorter self-consistent chain without an external
checkpoint.

Do not claim:

- WORM-like permanence unless an actual WORM/off-host backend is supplied and
  verified;
- global unforgeability beyond the configured trust anchors.

### EffectAttestation

Status:

> **NOT SHIPPED**

Future effect evidence, if built, is a separate lifecycle artifact. It is not
part of the authorization receipt. It must not be inferred from admission, audit,
OPA logs, telemetry, or downstream success text.

In this appendix, `EffectAttestation` means realized-effect evidence. It is
distinct from shipped signed `LifecycleAttestation` records.
`LifecycleAttestation` authenticates execution-lifecycle audit-record data; it
does not prove the realized external effect.

Current safe wording:

> "At-most-once authorized attempt with fail-closed `UNKNOWN`, not exactly-once
> effect; operators must reconcile ambiguous downstream outcomes out of band."

### KPI Reclassification

| Prior class | v2.2 wording |
|---|---|
| Partial interception target | 100% governed side-effect paths. Unknown paths are coverage gaps. |
| Replay consistency target | 100% for deterministic supported fragments. Others are classified unsupported, insufficient, redacted, tombstoned, or failed. |
| Latency target | Performance hypothesis requiring benchmark. |
| Pipeline / partner / PoC targets | Commercial assumptions, not evidence. |
| Six-person funded delivery model | Funded-team alternative scenario only. |

Primary resource assumption:

- solo-founder / minimal engineering baseline;
- Claude-agent-assisted development;
- external financing not assumed.

Funded-team alternative scenario:

- multi-person delivery model for planning sensitivity only;
- not the baseline roadmap;
- not evidence that the current repo can execute a broader program in parallel.

## W0 Dependency Alignment

W0 is the only execution roadmap. Integration work is subordinate to this
sequence.

| Phase | Required focus | What it unlocks |
|---|---|---|
| Phase 0 | W0-M0 capture/privacy | Qualified replay evidence capture, privacy profile, coverage metrics, side-store failure semantics. |
| Phase 1 | W0-M1 production signing | Production-profile signed Decision Receipts and verifier/key lifecycle discipline. |
| Phase 2 | W0-M2 locking/durability | Cross-platform audit/replay/consumption durability and crash/concurrency behavior. |
| Phase 3 | qualified partner + corpus | Partner-scoped receipt corpus measured by W0-M0 coverage, not raw receipt count. |
| Phase 4 | W3 replay diff | In-sample exact diff for deterministic supported fragments with explicit unsupported classifications. |
| Phase 5 | W2 mining | Window/coverage-qualified single-tenant findings such as unused-permission tightening. |
| Phase 6 | control plane/meta governance | Human-approved loop and meta-receipt work after W0/W3/W2 evidence exists. |

The following are explicitly **not** current execution-path items:

- OPA rollout;
- Paseo integration;
- all-agentic integration;
- registry platform;
- OpenFGA / SpiceDB;
- broad control plane buildout.

## Future Research Directions

These directions preserve ecosystem value without overriding W0:

1. **MCP conformance research.** Define tests that prove no direct downstream
   fallback, no credential passthrough, list-vs-call authority separation, and
   final executor verification.
2. **OPA adapter RFC.** Map OPA input/output, bundle digest, and decision-log
   diagnostics into the existing `Policy` / `PolicyArtifactSnapshot` model.
3. **Telemetry adapter RFC.** Define a redacted and versioned OpenTelemetry
   mapping that references receipt and audit ids without carrying raw PHI/PII or
   tool payloads.
4. **ReBAC requirement discovery.** Wait for a design partner that actually
   needs relationship authorization before selecting OpenFGA or SpiceDB.
5. **Framework adapter patterns.** Treat Paseo, all-agentic, LangGraph,
   OpenAI-style function calls, and other runtimes as adapter hosts whose raw
   side-effect paths must converge on the gove-zone executor.
6. **Partner proof-pack packaging.** Keep evidence export relative to external
   trust inputs and explicit limitations. Do not let proof packs certify their
   own trust roots.

## Non-goals

- Build a new `acgs/gateway/*` core.
- Build a new `acgs/receipt/*` core.
- Build a new `acgs/audit/*` core.
- Replace the gove-zone kernel with OPA, OpenFGA, SpiceDB, OpenTelemetry,
  Paseo, all-agentic, or MCP.
- Claim production certification, compliance certification, regulator approval,
  complete IAM/PKI, formal verification, or guaranteed safe AI.
- Claim WORM-like permanence without a verified WORM/off-host backend, legal
  non-repudiation beyond key assumptions, admission-time downstream output
  hashes, or exactly-once downstream effects.
- Make production paths call raw side-effect tools when the governed route is
  unavailable.
- Treat planner approval, hook approval, middleware approval, or policy-engine
  decision logs as execution authority.
- Rewrite the Python core kernel in TypeScript.
- Advance registry/control-plane/meta-governance work ahead of W0/W3/W2 gates.

## Appendix: External Ecosystem Notes

These notes are competitive and integration context only. They are not execution
authorization.

### AWS Bedrock AgentCore Policy

AWS announced Policy in Amazon Bedrock AgentCore as generally available on
2026-03-03. AWS describes centralized controls for agent-tool interactions,
natural-language policy authoring that converts to Cedar, policy attachment to
AgentCore Gateway, and Gateway interception of agent-tool traffic before allow
or deny decisions.

Research implication:

- Do not claim that no runtime governance product exists.
- ACGS differentiation must be narrower and evidence-based: signed strict-path
  receipt capability under key-management assumptions, production-profile
  default signing gated by W0-M1, gove-zone executor PEP semantics,
  receipt/audit/replay evidence, and honest replay boundaries.

Reference:

- <https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/>

### Styra Ecosystem and OPA

Styra and OPA demonstrate that policy engines, bundles, decision logs, and
decision-log replay concepts already exist in the authorization ecosystem. OPA
decision logs contain policy query events and support auditing and offline
debugging. OPA bundles support policy/data distribution.

Research implication:

- Do not describe replay diff as an invented mechanism.
- ACGS should describe W3 as receipt-corpus replay diff for captured agent
  tool-call inputs under explicit deterministic/stateless boundaries.
- OPA can be a future adapter, not the gove-zone execution authority.

References:

- <https://openpolicyagent.org/docs/>
- <https://openpolicyagent.org/docs/management-bundles>
- <https://openpolicyagent.org/docs/management-decision-logs>
- <https://docs.styra.com/das/observability-and-audit/decision-logs/log-replay>

### MCP

MCP is a tool/context protocol with separate host, client, and server roles.
Its security documentation identifies confused deputy, token passthrough, SSRF,
and session risks. For ACGS wording, per-call authorization should be framed as
a host/client security best practice and implementation responsibility, not a
universal protocol `MUST`.

Research implication:

- ACGS MCP work should extend the existing gove-zone MCP gateway and final
  executor boundary.
- OAuth, resource indicators, consent, and token-passthrough controls inform
  adapter design but do not replace Decision Receipts.

References:

- <https://modelcontextprotocol.io/specification/2025-11-25>
- <https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices>
- <https://modelcontextprotocol.io/docs/tutorials/security/authorization>

### OpenTelemetry GenAI

OpenTelemetry GenAI conventions are useful for observability alignment, but they
are telemetry conventions, not authorization receipts.

Research implication:

- Use a redacted, versioned telemetry adapter.
- Do not make OpenTelemetry schema stability a W0 dependency.
- Do not put raw tool arguments, PHI/PII, or response payloads into telemetry by
  default.

References:

- <https://github.com/open-telemetry/semantic-conventions-genai>
- <https://opentelemetry.io/docs/specs/semconv/gen-ai/>

### OpenFGA / SpiceDB / Existing Policy Engines

OpenFGA and similar systems are useful when a product has concrete
relationship-based authorization requirements. Existing policy engines and
authorization services reduce the space for broad market claims.

Research implication:

- Do not claim the market has no runtime governance solution.
- Defer ReBAC until a design partner supplies a specific relationship model.
- Treat ReBAC checks as policy inputs, never as receipt issuance or execution
  authority.

Reference:

- <https://openfga.dev/docs/concepts>
