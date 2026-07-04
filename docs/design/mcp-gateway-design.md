# Governed-MCP Gateway — Design (pilot-blocker core, G1–G6)

> Status: **design only, alpha**. Nothing here claims production-readiness,
> certification, compliance approval, or "regulator-ready" behavior (see
> `docs/CLAIMS.md`, `AGENTS.md` "Claim boundaries"). This document specifies a
> component to be *built and tested locally*; a matrix/claims row is minted only
> after the dispatcher-level conformance test in §6 is green (per
> `docs/INTEGRATION_MATRIX.md` tier rules).
>
> Date: 2026-07-03 (rev. 2 after adversarial review). Design input:
> [`docs/strategy/mcp-gateway-gap-analysis.md`](../strategy/mcp-gateway-gap-analysis.md).
> This design covers **G1–G6 only** — the pilot-blocking core (plan items 1–7).
> G7–G10 are explicit non-goals (§8).
>
> Every reuse point names a symbol and a `file:line` verified against the working
> tree on 2026-07-03 (branch `feat/governed-vulnclaw-pentest`). Corrections where
> the gap analysis's file references proved wrong are collected in §10.
>
> **Rev-2 note:** the review found that routing DENY/ESCALATE through
> `evaluate_tenant_action` and projecting the result into `rejection_dict` /
> `PendingApproval` is **broken** — `evaluate_tenant_action` returns a
> `DecisionReceipt`, which is a different type from the `DecisionRecord` those
> consumers require. §3.2/§3.6 are rewritten around the correct primitives.

---

## 1. Scope

**In scope (pilot-blocking):**

| Gap | One-line | Plan item |
|---|---|---|
| G1 | Transport-level proxy (stdio first, streamable-HTTP second) fronting an unmodified downstream MCP server | 1 |
| G2 | Real official `mcp` SDK on both sides, conformance-tested against a real server | 2, 7 |
| G3 | Partner-configurable policy / signing / audit via a config file, not code | 2 |
| G4 | Actor identity derived from the authenticated MCP session, never the request body | 4 |
| G5 | ESCALATE wired into an MCP response shape with a human approve → resume path | 6 |
| G6 | Policy evaluated on **raw** `params.arguments`, not the hashed hook summary | 3 |

**Out of scope (explicit non-goals — §8):** G7–G10, resources/prompts governance
(passed through), multi-tenant/multi-downstream fan-out in one process, and
authn of the host→gateway hop (assumed a trusted local transport in alpha; §3.4).

**Target file (new, not a dangerous-zone file):**
`packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`
(+ export in `adapters/__init__.py`). The gateway is *assembly and transport*: it
**reuses** the sealed kernel machinery and adds no new gate logic. The one place
this design contemplates touching a sealed file (`kernel.py`) is Option B in §3.6,
which is explicitly gated on human approval.

---

## 2. Reuse map (verified symbols)

| Need | Symbol | Location (verified) |
|---|---|---|
| Parse MCP `tools/call` shape | `_tool_name_and_input_from_payload` (MCP branch) | `integration.py:305`, MCP branch `327-334` |
| **Decision + audit, raising typed errors that carry the real record** | `Kernel.dispatch` | `kernel.py:94`; DENY raise `137`, ESCALATE raise `139-143` |
| DENY carries a real `DecisionRecord` + audit hash (+ `to_rejection_dict()`) | `DeniedError.record` / `.audit_hash` / `.to_rejection_dict` | `errors.py:66-77` |
| ESCALATE carries a **prebuilt** `PendingApproval` | `EscalateError.pending` | `errors.py:100`; built at `kernel.py:142` |
| ALLOW/TRANSFORM return the real record on the anchor | `Receipt.record` | `receipt.py:53` (dispatch returns `(result, Receipt)`, `kernel.py:159-165`) |
| Signed-receipt mint from a record (ALLOW) | `DecisionReceipt.from_record` | `receipt.py:248` |
| Signed execution gate (fail-closed, `expected_actor` required) | `execute_with_receipt` / `GovernedExecutor` | `executor.py:25`, `88` |
| Named secure posture + gate kwargs | `GovernanceProfile.production` / `.from_env` / `.as_gate_kwargs` | `profile.py:76,100,126` |
| DENY/ESCALATE → machine-readable envelope | `rejection_dict` (needs a `DecisionRecord`) | `rejection.py:58` |
| Escalation lifecycle | `PendingApproval`, `approve_escalation`, `resume_with_receipt` | `escalation.py:60,87,206` |
| Partner policy bundle store (JSON) | `TenantPolicyStore` | `tenant.py:54,61,77` |
| One-shot mint on ALLOW (Option A only) | `evaluate_tenant_action` | `tenant.py:106` — **re-exported from package root** `__init__.py:105,187`; *not* `evaluation.py` (§10) |
| Partner policy authoring (YAML, optional) | `YAMLPolicy` | `yaml_policy.py:17` — imports `yaml` at module scope (`:12`); `pyyaml` **undeclared** (§5, §10) |
| Tamper-evident audit store + offline verify | `ChainHashAuditStore` (`append`, `verify_chain`) | e.g. `kernel.py:280`, `demo.py:342` |
| Real-SDK fixture downstream server | `build_fastmcp_server` | `governed_mcp_v0/mcp_server.py:34` |

**Type contract that broke rev-1 (verified):** `DecisionReceipt` (receipt.py:124-151)
has **no `.record`**, no `reason`, no `decision_request_hash`, no `path`, no
`state_hash`; its `.decision` is a `str` and its tool field is `proposed_action`.
`rejection_dict` requires a `DecisionRecord` (`.tool`, `.reason`,
`.decision_request_hash`, `.matched_rules`, `.policy_version`, `rejection.py:83-102`);
`PendingApproval.__post_init__` checks `record.decision is not Decision.ESCALATE`
against an **enum** (`escalation.py:80`), which a `str` decision always fails. There
is no `DecisionReceipt → DecisionRecord` inverse. Hence rev-1's "project the receipt"
plan could not compile, let alone run.

---

## 3. Architecture

### 3.1 Process model (G1) and per-method disposition

The gateway is simultaneously an **MCP server** (to the host) and an **MCP client**
(to the downstream server it fronts). It is a transparent proxy for everything
except `tools/call`.

```
┌──────────┐  MCP (stdio)  ┌──────────────────────────┐  MCP (stdio)  ┌──────────────┐
│ MCP host │ ─────────────▶│   gove-zone gateway       │──────────────▶│  downstream  │
│ (client) │◀───────────── │  adapters/mcp_gateway.py  │◀───────────── │  MCP server  │
└──────────┘               │  receipt gate on          │               │ (unmodified) │
                           │  tools/call only          │               └──────────────┘
                           └──────────────────────────┘
```

- **stdio↔stdio first** (plan item 1): gateway spawns the downstream as a
  subprocess and speaks MCP over its stdio using the official `mcp` SDK
  (`stdio_client` on the client side; `Server`/`FastMCP` on the host side),
  mirroring the fixture server's own launch shape (`mcp_server.py:62-66`).
- **streamable-HTTP second**: same interception on decoded JSON-RPC messages, so
  HTTP is a transport swap, not a rewrite.

**Explicit per-method table** (bar #2: unknown/unparseable side-effecting methods
are denied, not forwarded):

| Method | Disposition | Rationale |
|---|---|---|
| `initialize` | pass through; capture `clientInfo` → session principal (§3.4) | handshake; identity anchor |
| `tools/list` | pass through verbatim; cache the tool set for wiring (§3.6) | host sees the real catalog |
| **`tools/call`** | **INTERCEPT — receipt gate (§3.2)** | the governed side-effect path |
| `resources/*`, `prompts/*`, `roots/*` | pass through | not gated in the pilot core (§8) |
| `ping`, progress, `logging/setLevel` | pass through | no side effect on the downstream tools |
| `completion/complete` | pass through | argument autocompletion; no tool execution |
| **`sampling/createMessage`** | **DENY by default (reverse channel)** — server→client LLM request; not forwarded/answered unless a partner explicitly opts in via config | a downstream server that can request model completions is a real reverse side-channel; fail closed until scoped |
| any unknown method that could cause a side effect | DENY, do not forward | bar #2 |

`sampling/createMessage`, `completion/complete`, and `logging/setLevel` are named
here deliberately because "pass everything but `tools/call`" would silently expose
the sampling reverse channel.

### 3.2 The `tools/call` gate — corrected primitives

One inbound `tools/call` yields exactly one governance decision and **one** audit
event (denials included → bar #5). The decision runs on **raw** arguments (G6,
§3.5). The three decisions map to three primitives, each of which hands the gateway
a **real `DecisionRecord` + audit hash** with no lossy reconstruction:

```
tools/call(name, arguments)                       ← from host, via mcp SDK
        │  actor = session principal (§3.4; NEVER from arguments)
        │  args  = RAW params.arguments (G6)
        ▼
decision via the kernel (one audit append)        ← §3.6 selects the exact primitive
   ├── DENY     → DeniedError.record + .audit_hash        → rejection_dict(record, audit_hash,
   │              (real DecisionRecord — errors.py:66)       resumable=False, resolution=REVISE_AND_RETRY)
   │                                                         → isError:true result; forward NOTHING
   ├── ESCALATE → EscalateError.pending                   → park the PendingApproval; isError:true
   │              (prebuilt PendingApproval — kernel.py:142) "pending approval" result; forward NOTHING
   └── ALLOW    → real record + audit_hash                → DecisionReceipt.from_record(record, audit_hash,
                  (from the dispatch anchor)                 validator=config.validator, signer=config.signer, …)
                                                            → execute_with_receipt(tool_fn = forward_downstream,
                                                              args = RAW_args, receipt = signed_receipt,
                                                              expected_actor = session_principal,
                                                              **profile.as_gate_kwargs())
                                                            → verify passes → forward downstream; wrap the real result
```

Load-bearing properties:

- **The downstream forward is the `tool_fn` inside `execute_with_receipt`**
  (`executor.py:25`), so a `tools/call` reaches the downstream server **only** after
  `DecisionReceipt.verify` passes (signature in production posture, tenant, boundary,
  action, argument binding, actor binding). No `tools/call` is forwarded on DENY,
  ESCALATE, or any error.
- **DENY/ESCALATE are lossless.** `DeniedError` carries the deciding
  `DecisionRecord` verbatim (with `reason`, `decision_request_hash`, `path`), and
  even offers `to_rejection_dict()` (`errors.py:71`). `EscalateError.pending` is a
  fully-formed `PendingApproval(record, audit_hash, args)` built by the kernel
  (`kernel.py:142`) — the gateway parks it directly; **no reconstruction, no field
  loss, no throwaway receipt.**
- **One audit event per call.** The decision append happens once, inside the kernel
  decision primitive; minting the signed receipt (`from_record`) and running
  `execute_with_receipt` append nothing further on the success path.
- **Under Option C (§3.6), the tool_fn registered in the kernel registry MUST be the
  inert echo (`lambda **a: a`) — NEVER the real downstream forward.** `dispatch()`
  executes the registered tool_fn as part of the same call that mints the anchor
  (`kernel.py:152-154`); registering the real forward there would execute the
  downstream **before** `DecisionReceipt.verify` runs (a "no execution before receipt
  validation" violation) and then a second time inside `execute_with_receipt`. The
  real forward exists in exactly one place: as the `tool_fn` argument to
  `execute_with_receipt`. (Option B has no registry involvement at all.)
- **`Decision.TRANSFORM` is out of scope for the pilot, enforced at config load.**
  The reused `TenantPolicyStore.load_bundle` (`tenant.py:97-100`) can deserialize a
  `TransformPolicy`, and `dispatch()` substitutes `record.transformed_args` before
  executing (`kernel.py:144-149`). The gateway does not implement transformed-arg
  routing in the pilot: forwarding RAW args for a TRANSFORM decision would be
  rejected fail-closed by `receipt.verify()` check 10c (`receipt.py:553-565`) — safe,
  but every TRANSFORM call would hard-fail, silently breaking the policy author's
  "sanitize and proceed" intent. Therefore config load MUST reject bundles containing
  a transform-policy id (mirroring the validator==actor config-load guard, §3.4/F10),
  with a test. Supporting TRANSFORM later means adding the
  `record.transformed_args`-routing branch plus its own binding test (§9).

### 3.3 DENY / ESCALATE → MCP responses (fail closed, never a tool success)

Both map to a **successful JSON-RPC result with `isError: true`** (the MCP-spec way
to report a tool-level failure the model can reason about) — never a bare protocol
error, never `isError:false`:

```jsonc
// DENY
{ "isError": true,
  "content": [{ "type": "text", "text": "gove-zone DENIED <tool>: <reason> [rules: …]" }],
  "structuredContent": { /* rejection_dict(record, audit_hash, resumable=false,
                            resolution="revise_and_retry") */ },
  "_meta": { "gove_zone": { "decision": "deny", "audit_hash": "…" } } }

// ESCALATE
{ "isError": true,
  "content": [{ "type": "text", "text": "gove-zone ESCALATED <tool>: awaiting human approval (event <id>)" }],
  "structuredContent": { /* rejection_dict(record, audit_hash, resumable=true,
                            resolution="human_approval", approval={event_id, how_to_approve}) */ },
  "_meta": { "gove_zone": { "decision": "escalate", "audit_hash": "…", "escalation_event_id": "…" } } }
```

- **`content` + `_meta` shape is proven** by `demo.py:109-129`. **`structuredContent`
  is NEW surface** — the demo response has no `structuredContent` field
  (`demo.py:109-120` emits only `isError`/`content`/`_meta`). Treat it as a new
  field with its own conformance assertion (§6), not as "already proven."
- `rejection_dict` is leak-safe by construction (`rejection.py:1-27`): redacts
  fail-closed-fallback reasons, carries only non-reversible hashes, never raw args /
  `state_hash` / `transformed_args`, and refuses to project ALLOW/TRANSFORM
  (`rejection.py:83-86`).

**Fail-closed error handling (bar #3), including the bare-error case (finding #4).**
Not every failure hands the gateway a record:

- **Policy raises / times out** → the kernel synthesizes a `fail-closed/*` DENY with
  a real record (`kernel.py:239-258`) → normal DENY envelope. `rejection_dict`
  redacts the exception-derived reason.
- **Audit append fails** → surfaces as `AuditError` (`kernel.py:283-285`) on the
  direct-kernel path, or as `PolicyError` (`tenant.py:168-171`) via
  `evaluate_tenant_action`. **Neither carries a `.record` or `.to_rejection_dict`.**
  The gateway MUST catch these and emit a **fixed, leak-safe** `isError` result with
  no request-derived text — a constant envelope
  (`{"decision":"deny","reason":"governance evidence could not be recorded; call refused",
  "audit_hash": null}`) mirroring `rejection_dict`'s discipline (no raw args, no
  exception message). Forward nothing. This handler is a required, tested code path
  (§6), not a fall-through.
- **Missing signer/verifier under production posture** → `execute_with_receipt`
  raises `ProductionProfileError` (`executor.py:63-64`); surfaced as a **startup**
  refusal (§3.6/§5), not a per-call surprise.

Under no error condition is a `tools/call` forwarded.

### 3.4 Actor / session binding (G4) — security-critical

The actor bound into every receipt is the **authenticated MCP session principal**,
derived once at `initialize` and held **per session**, never read from a
`tools/call` body.

1. At `initialize`, capture the client identity the transport authenticates
   (`clientInfo` + the gateway-config principal map, §4) → `session_principal`. If
   config requires a mapped principal and none resolves, **fail the `initialize`**
   (fail closed) rather than defaulting to anonymous.
2. **Session-scoped state (finding #5).** `session_principal` — and the per-session
   kernel/executor it parameterizes — is keyed by the **MCP session id**, not a
   process-global. stdio fronts one session per process, but keying by session id
   **now** means the streamable-HTTP transport swap (which multiplexes sessions in
   one process) cannot introduce cross-session actor bleed. The design mandates a
   `sessions[session_id] -> SessionContext(principal, kernel, executor, audit)` map;
   no module-global actor.
3. Every `tools/call` on that session passes `actor=session_principal` to the
   decision primitive **and** `expected_actor=session_principal` to
   `execute_with_receipt`. `params.arguments` is opaque tool data handed to the
   policy; never consulted for identity. `expected_actor` is **required** at the gate
   (`executor.py:59-62`) and anchors the MACI proposer-binding (verify check 2b).

**Threat cases:**

- **Forged actor in the request body.** `params.arguments = {"actor":"admin", …}` is
  ignored for identity; the receipt binds `session_principal`, and
  `execute_with_receipt(expected_actor=session_principal)` verifies against the
  session. *Test:* forge `actor` in the body; assert the receipt binds
  `session_principal` and a receipt minted for a different actor fails verify (2b).
- **Cross-tenant policy pull.** `TenantPolicyStore.load_bundle` raises
  `PermissionError` on `tenant_id != requester_tenant_id` (`tenant.py:86-90`) → DENY.
  The gateway passes `requester_tenant_id = tenant_id = config.tenant_id`; no
  request-controlled tenant selector in the pilot.
- **Self-validation.** `validator` (config, §4) must differ from `actor`. Config load
  rejects `validator_id == any mapped principal` up front. **Residual runtime guard
  (finding #7):** `from_record` raises `ReceiptValidationError` if `validator ==
  proposer` (`receipt.py:283-287`) — this fires at **ALLOW mint time, after** the
  decision was already audited, so it fails closed with no forward and is *not* a
  zero-audit case under §3.6 Options B/C. (Under Option A's `evaluate_tenant_action`,
  the equivalent guard at `tenant.py:136-141` raises **pre-audit** → a genuine
  zero-audit-event exception to the one-event invariant; that asymmetry is one more
  reason A is not recommended.)

**Trust boundary (stated honestly):** in alpha the **host→gateway** hop is a trusted
local transport (stdio subprocess, same trust domain). The gateway does not itself
authenticate the host; `session_principal` is only as strong as that transport's
authentication. Documented limitation, not an end-to-end authenticated-identity
claim (consistent with `docs/SECURITY_MODEL.md`).

### 3.5 Raw-argument policy evaluation (G6) — security-critical, independent of §3.6

The hazard (gap analysis §1.2; `demo.py:24-27`): through the *hook adapter*, raw
arguments are replaced by a hash before the policy sees them
(`integration.py:123-142`), so arg-keyed policies silently never fire.

**The gateway removes this by construction and independently of the §3.6 choice:**
the decision runs through the kernel, which evaluates `policy.evaluate` against a
`ToolCall` carrying the **raw** `arguments` mapping (kernel builds the call with raw
args at `kernel.py:126-133`; `evaluate_tenant_action` likewise at `tenant.py:159-166`).
`emit_receipt_for_hook` (the hashing path) is **not** on the decision path here — at
most an optional unsigned audit anchor, never the decision authority. Arg-keyed
partner policies (e.g. deny `execute_sql` where `query` contains `DROP`) therefore
fire. *Test:* an arg-keyed deny rule that only a raw-arg evaluator can trigger; assert
DENY + zero downstream side effect.

### 3.6 Decision primitive — human-decision-required-before-implementation

All three options below produce the correct §3.2 behavior and a **real
`DecisionRecord` + audit hash** for every decision. They differ in whether they touch
a sealed file and in ergonomic cost. **A human must choose before implementation; do
not default silently.** Recommendation follows.

**Option A — reconstruct a `DecisionRecord` from `evaluate_tenant_action`'s
`DecisionReceipt` (NO sealed change; LOSSY; not recommended).**
`evaluate_tenant_action` (`tenant.py:106`) evaluates raw args, appends one audit
event, and returns a **`DecisionReceipt`** for any decision. To feed
`rejection_dict` / `PendingApproval` the gateway would hand-build a synthetic
`DecisionRecord` from the receipt's flat fields.
*Fields lost* (absent on `DecisionReceipt`, receipt.py:124-151): **`reason`**,
**`decision_request_hash`**, `path`, `state_hash`.
*Consequences:*
  - DENY envelope loses `reason` (agent can't see *why*) and `decision_request_hash`
    (agent can't correlate the denial to its request).
  - **ESCALATE is worse:** `approve_escalation` derives `effective_request_id` from
    `pending.record.decision_request_hash` and intentionally *preserves* it to bind
    the approval to the original request (`escalation.py:163-185`). A reconstructed
    record with `decision_request_hash=""` degrades that binding to an empty string —
    a real weakening of the approval guarantee.
  - `evaluate_tenant_action` also mints a **throwaway signed receipt for denials** and
    **requires a `validator`** on every call, including denies (with the pre-audit
    zero-event guard noted in §3.4). Semantically wrong-grained for a denial.
*Verdict:* lossy in a security-relevant way (escalation binding). Reject unless no
sealed change is permitted **and** escalation is out of the first pilot.

**Option B — a small public `evaluate_and_record(call) -> (DecisionRecord,
audit_hash)` (SEALED change; cleanest; RECOMMENDED, human-gated).**
Expose the existing private `Kernel._evaluate_and_record` (`kernel.py:275-293`) as a
public method (or a thin `tenant.py` wrapper). The gateway then:
DENY → `rejection_dict(record, audit_hash, …)`; ESCALATE → `PendingApproval(record,
audit_hash, raw_args)`; ALLOW → `DecisionReceipt.from_record(record, audit_hash,
signer=…)` → `execute_with_receipt(forward)`. One append; real records; no throwaway;
no registry bookkeeping.
*Precise spec for human review (a dangerous-zone `kernel.py` change per AGENTS.md):*
  - **Signature:** `def evaluate_and_record(self, call: ToolCall) -> tuple[DecisionRecord, str]`.
  - **Invariants (unchanged from the private method):** evaluates under the
    fail-closed watchdog (`kernel.py:225-273`); appends **exactly one** audit event;
    **never executes** any tool; raises `AuditError` if the append fails; attaches
    kernel context (`_attach_context`).
  - **No weakening:** it neither bypasses receipt validation nor executes before
    audit; it is a read-and-append primitive with no new authority.
  - **Required tests:** (1) parity — for the same call, the returned record equals the
    record `dispatch` would reach (allow/deny/escalate/transform + fail-closed
    synthesis); (2) exactly one `audit.append`; (3) no `tool_fn` invocation; (4)
    `AuditError` on append failure. Plus the AGENTS.md obligation: negative-path tests
    proving no side effect ran.

**Option C — `Kernel.dispatch` with an inert per-tool echo handler (NO sealed change;
lossless; viable alternative).**
Register a benign echo (`lambda **a: a`) under each downstream tool name (from the
cached `tools/list`, §3.1), then `dispatch(name, raw_args, …)`:
DENY → `except DeniedError as e` → `rejection_dict(e.record, e.audit_hash, …)`;
ESCALATE → `except EscalateError as e` → use `e.pending` directly;
ALLOW/TRANSFORM → returned `(_, receipt)`; `receipt.record` is the real record
(`receipt.py:53`) → mint signed receipt → `execute_with_receipt(forward)`. One append
(dispatch's decision append; a successful echo appends nothing — only execution
*failures* append, `kernel.py:155-157`).
*Costs:* the gateway must register/refresh an echo per downstream tool name (registry
bookkeeping mirroring `tools/list`), and dispatch "executes" an inert echo whose
`result_hash` is discarded — harmless but obscure. Downstream forward failures (F7)
are handled outside the kernel loop by the gateway (as they must be anyway).

**Recommendation → Option B.** The sealed change is minimal and benign — it exposes an
existing, already-tested private read-and-append method as public with parity tests —
and it buys the cleanest semantics: real records for all three decisions, one audit
event, no throwaway signed receipt, and no echo-registry to keep in sync with
`tools/list`. **Option C is the correct fallback if no `kernel.py` change is
approved** (it is fully public-API and equally lossless, at the price of the echo
registry). **Option A is not recommended** — it degrades the escalation binding and
mints authorization-shaped artifacts for denials. This choice is
**human-decision-required before implementation.**

---

## 4. Config surface for a design partner (G3)

A partner governs a server they did not write by editing one config file — no Python.
Proposed `GatewayConfig` (loaded in `mcp_gateway.py`; a sibling
`adapters/mcp_gateway_config.py` is fine if it grows):

```toml
# gove-zone-gateway.toml  (illustrative; TOML/JSON — dep-free to parse)
[downstream]
transport = "stdio"                     # "stdio" | "streamable-http"
command   = ["python", "-m", "their_server"]   # stdio: downstream argv
# url     = "http://127.0.0.1:9000/mcp"        # http: downstream endpoint

[governance]
tenant_id          = "tenant-A"
execution_boundary = "mcp-partner-sandbox"
profile            = "production"        # default; "dev" is an explicit unsigned opt-out
policy_bundle      = "policies/tenant-A.bundle.json"   # JSON RuleSetPolicy (dep-free)
# policy_bundle_yaml = "policies/tenant-A.yaml"        # optional; requires the yaml extra (§5)

[identity]
validator_id   = "constitutional-council"   # MUST differ from every mapped principal
validator_role = "council"
[identity.principals]                        # clientInfo.name → actor principal
"claude-code"    = "agent:claude-code@tenant-A"
"claude-desktop" = "agent:desktop@tenant-A"

[signing]
signer_key   = "keys/tenant-A.ed25519.sk"    # issuance private key (production)
verifier_key = "keys/tenant-A.ed25519.pk"    # gate public key (production)

[audit]
sink = "evidence/tenant-A/audit.jsonl"       # ChainHashAuditStore path
```

Wiring:

- **Policy bundle** → `TenantPolicyStore` seeded from `policy_bundle` (`tenant.py:61,77`).
  Default is **JSON** `RuleSetPolicy` (dep-free). A YAML path pulls in `YAMLPolicy`
  (`yaml_policy.py:17`), which needs `pyyaml` — see §5/§10.
- **Profile / signing** → `GovernanceProfile.production(signer, verifier)` from the key
  paths (or `.from_env`), fed via `as_gate_kwargs()` (`profile.py:76,126`). Keys loaded
  from paths, never inlined.
- **Audit sink** → `ChainHashAuditStore(config.audit.sink)`; this directory is the
  proof-pack seam (G8, out of scope).
- **Identity** → `Validator(validator_id, validator_role)` + the `clientInfo.name →
  principal` map (§3.4). Config load **rejects** `validator_id` equal to any mapped
  principal (self-validation guard, fail closed).

Riskiest-assumption target (canvas #3): time-to-first-governed-call < 1h — not claimed
here; a measured G10 item after the §6 conformance test is green.

---

## 5. Dependency plan (official `mcp` SDK as an optional extra)

gove-zone core has **zero runtime dependencies** (`pyproject.toml:21`
`dependencies = []`; extras today are `schema`, `crypto`, `dev` at `:33-42`). The
gateway must not break that.

- **Add `mcp` as an optional extra:** `mcp = ["mcp>=<pinned>"]`. Installers use
  `gove-zone[mcp]`; a production gateway needs `gove-zone[mcp,crypto]`.
- **Lazy import + LOUD error.** Import the SDK inside the constructor/entry function,
  not at module top, so `import gove_zone.adapters` stays dep-free. Missing SDK raises
  a precise error — **not** the silent `None` fallback of `mcp_server.py:35-43` (that
  silent-None is exactly the footgun G2 flags):

  ```python
  try:
      import mcp  # official Model Context Protocol SDK
  except ModuleNotFoundError as exc:
      raise RuntimeError(
          "the governed-MCP gateway requires the official MCP SDK; "
          "install with `pip install gove-zone[mcp]` (add `,crypto` for signed receipts)"
      ) from exc
  ```

- **Undeclared-dep correction (§10):** `yaml_policy.py:12` imports `yaml` at module
  scope, but **no `yaml`/`pyyaml` extra is declared**. Any config path reaching
  `YAMLPolicy` imports an undeclared dependency. Fix before wiring YAML config: declare
  `yaml = ["pyyaml>=6"]` (and fold into `mcp` if YAML config is offered), or keep the
  **JSON bundle as the dep-free default** and gate YAML behind an explicit extra + lazy
  import. Pilot defaults to JSON.
- **`crypto` extra for signing.** Production posture needs `cryptography>=42`
  (`pyproject.toml:35`); absence fails closed at the gate (`ProductionProfileError`),
  surfaced at **startup** (§3.3), not mid-call.

Net: `import gove_zone` / `import gove_zone.adapters` stay zero-dep; SDK, crypto, and
optional yaml load only when the gateway runs.

---

## 6. Test plan (dispatcher-level, per the handler-wiring rubric)

A unit test calling a `handle_*` function directly does **not** prove wiring
(`~/.claude/rules/review-handler-wiring.md`; AGENTS.md §170-179). The load-bearing
tests drive a **real MCP client → gateway → real MCP server** over the actual
transport.

**New file:** `packages/gove-zone/tests/test_mcp_gateway_conformance.py` (runs only
when the `mcp` extra is installed; skip-marked otherwise so the zero-dep suite stays
green).

**Downstream fixture:** a real, unmodified `mcp`-SDK server with a temp-dir side
effect — reuse `governed_mcp_v0.build_fastmcp_server` (`mcp_server.py:34`) or a minimal
`FastMCP` server exposing one `write_file(path, content)` tool under `tmp_path`.
**Fixture guard (test-plan hardening):** `build_fastmcp_server` returns **`None`** when
the MCP runtime is absent (`mcp_server.py:42-43`); the test MUST assert the fixture is
not `None` **before** trusting any deny/no-side-effect assertion, or a skipped runtime
would make every assertion vacuously pass.

**Dispatcher-level assertions (wiring proof):**

1. **Allow executes exactly once downstream** — a permitted call reaches the downstream
   server; the temp file exists with expected content; the downstream tool ran once.
2. **Deny leaves zero downstream side effect** — `isError:true`,
   `_meta.gove_zone.decision == "deny"`, `structuredContent` present (new-surface
   check, §3.3); temp-dir untouched; downstream tool invoked **zero** times.
3. **Fail-closed startup** — production profile + no verifier refuses to start / refuses
   the first governed call (`ProductionProfileError`) before any forward.
4. **Audit-append failure** — inject an append failure; assert the fixed leak-safe DENY
   envelope (§3.3, finding #4), no request-derived text, no forward.
5. **Audit chain verifies** — `verify_chain()` is `valid:true`; the count includes the
   denial (bar #5).

**Negative-path tests:**

6. **Forged actor in body (G4)** — receipt binds `session_principal`; a receipt for a
   different actor fails verify (2b); no forward.
7. **Escalate unapproved stays blocked (G5)** — ESCALATE returns the pending response;
   an identical retry **without** approval still does not forward. Only after
   `approve_escalation` (distinct validator) + `resume_with_receipt` does the single
   side effect run — exactly once.
8. **Cross-pending escalation reuse (finding #2)** — two hash namespaces are involved
   and must not be conflated: `pending.audit_hash` is the hash of the **ESCALATE**
   audit event (`escalation.py:75-76`, populated at `kernel.py:142`), while the
   receipt minted by `approve_escalation` carries the hash of the **separate, later
   APPROVAL** audit event (`escalation.py:181-189`). These are never equal, for any
   escalation, correct or attacked — so pinning `expected_audit_hash` to
   `pending.audit_hash` would reject **every legitimate resume**, not just the attack.
   The correct pin: at `approve_escalation` time the gateway captures the
   freshly-minted receipt's own `audit_event_hash` (the approval-hash), keyed by the
   specific pending's `record.event_id`, and threads **that** value as
   `expected_audit_hash` at resume. Tests, both required:
   - **8a (negative):** create two identical pending escalations; approve pending#1;
     attempt to resume pending#2 with pending#1's approval receipt against
     pending#2's (absent) captured approval-hash → **must fail**.
   - **8b (positive):** resume pending#2 with pending#2's own correctly-approved
     receipt, using pending#2's captured approval-hash → **succeeds exactly once**;
     a second resume of the same approval raises `ReceiptAlreadyUsedError` via the
     consumption ledger (see F9).
   Without 8b, the negative test cannot distinguish "fix works" from "fix compares
   two hash namespaces that never intersect regardless."
9. **Raw-arg policy fires (G6)** — arg-keyed deny rule; DENY + zero side effect.
10. **Sampling reverse channel denied (§3.1)** — a `sampling/createMessage` from the
    downstream is not answered/forwarded unless config opts in.
11. **Unknown side-effecting method denied, not forwarded** (bar #2).

**Session isolation (finding #5):** a streamable-HTTP-style test (or a two-session stub)
asserting a `tools/call` on session B binds session B's principal, never session A's.

**Existing suites stay green:** the zero-dep package suite must pass unchanged with the
`mcp` extra absent (new tests skip). No dangerous-zone change is implied **unless**
Option B (§3.6) is chosen — which carries its own kernel test obligations (§3.6).

---

## 7. Failure modes

| # | Failure | Gateway behavior | Enforced by |
|---|---|---|---|
| F1 | Policy raises / times out | `fail-closed/*` DENY (real record) → DENY envelope; no forward | `kernel.py:239-258` |
| F2 | Production profile, no verifier | Refuse at startup / first call (`ProductionProfileError`); no forward | `executor.py:63-64` |
| F3 | Missing `expected_actor` | `TypeError`/`ReceiptValidationError`; no forward | `executor.py:59-62` |
| F4 | Forged actor in body | Ignored for identity; receipt binds session principal | §3.4; verify 2b |
| F5 | Cross-tenant bundle pull | `PermissionError` → DENY | `tenant.py:86-90` |
| F6 | **Audit append fails** | Catch `AuditError` (no `.record`) → fixed leak-safe DENY envelope; no forward. (`PolicyError` from `tenant.py:168-171` is reachable only under rejected Option A — under B/C the gateway never calls `evaluate_tenant_action`; handler still catches both defensively) | `kernel.py:283-285`; handler §3.3 |
| F7 | Downstream subprocess dies / transport error after ALLOW | `isError` result to host; the ALLOW is already audited → emit a post-execution failure record so replay shows "authorized, execution failed" | `kernel.py:155-157` pattern; §9 Q4 |
| F8 | Unknown / unparseable side-effecting method | DENY, not forwarded | bar #2, §3.1 |
| F9 | **Escalation approval reused** | Design **mandates two layers**: (1) the gateway constructs its executor and `resume_with_receipt` calls with a `ReceiptConsumptionLedger` (available **on master**: `consumption.py`, wired as `consumption_ledger` params at `escalation.py:250` and `executor.py:43`; burns the approval's audit anchor before the side effect, replay raises `ReceiptAlreadyUsedError`); (2) pinning `expected_audit_hash` = the **approval receipt's own `audit_event_hash`** captured at `approve_escalation` time keyed by the pending's `record.event_id` — NEVER `pending.audit_hash`, which anchors the earlier ESCALATE event and never matches any approval receipt (see test #8) | ledger + design-enforced pinning + tests #8a/#8b |
| F10 | Validator == actor | Config load rejects it up front; residual `from_record` guard raises post-audit on ALLOW (no forward); pre-audit zero-event only under Option A | `receipt.py:283-287`; `tenant.py:136-141` |
| F11 | `mcp` SDK not installed | Loud `RuntimeError` with install hint; never a silent no-op | §5 |
| F12 | Non-identifier MCP argument keys unpacked into `tool_fn(**args)` | Forwarder accepts `**arguments`; flagged as a conformance edge to test | §9 Q3 |
| F13 | `sampling/createMessage` reverse channel | Denied by default unless config opts in | §3.1 |

**Single-use dependency (finding #2) — SATISFIED on master.** Earlier revisions (and
the rev-1/rev-2 reviews) concluded `consumption.py` was "not in-tree" — that was a
**stale-branch artifact**: this design was drafted in a working tree checked out on
`feat/governed-vulnclaw-pentest`, which predates the ledger. On `origin/master`,
`packages/gove-zone/src/gove_zone/consumption.py` exists (landed via PR #171,
commit `80292bb`; single-use enforcement itself via PR #114), and it is already wired
as an opt-in `consumption_ledger` parameter on both `execute_with_receipt`
(`executor.py:43`) and `resume_with_receipt` (`escalation.py:250`): the approval's
audit anchor is burned before the side effect and a replay raises
`ReceiptAlreadyUsedError` (`escalation.py:126-134`, master). The gateway — which will
be implemented against master — MUST construct its executor/resume calls with a
ledger (F9); "approvals are single-use" then holds by construction. The
`expected_audit_hash` pin (F9, test #8) remains as defense-in-depth binding a
specific approval to a specific pending.

---

## 8. Non-goals (this design)

- **G7–G10** — deferred to their plan items; only the audit-sink seam (§4) is reserved.
- **No sealed-file change except the explicitly human-gated Option B (§3.6).** If B is
  not approved, Option C ships as reuse-only.
- **Governance of resources/prompts/roots/completion** — passed through; only
  `tools/call` is gated (and `sampling/createMessage` is denied by default).
- **Host→gateway authentication** — alpha assumes a trusted local transport (§3.4).
- **Multi-tenant / multi-downstream fan-out in one process** — one gateway process
  fronts one downstream under one tenant/boundary in the pilot (but session state is
  already session-keyed, §3.4/finding #5).
- **Any production / certification / compliance claim** — see the header and AGENTS.md.

---

## 9. Open questions

Split per the review into **human-must-answer before implementation** vs **deferrable
during build**.

### Human must answer before implementation

- **Q1 — decision primitive (§3.6).** Approve Option B (small human-gated `kernel.py`
  `evaluate_and_record` helper, recommended) or accept Option C (public-API dispatch +
  echo registry, lossless fallback)? **Option A is not recommended** (degrades the
  escalation binding). *This is the §3.6 human-decision-required gate.*
- **Q6 — escalation approval channel.** The single-use blocker is resolved: the
  `ReceiptConsumptionLedger` exists on master and the design mandates passing it at
  the executor/resume gates (F9, §7), so ESCALATE can ship in the pilot with
  single-use enforced by construction. The remaining human decision is the approval
  channel only: a CLI verb wrapping `approve_escalation` (fits the local stdio pilot)
  vs an out-of-band API (console integration, later). Recommendation: CLI verb for
  the pilot.
- **NEW — TRANSFORM scope (§3.2).** Confirm the pilot rejects transform-policy
  bundles at config load (recommended, mirrors the validator==actor guard), or
  approve implementing the `record.transformed_args`-routing branch now. Doing
  neither is not an option: an unrouted TRANSFORM decision hard-fails every such
  call at verify check 10c — fail-closed but silently breaking the policy author's
  intent.
- **Q7 — trust boundary (§3.4).** Confirm the host→gateway hop may be assumed trusted
  (local stdio) for alpha, with the limitation stated in `docs/SECURITY_MODEL.md`.

### Deferrable during build

- **Q2 — `pyyaml` (§5/§10).** Declare a `yaml`/`pyyaml` extra now, or keep JSON-only
  config for the pilot? (Independent latent bug in `yaml_policy.py`.)
- **Q3 — `tool_fn(**arguments)` forwarding (F12).** Forward via a `**arguments` sink and
  reconstruct the JSON-RPC call (handles non-identifier arg keys); add a conformance case.
- **Q4 — downstream failure after ALLOW (F7).** Emit a post-execution failure record so
  replay shows "authorized, execution failed"? Recommendation: yes.
- **Q5 — streamable-HTTP scope.** Is stdio-only acceptable for the first pilot (HTTP a
  transport swap), or is HTTP a pilot blocker for the intended partner?

---

## 10. Corrections where the gap analysis / rev-1 proved wrong against source

- **Rev-1's DENY/ESCALATE routing was broken.** Rev-1 routed both through
  `evaluate_tenant_action` and "projected" the result into `rejection_dict` /
  `PendingApproval`. `evaluate_tenant_action` returns a **`DecisionReceipt`**;
  `rejection_dict` needs a **`DecisionRecord`** (`rejection.py:83-102`) and
  `PendingApproval.__post_init__` compares `record.decision` to the **enum**
  `Decision.ESCALATE` (`escalation.py:80`) while `DecisionReceipt.decision` is a `str`
  (`receipt.py:134`) — so it always raises. No inverse exists. Corrected in §3.2/§3.6:
  DENY via `DeniedError.record` (`errors.py:66`), ESCALATE via `EscalateError.pending`
  (`kernel.py:142`), ALLOW via the record on the dispatch anchor / a public
  `evaluate_and_record`.
- **Plan item 3 file reference.** `evaluate_tenant_action` is in **`tenant.py:106`**
  (re-exported from `gove_zone.__init__:105,187`), not `evaluation.py`; `evaluation.py`
  is the fixture-eval module (`evaluate_policy_scenarios`, `evaluation.py:212`).
- **Undeclared `pyyaml`.** `yaml_policy.py:12` imports `yaml` at module scope, but no
  `yaml`/`pyyaml` extra is declared (`pyproject.toml` extras: `schema`, `crypto`, `dev`).
  Reusing `YAMLPolicy` without declaring the dep is a latent `ModuleNotFoundError`. Pilot
  defaults to dep-free JSON bundles.
- **No `mcp` extra exists yet.** The plan writes `gove-zone[mcp]` as if pre-defined; it
  is absent and must be added (§5).
- **"Single-use ledger is not in-tree" was itself wrong — a stale-branch artifact.**
  Rev-2 (and both review passes) checked only the `feat/governed-vulnclaw-pentest`
  working tree, where `consumption.py` is indeed absent (only an orphan
  `__pycache__/consumption.cpython-313.pyc`). On **`origin/master`** the ledger exists
  (`consumption.py`, PR #171 / commit `80292bb`; single-use enforcement PR #114) and is
  already accepted by `execute_with_receipt` (`executor.py:43`) and
  `resume_with_receipt` (`escalation.py:250`). Corrected in §7/F9/Q6: the gateway
  builds against master and MUST pass a ledger; single-use is a design mandate, not a
  pending dependency. Lesson recorded: verify claims against `origin/master`, not the
  checked-out branch.
- **Raw-arg gate is reuse, not new logic.** G6 is satisfied because the kernel evaluates
  the policy against a `ToolCall` carrying **raw** args (`kernel.py:126-133`;
  `tenant.py:159-166`); `emit_receipt_for_hook`'s hashing path is demoted to an optional
  audit anchor (§3.5).
