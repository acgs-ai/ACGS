# ACGS architecture and security boundary

Status: derived view over existing evidence. This document introduces no new
security claim. Every statement below is a restatement of a row in
[`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md) or a finding in
[`threat-model-v2.md`](./threat-model-v2.md), reorganised by **trust class**
rather than by threat. Where those documents disagree with this one, they win.

This is not a certification, a compliance attestation, or a substitute for an
operator threat assessment.

## Why this document exists

The threat table in `SECURITY_MODEL.md` is organised one row per threat. That
shape answers "is threat X handled?" but not the question a security reviewer
actually asks first: **"which kind of trust am I being asked to extend, and to
whom?"**

A reviewer must be able to separate four distinct classes of guarantee, because
they fail independently and are defended by different mechanisms:

| Class | Question it answers | Fails independently of |
|---|---|---|
| **A. Evidence integrity** | Can the record of what happened be altered without detection? | B, C, D |
| **B. Authorization integrity** | Can an effect be authorized that policy did not approve? | A, C, D |
| **C. Runtime enforcement** | Can an effect happen without passing the boundary at all? | A, B, D |
| **D. Host compromise resistance** | Does any of the above survive an attacker who owns the machine? | — (D failing degrades A, B, and C) |

The core invariant is unchanged:

> **No valid Decision Receipt, no governed side effect.**

The load-bearing word is **governed**. Class C is precisely the boundary of that
word, and it is the class with the largest openly documented residual.

## Terminology

Use these terms. They are narrower than the alternatives and each maps to a
concrete enforcement site.

| Use | Not | Because |
|---|---|---|
| **governance enforcement plane** | "security kernel" | ACGS mediates authorization decisions and effect dispatch. It is not a reference monitor over the machine, does not mediate syscalls, and has no privileged position relative to the host. |
| **authorization evidence layer** | "audit system" | The chain produces evidence *bound to an authorization decision* (receipt hash, policy attestation, argument hash) — not free-form logs. |
| **capability-mediated execution boundary** | "runtime isolation" / "sandbox" | Effects are mediated by *registration and dispatch*, not by containment. Authorization is not containment (`threat-model-v2.md` §Deployment topology requirement). |
| **assurance level** / **deployment profile** | "tier" | `tier.py` already models **action tiers** (`explore` / `commit`), an orthogonal concept. Overloading "tier" for deployment hardening would collide with a hash-bound receipt field. |

The three claim phrases the boundary audit set out to remove — *security
kernel*, *complete runtime isolation*, *universal prevention* — **appear nowhere
in this repository except as the quoted counter-examples in this section and the
table above.** Verified by literal grep across all `.md`, `.py`, `.ts`, `.tsx`
files (excluding `node_modules` and virtualenvs): the only matches are the four
occurrences in this file. `threat-model-v2.md`
and `SECURITY_MODEL.md` already use the precise form ("managed authorization
kernel", i.e. the authorization component, not a system security kernel). No
claim text required rewriting; this document adds the missing structural view
rather than correcting an overclaim.

---

## A. Evidence integrity

*Can the record of what happened be altered, deleted, or fabricated without
detection?*

**Guaranteed.** In-chain mutation of a hash-chained JSONL audit log is
detectable: each event carries `previous_hash` and `event_hash`, and a malformed
tail fails closed *before* append (`SECURITY_MODEL.md` — Audit-chain tampering).
Execution-lifecycle records cannot be fabricated or edited without the operator's
Ed25519 lifecycle key: a `LifecycleAttestation` signs a canonical payload that
excludes the attestation itself, a frozen `LifecycleVerifierRegistry` pins the
trusted authorities, and an unsigned attestation is refused at construction.
Stripping an attestation to dodge verification is a fail-closed error
(`lifecycle_attestation_invalid`) rather than a silent downgrade. One key may not
sign both the audit checkpoint and a lifecycle record — the executor refuses the
append when `key_id`s collide, or when the lifecycle authority id collides with
`audit-checkpoint` / `audit-checkpoint:<namespace>`.

**Not guaranteed — and this is the sharpest distinction in the class.** A *bare*
JSONL chain detects in-chain edits, reorders, and malformed tails **only**. It
cannot detect a trusted full rewrite, nor a truncation to a shorter
self-consistent chain, because nothing inside the file contradicts either one.

Deletion and truncation are detectable **only for externally checkpointed strict
chains**, where an `AuditCheckpoint` binds `namespace`, `generation`,
`head_hash`, and `previous_checkpoint_hash` under a signature **held outside the
chain**. That control is exactly as strong as the external anchor's availability
and independent custody, and no stronger. Without an external checkpoint there
is **no truncation detection at all**. This is why `threat-model-v2.md` rates
audit deletion **CONDITIONAL**, not CLOSED.

**Structural sealing is not governance evidence.** `proof_pack.py` is a generic
structural codec that deliberately knows nothing about receipt, policy, audit,
replay, or consumption semantics. A pack that verifies structurally proves only
that its bytes are internally consistent — *not* that any decision was governed
or any receipt was valid. Semantic verification lives in the product layer
(`release_proof.py`, `mcp_proof.py`, `spend_proof.py`) and is **relative** to a
caller-supplied expected digest plus external trust inputs the caller must
supply independently. An artifact must never be the thing that decides whether
its own signature is checked. Avoid unqualified "independently verifiable"; state
what the verification is relative to.

**Reviewer's takeaway for class A:** evidence integrity is real but is a
*two-tier* property. Bare chain ⇒ tamper-evident against edits. Externally
checkpointed chain ⇒ additionally tamper-evident against deletion, and only to
the strength of the anchor's custody. Local JSONL is not WORM and not off-host
durable.

---

## B. Authorization integrity

*Can an effect be authorized that policy did not approve?*

**Guaranteed for a receipt that reaches the gate.** The strict path rejects a
missing, malformed, expired, or field-mismatched receipt before the adapter.
Binding is comprehensive and hash-bound: actor, action, exact canonical
arguments (`argument_hash`), policy artifact, expiry, and action tier all
participate in `receipt_hash`, so editing any of them invalidates the receipt.
`PolicyArtifactAttestation` content-addresses the policy artifact and is
re-checked at the final adapter boundary, closing the window between
authorization and execution. For P0 release, an `ImmutableArtifactSnapshot`
captures the exact bytes immediately before the adapter, recomputes the digest,
and constant-time compares it to the receipted `artifact_digest`; a mismatch
refuses at the last controllable boundary with `adapter_attempted=False` and
emits a signed `EXECUTION_REFUSAL` (`FAILED_CLOSED`, never `OUTCOME_UNKNOWN`).

Replay is closed by atomic persistent consumption with argument-bound
idempotency state keyed by tenant-scoped HMAC digests — **but only when the path
is configured with all four of**: a trusted signature verifier, an externally
checkpointed audit store, an anchored schema-v4 consumption store, and a
lifecycle signer whose key and authority are distinct from the audit-checkpoint
key. Omit any one and the strict path refuses to run rather than degrading.
Legacy/evaluate-only APIs, unsigned local receipts, PURE compatibility dispatch,
and a bare `DecisionReceipt.verify` / `ReceiptVerifier` check supply **no
store-level guarantee** and must not be presented as strict evidence.

**Not guaranteed.** Three residuals define the real edge of this class:

1. **Identity is asserted, not authenticated.** The gate checks that the receipt's
   actor equals an `expected_actor` supplied by the runtime context — it does not
   establish *who that actor is*. Actor authentication is integrator-owned
   (`SECURITY_MODEL.md` — Mismatched actor). Consequently the separation-of-duty
   control that rejects self-validation compares **opaque string identities**;
   there is no built-in IAM (`SECURITY_MODEL.md` — Self-validation). An attacker
   who can choose the string an integrator passes as `expected_actor` is inside
   this boundary, not outside it.
2. **Action-tier enforcement is primarily policy-side.** The declared tier is
   untrusted and a registry is authoritative (`effective = min(declared,
   registered)`; unregistered or no registry ⇒ `commit`). The load-bearing
   control is at *minting*: a commit-only tool is evaluated under `commit`. The
   executor-side check is **opt-in** — it requires passing `tool_tier_registry`
   to `execute_with_receipt` / `GovernedExecutor`, and `ReceiptVerifier` does not
   thread one.
3. **Unsigned hashes are recomputable.** Receipt-hash tamper detection is only a
   cryptographic control when signing is engaged; under host compromise an
   unsigned hash can simply be recomputed (this hands off to class D).

**Reviewer's takeaway for class B:** authorization integrity is strong *given* an
authenticated principal and the fully configured strict profile. It binds
decisions to identities as supplied; it does not establish those identities.

---

## C. Runtime enforcement

*Can an effect happen without passing the boundary at all?*

This is the class where ACGS makes its narrowest claim, and honesty here is what
makes classes A and B meaningful.

**Guaranteed within the governed topology.** Kernel, `ManagedAgent`, and
`GovernedTool` registrations route `SIDE_EFFECT` tools to the strict dispatcher
or deny. The reference product topologies hide downstream adapters. Failure modes
fail closed rather than open: a policy exception synthesizes `DENY` and audits
it; an audit append failure raises `AuditError` *before* execution; an optional
`policy_timeout` converts a hung policy evaluation into `DENY`. The MCP gateway
enforces a dense set of transport and identity controls before dispatch —
redirect refusal, mandatory TLS, DNS-rebinding rejection, gateway-held downstream
credentials with no direct-call fallback, `Host`/`Origin` pinning with all
`Forwarded`/`X-Forwarded-*` headers rejected, and an authority check that stops a
`mcp.tools.list` health credential from ever reaching `tools/call`.

**Not guaranteed — the defining open residual.** *Executor bypass is OPEN.* A raw
callable retained by the application, or a downstream service exposed beside the
gateway, cannot be mediated (`threat-model-v2.md` — "Raw callable or downstream
service exposed beside the gateway", status **OPEN**). Nothing in the library
prevents an integrator from calling `requests.post` directly. Enforcement depends
on a **deployment topology** the repository does not establish: agents must be
unable to reach raw adapters, downstream MCP servers, deployment credentials, or
payment credentials except through the governed boundary, with independent
network and process controls.

Two further limits belong here rather than in B:

- **`policy_timeout` is configurable, not globally required.** An operator who
  never sets it has no hang protection.
- **At-most-once *attempt*, never exactly-once *effect*.** Strict execution
  commits a durable claim then makes at most one adapter attempt. If the outcome
  is ambiguous the executor persists terminal `UNKNOWN` and denies later reuse —
  but the downstream may already have acted, and ACGS cannot observe that.
  Operators must reconcile `UNKNOWN` records out of band.

**Reviewer's takeaway for class C:** ACGS mediates the channels registered with
it. It does not mediate the process. "No valid Decision Receipt, no governed side
effect" is true; whether *all* side effects are governed is a property of the
deployment, not of the library.

---

## D. Host compromise resistance

*Does any of the above survive an attacker who owns the machine?*

**Not claimed.** This is the honest answer and it is stated as such in both
source documents.

- **Host/process compromise: OPEN.** Signatures, external anchors, and isolation
  guidance reduce exposure; none of them constitute containment.
- **Managed PKI, key rotation, HSM custody, and service availability: OPEN —
  "None claimed."** The operator must supply and validate these. The
  `LifecycleVerifierRegistry` and the JWS `Ed25519TrustSnapshot` are *local
  pinned snapshots* read once from operator-supplied material, not a managed key
  lifecycle service. Trust reduces to the operator's key custody.
- **Authority separation is enforced on identity, not custody.** The executor
  refuses colliding `key_id`s, but an operator may still hold both keys in one
  place. Code separation is not custody separation.
- **Sandboxing is not supplied.** A Python-only `E2BSandbox` adapter exists, but
  the repository ships no E2B SDK, API key, remote service, or live proof. Node
  and worktree execution modes are **not** sandbox providers. The `bubblewrap`
  (`bwrap`) option currently fails closed on its anonymous response-FD transport
  and is not a working profile.
- **Unsigned dev mode is not production signing.** Unsigned local receipts are a
  legacy/dev surface explicitly excluded from strict evidence.
- **Local JSONL is not WORM.** A compromised host controlling the signing keys
  *and* all anchors is outside the proof entirely.

**Reviewer's takeaway for class D:** ACGS's cryptographic guarantees are
conditional on key custody the project does not provide. Class D is the operator's
to close, and no class A/B/C control survives its unconditional failure.

---

## What a reviewer should conclude

| If you need… | ACGS supplies | You must supply |
|---|---|---|
| Proof an approved decision was not silently edited | A (chain + lifecycle attestation) | Independent custody of checkpoint and lifecycle keys |
| Proof evidence was not deleted | A, **conditionally** | The external checkpoint anchor and its availability |
| Proof an effect matched its approval | B (full binding + final revalidation) | Authenticated principal identity behind `expected_actor` |
| Proof the effect could not be replayed | B, given the full strict profile | Durable consumption store backend |
| Proof *all* effects were governed | **Not supplied** — C is OPEN | Network/process topology making raw adapters unreachable |
| Survival of host compromise | **Not claimed** — D is OPEN | HSM/managed PKI, hardened runtime, WORM evidence sink |

The honest one-line statement of the current system:

> ACGS is a governance enforcement plane that cryptographically binds
> authorization decisions to identities, arguments, and policy artifacts, and
> produces tamper-evident evidence of every effect routed through it. It mediates
> the capabilities registered with it; it does not contain the process, establish
> identity, or custody keys.

## Relationship to the hardening programme

The gaps a reviewer will find in classes B, C, and D are **not undiscovered
holes**. Each is an already-tracked residual with an existing roadmap entry in
the final column of the `SECURITY_MODEL.md` threat table. Work to close them is
closure of documented limitations, not correction of an overclaim.

The phase-by-phase status of that closure work — what exists, what is partial,
and what is missing, with file-level evidence — is tracked in
[`hardening-ledger.md`](./hardening-ledger.md).

The three residuals with the widest blast radius, in priority order:

1. **Class C — executor bypass (OPEN).** Enforcement currently depends on
   integrators routing effects through ACGS. Until a bypass is detectable
   (static scan for ungoverned effect calls, plus a runtime effect registry),
   "all effects are governed" is a deployment property, not a verifiable one.
2. **Class B — identity is asserted, not authenticated.** Until an authenticated
   principal is bound into the receipt, actor binding and separation-of-duty
   both reduce to comparing operator-supplied strings.
3. **Class D — no managed key lifecycle.** Rotation, revocation, and grace
   periods are absent, so every signature-based control in A and B inherits the
   operator's key-custody posture with no in-band way to retire a key.

## Source documents

- [`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md) — per-threat table, protections, tests, residuals, roadmap.
- [`docs/security/threat-model-v2.md`](./threat-model-v2.md) — CLOSED/CONDITIONAL/OPEN status per threat for the P0/P1/P2 governed paths.
- [`docs/DECISION_RECEIPT_SPEC.md`](../DECISION_RECEIPT_SPEC.md) — receipt schema, binding rules, validation and strict execution algorithms.
- [`docs/CLAIMS.md`](../CLAIMS.md) — claim ledger and public wording rule.
