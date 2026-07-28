# Hardening ledger — spec phases vs. implemented reality

Companion to [`architecture-boundary.md`](./architecture-boundary.md). That
document partitions the *current* guarantees into trust classes. This one tracks
the **hardening programme** that aims to close the residuals, phase by phase.

Status vocabulary matches [`threat-model-v2.md`](./threat-model-v2.md):

- **EXISTS** — implemented and covered by tests in this repository.
- **PARTIAL** — a real mechanism exists but does not meet the stated goal.
- **MISSING** — no implementation. Not a regression; in most cases a documented
  residual with an existing roadmap entry in `SECURITY_MODEL.md`.

All file references are to `packages/gove-zone/src/gove_zone/` unless noted.
Evidence was gathered by direct inspection; see "How this was verified" below.

## Headline

The programme is **closure work on documented limitations, not correction of an
overclaim.** The receipt/authorization core (class B) and the evidence chain
(class A) are substantially built. The concentrated gaps are:

1. **Capability-mediated effect channels and bypass detection** (class C) — the
   largest genuine gap, and the one that gives "governed side effect" its scope.
2. **Binding an authenticated principal into the receipt** (class B) — the
   mechanism exists in the authorization layer but does not reach the receipt.
3. **A managed key lifecycle** (class D) — absent, and self-documented as absent.

## Phase 0 — Claim and security boundary audit — **EXISTS**

Delivered by `architecture-boundary.md`. The A/B/C/D partition the acceptance
criterion asks for is in place.

The audit's "remove ambiguous claims" instruction required **no changes**: the
three target phrases (*security kernel*, *complete runtime isolation*,
*universal prevention*) had zero pre-existing occurrences repo-wide. The
codebase already used the precise form ("managed authorization kernel",
`threat-model-v2.md:13`).

## Phase 1 — Close the bypass gap — **MISSING** (largest gap)

| Item | Status | Evidence |
|---|---|---|
| First-class `Capability` object (`capability_id`, `allowed_effects`, `constraints`, `policy_binding`, `signature`) | **MISSING** | No such type. `VerifiedPrincipal` (`authorization.py:391`) is the nearest analogue but models *who*, not *what may be done*. `path_capability.py` is artifact-snapshot capability, a different concern. |
| Governed effect adapters: filesystem, subprocess, HTTP, database, cloud | **MISSING** | `adapters/` contains only `autogen.py` and `langgraph.py` — *agent-framework* shims, not effect-channel adapters. Effects are mediated by tool registration and strict dispatch, not by a per-channel adapter layer. |
| Runtime effect registry (`effect_type` / `adapter` / `capability_requirement`) | **MISSING** | Zero occurrences of `effect_type` in the package. |
| Static AST bypass scan (`requests`, `httpx`, `subprocess`, `socket`, DB clients outside approved adapters) | **MISSING** | No scanner in `scripts/`. `ast` parsing appears only in `sandbox.py` and `tests/test_side_effect_kernel.py`, for unrelated purposes. |
| CI fails when a developer adds an uncontrolled side effect | **MISSING** | No such gate. |

This phase corresponds exactly to the **OPEN** row "Raw callable or downstream
service exposed beside the gateway" (`threat-model-v2.md:42`) and "Executor
bypass" (`SECURITY_MODEL.md`). Today, bypass resistance is a *deployment
topology* property. Phase 1 is what would make it a *verifiable* one.

**Cheapest first increment:** the static scanner plus effect registry. Both are
additive, neither touches a security-sensitive file, and together they convert
the residual from "operator must not do this" into "CI refuses it."

## Phase 2 — Harden identity binding — **PARTIAL**

| Item | Status | Evidence |
|---|---|---|
| Authenticated principal type | **EXISTS** | `VerifiedPrincipal` (`authorization.py:391`): `tenant_id`, `actor_id`, `role`, `authority`, `authentication_context`, `verified_at`, `expires_at`, with expiry-after-verification enforced in `__post_init__`. `PrincipalResolver` Protocol at `authorization.py:947`. `MCPPrincipalContext` at `mcp_identity.py:619`. |
| Signed workload identity | **EXISTS (MCP path only)** | `EdDSAJWSVerifier` with pinned `Ed25519TrustSnapshot`, exact `kid` selection, signature verified before claims parsed (`SECURITY_MODEL.md` — Remote workload identity forgery). |
| Tenant isolation | **EXISTS** | `tenant_id` on receipt and principal; `tests/adversary/test_tenant_boundary_isolation.py`. |
| **Receipt binds a principal identity hash** | **MISSING** | `DecisionReceipt.actor` is a plain `str`. No `principal_id` and no principal-identity hash participates in `receipt_hash`. |
| `issuer` / `public_key` / `attestation_state` on the principal | **MISSING** | Not fields of `VerifiedPrincipal`. |

**The gap in one sentence:** an authenticated principal exists at the
authorization boundary but does not reach the receipt, so the receipt's actor
binding is still a string comparison. Acceptance ("changing actor metadata
without the identity key invalidates the receipt") is **not met today**.

## Phase 3 — Receipt V3 cryptographic authorization — **PARTIAL**

Current `DecisionReceipt` fields (`receipt.py`) against the V3 spec:

| Spec field | Status | Current name / note |
|---|---|---|
| `receipt_id` | EXISTS | `receipt_id` |
| `action` | EXISTS | `proposed_action` |
| `argument_hash` | EXISTS | `argument_hash` |
| `policy_hash` | EXISTS | `policy_hash` (+ `policy_bundle_id`, `policy_version`) |
| `validator_identity` | EXISTS | `validator_id`, `validator_role` |
| `issued_at` | EXISTS | `timestamp` |
| `expires_at` | EXISTS | `expires_at`, hash-bound |
| `signature` | EXISTS | `signature`, `signature_algorithm`, `signing_key_id` |
| `principal_id` | **MISSING** | see Phase 2 |
| `effect_type` | **MISSING** | see Phase 1 |
| `capability_hash` | **MISSING** | see Phase 1 |
| `nonce` | **MISSING as a receipt field** | zero occurrences in `receipt.py` |
| `sequence_number` | **MISSING** | zero occurrences in `receipt.py` |

Beyond the field list:

- **Replay protection / single-use consumption: EXISTS**, but via the persistent
  consumption store (`consumption.py`), *not* a receipt nonce. `threat-model-v2.md`'s
  phrase "nonce/idempotency state" refers to consumption-store state. Precision
  matters: the anti-replay control is server-side and stateful, so it holds only
  when the strict profile is fully configured. Covered by
  `tests/adversary/test_standalone_receipt_replay.py`.
- **Expiration enforcement: EXISTS** (`expires_at`, hash-bound and checked).
- **Key lifecycle (active / revoked / expired, rotation, grace periods):
  MISSING**, and explicitly self-documented — `signing.py:21`: *"**Revocation**: a
  compromised key cannot be revoked; the verifier mapping must…"*. Acceptance
  ("a revoked key cannot authorize new effects") is **not met today**.

Note the acceptance criteria split cleanly: *"a valid old receipt cannot execute
twice"* is **already met**; *"a revoked key cannot authorize new effects"* is not.

## Phase 4 — Real role separation — **PARTIAL**

| Item | Status | Evidence |
|---|---|---|
| Proposer/validator/executor roles modelled | **EXISTS** | `validator_id` / `validator_role` on the receipt; separation-of-duty rejects actor==validator; `tests/test_maci_role_separation.py`. |
| Separate signing key per role | **MISSING** | Roles are compared as strings. `SECURITY_MODEL.md` states the residual directly: *"Opaque string identity; no built-in IAM."* |
| Process/service isolation (proposer-service / validator-service / executor-service) | **MISSING** | All in-process. |

**Partial credit worth noting:** genuine two-root key separation *does* exist,
but between *audit* roles, not MACI roles — the executor refuses a lifecycle
append when the lifecycle signer's `key_id` equals the checkpoint `key_id`, or
when authority ids collide. That is the pattern Phase 4 should generalise to
proposer/validator/executor.

Acceptance ("compromise of executor credentials cannot create valid validator
receipts") is **not met today**: with string identities and a shared signing key,
it can.

## Phase 5 — Immutable evidence system — **PARTIAL** (best effort-to-value ratio)

| Item | Status | Evidence |
|---|---|---|
| Local append-only hash chain | **EXISTS** | `audit.py`, `previous_hash` / `event_hash`; `tests/test_audit_chain_corruption.py`. |
| Signed checkpoint binding chain head | **EXISTS** | `AuditCheckpoint` (`audit.py:53`) binds `namespace`, `generation`, `head_hash`, `previous_checkpoint_hash`. |
| **Anchor interface** | **EXISTS** | `AuditCheckpointAnchor` Protocol (`audit.py:167`) — `read()` + `compare_and_swap()`, with documented anti-rollback and poison-on-indeterminate-CAS semantics. |
| **External anchor implementation** (transparency log / immutable object storage / witness service) | **MISSING** | Zero occurrences of transparency-log, witness, Sigstore/Rekor, S3/object-storage, or WORM in the package. |

**This is the highest-leverage remaining item.** The hard design work — the
monotonic CAS contract that makes an anchor sound — is already done and
documented in the Protocol. What is missing is one conforming implementation
against a durable external target. Landing it flips audit deletion from
**CONDITIONAL** to CLOSED for deployments that use it, and is the only Phase 8
attack (log deletion) that currently *cannot* be tested, because there is no
anchor to diverge from.

## Phase 6 — Trusted execution profile — **MISSING**

Assurance levels (library / governed runtime / sandboxed / attested) are not
modelled. Note the **naming collision**: `tier.py` already defines
`ToolTierRegistry` over *action* tiers (`explore` / `commit`), a hash-bound
receipt field. Deployment hardening levels must use a different word —
*assurance level* or *deployment profile*.

Containment status is unchanged from `threat-model-v2.md:48`: a Python-only
`E2BSandbox` adapter with no SDK/key/service/live proof; Node and worktree modes
are not sandbox providers; the `bwrap` path fails closed on anonymous
response-FD transport.

## Phase 7 — Enterprise security controls — **PARTIAL**

| Item | Status | Evidence |
|---|---|---|
| Audit export / incident replay / receipt investigation | **EXISTS** | `proof_pack.py`, `replay.py`, `cli.py`, product verifiers (`release_proof.py`, `mcp_proof.py`, `spend_proof.py`). |
| External KMS integration, no plaintext signing keys | **MISSING** | Zero occurrences of KMS/HSM/vault/keyring in the package. Consistent with the **OPEN** row "Managed PKI, key rotation, HSM custody… None claimed." |
| `docs/security/threat-model.md` | **EXISTS under another name** | `threat-model-v2.md`. Do not create a second file; extend that one. |
| `docs/security/control-mapping.md` (SOC2 / ISO27001 / NIST AI RMF / OWASP Agentic AI) | **MISSING** | `docs/COMPLIANCE_CROSSWALK.md` and `docs/crosswalks/` exist but are untracked working-tree files, and neither is a control mapping keyed to the A/B/C/D classes. |

## Phase 8 — Adversarial validation — **PARTIAL** (stronger than the spec assumes)

A dedicated `packages/gove-zone/tests/adversary/` suite already exists, including
a `test_coverage_manifest.py` that gates coverage of the suite itself.

| # | Attack | Status | Existing test |
|---|---|---|---|
| 1 | Direct HTTP bypass | **PARTIAL** | `adversary/test_adapter_bypass.py` covers adapter bypass generally; no HTTP-channel-specific case, and no CI static scan (Phase 1). |
| 2 | Fake actor identity | **PARTIAL** | `adversary/test_unsigned_forgery.py`, `adversary/test_tenant_boundary_isolation.py`. Cannot be fully closed until Phase 2 binds a principal. |
| 3 | Receipt replay | **EXISTS** | `adversary/test_standalone_receipt_replay.py`. |
| 4 | Validator impersonation | **PARTIAL** | `test_maci_role_separation.py`. Limited by string identity (Phase 4). |
| 5 | Log deletion | **EXISTS (in-chain)** | `adversary/test_audit_full_chain_rewrite.py`, `test_audit_chain_corruption.py`. External-anchor-mismatch case is **untestable until Phase 5** ships an anchor. |
| 6 | Executor compromise | **MISSING** | No simulation test. |
| 7 | New unmanaged tool addition ⇒ CI failure | **MISSING** | Requires the Phase 1 registry + gate. |

Also already covered beyond the spec's list: `test_policy_bundle_id_downgrade.py`,
`test_policy_version_downgrade.py`, `test_pql_silent_fail_open.py`,
`test_ruleset_default_allow.py`, `test_authority_scope_unenforced.py`.

## Recommended order

Sequenced by dependency and by value per unit of risk taken:

1. **Phase 5 anchor implementation** — additive, the interface already exists,
   and it unblocks attack #5. Lowest risk, highest immediate value.
2. **Phase 1 static scanner + effect registry** — additive; converts the OPEN
   bypass residual into a CI-enforced one; unblocks attacks #1 and #7.
3. **Phase 2 principal binding into the receipt** — first change that touches
   `receipt.py`, so it requires negative-path tests plus wiring proof, and a
   migration path for the existing `actor` field.
4. **Phase 3 key lifecycle** — depends on Phase 2's identity model.
5. **Phase 4 role separation** — depends on Phases 2–3; generalises the existing
   audit two-root key-collision pattern to MACI roles.
6. **Phases 6–7** — deployment and compliance surface; largely operator-facing.

Phases 2–4 modify files listed in `.claude/rules/security-sensitive-files.md`.
Each requires negative-path tests proving the side effect did **not** run, proof
of gate wiring (not just direct unit calls), and an explicit statement of whether
unsigned mode, signing, policy binding, expiry, actor binding, audit replay, or
executor enforcement changed.

## How this was verified

Direct inspection of the working tree on branch `feat/gove-zone-policy-identity`.
Field lists were read from the source dataclasses; MISSING verdicts were
established by literal repo-wide grep returning zero occurrences (`effect_type`,
`capability_hash`, `nonce`/`sequence_number` in `receipt.py`, KMS/HSM/vault,
transparency-log/witness/WORM). Test inventories are directory listings of
`packages/gove-zone/tests/` and `tests/adversary/`.

**Not verified:** no gove-zone runtime test suite was executed for this ledger —
it is a survey of what exists, not a claim that it passes. Run the package gate
(`uv run --package gove-zone python -m pytest packages/gove-zone/tests
--import-mode=importlib -q`) before relying on any EXISTS verdict as *working*
rather than *present*.
