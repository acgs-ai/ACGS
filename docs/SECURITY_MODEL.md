# Security model and threat table

Core invariant:

> **No valid Decision Receipt, no side effect.**

Status: alpha/local proof. This document is a threat model, not a certification claim.

## Threat table

| Threat | Risk | Current protection | Test coverage / demo | Remaining limitation | Roadmap item |
|---|---|---|---|---|---|
| Missing receipt | Executor runs a side effect with no authorization evidence. | `execute_with_receipt`, `GovernedExecutor`, and `ReceiptVerifier` reject `None`. | `test_executor_refuses_no_receipt`, `gove-zone proofpack`, `examples/tamper_demo`. | Direct tool paths outside the gate can bypass ACGS. | Integration hardening and gateway conformance tests. |
| Malformed receipt | Bad or incomplete evidence is accepted. | Required-field checks fail closed. | `test_executor_refuses_malformed_receipt`, `test_verification_rejects_missing_fields`. | External runtimes must not catch-and-ignore validation errors. | Standard error contracts for adapters. |
| Expired or revoked receipt | Old or withdrawn authorization is executed. | `expires_at` is hash-bound; the strict managed path also checks persistent revocation state. | Expiry and consumption-store tests. | The repository supplies a local store, not a hosted global revocation service. | Operator-managed durable store and availability controls. |
| Tampered receipt | Actor/action/policy/expiry/authority fields are edited. | `receipt_hash` recomputation detects edits; signing verifies hash when engaged. | `test_verification_rejects_altered_fields`, `test_receipt_signing.py`, demo output. | Unsigned hashes are recomputable under host compromise. | Signed receipts on by default for secure profile. |
| Mismatched actor | Receipt issued for one actor is used by another. | Gate requires `expected_actor` from runtime context and checks receipt actor. | `test_maci_role_separation.py`, executor tests. | Actor authentication is integrator-owned. | Identity binding adapters and production auth profile. |
| Mismatched action | Receipt for one tool authorizes another. | `expected_action` check. | `test_decision_receipt.py`, `test_executor_guard.py`. | None inside gate; bypass risk remains outside gate. | Gateway coverage for all tool entrypoints. |
| Argument substitution | Receipt for safe args is reused for dangerous args. | `argument_hash` and exact transform checks. | `test_argument_binding.py`, `test_executor_guard.py`. | Raw args are not stored in audit by default; strong replay needs side-store. | Proof packs with side-store or redaction policy. |
| Self-validation | Agent validates its own authority. | `Validator` role, `DecisionReceipt.from_record` guard, gate actor-anchor check. | `test_maci_role_separation.py`. | Opaque string identity; no built-in IAM. | Integrator identity and signed validator profile. |
| Replay or idempotency substitution | A receipt is consumed twice or an idempotency key is reused for different arguments. | Strict **standalone** (`execute_with_receipt` / `GovernedExecutor`) and strict **managed** execution both use atomic persistent consumption and argument-bound idempotency state, keyed by tenant-scoped HMAC digests. | Consumption, restart, concurrency, and idempotency tests. | The guarantee exists only when the path is configured with a signature verifier, checkpointed audit, an anchored schema-v4 consumption store, and a lifecycle signer. Legacy/evaluate-only APIs and raw receipt-only verification provide no store-level guarantee. | Operator-managed durable backend. |
| Lifecycle-record forgery | An attacker fabricates or edits an execution-lifecycle audit record to invent a claim, an outcome, or a successful execution. | Lifecycle records require an Ed25519 `LifecycleAttestation` over a canonical signing payload that excludes the attestation itself; a frozen `LifecycleVerifierRegistry` pins trusted authorities; unsigned attestations are refused at construction. | `test_lifecycle_verifier_registry.py`, replay-bundle tests. | Trust reduces to the operator's lifecycle key custody; the registry is a local snapshot, not a managed PKI. | Managed key lifecycle and authority distribution. |
| Lifecycle downgrade | A lifecycle record is stripped of its attestation, or replayed as an older unattested record, to dodge verification. | Strict replay fails closed when a lifecycle record's attestation is absent, malformed, or unverifiable (`lifecycle_attestation_invalid`); `from_dict` refuses to let a policy record acquire lifecycle material, and forbidden key/authority ids can be excluded. | `test_lifecycle_verifier_registry.py`, `test_replay.py`. | Historical records that predate `record_kind` are classified as policy decisions — they are **policy-compatible only** and cannot be presented as execution-lifecycle evidence. | Signed generation counters for authority rotation. |
| Lifecycle/checkpoint authority collision | One key or authority signs both the audit checkpoint and the lifecycle record, collapsing two independent trust roots into one. | The executor refuses to append a lifecycle record when the lifecycle signer's `key_id` equals the checkpoint `key_id`, or when the lifecycle authority id collides with `audit-checkpoint` / `audit-checkpoint:<namespace>`. | Executor lifecycle tests. | Code-separation is enforced on identity, not on physical key custody; an operator can still hold both keys in one place. | Separate custody guidance and HSM-backed roots. |
| Ambiguous execution outcome | An adapter call fails ambiguously and the caller retries the same receipt, causing a duplicate side effect. | The claim is committed durably before the single adapter attempt; on an ambiguous or exception outcome the executor attempts to persist and confirm terminal `UNKNOWN`, and once confirmed, later reuse of that receipt is denied. If persistence, readback, or evidence append fails, the path fail-stops and no retry is authorized, but the terminal state and its evidence may be unavailable. | Executor and side-effect-kernel tests. | **Residual: at-most-once *attempt*, not exactly-once *effect*.** The downstream may already have acted before the outcome became ambiguous; ACGS cannot observe that. Operators must reconcile `UNKNOWN` out of band. | Adapter-side reconciliation contracts. |
| Audit-chain tampering | Evidence is edited after the fact. | Hash-chained JSONL with `previous_hash` and `event_hash`; malformed tail fails closed before append. | `test_audit_chain.py`, `test_audit_chain_corruption.py`, tamper demo. | A **bare** JSONL chain detects in-chain edits, reorders, and malformed tails only. It cannot detect a trusted full rewrite or a truncation to a shorter self-consistent chain — nothing inside the file contradicts it. Local JSONL is not WORM/off-host durable. | WORM/SIEM/exportable proof packs. |
| Audit deletion or truncation | Evidence is removed or the chain is cut back and re-sealed self-consistently. | Detected only for **externally checkpointed strict chains**: `AuditCheckpoint` binds `namespace`, `generation`, `head_hash`, and `previous_checkpoint_hash` under a signature held outside the chain, so a rewrite or truncation diverges from the trusted checkpoint. `replay_checkpointed_bundle` fails closed when the checkpoint is missing, unavailable, malformed, or divergent. | `test_replay.py`, `test_replay_bundle_equivalence.py`, audit checkpoint tests. | The guarantee is exactly as strong as the external checkpoint anchor's availability and independent custody. Without an external checkpoint there is no truncation detection. | Off-host anchor and durable checkpoint service. |
| Unsigned dev mode misuse | Local unsigned receipts are marketed as production signing. | Docs and `CLAIM_BOUNDARY` identify unsigned local proof; signing mode exists. | `test_receipt_signing.py`, `docs/CLAIMS.md`. | Operator can still deploy unsigned mode if they choose. | Secure profile with signing required by default. |
| Policy-artifact substitution | Authorization is evaluated under one policy artifact but execution uses another. | `PolicyArtifactAttestation` binds the content-addressed artifact; the strict managed path revalidates it at the final adapter boundary. `PolicyArtifactAttestation` proves the *policy* artifact only — it never covers deployment bytes. | Policy-artifact and final-revalidation tests. | Policy distribution and attestation signer PKI are operator-owned. | Managed policy service and key lifecycle. |
| Deployment-artifact substitution after authorization (P0) | The receipted deployment digest is approved, then the on-disk artifact is swapped for different bytes before the deployment adapter runs. | The receipt binds the `artifact_digest`; the kernel captures an `ImmutableArtifactSnapshot` of the exact bytes immediately before the final adapter boundary, recomputes its digest, and constant-time compares it to the receipted digest — a mismatch refuses at the last controllable boundary with `adapter_attempted=False`, emitting a signed/audited `EXECUTION_REFUSAL` record (`FAILED_CLOSED`, not `OUTCOME_UNKNOWN`). Route registration (adapter + artifact requirement) is atomic under the executor registry lock, so no window exists where a route has an adapter but no artifact requirement. The snapshot bytes, source path, and pathname are execution-local and are never serialized into the receipt or proof pack. | `release_proof.py` reference-demo (`--pre-capture-tamper`), `path_capability.py` snapshot tests, `release_gate.py` route-registration tests. | Per-snapshot capture is bounded by a configurable default of 64 MiB and per-executor leased captures by a configurable default 256 MiB aggregate; these are defaults, not absolute guarantees, and an operator may raise or lower them. Abandoned leased snapshots release via a GC finalizer; an explicit close detaches exactly once. | Managed artifact-registry attestation and signed digest custody. |
| Action-tier downgrade | Agent declares the lenient `explore` tier to dodge strict `commit` policy rules or the gate. | Declared tier is untrusted; a tool-tier registry is authoritative (`effective = min(declared, registered)`; unregistered / no-registry ⇒ `commit`); tier is bound into `receipt_hash`. Primary enforcement is policy-side at minting (a commit-only tool is evaluated under `commit`); an optional executor-side check additionally refuses an `explore` receipt for a commit-only tool when a registry is supplied at the gate. Receipt gate, `expected_actor`, audit append, and `DENY`/`ESCALATE` non-executability apply to every tier. | `test_action_tiering.py` (T1/T2/T3/T5b/T8). | Registry is manual/declarative — no semantic side-effect detection; operator must register side-effecting tools as `commit` (already the default). Executor-side check is opt-in: pass `tool_tier_registry` to `execute_with_receipt` / `GovernedExecutor`; `ReceiptVerifier` does not thread one, so policy-side minting is the load-bearing control. | Semantic tool classification, signed tier registry, and registry threading through `ReceiptVerifier`. |
| MCP/tool-gateway misuse | MCP connects tools but execution happens before governance. | `integration.py` normalizes MCP/function-call shapes; examples show gateway placement. | `test_integration_hook.py`, `test_integration_gaps.py`, `examples/mcp_tool_gate`. | Adapter shape support is local; production MCP server enforcement must be wired by integrator. | MCP adapter conformance suite. |
| MCP downstream redirection / SSRF / DNS rebinding | The gateway is steered at an attacker-chosen or internal endpoint, or a resolved address changes between validation and connection. | Remote Streamable HTTP pins a validated origin and refuses redirects (`REDIRECT_FORBIDDEN`); HTTPS is required (`TLS_REQUIRED`) for public and private-service origins; loopback/private/link-local addresses are refused for public origins; resolution failure fails closed (`DNS_UNAVAILABLE`) and re-resolution divergence is rejected (`DNS_REBINDING`). The stdio transport targets a fixed, validated executable path with an ancestor-chain integrity snapshot. | `test_mcp_http_transport.py`, `test_mcp_reference_topology.py`. | Reference/fixture composition only. The one HTTP exception is the internally minted, capability-limited container fixture at the exact origin `http://downstream:8000/mcp` (`_MCPFixtureHTTPServicePin`, which callers cannot construct); it is fixture-only and non-production, and every public/private-service path remains HTTPS-only. Transport-level controls do not authorize the call — the receipt gate does; an operator who exposes the raw downstream server independently still has a bypass. | MCP adapter conformance suite. |
| MCP credential passthrough / fallback | An agent supplies its own token, or the gateway silently falls back to a direct downstream call when the governed route fails. | Downstream credentials are gateway-held (`MCPDownstreamCredential`), never taken from agent-supplied input; there is no direct fallback path — the reference composition fails closed instead of degrading to an ungoverned call. Timeouts are bounded and never become an unbounded wait or a blind retry of the effect. Their outcome depends on when uncertainty arises: a timeout **before** the call is dispatched fails closed with no downstream call at all, while a timeout **after** dispatch — a dropped or ambiguous response — is not a simple refusal, because the downstream may already have acted: the executor attempts to persist and confirm terminal `UNKNOWN`, and once confirmed there is no blind retry and no later reuse of the receipt; if that state cannot be persisted or confirmed the path fail-stops without authorizing a retry, though the terminal state and its evidence may then be unavailable. | `test_mcp_http_transport.py`, `test_mcp_reference_topology.py`. | Fixture-only. **Operator residual:** the raw downstream MCP server must be network/process isolated so it is unreachable except through the gateway; the repository does not establish that boundary. | Deployment isolation guidance and conformance checks. |
| Remote transport ambiguity (Host/Origin spoofing, proxied requests, oversized or resumed sessions) | A caller reaches the P1 remote listener through a mismatched Host/Origin, a spoofed `Forwarded`/`X-Forwarded-*` header, an oversized/chunked body, or an attempted SSE/session resume, and the listener admits it as if it were the canonical caller. | The remote guard (`_RemoteGuard`) checks, before any MCP dispatch: exactly one raw `Host` header matching the configured canonical authority (and the absolute-form target, if present); at most one `Origin`, matched against an allowlist, with an absent Origin refused unless `allow_absent_origin` is set and the asymmetric JWS verifier is configured; every `Forwarded`/`X-Forwarded-*` header rejected outright (`proxy_headers=False`, `forwarded_allow_ips=[]` in Uvicorn); `GET /mcp`, `Last-Event-ID`, and `Mcp-Session-Id` rejected (the SDK runs stateless JSON-response mode, so there is no session to resume); header count/byte, request-body, and `Content-Length` budgets enforced before the body is buffered; and an in-process concurrency semaphore that refuses (503) rather than queues once the configured slots are exhausted. TLS terminates directly in Uvicorn against a process-private snapshot of already-validated certificate/key bytes. | `test_mcp_runtime_e2e.py` remote-guard, resource-budget, and TLS-happy-path cases (part of the file's 111 passed). | Reference/local listener: TLS terminates in this process, not behind an operator load balancer, reverse proxy, or service mesh: an actual reverse proxy in front of this listener would need its own, separately verified Host/Origin/forwarded-header discipline. | Operator-managed load balancer / mesh conformance guidance. |
| Remote workload identity forgery (`none`/HMAC confusion, embedded or remotely fetched keys, claim substitution) | A caller crafts a token that authenticates as a different issuer, audience, resource, authority, tenant, client, user, session, or scope than the one actually trusted, or exploits algorithm/key negotiation to bypass signature verification. | `EdDSAJWSVerifier` accepts only `alg: EdDSA` / `typ: at+jwt` with an exact three-segment compact JWS and no non-canonical base64url encoding; the protected header key set is exact, so `jwk`/`jku`/`x5u`/`x5c`/`crit` are hard rejections rather than an alternate key source; the signing key comes only from a pinned, in-process `Ed25519TrustSnapshot` selected by exact `kid`, copied at construction so a later mutation of the source mapping cannot change what is trusted; the signature is verified before any claim is parsed; and `iss`/`aud`/`resource`/`sub`==`user_id`/`iat`/`nbf`/`exp` (bounded lifetime, clock-skew-checked) are all checked against an exact claim schema with no unknown or missing keys. | `test_mcp_identity_jws.py` (algorithm-confusion, header-key-material, claim-schema, and canonical-encoding cases; the canonical base64url/padding subset alone: 4 passed). | This is a local/reference trust profile: a fixed `kid -> public key` snapshot read once from an operator-supplied file, not a managed PKI, key-rotation, or key-custody service. | Managed key lifecycle and authority distribution (shared with the lifecycle-attestation roadmap item above). |
| Health/readiness credential escalation to a caller | The readiness probe's own credential is replayed against the public listener to attempt a `tools/call`, or is used to widen its own scope. | The health identity's signed `authority` claim is `mcp.tools.list`, not `mcp.tools.call`; the gateway checks that authority before policy, kernel, or adapter dispatch, so no scope grant, policy rule, or registry entry can turn a list-authority identity into a caller. The health identity's scopes admit only `tools:list` and `fixture:catalog` (metadata visibility for `fixture.read`), never `fixture:write`. Readiness itself is answered only to the operator's own loopback peer and a public caller cannot even learn the route exists. | `test_mcp_gateway_adversarial.py` list-authority-vs-call-authority subset: 9 passed. Live-container evidence (when Docker is available): `run-remote-demo.sh`'s health-attack case asserts `health_calls_executed == 0` across two attempted calls through the public TLS listener. | Enforcement is this gateway's own; a raw tool exposed outside the governed gateway remains a bypass, same as the general executor-bypass residual. | Semantic tool classification and conformance checks (shared with the action-tier-downgrade roadmap item above). |
| Executor bypass | A caller invokes the raw tool instead of the governed executor. | Kernel/ManagedAgent/GovernedTool registrations route SIDE_EFFECT tools to the strict dispatcher or deny; product references hide downstream adapters. | Strict-kernel, adapter-bypass, and product tests. | A raw callable retained or separately exposed outside the governed topology remains a bypass. | Deployment isolation and conformance checks. |
| Policy evaluation failure | Policy exception accidentally allows execution. | Kernel synthesizes DENY and audits it. | `test_fail_closed.py`. | Hanging policies need configured watchdog. | Secure defaults for `policy_timeout`. |
| Policy timeout/hang | Executor waits forever or eventually allows after stale evaluation. | Optional `policy_timeout` converts timeout to DENY. | `test_fail_closed_gaps.py`. | Timeout is configurable, not globally required. | Secure profile defaults. |
| Audit append failure | Side effect runs without durable evidence. | Kernel raises `AuditError` before execution. | `test_fail_closed.py`, `test_audit_chain_corruption.py`. | Local disk availability and durability are operator concerns. | Durable/off-host audit sink. |

## Strict managed profile and legacy compatibility

P0 Release Gate, P1 MCP Gateway, and P2 Spend Guard share the strict managed
authorization path. That path requires a trusted receipt signature, an anchored
audit decision, a `PolicyArtifactAttestation`, persistent consumption/receipt-revocation
state, idempotency binding, and final revalidation immediately before the adapter.
The persistent store format is **consumption-store schema v4**, not Decision
Receipt schema v4. `record_kind` is an authenticated *audit-record* field — it is
neither a Decision Receipt field nor a consumption-schema field — and it has
three kinds: `POLICY_DECISION`, `EXECUTION_LIFECYCLE`, and `EXECUTION_REFUSAL`.
An `EXECUTION_REFUSAL` record proves a bound attempt was refused *before any
adapter ran* (`adapter_invoked=False`); it never carries a lifecycle attestation
and must never be used to represent `OUTCOME_UNKNOWN`, which requires a terminal
`EXECUTION_LIFECYCLE` record.

The strict **standalone** path (`execute_with_receipt`, `GovernedExecutor`)
reaches the same replay/idempotency and lifecycle guarantees, but only when the
caller configures **all** of: a trusted signature verifier (the strict path
verifies with `require_signature=True`), an externally checkpointed audit store,
an anchored schema-v4 consumption store, and an explicit lifecycle signer whose
key and authority are separate from the audit-checkpoint key and authority. Omit
any one and the strict path refuses to run rather than degrading.

Legacy/evaluate-only APIs remain for compatibility and policy projection. An
unanchored evaluation record, unsigned local receipt, PURE legacy dispatch, or a
bare `DecisionReceipt.verify` / `ReceiptVerifier` check is not equivalent to
strict side-effect authorization — none of them supply consumption, idempotency,
lifecycle attestation, or checkpointed audit — and must not be presented as
production evidence.

## Execution outcome and reconciliation

Strict execution commits a durable claim, then makes **at most one** adapter
attempt. If the outcome is ambiguous or raises, the executor attempts to persist
and confirm terminal `UNKNOWN`. Once that state is confirmed, the receipt becomes
non-retryable: later reuse is denied rather than re-authorized. If `UNKNOWN`
cannot be persisted, read back, or evidenced, the path fail-stops and no retry is
authorized, but the terminal state and its lifecycle evidence may be unavailable.

This bounds *authorization*, not *effect*. ACGS cannot observe whether an
ambiguous downstream call took effect, so the residual is **at-most-once
attempt, never exactly-once effect** — a side effect may already have occurred
under an `UNKNOWN` outcome. Operators must reconcile `UNKNOWN` records out of
band against the downstream system; ACGS supplies the lifecycle evidence for
that reconciliation, not the resolution.

## Proof Pack semantics: generic versus product

`proof_pack.py` is a **generic structural codec**. It deliberately knows nothing
about release, MCP, receipt, policy, audit, replay, or consumption semantics; it
establishes canonical bytes, exact membership, content hashes, and stable path
identity. A sealed pack that verifies structurally proves only that those bytes
are internally consistent and unmodified — **not** that any decision was
governed, any receipt was valid, or any chain was checkpointed.

Semantic verification is the product layer's job: `release_proof.py`,
`mcp_proof.py`, and `spend_proof.py` perform the domain verify/replay (including
`record_kind` and lifecycle-attestation checks) on top of the codec. Do not cite
generic structural sealing as evidence of governance.

That product semantic verification is **relative**, not self-contained. It is
relative to a caller-supplied expected digest and to external trust inputs —
receipt verification keys, the signed audit checkpoint, the lifecycle verifier
registry, and consumption state — all of which the caller must supply and trust
independently of the pack. Trust material carried inside a pack, or asserted by
the pack about itself, is not independent proof: an artifact must never be the
thing that decides whether its own signature is checked. Avoid unqualified
"independently verifiable"; say what the verification is relative to.

## Deployment controls not supplied

The local fixtures do not establish a production network or process boundary.
Operators must make downstream adapters and credentials unreachable except
through the gate, authenticate identities, and provide durable/off-host evidence,
key custody, signing-key rotation/revocation, and PKI. The project includes a
Python-only `E2BSandbox` adapter but does not provide the SDK, API key, remote
service, or production proof; Node and worktree modes are not sandbox providers.
The `bwrap` option currently fails closed because anonymous response-FD transport
is incompatible, so no working bwrap profile is claimed. HSM custody, managed PKI,
and globally available signing-key revocation remain external. Receipt revocation
is provided separately by the configured strict consumption store.

## Security-sensitive files

- `packages/gove-zone/src/gove_zone/receipt.py`
- `packages/gove-zone/src/gove_zone/executor.py`
- `packages/gove-zone/src/gove_zone/kernel.py`
- `packages/gove-zone/src/gove_zone/audit.py`
- `packages/gove-zone/src/gove_zone/replay.py`
- `packages/gove-zone/src/gove_zone/signing.py`
- `packages/gove-zone/src/gove_zone/policy.py`
- `packages/gove-zone/src/gove_zone/tenant.py`
- `packages/gove-zone/src/gove_zone/integration.py`
- `.claude/hooks/acgs-emit-receipt.py`
- `.claude/settings.json`

## Required security review behavior

Any change to receipt, policy, audit, signing, replay, executor, hook, or adapter code must include:

- negative-path test proving the side effect did not run;
- wiring proof at the dispatcher/gateway boundary;
- claim updates in `docs/CLAIMS.md` if behavior changed;
- explicit note whether unsigned mode or signing mode semantics changed.
