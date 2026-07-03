# Security

> Status: foundational / Alpha (`0.1.0.dev0`). gove-zone is **not** production-,
> compliance-, or regulator-certified. This document states the security
> boundary honestly — what is enforced and what is explicitly out of scope.

## The security property

gove-zone enforces one invariant:

> **No valid Decision Receipt, no side effect.**

Everything below is in service of that. The single enforcement gate is
`DecisionReceipt.verify` (wrapped by `execute_with_receipt`, `GovernedExecutor`,
and `ReceiptVerifier`). There is no second, weaker path.

## Fail-closed by construction

Execution is refused — never silently allowed — on every one of:

- no receipt, malformed receipt, or tampered receipt (`receipt_hash` mismatch);
- a `DENY` or `ESCALATE` decision;
- tenant mismatch, execution-boundary mismatch, action mismatch;
- policy bundle id / policy hash mismatch;
- an expired receipt (`expires_at` in the past);
- an `ALLOW` whose executed arguments do not hash-match the arguments the
  receipt was issued for, or a `TRANSFORM` whose executed arguments are not
  exactly the approved transformed set (extra, missing, or altered fields);
- a self-validated receipt (validator is the proposer), a missing validator
  identity / role or authority binding, or — the gate requires the caller's own
  identity (`expected_actor`) — a receipt issued for a different principal or one
  whose validator is the invoking principal;
- an `approval_chain_summary` that disagrees with the bound validator / proposer
  fields.

In the issuing kernel: a policy that raises or times out becomes a `DENY`; an
audit-append failure raises `AuditError`. No exception path resolves to "allow"
(`kernel.py`, `test_fail_closed.py`, `test_fail_closed_gaps.py`).

## Tamper-evidence

- Receipts are self-hashing; tenant, boundary, policy hash, and `expires_at` are
  bound into `receipt_hash`, so altering them without re-issuing is detected.
- The audit log is an append-only hash chain; any edit, reorder, or truncation
  fails `verify_chain()` (`test_audit_chain*`, `test_audit_chain_corruption.py`).
- Concurrent audit appends are serialized with `fcntl.flock` + `fsync`.

## Role separation (MACI)

A Decision Receipt binds two distinct principals: the **proposer** (`actor` — the
agent that asked for the action) and the **validator** (`validator_id` +
`validator_role` — the authority that approved it), plus the `authority` grant
under which execution is permitted. All three are bound into `receipt_hash`.

Separation is enforced at two points:

- **Issuance.** `DecisionReceipt.from_record` (and `evaluate_tenant_action`)
  refuse to mint a receipt whose validator equals the proposer. A self-validated
  receipt cannot be created through the normal path.
- **The gate.** The gate surfaces — `execute_with_receipt`, `GovernedExecutor`,
  and `ReceiptVerifier` — now **require** `expected_actor` (the caller's own
  identity). Omitting it raises (`TypeError` for a missing kwarg,
  `ReceiptValidationError` for an empty string) rather than silently downgrading
  to a weaker check. `verify()` then rejects a receipt not issued for that caller
  and rejects one whose validator is the invoking principal. `expected_actor`
  comes from the caller's runtime context, never from the receipt, so a receipt
  author cannot satisfy it by editing receipt fields. The strong caller-anchored
  check is therefore the default at every gate, not an opt-in.

This is the kernel's MACI invariant: *an agent can propose an action but can
never validate its own authority to execute it.*

**Residual (honest scope).** The weak heuristic — which only catches a receipt
whose `validator_id` and `actor` fields are literally identical — is **no longer
reachable through the gate**: every gated path requires `expected_actor`, so the
strong actor-anchored check always runs. The heuristic survives solely as
residual defense-in-depth for direct `DecisionReceipt.verify()` callers who pass
no `expected_actor`; against that path, a forger who recomputes `receipt_hash`
and sets `actor` to a phantom value while keeping the real proposer as
`validator_id` is still not caught. Requiring the anchor relocates trust to the
integrator: it does **not** manufacture an authenticated proposer identity the
architecture lacks. Unsigned (dev-mode) proposer-binding is therefore only as strong
as the integrator's external authentication of the caller; the actual
cryptographic closure is **signed issuance** (`require_signature=True` + a
trusted public-key verifier — see *Ed25519 receipt signing* below), which
is the default production posture. The separation is enforced-by-verifier and
audited; it is **not** cryptographically unforgeable under host compromise on the
unsigned path.

## Argument binding

A receipt authorizes a specific tool *with specific arguments*, not the tool in
general. The proposed arguments are hashed (`argument_hash`, bound into
`receipt_hash`) at issuance. At the gate, `execute_with_receipt` passes the
about-to-run arguments as `expected_args`, and `verify()` refuses execution
unless they match: for `ALLOW`, the executed args must hash-match
`argument_hash`; for `TRANSFORM`, they must be exactly the approved transformed
set. A valid receipt for `write_file(path="/tmp/safe")` therefore cannot
authorize `write_file(path="/etc/shadow")`.

This binding is enforced at the gate (`execute_with_receipt` / `GovernedExecutor`
always supply `expected_args`). A bare `DecisionReceipt.verify()` call with
`expected_args=None` skips the argument comparison — verify the gate, or pass
`expected_args`, when checking receipts directly.

## Multi-tenant isolation

A receipt or policy bundle issued for one tenant cannot be used by another;
missing tenant identity fails closed (`test_tenant_safety.py`). See
`docs/policy-bundles.md`.

## Ed25519 receipt signing (default in the production profile)

gove-zone signs Decision Receipts with asymmetric keys **by default**: the
production profile — the secure default posture — requires a verified signature
at the gate (``require_signature=True``). Signing closes the recomputed-receipt
residual: anyone can verify a receipt with the public key; only the private-key
holder can produce a valid signature, so a recomputed-hash forgery is
cryptographically infeasible.

Select the posture explicitly with ``GovernanceProfile.production()`` (the
default) or ``GovernanceProfile.dev()``, or via the ``GOVE_ZONE_PROFILE``
environment variable (``production`` | ``dev``; unset → production). A gate that
runs under the production profile with no verifier configured fails closed loud
(``ProductionProfileError``) — it never silently downgrades and never
auto-generates an ephemeral key.

**How it works.** Issue receipts with a private-key signer and verify at the
gate with the matching public-key verifier. ``require_signature=True`` is the
**default** at the gate surfaces (``execute_with_receipt``, ``GovernedExecutor``,
``ReceiptVerifier``); it is shown explicitly below for clarity:

```python
signer  = Ed25519Signer.generate()
receipt = evaluate_tenant_action(…, signer=signer)

verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
execute_with_receipt(…, verifier=verifier, require_signature=True)
```

A receipt that advertises a signature (``signature_algorithm != "none"``) is
**always** verified cryptographically — presenting it without a verifier is a
hard rejection, regardless of ``require_signature``.

**Dev mode is explicitly unsigned.** The dev profile
(``GovernanceProfile.dev()`` / ``require_signature=False``) is the deliberate
opt-out: without a ``signer`` at issuance and a ``verifier`` at the gate,
receipts remain unsigned (``signature = "unsigned_local"``) and integrity rests
on ``receipt_hash`` and the audit chain alone. Dev mode is a conscious choice,
not a silent default — the secure production posture is what you get unless you
ask for less.

**Residuals not addressed by signing:**
- **Private-key custody.** A compromised signing key lets an attacker issue
  valid-looking receipts. Key custody is the operator's responsibility.
- **Key distribution / trust establishment.** There is no PKI, certificate chain,
  or trust-store bootstrapping. The verifier mapping is static; the operator must
  manage it.
- **Revocation.** A compromised signing key *can* be revoked at the live gates
  (`ReceiptVerifier` / `GovernedExecutor` / `execute_with_receipt`, and via them
  `resume_with_receipt`), the offline `verify_workflow_replay` inner-receipt path,
  and the **offline** proof-pack verifier (`verify_proof_pack` /
  `verify-proofpack --revoked-keys`) by passing a `RevocationList`
  (`revoked_keys=`): a receipt signed by a revoked `key_id` is rejected before its
  signature is trusted — at the live gates, even with a valid signature still
  present in the verifier map (revocation is independent of map membership); and a
  relying party verifying a distributed pack offline rejects a key compromised
  *after* the pack was minted. The residual gap is *distribution* — the verifier
  mapping and the revocation list remain static config the operator deploys (no
  PKI / CRL fetch / expiry) — and the workflow envelope/authorization signatures
  (a distinct key population) do not yet honor `revoked_keys`.

## Workflow receipt chaining

`workflow.py` extends the per-action gate to a declared DAG of steps. Each step's
execution is gated by a `WorkflowStepReceipt` that wraps a fully valid inner
`DecisionReceipt` (verified by the unchanged single-action gate) and binds it to
a workflow position. The envelope's `step_receipt_hash` covers `workflow_id`,
`step_id`, sorted predecessors, predecessor receipt hashes, `dag_hash`, the
signing algorithm/key id, **and the inner receipt's `receipt_hash`** — so a
tampered envelope or a swapped inner receipt is detected. `signature` signs that
hash and stays out of it, identical to the inner receipt's discipline.

**Order is load-bearing.** `WorkflowExecutor.execute_step` completes every
envelope check — present, hash, signature (when engaged), workflow binding, DAG
binding (`dag_hash` + step membership + declared-predecessor match), no-replay,
and predecessor satisfaction — **before** the atomic inner gate-and-execute. The
single-action gate verifies-and-executes in one call, so if the inner gate ran
first, a reordered or cross-workflow step's side effect would fire before the
envelope rejection. Every negative-path test asserts the side effect did not run.

**What it proves.** A step ran in the approved order, with approved arguments,
under a valid per-step receipt bound to the approved plan. The per-run `ledger`
(trusted runtime state) is what detects replay, reordering, and
predecessor-substitution.

**Honest scope (residuals).**
- Workflow chaining adds **no** cryptographic guarantee beyond the per-step
  receipts and their envelopes.
- **Plan-level governance is the next layer up** (see "Plan-level governance"
  below): a `WorkflowAuthorization` makes the DAG a proposer≠validator-authorized
  object. Within *this* workflow-chaining section, `dag_hash` is still only a
  consistency binding, not an authority decision; the plan authority decision
  lives in `plan.py`.
- **Unsigned `verify_workflow_replay()` proves internal chain consistency and
  topological faithfulness, NOT unforgeability**: an attacker who can recompute
  envelope hashes (and re-sign, if they hold the key) can produce a consistent
  chain. Envelope signing (`ReceiptSigner`) is the closure for cross-workflow and
  ordering integrity — and only when engaged — exactly as Ed25519 closes the inner
  recomputed-receipt residual.
- The ledger's substitution/reorder detection rests on it being trusted runtime
  state; offline replay has no ledger and relies on envelope integrity (hashes,
  and signatures when engaged).
- Under host compromise, the same residuals as the single-action gate apply.

## Plan-level governance

`plan.py` makes the workflow **plan** a governed object. The invariant grows to
add: *"no authorized plan, no workflow step executes."* A **plan proposer**
proposes the DAG; a **distinct plan validator** authorizes it (a
`WorkflowAuthorization`), and `WorkflowExecutor` runs steps only under that
authorization.

**The authorization.** `WorkflowAuthorization.authorization_hash` binds `dag_hash`
(the exact plan), `plan_proposer`, `plan_validator_id`, and the signing
algorithm/key id (anti-downgrade); `signature` signs that hash and stays out of
it. `from_plan` is fail-closed: it refuses to mint a self-validated plan
(`plan_validator_id == plan_proposer`). Each `WorkflowStepReceipt` carries an
`authorization_hash` bound into its own hash, tying the step to a *specific*
authorized plan.

**The gate.** `WorkflowExecutor` now **requires** the authorization — a missing
authorization is a construction-time error, not a silent downgrade — and verifies
it on **every** `execute_step` (it is independently callable), before the existing
envelope checks and the atomic inner gate. The checks, in order: (A) authorization
integrity (hash + signature when engaged); (B) plan binding (`workflow_id`,
`dag_hash`, tenant, boundary, expiry); (C) plan MACI + runner anchor
(`plan_validator_id` ≠ `plan_proposer` **and** ≠ the runner —
`governed.expected_actor`, taken from runtime context, never the authorization);
(D) step→authorization binding (`step_receipt.authorization_hash` must match);
(E) **cross-level separation, strict (b)** — `proposers = {plan_proposer, runner}
∪ {step actors}` must stay disjoint from `validators = {plan_validator_id} ∪ {step
validator_ids}`. There are two collusion shapes, and (E) is independently
load-bearing for the second: (i) a step **proposer** that is also the plan
**validator** — since a step proposer is the inner `actor`, pinned to the runner
by the inner gate, this is *the runner validating its own plan*, already caught by
(C); (ii) a step **validator** that is also the plan **proposer** — not pinned to
the runner and caught by no other check, so (E) is the **sole** guard against the
side effect for this case. Every negative-path test asserts the side effect did
not run.

**What it proves.** Plan-level role separation enforced by the verifier: proposer
≠ validator over the *plan*, steps bound to an authorized plan, and no principal
proposing and validating anywhere in the workflow. Cross-plan step lifting (a step
minted under authorization A replayed under B) is rejected by (D); cross-plan
authorization reuse by (B).

**Honest scope (residuals).**
- This adds **no** cryptographic guarantee beyond the authorization receipt and
  its signature. Unsigned authorizations are tamper-evident (hash) but forgeable
  by a party who can recompute the hash; **signing** (`ReceiptSigner`) is the
  closure, exactly as Ed25519 closes the inner recomputed-receipt residual, and
  only when engaged.
- **Not multi-agent governance.** No mutual authentication between agents, no
  delegation chains, no distinct cryptographic agent identities. Principals are
  opaque strings; the cross-level check proves *distinctness of strings*, not
  *authenticated identity*. Multi-agent governance is a separate future increment.
- **`workflow_id` is a nonce.** The authorization binds it; the integrator MUST
  NOT reuse a `workflow_id` across runs, or an old authorization (and its step
  receipts) could replay. The executor enforces single-execution *within* a run
  via the ledger, but cannot detect reuse across separate executor instances.
- **Replay has no runner.** The runner is runtime-only and deliberately not in the
  authorization, so `verify_workflow_replay` enforces plan MACI (validator ≠
  proposer) and cross-level separation over the recorded set, but **not** the
  runner anchor.
- Under host compromise, the same residuals as the single-action gate apply.

## What gove-zone does NOT do (security non-goals today)

- **No PKI or key lifecycle management.** Ed25519 signing is point-to-point
  (issuer ↔ gate); there is no certificate authority, trust chain, or revocation
  infrastructure. Key distribution and custody are the operator's responsibility.
- **No durable external audit sink.** The chain is local JSONL. WORM storage,
  SIEM shipping, and off-host append-only durability are roadmap.
- **No bundle lifecycle / revocation.** No active/stale/revoked state, no
  revocation lists.
- **No approval workflow.** `ESCALATE` blocks; it does not yet resolve into an
  authorization.
- **No sandboxing of the side effect itself.** gove-zone decides *whether* and
  *with which arguments* an action runs; it does not contain the blast radius of
  the tool you register. Run tools in your own sandbox.
- **Not a guarantee against a compromised host.** An attacker with write access
  to the audit file + the ability to run the issuer can forge a consistent local
  chain. The chain proves tamper-evidence for *readers*, not unforgeability under
  full host compromise.

## Reporting

This is alpha research software in a monorepo. Report suspected security issues
through the repository's normal issue/security channel. Do not assume any
deployment of gove-zone is production-hardened without independent review.
