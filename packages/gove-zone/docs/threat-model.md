# gove-zone — Threat Model (one page)

> Status: `1.0.0rc1` / Beta source metadata; candidate release reconciliation
> remains open. This is a boundary statement, not release or certification
> evidence. For the deep treatment of every property below, see
> [`../SECURITY.md`](../SECURITY.md).

## Scope

This covers the **gove-zone governance plane** — the enforcement kernel inside
the govern-zone / ACGS workspace that sits immediately before a high-risk side
effect. It governs **one decision per action**:

> **No valid Decision Receipt, no side effect.**

It does **not** cover the agent that proposes actions, the tool that performs
them, the host they run on, or the network in between. Those are trust
boundaries you own — see *What you must supply externally*.

## Trust boundaries

1. **Policy-evaluation gate** — every action routed through
   `execute_with_receipt`, `GovernedExecutor`, or `ReceiptVerifier` is evaluated
   and bound to trusted expected context before it runs. The library cannot stop
   a raw-tool path that an integrator exposes outside those wrappers; bare
   `DecisionReceipt.verify()` is a lower-level primitive with optional checks.
2. **Receipt integrity** — tenant, boundary, policy hash, arguments, and expiry
   are bound into `receipt_hash`. Issuance signs only when given a signer; the
   default production gate requires a trusted signature and fails closed if the
   issuer/verifier configuration is absent.
3. **Audit chain** — append-oriented, hash-linked local JSONL written *before*
   execution and offline-verifiable, with external anchoring required to detect
   a consistently truncated suffix.
4. **Role separation (MACI)** — proposer (the requesting agent) and validator
   (the approving authority) are distinct principals, enforced at issuance and
   at the gate.
5. **Tenant isolation** — a receipt or policy bundle issued for one tenant
   cannot execute in another's context.

## 1. What gove-zone prevents

- **Unauthorized execution.** An action runs only if a valid receipt verifies;
  a `DENY`/`ESCALATE`, a missing/expired/tampered receipt, or any evaluation
  error fails closed — never silently allows. [SECURITY.md → *Fail-closed by
  construction*]
- **Argument substitution.** A receipt authorizes a tool *with specific
  arguments*; executed args are hash-checked at the gate. A receipt for
  `write_file(path="/tmp/safe")` cannot authorize `path="/etc/shadow"`.
  [→ *Argument binding*]
- **Silent in-place tampering of the record.** An edit or reorder of retained
  audit events fails `verify_chain()`; an altered receipt fails its
  `receipt_hash` check. Detecting suffix truncation requires an external event
  count or final-hash anchor. [→ *Tamper-evidence*]
- **Receipt forgery (configured production profile).** When the issuer signs
  and the gate verifies with a trusted Ed25519 key, recomputed-hash forgery is
  cryptographically infeasible without the private key.
  [→ *Ed25519 receipt signing*]
- **Self-authorization.** An agent cannot both propose and validate its own
  action; self-validated receipts are rejected at issuance and at the gate.
  [→ *Role separation (MACI)*]
- **Cross-tenant leakage.** One tenant's policy/receipt is rejected in another's
  execution context. [→ *Multi-tenant isolation*]

## 2. What gove-zone does NOT prevent

- **A compromised host.** An attacker who can write the audit file *and* run the
  issuer can forge a consistent local chain. The chain proves tamper-evidence to
  *readers*, not unforgeability under full host compromise.
- **A stolen signing key.** A leaked private key lets an attacker mint
  valid-looking signed receipts. Signing closes forgery-by-recompute, not
  key theft.
- **The blast radius of the tool itself.** gove-zone decides *whether* and *with
  which arguments* an action runs; it does not sandbox the side effect. Run your
  tools in your own sandbox.
- **Turnkey approval workflow.** `ESCALATE` blocks the action and the kernel
  exposes approval/resume primitives, but routing, notification, reviewer UI,
  and authenticated human identity remain integrator responsibilities.
- **Authentication of the caller.** The gate checks a caller-supplied
  `expected_actor`; it does not authenticate identity. On the unsigned (dev)
  path, proposer-binding is only as strong as your external authentication.
- **Compliance / regulatory certification.** Local receipts and smoke proofs are
  readiness evidence, not certification or regulator validation.

[All of the above are enumerated in SECURITY.md → *What gove-zone does NOT do*.]

## 3. What you must supply externally

- **Caller authentication** — establish *who* the actor is; pass it as
  `expected_actor`. gove-zone enforces separation over identities you assert.
- **Key custody, distribution, and rotation** — production signing is
  point-to-point; there is no PKI or managed trust service. An implemented,
  operator-supplied static `RevocationList` rejects configured receipt-signing
  key IDs, but you must distribute that list and manage keys/verifiers yourself;
  there is no automatic rotation or global receipt/nonce revocation.
- **Tool sandboxing** — contain what an allowed tool can do at the OS/network
  level.
- **Durable / off-host audit storage** — the chain is local JSONL; ship it to
  WORM storage or a SIEM if you need durability beyond the host.
- **Policies** — you author the rules; gove-zone enforces them.
- **Approval routing** — wire `ESCALATE` to your own approval system.

## Operational guidance

- Keep the production profile (the default gate posture): configure signed
  issuance plus the matching trusted verifier. The profile requires a signature
  but does not create one; missing verifier/signing configuration fails closed
  (`ProductionProfileError`) rather than downgrading to
  `GovernanceProfile.dev()`.
- Select posture explicitly in deployment via `GOVE_ZONE_PROFILE=production`
  (default) or `dev`.
- Treat the audit JSONL as tamper-evident, not unforgeable, unless signing is
  engaged and keys are protected.
- Use `gove-zone replay --audit audit.jsonl --event <id>` for audit/event and
  policy-version verification only. To re-derive a decision, retain the opt-in
  raw-call side store and matching original policy, then use the side-store or
  bundle replay path.
- Never commit private signing keys to source control; rotate keys and audit
  logs on a schedule.
