# Deployment Options — ACGS / gove-zone

> **Core invariant: No valid Decision Receipt, no side effect.**

Honest maturity note up front: **what ships today is a self-hosted library +
CLI + alpha MCP gateway.** "SaaS" below is a proposed offering, not a running
service. Regulated-environment posture is a hardening recipe over today's
kernel plus named roadmap gaps — not a certified deployment. See
[`docs/CLAIMS.md`](../CLAIMS.md).

## Option matrix

| Dimension | SaaS (proposed) | Private cloud | On-premise | Regulated environment |
|---|---|---|---|---|
| Status | **Roadmap** — no managed service exists today | Available today (self-managed) | Available today (self-managed) | Hardening profile over on-prem/private cloud; residual gaps named below |
| Kernel location | Vendor-run control plane; gate still colocated with customer executors | Customer VPC (any cloud) | Customer datacenter / air-gapped host | Customer-controlled, typically air-gapped or restricted egress |
| Evidence (audit chain, ledger, proof packs) | Hosted evidence store with retention (proposed) | Customer storage (object store / WORM of choice) | Customer disk / WORM appliance | WORM/off-host mandatory; sidecars (`.hwm`, `.pwm`) on append-only storage |
| Signing keys | Vendor-managed KMS option (proposed) | Customer KMS | Customer HSM/KMS | Customer HSM; custody + rotation procedures required |
| Identity | Vendor IdP federation (proposed) | Customer IdP → `expected_actor` mapping | Customer IdP | Customer IdP; documented actor-mapping evidence |
| Network dependency of the gate | None for enforcement (gate is in-process/local by design) | None | None; fully offline-capable | Fully offline-capable; `gove-zone verify-proofpack` runs offline |
| Best for | Teams wanting evidence retention without ops burden | Platform teams standardizing a side-effect gate | Security-sensitive self-hosters | Finance, health, legal — audit-facing teams |

A structural advantage worth stating: the kernel has **zero runtime
dependencies** and enforcement happens in-process at the executor boundary.
There is no phone-home requirement, no license server in the enforcement path,
and nothing that stops a fully air-gapped deployment. That is why on-premise is
the *most* mature option, not the least — the opposite of most governance SaaS.

## 1. SaaS (proposed — not shipped)

What a managed offering would add on top of the self-hosted kernel:

- hosted, WORM-backed evidence store (audit chains, proof packs, retention SLAs);
- tenant/policy administration console (over `TenantPolicyStore`);
- managed signing (KMS-held keys, rotation, revocation registry);
- fleet observability: blocked-replay and verify-failure alerting (the
  `gove_zone.consumption` logger + `observability()` counters are the shipped
  integration points).

What would *never* move to SaaS: the enforcement gate itself. The receipt check
stays colocated with the customer's executor so that a network outage degrades
to fail-closed locally, not to an unenforced side effect.

Prerequisites before this can be sold: multi-tenant isolation evidence beyond
`test_tenant_safety.py`, an authenticated remote identity hop (the alpha MCP
gateway explicitly assumes a trusted local transport), and an operations story
(SLOs, on-call). ADV13 in the security model prices the availability trade-off:
fail-closed turns integrity attacks into availability attacks, so a managed
offering needs an error budget and degraded-mode policy.

## 2. Private cloud (available today, self-managed)

Reference shape (AWS/GCP/Azure equivalent):

```text
customer VPC
├── agent runtime (any framework)
├── ACGS gate — in-process library or governed-MCP gateway sidecar
├── audit sink: object store with object-lock/WORM (e.g. S3 Object Lock, GCS retention)
├── keys: cloud KMS (Ed25519 signing key never leaves customer account)
└── SIEM export: gove_zone.consumption WARNING logger → alerting
```

Deployment steps: `pip install acgs-lite` or vendor the `gove-zone` package;
wire the gate per [`docs/INTEGRATION_GUIDE.md`](../INTEGRATION_GUIDE.md); run
the default profile (`require_signature=True` + configured trusted verifier);
enable the consumption ledger for single-use receipts; ship audit JSONL to
WORM storage on rotation.

## 3. On-premise (available today, self-managed)

Same as private cloud minus cloud services:

- kernel + CLI run anywhere Python ≥3.11 runs; no runtime dependencies to vet
  (crypto extra is the only optional dependency — relevant for supply-chain review);
- keys in a local HSM or file-based custody with documented procedures;
- audit chain on local disk, exported to a WORM appliance or offline media;
- proof packs (`gove-zone proofpack`) are the hand-off artifact to auditors and
  verify offline with `gove-zone verify-proofpack` — no network, no vendor.

Air-gap note: nothing in the enforcement path performs network I/O. Policy
bundles are files; receipts and audit chains are local artifacts.

## 4. Regulated environment (hardening profile + named residuals)

The target segment (S1 in [`docs/PRODUCT_STRATEGY.md`](../PRODUCT_STRATEGY.md)):
teams whose agents act with real consequences under audit pressure.

**Hardened configuration (all shipped):**

1. Default secure profile: `require_signature=True` with a configured trusted
   verifier (the default fails closed — raises `ProductionProfileError` —
   rather than silently emitting unsigned receipts).
2. Anti-replay ON: `ReceiptConsumptionLedger(path, checkpoint=True)` so every
   ALLOW is single-use and the high-water-mark sidecar catches tail truncation.
3. Short `expires_at` on every receipt (there is no global revocation list —
   expiry is the bound).
4. `policy_timeout` configured so a hanging policy becomes DENY.
5. Audit chain + `.hwm`/`.pwm` sidecars on append-only/off-host storage.
6. Dispatcher-level wiring tests in the customer's CI proving every
   side-effect path routes through the gate (ADV9 is the keystone risk; a unit
   test that calls the handler directly proves nothing).
7. Periodic `gove-zone verify-ledger --audit <chain>` reconciliation, alerts on
   the `gove_zone.consumption` logger.

**What regulated buyers can map today:**
[`docs/COMPLIANCE_CROSSWALK.md`](../COMPLIANCE_CROSSWALK.md) maps enforced
controls to NIST AI RMF 1.0, NIST CSF 2.0, MITRE ATLAS, and OWASP LLM/Agentic
risk lists — explicitly a self-assessment producing *evidence toward* outcomes,
not a certification.

**Named residual gaps (do not paper over these in a sales cycle):**

- No certification of any kind: not SOC 2, not ISO 27001, not regulator-approved.
- Identity, key custody, rotation, and revocation procedures are operator-owned.
- Local JSONL is tamper-*evident*, not tamper-*proof*; WORM placement is the
  customer's control.
- Insider with host access (ADV2/ADV3): detection today, not prevention;
  attestation and transparency witnessing are roadmap.
- The kernel cannot govern code paths it is not wired into.
