# Stage 3 — Release Evidence Summary

Verified against anchor commit `f9a8f37` (gove-zone `0.1.0.dev0`), in-session.
All numbers below are literal command output, captured in this directory.

## gove-zone

- **Proof pack** (`gove-zone proofpack`) → `status: pass`, all 6 conformance
  checks `true` (`conformance-results.json`); audit chain `verification.json`
  → `valid: true`, `failures: []`.
- **Test suite** (`gove-zone-pytest.txt`): **253 passed, 0 skipped, 0 failed**
  (exit 0) — run with the optional `cryptography` dependency so the opt-in
  Ed25519 signing tests are active.
  - Without `cryptography`: 231 passed + 9 skipped (signing tests skip; the
    `test_receipt_signing` module is import-skipped). This is why the prior
    handoff's "256" and a bare run's "240" differ — the delta is the opt-in
    signing surface, not a regression.
- Proof-pack receipts are `signature: "unsigned_local"` / `signature_algorithm:
  "none"` — i.e. **unsigned by default**, consistent with signing being opt-in.

## CaLegal companion (`ca-legal-agent-skills`)

- **Governance suite** (`calegal-governance-pytest.txt`): **754 passed, 2 skipped,
  0 failed** (exit 0) across the configured testpaths (`runtime/tests`,
  `runtime/audit`, `runtime/bus`, `runtime/execution`, `runtime/governance`),
  excluding `test_golden_contract.py` (the only file importing the unpublished
  `warp-oz` `[oz]` extra; not governance).
- **Governance-core subset** (cross-matter block, audit-chain integrity, evidence
  auditor, jurisdiction gate, `runtime/governance`): **186 passed, 0 failed**.

## Recommended public phrasing (per claims map §6)

- gove-zone: "250+ tests green, 0 failing" (not a bare "256").
- CaLegal: "180+ governance tests green, 0 failing" (not a bare "165").
- Exact counts shift with optional dependencies; the stable claim is **0 failing**.
