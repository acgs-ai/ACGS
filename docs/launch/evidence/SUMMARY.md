# Stage 3 — Release Evidence Summary

gove-zone numbers below are re-anchored to commit `a2162fe` (gove-zone
`0.1.0.dev0`) and are literal command output re-run in this session, in this
directory. The CaLegal numbers are **not** re-run here — they are carried from a
prior `ca-legal-agent-skills` run and are flagged as such (see that section).

## gove-zone

- **Proof pack** (`uv run --extra crypto --package gove-zone gove-zone proofpack`)
  → `status: pass`, all 6 conformance checks `true` (`conformance-results.json`);
  audit chain `verification.json` → `valid: true`, `failures: []`.
- **Test suite** (`gove-zone-pytest.txt`): **498 passed, 0 skipped, 0 failed**
  (exit 0) — run with the optional `cryptography` dependency (`--extra dev`) so
  the opt-in Ed25519 signing tests are active. The count rose from the prior
  handoff's 253 because the consumption-ledger and related work landed since the
  old `f9a8f37` anchor; this is added surface, not a regression. Exact counts
  shift with optional dependencies — the stable claim is **0 failing**.
- Proof-pack receipts are `signature: "unsigned_local"` / `signature_algorithm:
  "none"` — i.e. **unsigned by default**, consistent with signing being opt-in.

## CaLegal companion (`ca-legal-agent-skills`) — not re-run this session

> These numbers are from the separate `ca-legal-agent-skills` repository, which is
> not part of this worktree and was **not** re-run at the gove-zone `a2162fe`
> anchor. They are retained from the prior handoff for context only; treat them as
> historical, not freshly verified.

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
