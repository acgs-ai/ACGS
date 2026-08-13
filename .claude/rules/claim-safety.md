# Claim Safety (govern-zone)

> Always-On: Extraction of AGENTS.md — claim boundaries, reporting uncertainty, and how to
> verify behavior before editing docs. AGENTS.md remains the authoritative source.

## Claim boundaries

Safe wording:

- "local receipt-gated kernel"
- "alpha / production-shaped foundation"
- "local proof pack"
- "tamper-evident JSONL audit chain"
- "opt-in Ed25519 signing mode"
- "integration adapter shapes for MCP/function-call/runtime hooks"

Unsafe unless independently evidenced:

- "production-certified"
- "compliance-certified"
- "regulator-approved"
- "formal verification complete"
- "complete IAM/PKI system"
- "guaranteed safe AI"
- "all agent frameworks supported in production"

Never describe ACGS as compliance-certified, regulator-approved, or production-ready without
release and external evidence. Never fill gaps with marketing language.

## Reporting uncertainty

When unsure, say exactly what is known, what file/test proves it, and what remains
unverified. Prefer: "Implemented and tested locally by X; production deployment not claimed."

## How to verify behavior before editing docs

Before changing claims about receipts, policy, audit, signing, replay, or executors:

1. Inspect the implementation and tests named in `docs/CLAIMS.md`.
2. Run at least one proof command that exercises the claim (see `verification-gates.md`).
3. If the claim is broader than local code/tests prove, downgrade wording and add a limitation.
4. If a gap is found, document it in `docs/CLAIMS.md` or `docs/ROADMAP.md`; do not silently
   imply it is solved.

Numeric claims (test counts, pass/fail, benchmarks) require the literal command output
pasted immediately before the claim.
