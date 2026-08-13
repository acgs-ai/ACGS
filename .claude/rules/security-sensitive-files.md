# Security-Sensitive Files (govern-zone)

> Always-On: Extraction of AGENTS.md — dangerous edit zones, forbidden changes, and required
> behavior for receipt/policy/audit/signing/executor changes. AGENTS.md remains authoritative.

## Dangerous edit zones

Treat as security-sensitive. Read the code and its tests before changing claims or behavior:

- `packages/gove-zone/src/gove_zone/receipt.py`
- `packages/gove-zone/src/gove_zone/executor.py`
- `packages/gove-zone/src/gove_zone/kernel.py`
- `packages/gove-zone/src/gove_zone/audit.py`
- `packages/gove-zone/src/gove_zone/replay.py`
- `packages/gove-zone/src/gove_zone/replay_store.py`
- `packages/gove-zone/src/gove_zone/signing.py`
- `packages/gove-zone/src/gove_zone/policy.py`
- `packages/gove-zone/src/gove_zone/tenant.py`
- `packages/gove-zone/src/gove_zone/integration.py`
- `.claude/hooks/acgs-emit-receipt.py`
- `.claude/settings.json`
- `.github/workflows/**`
- `docs/constitutional-hashes.lock` and any file marked `Constitutional Hash`, `@generated`,
  `DO NOT EDIT`, or with lock-file semantics.

## Forbidden changes without explicit user approval

Do not:

- weaken fail-closed behavior;
- bypass receipt validation;
- make execution happen before audit/receipt validation;
- treat `DENY` or `ESCALATE` as executable;
- skip `expected_actor` at executor gates;
- remove actor/action/argument/policy/audit binding checks;
- turn unsigned dev mode into a production claim;
- edit security claims without checking the relevant source and tests;
- hand-edit generated/sealed/hash-marked outputs;
- use `git add -A` or `git add .`.

## Required behavior for receipt/policy/audit/signing/executor changes

If you change any security-sensitive file above:

1. Add or update negative-path tests that prove the side effect did **not** run.
2. Prove handler/gate wiring, not only direct unit calls
   (`~/.claude/rules/review-handler-wiring.md`).
3. Run the relevant package tests, not just docs tests.
4. Update `docs/DECISION_RECEIPT_SPEC.md`, `docs/SECURITY_MODEL.md`, and `docs/CLAIMS.md`
   only after code/tests are verified.
5. Explicitly state whether unsigned mode, signing mode, policy bundle binding, expiry,
   actor binding, audit replay, or executor enforcement changed.
