# ACGS / gove-zone — Agent Operating Manual

This file is the operating contract for AI coding agents working in `/home/martin/Documents/ACGS` and adjacent ACGS / govern-zone checkouts.

## Project purpose

ACGS / gove-zone is a receipt-gated governance layer for AI-agent side effects. It enforces policy before execution, emits a verifiable Decision Receipt, and makes executors fail closed without a valid receipt.

**Core invariant: No valid Decision Receipt, no side effect.**

ACGS is not an agent framework. It is the execution membrane below agent reasoning and above side-effectful tools. Agent frameworks may plan or request actions; ACGS decides whether an executor may actually run them.

## Mandatory scope gate

Before editing, reviewing, testing, documenting, or planning:

1. Detect the real git root and submodule topology.
2. Read the nearest `AGENTS.md`, `CLAUDE.md`, `.codex/`, `.claude/`, package manifest, and local README for the touched directory.
3. Split work by subproject boundary.
4. Do not stage or commit across nested repo/submodule boundaries.
5. Use the package-local validation command, not a command copied from another package.

Helpful commands in this environment:

```bash
python3 /home/martin/.claude/scripts/scope-detect.py --json .
python3 /home/martin/.claude/scripts/validate-subproject.py .
```

If `/home/martin/.Codex/scripts/*` exists in your environment, it may be the equivalent path. Trust the script output over filesystem guesses.

## Repository map

| Path | Owner/meaning | Notes |
|---|---|---|
| `packages/gove-zone/` | Governed runtime kernel | Main receipt-gated execution code. Python >=3.11. |
| `packages/acgs-lite/` | PyPI-facing governance library | Nested repo/submodule. Do not stage from parent. Public API stability matters. |
| `packages/Acgs-Swarm/` | Constitutional swarm research | Nested repo/submodule. Package-local tests only. |
| `packages/clinicalguard/` | Clinical-domain agent | Nested/private submodule; path-filtered and may be unavailable. |
| `acgi-ai/` | Frontend/console | Privileged origin; no public-only CDN/script patterns in console routes. |
| `acgs_governance_eval_mvp/` | Evaluation/governance MVP | Python package. |
| `acgs-cft-governance-pack/` | Infrastructure governance pack | Python package. |
| `docs/` | Claim-safe documentation | Do not edit sealed/hash-marked files without the regeneration path. |
| `examples/` | Root integration examples | Must be lightweight, local-only, and runnable. |
| `tests/docs/` | Documentation/example smoke checks | Keep docs from rotting. |

## Safe edit zones for documentation work

These are safe for documentation-focused PRs when local checks pass:

- `README.md`
- `AGENTS.md`
- `llms.txt`
- `docs/START_HERE.md`
- `docs/HUMAN_GUIDE.md`
- `docs/ARCHITECTURE.md`
- `docs/DECISION_RECEIPT_SPEC.md`
- `docs/SECURITY_MODEL.md`
- `docs/CLAIMS.md`
- `docs/QUICKSTART.md`
- `docs/DEMO_SCRIPT.md`
- `docs/INTEGRATION_GUIDE.md`
- `docs/COMPARISON.md`
- `docs/ROADMAP.md`
- `docs/GLOSSARY.md`
- `docs/REVIEW_CHECKLIST.md`
- `docs/ADOPTION_GUIDE.md`
- `docs/PROOF_PATH.md`
- `examples/**` and `tests/docs/**` when examples remain local-only.

## Dangerous edit zones

Treat these as security-sensitive. Read code and tests before changing claims or behavior:

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
- `docs/constitutional-hashes.lock` and any file with `Constitutional Hash`, `@generated`, `DO NOT EDIT`, or lock-file semantics.

## Forbidden changes without explicit user approval

Do not:

- weaken fail-closed behavior;
- bypass receipt validation;
- make execution happen before audit/receipt validation;
- treat `DENY` or `ESCALATE` as executable;
- skip `expected_actor` at executor gates;
- remove actor/action/argument/policy/audit binding checks;
- turn unsigned dev mode into a production claim;
- describe ACGS as compliance-certified, regulator-approved, or production-ready without release and external evidence;
- edit security claims without checking the relevant source and tests;
- hand-edit generated/sealed/hash-marked outputs;
- use `git add -A` or `git add .` in this workspace.

## Test and demo commands

Root documentation smoke:

```bash
uv run python -m pytest tests/docs --import-mode=importlib -q
```

Main gove-zone runtime gate:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

Fast proof commands:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Root docs invariant check:

```bash
make lint-docs
```

Broad monorepo gate when intentionally validating the whole workspace:

```bash
make verify
```

## How to verify behavior before editing docs

Before changing claims about receipts, policy, audit, signing, replay, or executors:

1. Inspect the implementation and tests named in `docs/CLAIMS.md`.
2. Run at least one proof command that exercises the claim.
3. If the claim is broader than local code/tests prove, downgrade wording and add a limitation.
4. If a gap is found, document it in `docs/CLAIMS.md` or `docs/ROADMAP.md`; do not silently imply it is solved.

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

## Required behavior for receipt/policy/audit/signing/executor changes

If you change any of the security-sensitive files listed above:

1. Add or update negative-path tests that prove the side effect did **not** run.
2. Prove handler/gate wiring, not only direct unit calls.
3. Run the relevant package tests, not just docs tests.
4. Update `docs/DECISION_RECEIPT_SPEC.md`, `docs/SECURITY_MODEL.md`, and `docs/CLAIMS.md` only after code/tests are verified.
5. Explicitly state whether unsigned mode, signing mode, policy bundle binding, expiry, actor binding, audit replay, or executor enforcement changed.

## Reporting uncertainty

When unsure, say exactly what is known, what file/test proves it, and what remains unverified. Prefer: "Implemented and tested locally by X; production deployment not claimed." Never fill gaps with marketing language.

## Git discipline

Use explicit paths only:

```bash
git status --short
git diff --stat
git diff --check
git add README.md docs/CLAIMS.md examples/tamper_demo/demo.py
```

For submodules/nested repos, enter the nested repo and stage there. Do not accidentally stage parent gitlink drift.
