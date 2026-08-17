---
description: Select and run the correct govern-zone verification gate for a given path or package, then report the literal command output.
argument-hint: "[path or package name] (e.g. tests/docs, gove-zone, acgi-ai, packages/acgs-lite, or 'all')"
allowed-tools: Bash, Read, Grep, Glob
---

# /verify — path-selected verification gate

Map `$ARGUMENTS` to the **correct** gate from `.claude/rules/verification-gates.md`,
run it, and report the literal output (paste it — never claim a pass/fail without
it, per `.claude/rules/claim-safety.md`). Run the **narrowest** gate that covers
the touched path; use `make verify` only when intentionally validating the whole
workspace.

Target: **`$ARGUMENTS`**

## Mapping table

| `$ARGUMENTS` matches | Gate to run |
|---|---|
| empty, `all`, `verify`, `make`, root-wide | `make verify` |
| `tests/docs`, `docs`, `docs-smoke`, docs-only edits | `uv run python -m pytest tests/docs --import-mode=importlib -q` |
| `gove-zone`, `packages/gove-zone`, gove_zone source/tests | `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` |
| `acgi-ai`, `console`, `marketing`, frontend | `pnpm run test:all` — run **inside `acgi-ai/`** (the package's aggregate gate; it starts with `lint` and ends with the vitest unit suite — there is no `typecheck` script) |
| `acgs-lite`, `packages/acgs-lite` | package-local gate **inside the nested repo** (its `Makefile`/`pyproject`; e.g. `uv run --package acgs-lite python -m pytest packages/acgs-lite/tests -q`) |
| `Acgs-Swarm`, `acgs-swarm`, `packages/Acgs-Swarm` | package-local pytest **inside the nested repo** (package-local tests only) |
| `clinicalguard`, `packages/clinicalguard` | package-local gate inside the nested repo (path-filtered; may be unavailable) |
| any other `packages/<pkg>` | that package's local `pytest` / `Makefile` gate, run from inside the package |
| `docs-invariant`, `lint-docs` | `make lint-docs` |

### Fast proof commands (when the ask is "prove the runtime works", not "run tests")

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Or run all of them plus the docs smoke as one structured JSON report:
`bash scripts/claim_verify_headless.sh` (see `/claim-verify`).

## Procedure

1. **Resolve the gate.** Match `$ARGUMENTS` against the table above. If it names
   a nested repo (`acgs-lite`, `Acgs-Swarm`, `clinicalguard`), `cd` into that
   package and use its **own** command — never a command copied from another
   package (`.claude/rules/repo-boundaries.md`). If it's ambiguous, prefer the
   narrowest matching gate and say which you chose and why.
2. **Run it** and capture the literal output + exit code. Prefer `git -C`/`cd`
   into the correct package dir; for `acgi-ai` and nested repos the gate must run
   from inside that directory, not the repo root.
3. **Report** the exact command, its literal output (or a stable digest), and
   the exit status. A passing unit test does not prove handler wiring — flag that
   caveat for security-sensitive paths (`~/.claude/rules/review-handler-wiring.md`).
4. **Do not** invent a command the project doesn't define, and do not report
   success without the literal output in front of you.
