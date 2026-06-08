# Contributing to ACGS / gove-zone

Thanks for considering a contribution. ACGS / gove-zone is a **receipt-gated
governance layer for AI-agent side effects** — the enforcement membrane an
agent, MCP tool, workflow engine, or CI runner calls *before* it acts.

> **Core invariant: No valid Decision Receipt, no side effect.**

This is an alpha project (`gove-zone` reports `0.1.0.dev0`). The most useful
contributions right now are the ones that make the core promise easier to
*prove*, easier to *adopt*, and harder to *overclaim*.

---

## Before you start

1. Read [`README.md`](README.md) and run the proof path — you should see an
   allowed side effect execute and a denied/tampered one fail closed.
2. Read [`AGENTS.md`](AGENTS.md). It is the operating contract: safe edit zones,
   dangerous (security-sensitive) zones, and forbidden changes.
3. This is a **multi-package monorepo with nested git repos**
   (`packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`).
   Run `git add` / `git commit` *from inside* the package you changed, never
   `git add -A` from the parent. See [`MONOREPO.md`](MONOREPO.md) for the
   package registry and per-package gates.

## Ground rules (non-negotiable)

These mirror the forbidden-changes list in [`AGENTS.md`](AGENTS.md):

- **Do not weaken fail-closed behavior.** `DENY` and `ESCALATE` are never
  executable; execution never happens before audit/receipt validation.
- **Do not overclaim.** This project is *not* production-certified,
  compliance-certified, regulator-approved, a sandbox replacement, or a complete
  IAM/PKI system. Every capability claim in a doc or PR must point at code +
  a test that proves it. See [`docs/CLAIMS.md`](docs/CLAIMS.md) and the
  README "What is implemented now" / "What this repository is not claiming"
  tables.
- **Do not hand-edit sealed/generated files.** Files carrying
  `# Constitutional Hash:`, `@generated`, `DO NOT EDIT`, or lock semantics
  (e.g. [`docs/constitutional-hashes.lock`](docs/constitutional-hashes.lock))
  must be regenerated, not edited by hand.
- **Handlers must be wired.** A new adapter, route, CLI command, or hook is
  incomplete until it is registered in the real execution path *and* has a
  dispatcher-level test — not just a unit test that imports and calls it.

## Local setup & validation

```bash
make install          # pnpm install + uv sync

# Documentation-only changes — the fast, safe gate:
uv run python -m pytest tests/docs --import-mode=importlib -q
make lint-docs

# gove-zone kernel changes:
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q

# Broad multi-package change:
make verify
```

Always run the **package-local** gate for the package you touched. A passing
unit test does not prove handler wiring.

## Pull request checklist

- [ ] Scoped commit — only files I changed, staged from the right repo boundary.
- [ ] Package-local validation command run, with literal output in the PR body.
- [ ] No new overclaim; any new capability claim cites code + test.
- [ ] No sealed/generated file hand-edited (or: regenerated via its generator).
- [ ] New handler/adapter/route is wired and has a dispatcher-level test.
- [ ] Docs updated only where behavior, public API, or commands actually changed.

## Commit & branch conventions

- Work on a feature branch; never commit directly to `main`.
- Keep parent-repo changes and nested-repo (submodule) changes in separate
  commits. Do not stage submodule pointer drift unless that *is* the task.

---

## Good first issues

These are real, scoped, and grounded in the current roadmap
([`ROADMAP.md`](ROADMAP.md)) and the integration task map
([`docs/integration-readiness-task-map.md`](docs/integration-readiness-task-map.md)).
They are starting points — open a discussion issue first if you want to claim
one or scope it further. (The maintainer will convert the strongest of these
into labelled GitHub issues; until then, treat this list as the source of
truth for "where help is wanted.")

### Documentation & onboarding (lowest barrier)

- **Translate `README.md` / `docs/START_HERE.md`** into another language under
  `docs/i18n/`. Keep all claim-safety wording intact in translation.
- **Tighten the QUICKSTART smoke path** — verify every command in
  [`docs/QUICKSTART.md`](docs/QUICKSTART.md) runs from a clean checkout and
  report any drift.

### Policy & examples

- **Contribute a reviewed policy bundle** for a common scenario (read-only file
  access, allow-listed HTTP egress, DB read vs. write separation). The
  `RuleSetPolicy` shape already exists; add the bundle + a fixture test that
  proves the intended allow/deny/escalate decisions. Follow
  [`docs/runbooks/add-a-policy-bundle.md`](docs/runbooks/add-a-policy-bundle.md).
  *Touch:* `packages/gove-zone/` policy examples + tests.
- **Add an evaluation scenario fixture** for the existing AgentDojo /
  InjecAgent / ToolEmu adapters (`gove-zone eval --benchmark-format ...`) and
  assert the expected decision-mismatch metrics. *Touch:*
  `packages/gove-zone/tests/test_benchmark_adapters.py`.

### Runtime adapters (one framework each — good "first real feature")

The hook adapter already normalizes Claude/Codex-style, MCP `tools/call`,
function-call, OpenAI Responses/Chat, and LangChain payloads in
`gove_zone.integration` (see the `tool_call_from_hook_payload` /
`tool_calls_from_hook_payload` pattern). Adding one more framework is a
self-contained contribution. Follow
[`docs/runbooks/add-a-runtime-adapter.md`](docs/runbooks/add-a-runtime-adapter.md) —
it names where to extend (there is no adapter registry), the fail-closed
`runtime.malformed_batch` rule, and the exact gate-level tests to add (a
parser-only unit test is not sufficient):

- **CrewAI tool-call normalization** + gate-level enforcement test.
- **AutoGen tool-call normalization** + gate-level enforcement test.
- **LlamaIndex tool-call normalization** + gate-level enforcement test.

Each must follow the existing fail-closed rule: a recognized multi-call
container with an unparseable child fails closed as `runtime.malformed_batch`.

### Packaging & portability

- **PyPI publish readiness for `gove-zone`** — see the gap report at
  [`docs/gove-zone-pypi-readiness.md`](docs/gove-zone-pypi-readiness.md).
  Discrete, reviewable sub-tasks are listed there.
- **Windows support pass for the `gove-zone` CLI** — exercise `smoke`, `gate`,
  and audit-JSONL paths on Windows and fix any path/encoding assumptions.

---

## Reporting security-sensitive issues

If you find a way to make a side effect execute *without* a valid Decision
Receipt — or to make `DENY`/`ESCALATE` executable, bypass the executor gate, or
forge the audit chain — that is a core-invariant break. Do not open a public PR
with a working bypass; contact the maintainer privately first.

## Questions

Open a GitHub Discussion or issue. For "where do I look first", the map is in
[`README.md`](README.md) → "Where to look first" and [`AGENTS.md`](AGENTS.md).
Hosted documentation: <https://acgs.ai/docs>.
