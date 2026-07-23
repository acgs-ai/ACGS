<!-- Thanks for contributing to ACGS / gove-zone. Keep PRs scoped and verifiable. -->

## What changed

<!-- One or two sentences. Link any related issue (Fixes #NNN). -->

## Scope

- [ ] Change is scoped to one subproject / concern (see `AGENTS.md` boundaries)
- [ ] No unrelated files staged; `git diff --stat` reviewed for scope creep
- [ ] Nested submodules (`packages/acgs-lite`, `Acgs-Swarm`, `clinicalguard`,
      `ACGS-agency-agents`) not modified from the parent (or a pin bump is the
      explicit intent, called out below)

## Security-sensitive?

If this touches receipts, executor gates, kernel, audit chain, policy, signing,
or constitutional-hash logic (`.claude/rules/security-sensitive-files.md`):

- [ ] Added/updated **negative-path** tests proving the side effect did **not** run
- [ ] Proved handler/gate **wiring**, not just direct unit calls
- [ ] Stated explicitly what changed (unsigned mode / signing / policy binding /
      expiry / actor binding / audit replay / executor enforcement)
- [ ] Did **not** weaken fail-closed behavior or bypass receipt validation

## Claims

- [ ] No new unsupported claims (no "production-certified" / "compliance-certified"
      / "regulator-approved" / "formally verified" — see `docs/CLAIMS.md`)
- [ ] Numeric claims (test counts, benchmarks) backed by literal command output

## Verification

<!-- Paste the literal output of the relevant gate. -->

```
$ <package-local gate, e.g. cd packages/gove-zone && uv run python -m pytest -q>
```

- [ ] Ran the package-local gate (or `make verify` for multi-package changes)
- [ ] Docs/examples smoke green if docs changed (`make lint-docs`, `tests/docs`)
