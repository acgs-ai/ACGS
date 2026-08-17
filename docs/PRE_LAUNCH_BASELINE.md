# Pre-Launch Baseline

> Snapshot of repository state at the start of the pre-launch hardening pass.
> Read-only baseline — no runtime code was modified to produce this document.
> Every number below is literal command output captured on the date shown.

- **Repository:** `dislovelhl/ACGS`
- **Audited tree:** clean worktree off `origin/master` (not any in-flight dev branch)
- **Branch:** `feat/pre-launch-hardening`
- **Commit SHA:** `93df49a31ac7d3fdd1f62eb86f4608dc75f07067`
  (`Merge pull request #349 from dislovelhl/docs-version-pin-fix`, 2026-07-22)
- **Working tree:** clean (only untracked `.claude/hooks/__pycache__/`, a gitignore candidate)
- **Date captured:** 2026-07-22

## Why a fresh worktree

The initial checkout was on `feat/governed-vulnclaw-pentest`, which measured
**350 commits behind `origin/master`, 28 ahead, with 285 uncommitted files**.
Auditing there would have recorded a fictional baseline — code and claims a
public reviewer would never see. The audit was therefore run against a clean
worktree created from `origin/master` (today's public HEAD), which is exactly
what an anonymous reviewer clones.

## Test status

### Root documentation smoke gate

```
$ uv run python -m pytest tests/docs --import-mode=importlib -q
77 passed, 5 skipped, 1 warning in 0.78s
```
Exit 0. This was a cold-`.venv` run (the environment was being created); 5
dependency-gated tests skipped. On a warm `.venv` the same suite reports
**82 passed, 0 skipped, 1 warning** (the `acgs-lite` submodule-dependent example
surfaces as a passing-test warning, not a skip). Green in both states; the 82
tests are the full collection either way.

### gove-zone runtime gate — with required extras

```
$ uv run --package gove-zone --extra crypto --extra yaml --extra mcp \
    python -m pytest packages/gove-zone/tests --import-mode=importlib -q --junitxml=…
tests=1101 failures=0 errors=0 skipped=2
```
Exit 0. This is the true green baseline for the enforcement kernel.

### gove-zone runtime gate — bare documented command (FAILS)

```
$ uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
15 FAILED  (test_cli_validate, test_escalation_resume, test_examples_run,
            test_managed_agent, test_yaml_policy)
```
The command as written in `.claude/rules/verification-gates.md` and the
package docs omits `--extra crypto --extra yaml --extra mcp`. Without them,
15 tests fail on missing optional dependencies (Ed25519 signing → `crypto`,
YAML policy loading → `yaml`, MCP demos → `mcp`). **This is a reviewer trap**
(see `docs/REPRODUCIBILITY.md`): a reviewer who copies the documented gate
sees a red suite that is actually green with the correct extras.

## Constitutional-hash verification status

```
$ python3 scripts/verify_constitutional_hashes.py ; echo $?
FAIL — constitutional-hash drift detected:
  REMOVED (221): packages/acgs-lite/…, packages/clinicalguard/…  (608508a9bd224290)
1
```
On a submodule-free clone the verifier **exits 1**. All 221 pinned markers live
inside submodules (`packages/acgs-lite`, `packages/clinicalguard`, …), so the
invariant cannot be verified without initialized submodules. See
`docs/HASH_VERIFICATION_REPORT.md` for the full characterization (all 221
entries carry a single hash value — effectively one global constitutional hash
replicated per-file, not 221 distinct content digests).

## Build / typecheck status

Not run in full for the baseline (the full `make verify` fans out across the JS
and Python workspaces plus every submodule and is the CI gate). The two
representative Python gates above stand as the runtime-correctness baseline.
Frontend gates (`pnpm lint && pnpm typecheck && pnpm test` inside `acgi-ai/`)
and the full `make verify` remain the authoritative pre-merge gates and were
not re-run here.

## Submodule state on a fresh clone

`git submodule status` shows all 8 submodules uninitialized (leading `-`):

| Submodule | Owner | Role |
|---|---|---|
| `packages/acgs-lite` | dislovelhl | Published PyPI library |
| `packages/Acgs-Swarm` | dislovelhl | Constitutional-swarm research |
| `packages/clinicalguard` | dislovelhl | Clinical-domain agent (private) |
| `packages/ACGS-agency-agents` | dislovelhl | Agency agents |
| `external/UI-TARS-desktop` | bytedance | Third-party reference |
| `external/openswarm` | VRSEN | Third-party reference |
| `external/everything-claude-code` | affaan-m | Third-party reference |
| `external/natural_language_autoencoders` | kitft | Third-party reference |

The 4 `external/*` submodules are not ACGS code (see `docs/REPRODUCIBILITY.md`
and the Phase-7 hygiene plan).

## Known risks at baseline

1. **Constitutional-hash gate fails on a bare clone** (submodule-dependent).
2. **Documented gove-zone gate omits required extras** → false-red for reviewers.
3. **Version skew**: canonical surfaces say `gove-zone 1.0.0rc1`/Beta; many
   docs still say `0.1.0.dev0` / `0.1.0a1` / Alpha (see `docs/VERSIONING.md`).
4. **4 third-party `external/*` submodules** embedded in the tree (clone weight
   + credibility; see Phase 7 hygiene plan).
5. Internal dev-process material and go-to-market drafts committed in `docs/`
   (see `docs/CLAIM_AUDIT.md` and the Phase-4 relocation plan).

## Files inspected (baseline)

`README.md`, `Makefile`, `.gitmodules`, `pyproject.toml`, `package.json`,
`MONOREPO.md`, `docs/constitutional-hashes.lock`,
`scripts/verify_constitutional_hashes.py`, plus the two Python test suites above.

## Commands executed (baseline)

```bash
git worktree add ../ACGS-prelaunch -b feat/pre-launch-hardening origin/master
git rev-parse HEAD                      # 93df49a…
git submodule status                    # all 8 uninitialized
uv run python -m pytest tests/docs --import-mode=importlib -q
uv run --package gove-zone --extra crypto --extra yaml --extra mcp \
  python -m pytest packages/gove-zone/tests --import-mode=importlib -q --junitxml=/tmp/gz.xml
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
python3 scripts/verify_constitutional_hashes.py
```
