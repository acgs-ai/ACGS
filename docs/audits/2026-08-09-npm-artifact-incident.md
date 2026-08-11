# Incident Record — Unreviewed npm Artifacts in pnpm Workspace Root

- **Record date:** 2026-08-09
- **Incident date:** 2026-08-08
- **Scope:** repository root (`/tmp/claude-1000/ACGS`), branch `docs/comparison-agt-permit`
- **Classification:** `QUARANTINED` — owner-attributed, not agent-attributed; disposition pending owner + security sign-off
- **Release impact:** none observed (see §5)

This record covers three events that surfaced together in one `git status` but are
causally independent. Events 2 and 3 are recorded here only so they are not
conflated with Event 1 in future reviews; each has its own disposition.

---

## 1. Incident timeline

All timestamps are `America/New_York` (EDT), derived from `~/.zsh_history` epoch
fields and corroborated by filesystem mtimes.

| Time | Event | Evidence |
|---|---|---|
| 2026-08-08 15:43:17 | Interactive `codex` invoked from the user's shell | `.zsh_history` epoch `1786218197` |
| 2026-08-08 15:45:13 | `.codex/config.toml` rewritten (TOML reserialization + `shell_environment_policy` added) | file mtime `2026-08-08 15:45:13` |
| 2026-08-08 19:10:15 | `npm install @openai/codex-security` run interactively at repo root | `.zsh_history` epoch `1786230615` |
| 2026-08-08 19:10 | `package-lock.json` created; 53 top-level entries written to `node_modules/`; `package.json` gains a `dependencies` block | mtimes all `19:10`, single-minute spread |
| 2026-08-08 19:13:52 | `npm audit` run | `.zsh_history` epoch `1786230832` |
| 2026-08-08 19:14:26 | `codex` invoked again | `.zsh_history` epoch `1786230866` |
| 2026-08-08 23:21:46 | `claude` session started | `.zsh_history` epoch `1786245706` |
| 2026-08-08 23:22 | Sandbox mask mounts materialize at repo root (Event 3) | `/proc/self/mountinfo` |

**Attribution.** Both Event 1 and Event 2 trace to the repository owner's own
interactive shell, not to an agent, plugin, hook, or automated system. The
`npm install` command appears verbatim in interactive history. This is the
material correction to the prior assessment, which left the actor open.

**Attribution does not equal authorization.** The command was run by the owner;
it was not reviewed against the workspace's package-manager, license, SBOM, or
vulnerability gates. The artifacts stay quarantined until that review happens.

---

## 2. Event 1 — npm artifacts (primary incident)

### 2.1 What was installed

`@openai/codex-security@0.1.8` (`license: Apache-2.0`), resolved from
`https://registry.npmjs.org/@openai/codex-security/-/codex-security-0.1.8.tgz`,
integrity `sha512-GFlCb0UPh/kWp6UJsNhWq4LGxIKMRv0dM9fL+xCWqoXV5uVNq4YK7+i/ld1twyD4hNhPTdulvKq0kpB9+zZgGQ==`.

Its direct dependencies pull the Codex runtime into the workspace root:
`@openai/codex@0.144.6`, `@openai/codex-sdk@0.144.6`, `@inquirer/prompts@8.3.0`,
`@octokit/core@7.0.6`, `ajv@8.20.0`, `extract-zip@2.0.1`, `fast-uri@3.1.5`,
`fflate@0.8.2`, `incur@0.4.13`, `papaparse@5.5.3`, `pdfjs-dist@5.6.205`,
`smol-toml@1.6.1`.

### 2.2 Blast radius

| Measure | Count |
|---|---:|
| `"resolved"` entries in `package-lock.json` | 107 |
| Installed packages (`package.json` files under `node_modules/`) | 103 |
| Top-level `node_modules/` entries | 53 |
| Executable shims in `node_modules/.bin` | 7 |

`node_modules/.bin` contents: `codex`, `codex-security`, `extract-zip`, `incur`,
`incur.src`, `turbo`, `yaml`.

Every top-level entry carries mtime `2026-08-08 19:10` — a single install event
with no pre-existing root tree underneath it.

### 2.3 Why this is a finding, not routine dependency work

1. **Wrong package manager.** Root `package.json` declares
   `"packageManager": "pnpm@9.15.4"` and `"engines": { "pnpm": ">=9" }`. The
   install used npm, producing a `package-lock.json` that is foreign to the
   declared toolchain. The workspace's real JS lockfile is
   `acgi-ai/pnpm-lock.yaml`; there is no root `pnpm-lock.yaml`.
2. **Runtime dependency on a root that publishes nothing.** The root package is
   `"private": true` and previously carried only `turbo` as a devDependency. A
   `dependencies` block at this level is new surface.
3. **`turbo` was re-provisioned by npm.** The legitimate `turbo` devDependency now
   resolves from an npm-built tree rather than a pnpm store, so any local
   `turbo run` at root executes through unreviewed resolution.
4. **Seven new executable shims**, including two that ship an agent runtime, landed
   in a governance repository without license/SBOM/vulnerability review.
5. **No review record.** `npm audit` was run at 19:13:52 but its output was not
   captured, so it is not evidence.

The repository had already anticipated this failure mode. `.gitignore:9–13`
carries a standing comment: *"This is a pnpm workspace — pnpm-lock.yaml is the
only JS lockfile that should ever land in the parent. package-lock.json (npm)
and yarn.lock slip in when someone runs `npm install` inside a workspace member;
they split resolution and break `pnpm install --frozen-lockfile`."* The ignore
rule contained the blast radius exactly as designed; what it could not contain
was the `package.json` manifest edit, which is why that edit is the one thing
reverted here.

### 2.4 Artifact hashes

| Artifact | SHA256 |
|---|---|
| `package.json` (as mutated, pre-remediation) | `b3b048c67dbd60a1d537eaa5e060ae58acad81ced41f0b4a43f2c5bf6960622e` |
| `package.json` (`HEAD`, restored baseline) | `47cb8c87a4c789406249ca1be40946391c2520138fe5c6afa927dbe95585aad8` |
| `package-lock.json` | `92d35c9ea7b0044874d3bd85b1b611b0d1cda26f9a7740d294c39ae745fa9374` |

`package-lock.json` metadata: `lockfileVersion: 3`, `name: govern-zone`,
`version: 0.0.0`.

---

## 3. Event 2 — `.codex/config.toml` rewrite

Independent of Event 1: mtime `15:45:13`, three and a half hours before the npm
install, immediately after an interactive `codex` invocation at `15:43:17`.

The diff has two distinct parts:

- **Machine reserialization** — inline `args` arrays expanded to multi-line form,
  consistent with a TOML writer round-tripping the file. This dropped two
  provenance lines: the `#:schema https://developers.openai.com/codex/config-schema.json`
  pragma and the `# ECC Tools generated Codex baseline` header comment.
- **Semantic addition** — a new `[shell_environment_policy]` block.

> **Evidence limitation.** The mutated file was **not** hashed before it was
> reverted with `git checkout -- .codex/config.toml`, and that working-tree
> version is now irrecoverable. The complete unified diff below, captured before
> the revert, is the only surviving record of the mutation. There is no hash and
> no copy of the mutated artifact.

```diff
--- a/.codex/config.toml
+++ b/.codex/config.toml
@@ -1,32 +1,45 @@
-#:schema https://developers.openai.com/codex/config-schema.json
-
-# ECC Tools generated Codex baseline
 approval_policy = "on-request"
 sandbox_mode = "workspace-write"
 web_search = "live"

 [mcp_servers.github]
 command = "npx"
-args = ["-y", "@modelcontextprotocol/server-github"]
+args = [
+    "-y",
+    "@modelcontextprotocol/server-github",
+]

 [mcp_servers.context7]
 command = "npx"
-args = ["-y", "@upstash/context7-mcp@latest"]
+args = [
+    "-y",
+    "@upstash/context7-mcp@latest",
+]

 [mcp_servers.exa]
 url = "https://mcp.exa.ai/mcp"

 [mcp_servers.memory]
 command = "npx"
-args = ["-y", "@modelcontextprotocol/server-memory"]
+args = [
+    "-y",
+    "@modelcontextprotocol/server-memory",
+]

 [mcp_servers.playwright]
 command = "npx"
-args = ["-y", "@playwright/mcp@latest", "--extension"]
+args = [
+    "-y",
+    "@playwright/mcp@latest",
+    "--extension",
+]

 [mcp_servers.sequential-thinking]
 command = "npx"
-args = ["-y", "@modelcontextprotocol/server-sequential-thinking"]
+args = [
+    "-y",
+    "@modelcontextprotocol/server-sequential-thinking",
+]

 [features]
 multi_agent = true
@@ -45,4 +58,10 @@ config_file = "agents/reviewer.toml"

 [agents.docs_researcher]
 description = "Documentation specialist that verifies APIs, framework behavior, and release notes."
-config_file = "agents/docs-researcher.toml"
\ No newline at end of file
+config_file = "agents/docs-researcher.toml"
+
+[shell_environment_policy]
+inherit = "core"
+
+[shell_environment_policy.set]
+CLAUDE_CODE_WORKFLOWS = "1"
```

Note that `smol-toml` — a TOML serializer — is a direct dependency of the package
installed in Event 1. It is **not** the writer here: this rewrite predates that
install by three and a half hours. The writer was the already-present `codex`
CLI invoked at 15:43:17.

**The file is an orphaned generated artifact.** Established from git history
after the unshallow:

```
$ git log --oneline --diff-filter=A -- .codex/config.toml
75c5224 feat: add govern-zone ECC bundle (.codex/config.toml)   # 2026-05-28

$ git log --oneline -- .codex/config.toml | wc -l
1

$ git merge-base --is-ancestor 35ebf7d 75c5224   # exit 0
```

It was force-added past `.gitignore:69`, which has ignored `.codex` since the
initial commit `35ebf7d`. Its commit contains that file alone (48 lines). Its
header declared it generated (`# ECC Tools generated Codex baseline`), yet
grepping all source for `ECC Tools` finds **no generator in the repository**. It
was untouched for three months before the 15:45 rewrite.

This is why the mutation went unchallenged: the file's ignore rule signals
disposable while its tracked status signals source, and the repository's
Generated File Policy ("modify the generator, not the output") is unfollowable
when the generator does not exist. Resolving the file's status — authored,
generated-with-source, or untracked — is a prerequisite for closing G0-4.

**Disposition:** provenance markers restored; `shell_environment_policy` reverted
pending a named owner and stated purpose. Rationale in §6.

---

## 4. Event 3 — sandbox mask artifacts (not a repository mutation)

Ten paths appeared as untracked or modified at repo root. They are read-only bind
mounts of `/dev/null` created by the session sandbox at `23:22`, not files written
into the repository. Proof from `/proc/self/mountinfo`:

```
0:7 /null /tmp/claude-1000/ACGS/.mcp.json   ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.gitconfig  ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.bashrc     ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.zshrc      ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.profile    ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.ripgreprc  ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.vscode     ro,nosuid,nodev - devtmpfs
0:7 /null /tmp/claude-1000/ACGS/.idea       ro,nosuid,nodev - devtmpfs
```

Root `.env` is a character device (`1, 3`, owner `nobody`) by the same mechanism.
`acgi-ai/.env.example` is on the session's read-deny list, which is why
`git diff` on it returns `fatal: cannot hash`.

Two commit hazards follow, and both are addressed in §6:

1. The masked dotfiles are reported `??`, so `.gitignore` did not cover them. Any
   `git add -A` at root would commit zero-byte `.bashrc` / `.zshrc` / `.gitconfig`
   into the repository.
2. `acgi-ai/.env.example` is **tracked** while being a non-regular file, so it is
   reported ` M` and `git add` on that path errors instead of staging.

---

## 5. Release-scope containment (verified)

| Check | Result |
|---|---|
| `git check-ignore node_modules` | ignored — `.gitignore:8` |
| `git check-ignore package-lock.json` | ignored — `.gitignore:13` |
| npm references in `Makefile` | none; `PNPM ?= pnpm`, `make install` = `pnpm install + uv sync` |
| `npm ci` / `npm install` / `package-lock` in `.github/workflows/` | none — all seven workflows use `pnpm install --frozen-lockfile --ignore-workspace` |
| Repo-wide stray lockfiles — `find . \( -name package-lock.json -o -name yarn.lock \) -not -path '*/node_modules/*'` | one hit: `./package-lock.json`, the quarantined root artifact. No `yarn.lock`, no lockfile under any package. |

The repo-wide scan matters because `.gitignore:13` is unanchored: it matches
`package-lock.json` at any depth, so a stray lockfile inside a workspace member
would be invisible to `git status`. The scan confirms none exists.

No npm artifact is reachable from git history, CI, or the release path. The
contamination is confined to the local working tree.

**Residual local hazard:** root `node_modules/` remains npm-built while quarantined.
Do not run root `turbo` tasks or `make verify`'s JS lanes against this tree. Run
`make clean` (`rm -rf node_modules .venv .turbo`) followed by `make install` only
**after** the owner records a disposition — `make clean` destroys the evidence.

---

## 6. Artifact disposition

| Artifact | Classification | Action taken | Evidence preserved |
|---|---|---|---|
| `node_modules/` (103 pkgs, 7 shims) | QUARANTINED | left in place, untouched; gitignored | yes — on disk, inventoried in §2.2 |
| `package-lock.json` | QUARANTINED | left in place, untouched; gitignored | yes — on disk, hashed in §2.4 |
| `package.json` `dependencies` block | UNAUTHORIZED | reverted to `HEAD` | yes — hash in §2.4, lockfile retains full spec |
| `.codex/config.toml` provenance lines | LOST → RESTORED | `#:schema` + ECC baseline header restored | **partial** — unified diff in §3 only; mutated file was not hashed before revert and is irrecoverable |
| `.codex/config.toml` `shell_environment_policy` | UNATTRIBUTED → REVERTED | removed; no named owner or stated purpose | **partial** — same limitation; diff is the only record |
| Sandbox mask dotfiles (9 paths) | NOT A MUTATION | added to `.gitignore` with rationale | n/a |
| `acgi-ai/.env.example` | TRACKED + MASKED | `skip-worktree` bit set (local index only) | n/a |

**Reverting `package.json` is not evidence deletion.** The mutation is recorded by
hash in §2.4, preserved in `package-lock.json`, and reproducible from
`git diff` history. Reverting removes the only path by which the dependency could
reach a build or a commit.

---

## 7. Executed actions and verification

All evidence in §2 was captured **before** any mutation. No artifact was deleted.

| # | Action | Verification | Result |
|---|---|---|---|
| 1 | Reverted the `dependencies` block in `package.json` | `sha256sum package.json` vs `git show HEAD:package.json \| sha256sum` | both `47cb8c87…5aad8` — byte-identical to baseline |
| 2 | Reverted `.codex/config.toml` to `HEAD` | `head -3` shows `#:schema` + `# ECC Tools generated Codex baseline`; `grep -c shell_environment_policy` → `0`; `git diff --stat` → empty | provenance restored, unattributed block removed |
| 3 | Added 9 sandbox-mask paths to `.gitignore` | `git check-ignore -v` on each | all matched |
| 4 | Set `skip-worktree` on `acgi-ai/.env.example` | `git ls-files -v acgi-ai/.env.example` → `S` | masked non-regular file no longer stageable or reported |
| 5 | Un-shallowed the repository (G0 blocker) | `git rev-parse --is-shallow-repository` → `false`; `git rev-list --count HEAD` → `1032` (was `2`) | full history restored |

`.mcp.json` was deliberately **excluded** from the `.gitignore` block. It is the
peer of `/.claude/settings.json` and `/.claude/hooks/**`, which lines 98–116
explicitly *un*-ignore as shared team configuration. It is untracked today only
because it is currently a `/dev/null` mount; ignoring it would silently prevent a
future real one from ever being tracked. The `git add -A` hazard it would have
defended against is already forbidden outright by `AGENTS.md:107`. Consequence:
`.mcp.json` still appears as `??` in `git status` for as long as the sandbox
masks it. That is intended — do not stage it while it is a `/dev/null` mount.

Action 4 sets a **local index bit only**. It is not committed and does not
propagate to other clones. It does, however, live in `.git/index` and **persists
across sessions**. Once the sandbox no longer masks that path, real upstream
changes to `acgi-ai/.env.example` become invisible and `git pull` may refuse to
update the file. **Owner: whoever next runs a non-sandboxed session in this
checkout must clear it** with:

```bash
git update-index --no-skip-worktree acgi-ai/.env.example
```

### G0 readiness checks

The docs suite failure recorded in the prior assessment is resolved, and its root
cause is confirmed: the three commits frozen into
`tests/docs/test_saas_current_state_survey.py` were unreachable in a 2-commit
shallow clone, not corrupt survey data.

```
$ for s in 1d9c9b21… b2aa0c92… e4af0731…; do git cat-file -t $s; done
commit
commit
commit

# UV_CACHE_DIR is required in this sandbox: the default ~/.cache/uv is
# read-only here and uv fails with "Could not acquire lock ... os error 30".
$ export UV_CACHE_DIR=<writable-path>
$ uv run python -m pytest tests/docs --import-mode=importlib -q
115 passed, 1 warning in 0.81s

$ make lint-docs
Governance stack index check passed.
internal markdown links ok: 24 markdown files checked
AI governance hub docs validation passed: 26 files checked
exit=0
```

Prior state was `114 passed, 1 failed`. No test file, no frozen SHA, and no
survey datum was modified to achieve this.

The single remaining warning is pre-existing and unrelated:
`examples/dynamic_swarm/demo.py` is skipped because the `packages/acgs-lite`
submodule is not initialized in this checkout — see the topology finding below.

### G0 verdict: NO-GO

G0 has three criteria. Restoring history closed one of them; it did not close the
gate.

| G0 criterion | State | Evidence |
|---|---|---|
| Docs suite passes after history restoration | **PASS** | `115 passed`; `make lint-docs` exit 0 |
| Package incident signed disposition | **FAIL** | this record is unsigned; owner + security sign-off outstanding (§8) |
| Source / topology verified | **FAIL** | all five submodules uninitialized (below) |

```
$ git submodule status
-24485830cd4b3c63a4a357b0664d9dedbab9653a packages/ACGS-agency-agents
-39c4464da11d28b2b9b88d5f288341e23eb55e5b packages/Acgs-Swarm
-4cbc62cfed18285e8160fcf988d673375e53cf8e packages/acgs-control-plane
-1580b847ab2f5cb353ccd6c75b0f4da3a1eac088 packages/acgs-lite
-7673183b6a7ee80be9fca6a25b9b45874f7aeb20 packages/clinicalguard
```

The leading `-` on every line means **not initialized**. This includes
`packages/acgs-control-plane`, extracted to a private submodule in commit
`2694983`. The risk register names this exact condition — *"control-plane/source
cannot be verified → G0 NO-GO"* — so this is a triggered NO-GO, not a caveat.
Unshallowing restored parent history only; it does not fetch submodule content.

No pointer drift was introduced: all five gitlinks match `HEAD` and nothing was
staged.

Branch divergence could not be measured: `docs/comparison-agt-permit` has no
remote-tracking branch (`fatal: upstream branch … not stored as a remote-tracking
branch`), so it is local-only. The unshallow did advance `origin/master`
`2694983..a8b5f07`, so this branch is now behind an updated master by an
unmeasured amount.

### Working tree after remediation

```
$ git status --short
 M .gitignore                                          <- this remediation
 M COMPARISON.md                                       <- prior session, untouched
?? docs/audits/2026-08-09-npm-artifact-incident.md      <- this record
?? docs/governance/                                     <- prior session, untouched
?? docs/research/2026-08-08-acgs-strategic-intelligence/ <- prior session, untouched
?? docs/research/2026-08-08-self-evolving-agents/        <- prior session, untouched
```

Every incident artifact has cleared the working tree. `COMPARISON.md` and the
three `docs/` directories belong to a prior session and were deliberately not
touched, staged, or reverted.

---

## 8. Open decisions for the owner

1. **`@openai/codex-security` — reinstate or drop?** If reinstate: install through
   `pnpm` per `packageManager`, and complete lock, license, vulnerability, and SBOM
   review for all 103 packages before committing. If drop: run `make clean`, which
   releases the quarantine and destroys the evidence tree.
2. **`shell_environment_policy` in `.codex/config.toml`** — if
   `CLAUDE_CODE_WORKFLOWS=1` with `inherit = "core"` is intended, reinstate it with
   a named owner and a comment stating its purpose, so the next reserialization
   does not make it look unattributed again.
3. **Should the Codex CLI be permitted to rewrite tracked config in-place?** It
   silently dropped a schema pragma and a provenance comment. Consider treating
   `.codex/config.toml` as generated-with-source, or pinning it read-only.

---

## 9. Governance note

This incident must **not** be cited as evidence that R6 (autonomous development
governance) is implemented. It demonstrates the opposite: an unreviewed
dependency install reached the workspace root with no receipt, no attribution
record, and no enforcement, and was reconstructed after the fact from shell
history and filesystem mtimes. R6 remains `FAIL`.

Related: `docs/CLAIMS.md`, `docs/ROADMAP.md` (G0 gate).
