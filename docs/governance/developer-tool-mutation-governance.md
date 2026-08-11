# Developer Tool Mutation Governance

**A control model for high-agency software actors, derived from incident 2026-08-09.**

- **Status:** historical pre-P11 analysis and proposal. For current
  implementation status, see [ADR-0010](../adr/0010-execution-governance-layer.md)
  and [ACGS vNext](acgs-vnext-execution-governance-layer.md).
- **Date:** 2026-08-09
- **Source incident:** [`docs/audits/2026-08-09-npm-artifact-incident.md`](../audits/2026-08-09-npm-artifact-incident.md)
- **Audience:** ACGS architecture, security owner, board/investor discussion
- **Claim status:** every "today" statement describes the pre-P11 snapshot and
  is cited to a file:line. Every "proposed" statement remains design unless the
  current ADR/vNext status explicitly says it landed.

---

## Executive summary

**Historical finding (pre-P11).** ACGS's receipt layer was live and appending throughout the
incident and recorded neither event. It is scoped to agent `Edit`/`Write` calls
only, emits `decision: allow` 100% of the time, and attributes 100% of records
to a fallback identity. The two mutations that mattered — an unreviewed
103-package install and a tool silently rewriting tracked config — came from an
interactive terminal, which no agent hook can see.

**The cheapest fix is also the biggest.** ACGS has already built and tested a
stronger adapter, `UniversalGateway.handle_claude_hook`, which evaluates real
policy and mints signable Decision Receipts. At the time of this analysis the
repository's own hook did not use it (§5.4a); P11 subsequently wired it.
Separately, a one-line check — *is the invoked package manager
the one this repo declares?* — would have stopped the incident outright (§6, C3).
**The highest-value control is also the cheapest**, which is the strongest
evidence that this gap is architectural rather than resource-bound.

**The model.** Classify mutations by blast radius and reversibility, never by
actor: M0 read-only → M1 workspace-local → M2 tracked source → M3 dependency
graph (executes third-party code) → M4 control surface → M5 trust root → M6
production-impacting. Same class, same controls, whether the actor is an agent, a
CLI tool, CI, or a human. A class is governed only when *every* path producing it
is mediated (§4).

**Sequencing** (§6, full table with effort and impact): (0) migrate the hook to
the existing gateway; (1) deny non-canonical package managers; (2) provenance
sidecars; (3) control-surface ownership inventory; (4) rollback evidence capture;
then checkpoints, SBOM delta, receipts, attestation.

**Strategic read** (§8): every mature control — SCA, SBOM, secret scanning,
pre-commit, branch protection, SLSA, EDR, agent guardrails — sits at commit,
merge, build, or runtime. This incident happened at **local mutation time**,
which has essentially no governance tooling and is exactly where AI coding agents
and their tools operate. The differentiating position is governing *high-agency
software actors*, of which AI agents are the newest and package managers the
largest and most privileged.

**Status.** Historical pre-P11 analysis. Its unimplemented controls remain
proposals; current delivery status is tracked by ADR-0010 and ACGS vNext. Claim
discipline in §5.7.

---

## 0. Why this document exists

On 2026-08-08 a single interactive command installed 103 packages and 7
executable shims into the root of a governance repository, and a developer tool
silently rewrote a tracked configuration file, dropping its provenance header.
Neither event produced a receipt. Neither was authorized by any control. Both
were reconstructed after the fact from shell history and filesystem mtimes.

The uncomfortable part is not that this happened. It is that **ACGS builds the
control plane that is supposed to prevent exactly this class of event, and that
control plane did not apply to its own repository.** The kernel governs
*agent-requested tool calls*. It does not govern the developer, the developer's
terminal, or the developer's tools — which in 2026 are themselves high-agency
actors that write code, install dependencies, and mutate configuration.

This document converts that gap into a reusable control model.

---

## 1. Incident reconstruction

### 1.1 Timeline

Times are `America/New_York`. Sources: `~/.zsh_history` epoch fields,
filesystem mtimes, `/proc/self/mountinfo`, and git object state.

| Time (2026-08-08) | Event | Actor | Evidence class |
|---|---|---|---|
| 15:43:17 | `codex` invoked interactively | human, interactive shell | proven |
| 15:45:13 | `.codex/config.toml` rewritten: reserialized, `#:schema` + ECC baseline comment dropped, `[shell_environment_policy]` added | Codex CLI, acting as the human | inferred (strong) |
| 19:10:15 | `npm install @openai/codex-security` | human, interactive shell | proven |
| 19:10 | `package-lock.json` created; 103 packages, 53 top-level entries, 7 bin shims written; `package.json` gains `dependencies` | npm, acting as the human | proven |
| 19:13:52 | `npm audit` run | human | proven (command); output never captured |
| 19:14:26 | `codex` invoked again | human | proven |
| 23:21:46 | `claude` session started | human | proven |
| 23:22 | Sandbox mask mounts materialize at repo root | agent sandbox | proven |
| 2026-08-09 | Detection, evidence capture, containment | governed agent session | proven |

Detection latency: **~14 hours**, and detection was incidental — the artifacts
were noticed during an unrelated readiness assessment, not by any control.

### 1.2 The five-way decomposition

The single most important analytical move is refusing to collapse these into
one judgment. They are independent axes and they disagree with each other.

| Axis | Event 1 (npm) | Event 2 (Codex config) |
|---|---|---|
| **Action attribution** | Repository owner, own interactive shell. Proven by verbatim history entry. | Codex CLI process, launched by the owner 116 seconds earlier. Inferred from timing + the mechanical nature of the diff. |
| **Authorization status** | **None.** No control evaluated this. Not denied — never asked. | **None.** Same. |
| **Intent** | Benign and coherent: install a security tool to use with Codex. `npm audit` at 19:13 shows the operator was actively thinking about supply-chain risk. | Benign: tool persisting its own configuration. No adversarial intent. |
| **Technical impact** | 103 packages, 7 shims incl. an agent runtime, into a repo declaring `pnpm@9.15.4`. Contained by `.gitignore` from reaching git/CI. `package.json` manifest edit was **not** contained. | Provenance metadata destroyed. One semantic policy addition with no owner. Fully within tracked source. |
| **Governance failure** | Total. No authorization, no receipt, no evidence, no attribution record, no rollback plan. Reconstruction was forensic. | Total, plus **silent** — a tool rewrote tracked source with no diff review and no notification. |

### 1.3 Proven / inferred / unknown

Stating this explicitly is the discipline that separates an incident record from
a story.

**Proven** — direct evidence, reproducible:
- The `npm install` command text, its timestamp, and the operator's shell.
- The full artifact inventory: 107 lock entries, 103 installed packages, 53
  top-level directories, 7 bin shims, all mtimes within one minute.
- Release-scope containment: `.gitignore:8,13` cover `node_modules/` and
  `package-lock.json`; all seven CI workflows use `pnpm install
  --frozen-lockfile`; a repo-wide scan finds no stray lockfile.
- The complete `.codex/config.toml` diff (captured before revert).
- The sandbox masks are `/dev/null` bind mounts, not written files.
- The docs-suite failure was caused solely by a 2-commit shallow clone.

**Inferred** — consistent with all evidence, not directly witnessed:
- That the Codex CLI wrote `config.toml`. Timing (116s after invocation) and the
  machine-reserialization character of the diff support it. No process-level
  evidence exists.
- That `[shell_environment_policy]` was written by the same tool rather than by
  a human editing afterward. The block is syntactically consistent with the
  reserialized output.
- That intent was benign. Supported by `npm audit` and by the coherence of the
  action; not provable.

**Unknown** — and material:
- **What `npm audit` reported.** Output was never captured. There is no record
  of whether the 103 packages carried known vulnerabilities at install time.
- **What the pre-install `node_modules` state was.** Every entry now carries the
  19:10 mtime, so any prior root tree is unrecoverable.
- **Whether any postinstall script executed.** npm runs lifecycle scripts by
  default. Nothing recorded whether any of the 103 packages did, or what it did.
  This is the single largest unknown in the incident.
- **Whether the `.codex/config.toml` mutation was the tool's first.** No prior
  provenance record exists to compare against.
- **The full content of the mutated `config.toml`.** It was reverted before
  hashing; only the diff survives. This is a self-inflicted evidence gap and is
  recorded as such in the incident file §6.

---

## 2. G0 closure plan

Six items. G0 is `NO-GO` until every one reads PASS.

**Relationship to G0's three criteria.** The incident record states G0 has three
criteria; this section lists six items. They are the same gate at different
granularity — the three are the criteria, the six are the work:

| G0 criterion | Closed by |
|---|---|
| Docs suite passes after history restoration | already PASS (`115 passed`, `make lint-docs` exit 0) |
| Package incident signed disposition | G0-2, with G0-3 as its substantive prerequisite |
| Source / topology verified | G0-1 and G0-6 |

G0-4 and G0-5 are remediation prerequisites that do not map to a criterion but
must not be left open — G0-4 because the mutation will otherwise recur, G0-5
because it leaves an invisible flag in `.git/index`.

Evidence rules that apply to all items: an artifact URI plus a SHA256, the exact
verification command, the observed result, a freshness timestamp, and a named
reviewer who is not the person who performed the action.

### G0-1 — Submodule initialization and verification

- **Owner:** repository owner
- **Why:** all five gitlinks are uninitialized, including
  `packages/acgs-control-plane` (private, extracted in `2694983`). The risk
  register names this a NO-GO trigger.
- **Evidence required:** every submodule initialized at the pinned commit, or a
  written, signed exclusion for any that is intentionally unavailable.
- **Verification:**
  ```bash
  git submodule update --init --recursive
  git submodule status
  git submodule foreach --quiet 'git rev-parse HEAD'
  ```
- **PASS:** no line in `git submodule status` begins with `-` or `+`. A leading
  `-` means uninitialized; a leading `+` means the checkout does not match the
  pinned commit. Either fails.
- **FAIL:** any `-`, any `+`, or any submodule that cannot be fetched.
- **Residual risk:** a private submodule may be unfetchable for credential
  reasons rather than governance reasons. That still fails G0 — "we cannot see
  the source" and "the source is fine" are not the same statement. Record the
  exclusion explicitly rather than initializing around it.

### G0-2 — Incident disposition signing

- **Owner:** repository owner **and** security owner — two signatures, not one
- **Why:** the incident record is currently unsigned. An unsigned disposition is
  a draft.
- **Evidence required:** both names, the date, the chosen disposition
  (unauthorized / quarantined / approved), and an explicit statement that the
  signer reviewed the artifact inventory.
- **Verification:** the signature block exists in
  `docs/audits/2026-08-09-npm-artifact-incident.md` and names two distinct people.
- **PASS:** two distinct signatures, disposition stated, dated.
- **FAIL:** one signature, or the same person in both roles. Self-signing here is
  the same defect as `authz_self_validation` in the benchmark
  (`acgs_benchmark/scenarios/authorization.json:243`) — the runtime rejects it;
  the humans should not exempt themselves from it.
- **Residual risk:** signing attests to a decision, not to the safety of 103
  packages. It does not substitute for G0-3.

### G0-3 — npm artifact final decision

- **Owner:** security owner
- **Why:** the quarantine is a holding state, not a resolution. The largest
  unknown — whether postinstall scripts ran — is still open.
- **Evidence required:** one of two paths, fully executed.
  - **Drop:** `make clean`, then `make install`, then confirm no npm artifact
    returns. Note this destroys the evidence tree, so it must follow G0-2.
  - **Reinstate:** re-install via `pnpm` per `packageManager`, plus a captured
    vulnerability report, license inventory, and SBOM for all 103 packages, plus
    a lockfile diff review.
- **Verification:**
  ```bash
  find . \( -name package-lock.json -o -name yarn.lock \) -not -path '*/node_modules/*'
  git status --short
  ```
- **PASS:** drop path — the find returns nothing and the tree is clean.
  Reinstate path — the find returns nothing, `pnpm-lock.yaml` carries the
  dependency, and the SBOM/vulnerability/license artifacts exist and are hashed.
- **FAIL:** any npm lockfile survives; or reinstatement without captured review
  artifacts.
- **Residual risk:** **this cannot be fully closed.** Postinstall execution at
  19:10 is unrecoverable. The honest disposition is to treat this workstation as
  having run unreviewed third-party code, and to decide separately whether that
  warrants credential rotation. Do not let a clean `find` imply a clean machine.

### G0-4 — Codex configuration governance

- **Owner:** repository owner
- **Why:** a tool rewrote tracked source and destroyed provenance. Reverting the
  file fixed the instance; nothing prevents the next one.
- **Evidence required:** a decision on each of three questions — is
  `[shell_environment_policy]` wanted (and if so, who owns it); is
  `.codex/config.toml` authored or generated; and may the Codex CLI write it in
  place.
- **Verification:**
  ```bash
  git diff --exit-code -- .codex/config.toml
  head -3 .codex/config.toml
  ```
- **PASS:** `git diff --exit-code` returns 0, the `#:schema` pragma and ECC
  baseline comment are present, and the decision is recorded in the incident file.
- **FAIL:** provenance header absent, or an unattributed block present.
- **Residual risk:** high and recurring — and worse than it first appears. Git
  history shows the file is an **orphaned generated artifact**:

  ```
  $ git log --oneline --diff-filter=A -- .codex/config.toml
  75c5224 feat: add govern-zone ECC bundle (.codex/config.toml)   # 2026-05-28

  $ git log --oneline -- .codex/config.toml | wc -l
  1

  $ git merge-base --is-ancestor 35ebf7d 75c5224 && echo "ignore rule predates the file"
  ignore rule predates the file
  ```

  Four facts compound. The file was **force-added** past `.gitignore:69`, which
  has ignored `.codex` since the initial commit. Its commit contains nothing else
  — 48 lines, one file, described as a "bundle." It declares itself generated in
  its own header (`# ECC Tools generated Codex baseline`). And **no generator
  exists anywhere in the repository** — grepping for `ECC Tools` across all
  source returns only this document and the incident record.

  So the repository tracked a file that says it is generated, by a generator it
  does not contain, in a directory it claims to ignore, untouched for three
  months. `CLAUDE.md`'s Generated File Policy says never hand-edit generated
  output and always modify the generator instead — an instruction that is
  unfollowable here, because there is nothing to modify. The ambiguity was not a
  side issue; it is *why* a tool rewriting the file went unnoticed and
  unchallenged. Resolve the file's status — authored, generated-with-source, or
  untracked — before anything else in G0-4.

### G0-5 — skip-worktree cleanup

- **Owner:** next operator working outside a sandboxed session
- **Why:** the bit lives in `.git/index` and persists across sessions. Left set,
  real upstream changes to `acgi-ai/.env.example` become invisible and `git pull`
  may refuse to update it.
- **Evidence required:** the bit cleared once the sandbox no longer masks the path.
- **Verification:**
  ```bash
  git ls-files -v | grep '^[a-z]'   # lowercase tag = skip-worktree/assume-unchanged
  ```
- **PASS:** no lowercase-tagged entries, or each remaining one has a documented
  reason and owner.
- **FAIL:** any undocumented lowercase entry.
- **Residual risk:** this is a governance control that is itself invisible — the
  defect it creates looks like "git is behaving strangely," not like a set flag.
  It is the clearest small example of the document's thesis: a local mutation
  with no receipt.

### G0-6 — Branch and repository state verification

- **Owner:** repository owner
- **Why:** `docs/comparison-agt-permit` has no remote-tracking branch, so
  divergence cannot be measured, and the unshallow advanced `origin/master`
  `2694983..a8b5f07`.
- **Evidence required:** the branch published or explicitly declared local-only,
  and divergence from master measured.
- **Verification:**
  ```bash
  git rev-parse --is-shallow-repository          # must print false
  git rev-list --left-right --count origin/master...HEAD
  git log --oneline 2694983..a8b5f07
  ```
- **PASS:** not shallow, divergence measured and reviewed, no unintended
  submodule pointer drift in `git status --short`.
- **FAIL:** shallow, or unreviewed divergence, or pointer drift.
- **Residual risk:** low. Note that G0-1 and G0-6 interact — initializing
  submodules can surface pointer drift that was invisible while they were
  uninitialized.

---

## 3. Root cause analysis

Framing this as operator error would be both unkind and analytically useless.
The operator ran a plausible command, in their own shell, on their own machine,
and even thought about supply-chain risk afterward. The system offered them no
control surface, no prompt, and no record. **A control that depends on the
operator remembering it is not a control.**

Five systemic causes.

### 3.1 The governance plane is bound to the agent, not to the repository

This is the root cause under all the others.

The repository has **zero git-level guards**: no `core.hooksPath`, no
`.git/hooks` beyond samples, no `.githooks/` directory, no `.gitattributes`, no
`CODEOWNERS`, and no pre-commit configuration. The only mutation-intercepting
layer is `.claude/hooks/`, which is specific to one agent harness.

The consequence follows mechanically: **governance applies to whoever happens to
be using the governed agent, and evaporates for everyone and everything else.**
An interactive `npm install`, a `codex` invocation, an IDE's auto-format on save,
a `curl | sh` — all bypass the entire control plane, not by defeating it, but by
never entering it.

A repository-bound control (a git hook, a CI gate, a pre-commit guard) would
have applied to the operator's `npm install` and to the Codex CLI equally,
because it binds to the *artifact being mutated* rather than to the *identity of
the mutator*.

### 3.2 Package managers are unmediated executors with root-equivalent authority

`npm install` is not a dependency-resolution command. It is: fetch arbitrary
code from a network registry, write it to disk, execute arbitrary lifecycle
scripts under the operator's full privileges, and mutate the project manifest.
Four side-effect classes, one command, zero approval points.

ACGS's own kernel exists precisely to mediate this shape — a request for a
side effect that must be authorized before it happens. But `npm` is not routed
through any dispatcher. It **is** the dispatcher, and it is unmediated.

The `.gitignore:9-13` comment shows the team had already reasoned about this
exact failure — *"package-lock.json (npm) and yarn.lock slip in when someone
runs `npm install` inside a workspace member"* — and shipped the only control
available to them: an ignore rule. That control worked exactly as designed and
contained the blast radius. It could not contain the `package.json` edit, and it
could not contain execution, because **an ignore rule is a visibility control,
not an authorization control.** The team's analysis was right; the available
mechanism was too weak.

### 3.3 Developer tools write tracked source with no diff surface

The Codex CLI rewrote a tracked file and dropped two provenance lines. Nothing
notified anyone. It surfaced 14 hours later as an unexplained ` M` in
`git status`, at which point the natural human response — "some tool did that" —
is indistinguishable from the response to a genuine compromise.

This is the more dangerous of the two events, despite the smaller blast radius.
Unattributed mutations in tracked source **destroy the signal-to-noise ratio of
`git status` itself**. Once operators learn that dirty files are usually just
tooling noise, the one time it is not becomes invisible.

Provenance loss compounds it. The `#:schema` pragma and the
`# ECC Tools generated Codex baseline` comment were the file's only markers of
where it came from. A serializer round-trip deleted them, because comments are
not part of the TOML data model. **Any format whose serializer discards comments
will silently destroy comment-carried provenance on every round-trip.** Storing
provenance in comments is therefore structurally unsafe for machine-written files.

There is a deeper failure underneath. Git history (G0-4) shows this file was
force-added past its own ignore rule, declares itself generated, and has **no
generator anywhere in the repository**. It sat in that state for three months.
An orphaned generated artifact is precisely the file a tool can rewrite without
consequence: no one owns it, no gate covers it, no regeneration command can
contradict it, and its ignore rule signals "disposable" while its tracked status
signals "source." The tool did not defeat a control. It wrote to a file that had
fallen out of every control's scope — including the repository's own written
Generated File Policy.

### 3.4 Rollback preceded evidence capture

During this remediation, `.codex/config.toml` was reverted with
`git checkout --` before the mutated version was hashed. That version is now
irrecoverable; only the diff survives.

The generalizable defect: **the cleanest-looking remediation action is
irreversible and destroys the artifact.** `git checkout --` feels safe because
it restores a known-good state, which is exactly why it gets reached for first,
and exactly why it destroys evidence first. Nothing in the tooling made capture
the precondition of revert.

Note the asymmetry — `package.json` *was* hashed before its revert, and
`node_modules/` was inventoried before anything was touched. The failure was not
a missing principle. It was that the principle depended on remembering it at the
moment of action, on a file that seemed minor. See 3.1: same structural defect.

### 3.5 There is no mutation authority model below the agent layer

ACGS has a rich authority vocabulary for agents: approval tiers, protected
governors, self-approval prohibitions, authority invalidation. None of it
applies to a human in a terminal or to a CLI tool the human launched.

So the system has two regimes: **agent actions**, subject to policy, receipts,
and audit; and **everything else**, subject to nothing. The boundary between
them is not a security boundary — it is an accident of which interface the
mutation arrived through. An agent asking to run `npm install` would be
governed. A human running the identical command would not. The blast radius is
identical.

---

## 4. The Developer Tool Mutation Governance Framework

### 4.0 The one architectural commitment

> **Mutations are classified by blast radius and reversibility, never by who or
> what performed them.**

A dependency install is class M3 whether it came from an agent, a human at a
prompt, an IDE extension, or a CI job. The controls attach to the *mutation
class*, and every actor entering the repository is subject to the same ones.

This directly answers §3.5. The current two-regime split — agents governed,
everyone else ungoverned — is replaced by a single regime in which the agent is
simply one actor among several, and not the most dangerous one.

The corollary is the enforcement rule:

> **A mutation class is governed only when every path that can produce it is
> mediated. One unmediated path makes the class ungoverned.**

This is why adding more agent-side hooks cannot fix the incident. The gap is not
depth of coverage on the agent path; it is the existence of unmediated paths
beside it.

### 4.A Mutation classes

| Class | Name | Definition | Reversible? | Executes code? | Incident example |
|---|---|---|---|---|---|
| **M0** | Read-only | Observation only: read, search, analyze, report. No write. | n/a | no | Reading `package-lock.json` during triage |
| **M1** | Workspace-local | Writes only untracked/ignored paths. No execution, no tracked state. | trivially | no | Scratch files, build output, `.omc/` state |
| **M2** | Tracked source | Modifies tracked, version-controlled source. | via git | no | Ordinary code edits |
| **M3** | Dependency graph | Alters the resolved dependency set — manifest, lockfile, or installed tree. **Executes third-party lifecycle code.** | partially — installs revert, execution does not | **yes** | `npm install @openai/codex-security` |
| **M4** | Control surface | Modifies a file that governs behavior: CI workflows, hooks, policy, agent settings, ignore rules, tool config. | via git | indirectly — changes what runs later | `.codex/config.toml` rewrite |
| **M5** | Trust root | Keys, approvers, credentials, enforcement tiers, witness destinations, rollback authority. | only by authority rotation | no | none in this incident |
| **M6** | Production-impacting | Side effects outside the repository: deploys, live data, external systems. | only by compensation | yes, externally | none in this incident |

Two ordering claims deserve defense.

**M3 ranks above M2 because it executes code.** An intuition that "editing source
is riskier than adding a dependency" is exactly backwards. A source edit is
inert until reviewed, merged, and run. A dependency install runs arbitrary
third-party code *at install time*, under the operator's full privileges, before
any review. In this incident the source edit was trivially reverted; the
execution is permanently unknown (§1.3).

**M4 ranks above M2 because it is second-order.** Editing a control surface does
not change behavior directly — it changes what will be permitted, run, or
audited later. A weakened CI gate does no damage on the day it is weakened.
`.codex/config.toml`'s `[shell_environment_policy]` block was M4: it set an
environment variable for every subsequent tool invocation.

### 4.B Required controls per class

Six control dimensions. Each row states the minimum; higher classes inherit
everything below them.

| Class | Authorization | Evidence capture | Approval | Rollback | Audit record | Reproducibility |
|---|---|---|---|---|---|---|
| **M0** | none | none | none | n/a | sampled only | n/a |
| **M1** | actor identity recorded | path list | none | delete | batched, low-detail | none |
| **M2** | authenticated actor | pre-image hash of each touched file | none for routine; review at merge | `git revert` | one record per mutation batch | diff reproducible from VCS |
| **M3** | authenticated actor **+ policy decision before fetch** | pre-image manifest+lock hashes, **post-image SBOM**, resolved-set diff, lifecycle-script inventory | **human approval on any new direct dependency or any new transitive package executing install scripts** | manifest+lock revert; **execution is not reversible — escalate to compensation** | signed receipt, retained with the SBOM delta | pinned integrity hashes; install replayable offline |
| **M4** | authenticated actor + policy decision | full pre-image **file copy**, not just a hash | **second-party approval; author may not self-approve** | `git revert` + re-verify dependent gates | signed receipt naming the control surface | provenance block preserved and machine-verifiable |
| **M5** | authenticated actor + explicit authority grant + **authority freshness check** | full pre-image, prior authority state, grant chain | **second-party approval by a distinct authority holder** | authority rotation, not file revert | signed receipt + external anchor | full re-derivation of the decision |
| **M6** | everything in M5 + dispatcher mediation + stable attempt ID | pre-state, attempt record, **effect attestation** | per existing pilot gates | compensation or `IRRECONCILABLE` | signed receipt + customer-anchored checkpoint | decision re-derivable; effect never replayed |

Three rules are non-negotiable and apply across the table.

1. **Evidence capture precedes mutation, always.** Not "should" — the capture is
   the precondition, and a failed capture blocks the mutation. This is the direct
   fix for §3.4. Had it been in force, `.codex/config.toml`'s mutated form would
   exist today.
2. **M4 and above forbid self-approval.** The runtime already rejects this
   (`authz_self_validation`, `acgs_benchmark/scenarios/authorization.json:243`).
   Humans get the same rule.
3. **Reversibility is a property of the mutation, not of the file.** M3's
   *artifacts* are reversible; M3's *execution* is not. Treating "I deleted
   `node_modules`" as full rollback is the same error as treating a replayed
   decision as an undone side effect.

### 4.C Actor policy model

Every actor is classed by the highest mutation class it can produce **without
passing through a mediated path**. That number, not its reputation, sets its
policy.

| Actor | Unmediated ceiling today | Required posture |
|---|---|---|
| **Claude Code** | M4 — hooks fire on `Edit`/`Write`/`Bash` but emit receipts for `Edit`/`Write` only, always `decision: allow` | Keep hooks, but call them what they measurably are: **telemetry, not enforcement**. Exactly one running hook blocks anything (`seal-block.sh`, and only for files carrying a constitutional-hash marker). Real gating moves to the repository-bound layer so it survives the agent being bypassed. Evidence in §5.1. |
| **Codex CLI** | M4 — demonstrated: rewrote tracked config unannounced | Must declare tool identity and emit a mutation record for any tracked-file write. Until it does, its config must be treated as generated-with-source (§6.6) so a round-trip cannot destroy provenance. |
| **Cursor / IDEs** | M2, occasionally M4 (auto-format, settings sync) | Repository-bound guards apply automatically — this is the payoff of binding to artifacts rather than actors. No per-IDE integration needed. |
| **Package managers** (`npm`, `pnpm`, `pip`, `uv`, `cargo`) | **M3 with arbitrary execution** — the highest unmediated authority any actor holds here | Wrap. A package manager invoked directly is an unmediated M3 dispatcher. Route through a gate that classifies, captures, and decides *before* fetch, and denies non-canonical managers outright. |
| **CI automation** | M4, and M6 where it deploys | Already partly governed — pinned workflows, `--frozen-lockfile`. Extend to SBOM-delta enforcement so a lockfile change cannot land unreviewed. |
| **Human at a terminal** | **M5** — no ceiling at all | The honest entry. Humans cannot and should not be blocked from their own machines. The goal is not to gate the human but to ensure the *artifact* records what happened, via repository-bound hooks the human's tools trigger automatically. |

The package-manager row is the load-bearing one. `npm`/`pnpm`/`pip` hold more
unmediated authority than any AI agent in this repository, and they have held it
for a decade without anyone classing them as high-agency actors. The incident is
what that looks like when it finally matters.

The human row is the honest one. This framework does not attempt to make a
developer's terminal fail closed. It attempts to make **every mutation leave a
record regardless of origin**, so that reconstruction is a query rather than a
forensic exercise — 14 hours of mtime archaeology reduced to reading a log.

---

## 5. ACGS integration mapping

The uncomfortable finding first.

> **The receipt layer was live and running throughout the incident.** The
> hash-chained audit store at `.gove-zone/audit.jsonl` was appending records on
> 2026-08-08 and is still growing. It recorded nothing about either event.

This is not a story about governance being absent. It is a story about
governance being **present, running, and scoped to the wrong thing** — and, as
§5.4a shows, wired to the weakest of the two adapters ACGS has already built and
tested.

### 5.1 What the audit chain actually contains

The chain is **live and appending** — it grew from 366 to 381 records across the
readings taken while this document was written, because the document's own edits
are being receipted into it. Treat the absolute count as incidental; the
invariants below are the load-bearing claims and they held at every reading.

At 381 records:

| Field | Observed distribution |
|---|---|
| `tool` | `runtime.Edit` 251, `runtime.Write` 130, **`runtime.Bash` 0** |
| `actor` | `govern-zone-hook` — 100% |
| `decision` | `allow` — 100% |
| `policy_version` | `hook-observer/v0` — 100% |

Every column is a finding. And note what the growth itself demonstrates: the
session writing this analysis is being recorded as an anonymous actor whose every
action is pre-approved.

**Zero Bash records.** The hook *is* wired to `Bash`
(`.claude/settings.json:112`) and *does* execute on every Bash tool call. It
emits nothing because `_classify`
(`.claude/hooks/acgs-emit-receipt.py:58-69`) returns `None` for anything that
is not `Edit`/`Write`/`MultiEdit`/`NotebookEdit` or a literal substring match on
`autopilot` / `ralph` / `team`. `npm install` falls through to line 69 and the
hook exits 0 unaudited — a documented design choice, stated in its own docstring
at lines 5-9.

The classifier is a substring test over the lowercased command, so it fails in
both directions: `git commit -m "fix team dashboard"` emits a spurious `team`
receipt, while `npm install` emits none. It is a keyword matcher, not a mutation
classifier — precisely the gap §4.A exists to fill.

**100% `allow`.** `_ObserverPolicy.evaluate`
(`packages/gove-zone/src/gove_zone/integration.py:583-600`) returns
`Decision.ALLOW` unconditionally. The layer is an observer by construction. It
records; it has never denied anything.

**100% fallback actor.** `acgs-emit-receipt.py:111-112` reads
`PAPERCLIP_AGENT_ID` / `PAPERCLIP_RUN_ID`, which are set nowhere in the
repository. Every record carries the literal fallback `govern-zone-hook`. Worse,
`run_id` is accepted in both `integration.py` signatures (`:652`, `:723`) and
used exactly once — interpolated into an error string at `:714`. The `Receipt`
construction at `:700-707` never passes it. **Run attribution is accepted and
silently discarded.**

**100% unsigned.** `settings.json:107,116` sets `GOVE_ZONE_PROFILE=dev`, the
escape hatch at `integration.py:676-686` that suppresses the loud unsigned-receipt
failure. Receipts carry `signature: "unsigned_local"`.

### 5.2 Concept-by-concept mapping

**Vocabulary warning — read before using this table.** Of the seven concepts
this mapping was asked to cover, **only "decision receipt" is defined ACGS
vocabulary.** The other six are industry terms that do not appear in
`docs/GLOSSARY.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`,
`docs/DECISION_RECEIPT_SPEC.md`, or `CONCEPTS.md`. Each row therefore names the
official ACGS substitute, and **the substitute is what should be used in any
ACGS-facing document.** Coining them would be a claim-discipline violation under
`docs/CLAIMS.md:46-48`.

The most dangerous of the six is "authority boundary": ACGS already defines
`authority` (`GLOSSARY.md:24`, "the grant or basis under which a validator may
authorize the action") and `execution_boundary`
(`DECISION_RECEIPT_SPEC.md:30`, "boundary where execution is allowed") as
*separate* things. Fusing them into one term collides with two real ones.

| Requested concept | ACGS status | Official substitute | What the incident showed |
|---|---|---|---|
| **Decision receipt** | ✅ defined vocabulary; `tested` (`CLAIMS.md:8`) | — | Not emitted for either event. The hook's receipts record *path touched at time T*: no raw-argument field, no `run_id`. A dependency install has no `file_path`, so `_path_from_tool_input` (`integration.py:507-511`) would yield an empty path even if it fired |
| **Authority boundary** | ❌ **not ACGS vocabulary** | `authority` + `execution_boundary`, kept separate | The kernel's MACI role separation is real and elegant — `Validator` (`receipt.py:100`) is a distinct type from the proposer, and `validator_id`/`validator_role`/`authority` are bound into `receipt_hash`. **It was never exercised.** The observer policy allows unconditionally, so no authority decision is ever made. The kernel can express "validator ≠ proposer"; the repository's own hook layer never asks it to |
| **Evidence graph** | ❌ not ACGS vocabulary | "tamper-evident evidence" (`GLOSSARY.md:38`); "hash-chained JSONL audit chain" (`ARCHITECTURE.md:17`) | Real, working, live — but covering `Edit`/`Write` only. The two mutations that mattered are not records in it |
| **Artifact lineage** | ❌ not ACGS vocabulary (zero hits repo-wide) | `previous_audit_hash` / `audit_event_hash` (`DECISION_RECEIPT_SPEC.md:45-46`); "provenance" (`CONCEPTS.md:11`) | The incident's central gap. 103 packages arrived with no provenance record; `.codex/config.toml` is a generated artifact with no generator (§3.3). Addressed by C5 |
| **Credential lifecycle** | ❌ not ACGS vocabulary | "key lifecycle" (`SECURITY_MODEL.md:17-18`); "key custody, revocation" (`ARCHITECTURE.md:71`) | Untouched directly — but §1.3's unresolved question of whether postinstall scripts executed is exactly a credential-exposure question this system cannot answer |
| **Trust anchor** | ❌ not ACGS vocabulary in the canonical docs | "trusted verifier" / "trusted key" / "scoped trust purpose" (`DECISION_RECEIPT_SPEC.md:184-201`) | Every receipt written in the incident window was `unsigned_local`. An unsigned local chain is tamper-*evident* to its holder, not attestable to a third party |
| **Autonomous execution control** | ❌ not ACGS vocabulary | "receipt-gated execution" (`GLOSSARY.md:36`); "execution membrane" (`ARCHITECTURE.md:3`) | Approval tiers exist on paper — `trust_tiers: [release-manager]` (`.claude/policy/build.yaml:99-100`) — but are **dead twice**: the file concedes at lines 90-93 that "the PreToolUse payload carries no trust tier," and its only consumer, `loop-pretool-guard.sh`, exits at line 16 because `evidence/loop-active` does not exist |

### 5.3 Which existing controls would have prevented this

Honest answer: **none.** Traced individually so the claim is checkable.

| Control | Wired? | Would it have fired? | Why not |
|---|---|---|---|
| `acgs-emit-receipt.py` | yes, incl. `Bash` | **No** | `_classify` returns `None` for `npm` (line 69) |
| `seal-block.sh` | yes — the one running blocking gate | **No** | Only guards files carrying `^# Constitutional Hash:` |
| `submodule-warn.sh` | yes | No | Advisory; wrong paths |
| `loop-pretool-guard.sh` — blocks `rm -rf`, force-push, pipe-to-shell | yes | **No** | Dormant: exits line 16, no `evidence/loop-active` |
| `automation/policies/constitution.yaml` — `no_destructive_without_approval` | **no** | No | A file, not a gate. `automation/registry.yaml` is `automations: []`; proposal directories hold only `.gitkeep`; no workflow or Makefile target invokes `automation/scripts/*` |
| `build.yaml` escalation tiers | no | No | Payload carries no tier; consumer dormant |
| `socket-security.yml` | conditionally | **No** | No-ops entirely when `SOCKET_SECURITY_API_TOKEN` is unset; `on: pull_request` only, so blind to a local install |
| `pnpm install --frozen-lockfile` × 7 workflows | yes | No | Consistency check on `acgi-ai/pnpm-lock.yaml`. **No workflow reads a root `package-lock.json`** — the exact artifact created |
| `settings.json` permissions | yes | **No** | `Bash(pnpm:*)` and `Bash(uv:*)` are allowed; `npm` appears in *neither* the allow nor the deny list (lines 7-79), so it falls to an interactive prompt that leaves no durable record |

And the layer that matters most: **the incident happened in an interactive
terminal.** Claude Code hooks fire only on Claude Code tool calls. No matcher,
however well written, can see a command typed into a shell. That is §3.1 stated
as a mechanism rather than a principle.

There is a second-order finding worth surfacing on its own: `automation/`'s tests
**never run in CI**. `tests-root.yml:32,44` lists `automation/**` as a path
filter that *triggers* the job, but the job's pytest scope (lines 88-99) is
`tests/` only. Editing `automation/` triggers a CI job that does not test
`automation/`. Its `README.md:3` documents a
`Spec → Plan → Risk Review → Generate → Test → Approve → Install → Monitor`
pipeline that nothing has ever entered.

### 5.4 New controls, mapped to kernel primitives

The proposals in §6 are deliberately not new cryptography. Each reuses a kernel
primitive that already exists and is tested.

| Proposed control | Kernel primitive reused | What must be built |
|---|---|---|
| C1 checkpoint | audit store append | pre-image capture; full copies for M4+ |
| C2 surface guard | `seal-block.sh` pattern — the one proven blocking gate | generalize from constitutional-hash marker to a declared surface inventory |
| C3 dependency gate | `Decision` ALLOW/DENY/ESCALATE + fail-closed gate | replace `_ObserverPolicy` with a real policy for a mutation class that is not `Edit`/`Write` |
| C5 provenance | none — new | sidecar + CI verification |
| C8 mutation receipt | `DecisionReceipt` | a `runtime.Bash`-class emitter with real arguments |

**Field alignment for C8 — but first, there are two receipt types, and the
difference is the whole story.**

| | `Receipt` (`receipt.py:69-96`) | `DecisionReceipt` (`receipt.py:119-185`) |
|---|---|---|
| Fields | 5 | 32 |
| Signature | **no signature field exists** | `signature`, `signature_algorithm`, `signing_key_id` |
| Expiry | none | `expires_at` |
| Accepted by `execute_with_receipt` | **no** | yes (`executor.py:35`) |
| Emitted by the repo's hook | **yes** (`integration.py:700-708`) | no |

§5.1 said the hook's receipts are unsigned. That understates it. The hook emits
the 5-field `Receipt`, which **has no signature field at all** — it is an audit
anchor, not an authorization token. No configuration change can sign it.

`DecisionReceipt` already carries everything a mutation receipt needs — `actor`,
`proposed_action`, `argument_hash`, `policy_hash`, `decision`, `matched_rules`,
`previous_audit_hash`, `audit_event_hash`, `expires_at`, `validator_id`,
`authority`, `receipt_hash`, `signature*` — all bound into `receipt_hash` via
`_hash_payload()` (`receipt.py:332-374`), with signature algorithm and key id
inside the hash so downgrade breaks verification. C8 should **populate this
schema**, not define a parallel one.

Two corrections to assumptions elsewhere in this document:

- **`Decision` has four values, not three** (`decision.py:18-24`): `ALLOW`,
  `DENY`, `TRANSFORM`, `ESCALATE`. C3's gate should account for `TRANSFORM`
  (e.g. "install, but pinned to this exact resolved set").
- **There is no nonce field.** Replay defense is the opt-in
  `ReceiptConsumptionLedger`, keyed on `audit_event_hash`
  (`consumption.py:234,245`), always-on only inside `UniversalGateway`
  (`gateway.py:827`). `verify()` alone is stateless.

### 5.4a Historical pre-P11 wiring gap

This is the most actionable finding in the audit.

`UniversalGateway.handle_claude_hook` (`gateway.py:1022-1109`) evaluates every
proposed call individually, is **deny-wins across a batch** (`:1068-1070`),
routes `TRANSFORM` to `"ask"` because a hook cannot rewrite runtime arguments
(`:1071-1082`), and **mints a real `DecisionReceipt` per call** with anchors
carrying `receipt_hash`, `audit_hash`, `policy_hash`, `signature_algorithm`
(`:1094-1108`). It is implemented and tested
(`test_universal_gateway.py::test_claude_hook_batch_deny_wins:431`,
`test_claude_hook_batch_all_allowed_mints_receipt_per_call:450`).

**At the time of this analysis, the repository's own hook did not use it.**
`acgs-emit-receipt.py` called
`integration.emit_receipt_for_hook`, the passive adapter whose default
`_ObserverPolicy` allows everything and whose output is the unsigned 5-field
`Receipt`. P11 subsequently wired the hook to
`UniversalGateway.handle_claude_hook`; see ADR-0010 and ACGS vNext for the
current, still-partial boundary.

So the gap between what ACGS has built and what ACGS runs on itself is not a
missing capability — it is a wiring choice. Migrating the hook from
`integration.emit_receipt_for_hook` to `UniversalGateway.handle_claude_hook`
would, with no new cryptography:

1. replace the unconditional-allow observer with a real policy evaluation,
2. upgrade `Receipt` → signable `DecisionReceipt`,
3. give the hook a genuine `deny` / `ask` verdict for the host to honor.

It would still not cover `npm install` — that is an interactive-terminal event no
hook can see (§5.3) — so C3 remains necessary. But it converts the agent path
from passive telemetry into policy-decision and audit mediation, and it should
be sequenced ahead of every proposal in §6.

**One boundary to state precisely, since it is easy to overclaim.** Even on the
gateway path, `execute_with_receipt` is *not* called — the host runtime performs
the side effect, and the gateway's own docstring says so (`gateway.py:1029-1030`).
A receipt is minted and verifiable; the executor gate is not in that loop. Call
it *"a minted, verifiable Decision Receipt for the hook decision"* — **not**
"receipt-gated execution." `UniversalGateway.invoke` (`:458-616`) is the only
surface that closes the full Policy → Receipt → Executor loop, with sealed-tool
bypass detection (`gateway.py:157-198`) and an always-on consumption ledger
for that strong invocation path.

### 5.4b Remaining gaps in C8

1. `actor` must carry a real identity, not the `govern-zone-hook` fallback.
2. `run_id` must reach the persisted record — dropped today at
   `integration.py:700-707`.
3. `validator_id` must be populated for M4+, which requires a real approval step.
4. `signature` must stop being `unsigned_local`, which requires resolving the key
   custody residual `signing.py:20-32` already names as out of scope.

Items 1-3 are wiring. Item 4 is genuinely unsolved and should be stated as such
rather than folded into an implementation estimate.

**Evidence-integrity caveat for any claim built on the audit chain.** The chain
detects mutation but **not trailing truncation** — a deleted tail re-walks
cleanly, because a prefix of a valid chain is itself valid
(`audit.py:325-341`). Truncation detection requires an out-of-band
`expected_count` or `expected_last_hash`. Any statement that local mutations are
"provably complete" is false without that external anchor.

### 5.5 Benchmark scenario

The benchmark is the natural home for this, and the extension point is clean:
`GovernanceTarget.run_probe` dispatches `getattr(self, f"_probe_{scenario.probe}")`
(`acgs_benchmark/targets.py:394`), so a new probe is a new method.

**Constraint, stated honestly:** `CATEGORIES` (`acgs_benchmark/schema.py:41-48`)
is a closed six-value vocabulary and `OUTCOMES` (`:64-83`) is a closed
frozenset. A `dependency_governance` category requires editing `schema.py`, not
just adding a JSON file. Two options:

- **Now, no code change** — file the scenarios under `fail_closed`, since the
  property tested is "an unauthorized mutation must not proceed."
- **Properly** — add a seventh category and its probes.

Proposed scenarios, conforming to the real schema:

```json
{
  "suite": "acgs-benchmark/v1",
  "category": "fail_closed",
  "scenarios": [
    {
      "id": "DEPGOV-001",
      "category": "fail_closed",
      "probe": "depgov_noncanonical_manager",
      "title": "Install attempted with a package manager the repo does not declare",
      "description": "Repository declares packageManager pnpm@9.15.4. An npm install must be denied before any fetch. Models incident 2026-08-09.",
      "severity": "critical",
      "attack": true,
      "expected_outcome": "deny",
      "params": { "declared_manager": "pnpm@9.15.4", "invoked_manager": "npm" },
      "tags": ["dependency-governance", "supply-chain", "incident-2026-08-09"]
    },
    {
      "id": "DEPGOV-002",
      "category": "fail_closed",
      "probe": "depgov_install_scripts",
      "title": "New transitive package with lifecycle scripts must escalate",
      "description": "A package executing install-time scripts must not be installed without human approval; execution is not reversible.",
      "severity": "critical",
      "attack": true,
      "expected_outcome": "escalate",
      "params": { "package": "example-pkg@1.0.0", "install_scripts": true, "direct": false },
      "tags": ["dependency-governance", "arbitrary-execution"]
    },
    {
      "id": "DEPGOV-003",
      "category": "fail_closed",
      "probe": "depgov_canonical_noop",
      "title": "Positive control: canonical manager, no resolved-set change, must proceed",
      "description": "Prevents scoring a deny-everything gate as safe.",
      "severity": "medium",
      "attack": false,
      "expected_outcome": "allow",
      "params": { "declared_manager": "pnpm@9.15.4", "invoked_manager": "pnpm", "resolved_delta": 0 },
      "tags": ["dependency-governance", "positive-control"]
    }
  ]
}
```

`DEPGOV-003` is not filler. The existing suite pairs every attack with a
positive control for exactly this reason (`authorization.json:5-25`) — a gate
that denies everything scores perfectly against attacks alone and is useless.

A fourth scenario worth adding once C2 exists: a tool rewriting a tracked M4
control surface with no owner and no approval must be rejected — the Codex
config event, made reproducible.

### 5.6 Relationship to existing ACGS work

This proposal must not be read as new territory in areas the repository has
already staked out. Four adjacent surfaces, with their real status labels.

**ADV6 — Supply-chain attacker** (`SECURITY_MODEL.md:70`), tagged
`[on-master, partial]`. This is the existing supply-chain threat row, and the
closest home for dependency-graph governance. Its caveat must be quoted rather
than summarized (`SECURITY_MODEL.md:86-90`):

> "**Constitutional-hash CI caveat (ADV6).** `.github/workflows/constitutional-hash.yml`
> runs on every PR/push, but its inventory of sealed `# Constitutional Hash:`
> markers is currently empty in the parent-tracked tree — so it presently guards
> an empty set. ADV6's supply-chain defense is real plumbing over a currently
> no-op gate; populating the inventory is part of the remaining work, not a
> finished control."

That caveat and this incident describe the same shape from two directions: a
control that exists, runs, and covers nothing. **This document should extend
ADV6, not open a parallel threat namespace.** Note that `SECURITY_MODEL.md:57-61`
forbids reusing `COMPARISON.md`'s `A1–A8` namespace for threats.

**Skill trust** (`ROADMAP.md:61`, ⬜ PLANNED) and
`docs/design/agent-skill-trust-pipeline-adoption.md` (proposal, 2026-08-01).
That document governs `.claude/skills/**` and `.agents/skills/**`, and its own
assessment — *"the least governed surface we own"* — is the same argument this
one makes about package managers. The relationship is **adjacent, not
overlapping**: skills are agent-invoked capability; package managers are
actor-agnostic executors. Both conclude that the ungoverned surface sits outside
the kernel's current scope.

**`docs/governance/self-evolving-agent/`** (design specification, 2026-08-08),
specifically `MUTATION_POLICY.md`, which governs *"a change to the governing
artifacts themselves — a policy bundle, a risk-tier map, a principal registry, a
tool catalogue, an enforcement mode."* Its finding is stark: *"No module, class,
or function anywhere in the kernel package governs a change to a policy."*

This is the closest existing work, and the two must be reconciled rather than
allowed to drift. **Its `T1–T5` trust tiers and this document's `M0–M6` mutation
classes are different axes and must not be merged.** `T*` grades *how much
authority a mutation of a governing artifact requires*; `M*` grades *the blast
radius and reversibility of any repository mutation, by any actor*. Where they
meet — classes M4 and M5 — `MUTATION_POLICY.md` is the more specific document
and should govern. If either is implemented, the mapping between the two axes
must be written down explicitly, or the repository will end up with two
incompatible risk vocabularies.

**`docs/hooks-or-runtime/overview.md`** already draws the boundary this
incident tested, contrasting a "developer productivity guardrail" with a
"governance and security evidence boundary." The incident is evidence that the
hook surface currently sits on the guardrail side of that line — 100% `allow`,
100% fallback actor, unsigned.

**Headroom.** With those four accounted for, nothing in the repository covers
package-manager or lockfile mutation governance, SBOM emission, third-party
dependency admission, or supply-chain receipts. **`docs/CLAIMS.md` contains no
row for any of it** across all 44 claims. That is genuine non-duplication, and
it is also why no control fired.

### 5.7 Claim discipline for anything derived from this document

This document is a **proposal**. Nothing in it is implemented, and it must not
be cited as evidence of capability. Three rules bind any downstream use:

1. **`docs/CLAIMS.md:46-48`** — *"If a claim is not in this table, add it here
   before using it in public docs. If evidence is partial, use partial wording.
   If evidence is roadmap-only, say planned."* No claim from this document may
   reach public material without a CLAIMS.md row and a Safe public wording cell.
2. **`ROADMAP.md:77-79`** — use "planned", "roadmap", or "not implemented yet"
   unless a source file, test, demo output, *and* claim-ledger entry all exist.
3. **`SECURITY_MODEL.md:52-55`** — any new threat row must carry `[on-master]`,
   `[on-master, partial]`, or `[proposed]`. Every control in §6 is `[proposed]`.

The incident itself must not be cited as evidence that R6 is implemented. It is
evidence of the opposite, and the incident record says so.

---

## 6. Proposed controls

Eight controls. Each states where it binds, what it does, its failure mode, and
what it cannot do. None is implemented.

The binding target matters more than the logic. Per §4.0, a control bound to an
agent governs one actor; a control bound to the repository or to the artifact
governs all of them.

### C1 — Pre-mutation evidence checkpoint

**Binds:** repository, via `core.hooksPath` → `.githooks/`, plus a wrapper for
non-git mutations (C3).

**Does:** before any M2+ mutation, write a pre-image record to an append-only
local store. For M2/M3, content hashes. For M4+, a full file copy — hashes are
insufficient when the artifact itself may be needed (§3.4).

```json
{
  "schema": "acgs.mutation.checkpoint/v1",
  "checkpoint_id": "ckpt-01JQ...",
  "captured_at": "2026-08-08T19:10:14.887-04:00",
  "mutation_class": "M3",
  "actor": { "kind": "human", "id": "...", "auth": "unauthenticated-local" },
  "tool": { "name": "npm", "version": "10.9.2", "attested": false },
  "targets": [
    { "path": "package.json", "sha256": "47cb8c87...", "tracked": true },
    { "path": "package-lock.json", "present": false, "tracked": false }
  ],
  "preimage_copies": [],
  "trigger": "pre-install"
}
```

**Fails:** closed for M4+ — no capture, no mutation. Open-with-warning for
M2/M3, because a developer's terminal that cannot write a checkpoint must not
become a developer who cannot work.

**Cannot:** capture what a mutation *will* do, only the state before it. It
would not have predicted the 103 packages; it would have made the before-state
provable and made §1.3's unknowns knowable.

### C2 — Tracked-file mutation guard

**Binds:** repository, `.githooks/pre-commit` + a filesystem watcher for
out-of-band writes.

**Does:** classifies every tracked-file modification and refuses M4+ changes
lacking a checkpoint and an approval record. Maintains a declared inventory:

```yaml
# .acgs/control-surfaces.yaml
surfaces:
  - path: .codex/config.toml
    class: M4
    status: generated          # authored | generated | generated-with-source
    generator: null            # ← the incident: declares generated, has no generator
    owner: UNASSIGNED          # ← blocks G0-4
    provenance: .codex/config.toml.provenance.json
  - path: .github/workflows/**
    class: M4
    status: authored
    owner: ci-owner
  - path: package.json
    class: M3
    status: authored
    owner: repo-owner
```

**Fails:** closed on any M4+ path lacking an owner. That single rule would have
blocked the Codex rewrite — not because it detected the tool, but because the
file had no owner and no declared status.

**Cannot:** prevent a determined local write. It makes the write *visible and
attributable*, which is the achievable goal (§4.C, human row).

### C3 — Dependency-graph approval gate

**Binds:** the package-manager invocation itself — shim on `PATH` ahead of
`npm`, `pnpm`, `pip`, `uv`, `cargo`.

**Does:** intercepts before fetch. Resolves the intended dependency set without
installing, diffs against current, classifies, then decides:

| Condition | Decision |
|---|---|
| Non-canonical manager for this repo (`npm` where `packageManager` says `pnpm`) | **DENY** |
| No change to resolved set | ALLOW |
| Transitive-only change, no new install scripts | ALLOW + receipt |
| New direct dependency | **ESCALATE** — human approval |
| Any new package with lifecycle scripts | **ESCALATE**, and name the scripts |
| Approval unavailable | **DENY** (fail closed) |

**Fails:** closed.

This is the control that would have stopped the incident outright, at the first
row: `npm` is not this repository's declared manager. That check costs one read
of `package.json` and is the highest-value control in this document.

**Cannot:** govern a manager invoked by absolute path, or one running inside a
container that bypasses the shim. Both are detectable by C2 after the fact, not
preventable. State this limitation plainly rather than claiming enforcement.

### C4 — SBOM delta enforcement

**Binds:** CI, as a required check.

**Does:** generates an SBOM per commit and compares against the previous. Any
added component must map to an approval receipt (C3) or the check fails.

```json
{
  "schema": "acgs.sbom.delta/v1",
  "base_commit": "2694983", "head_commit": "a8b5f07",
  "added": [ { "purl": "pkg:npm/%40openai/codex-security@0.1.8",
               "direct": true, "install_scripts": true,
               "approval_receipt": null } ],
  "removed": [],
  "verdict": "fail",
  "reason": "1 added component without an approval receipt"
}
```

**Fails:** closed — blocks merge.

**Cannot:** see local-only changes. In this incident the lockfile was gitignored,
so C4 would never have fired. It is the backstop for what reaches shared
history, not for what happens on a workstation. C3 covers that; the two are not
substitutes.

### C5 — Provenance preservation

**Binds:** the artifact, via a sidecar file.

**Does:** moves provenance out of comments — which serializers destroy (§3.3) —
into `<file>.provenance.json`, and verifies it in CI.

```json
{
  "schema": "acgs.provenance/v1",
  "subject": ".codex/config.toml",
  "subject_sha256": "a95a120...",
  "status": "generated-with-source",
  "generator": { "name": "ECC Tools", "version": null, "command": null },
  "owner": "UNASSIGNED",
  "may_be_rewritten_by_tools": false,
  "last_verified": "2026-08-09T00:00:00-04:00"
}
```

**Fails:** closed in CI when `subject_sha256` does not match and
`may_be_rewritten_by_tools` is false.

**Cannot:** stop the rewrite. It converts a silent rewrite into a failed check —
which is the whole difference between 14 hours of archaeology and a red build.

### C6 — Tool identity attestation

**Binds:** the tool, at invocation.

**Does:** requires every actor producing M2+ to declare identity — name,
version, session, and whether it is acting for a human or autonomously. Feeds
the `tool` block of C1 and the receipt of C8. Unattested tools are recorded as
`attested: false` rather than blocked.

**Fails:** open initially, by necessity — `npm` will not attest to anything, and
a control that blocks unattested tools blocks all of them. `attested: false` is
itself the useful signal.

**Cannot:** be trusted as authentication. A tool's self-declared identity is a
claim, not a credential. It aids attribution; it must never gate authorization.
This is the control most likely to be overclaimed — it is telemetry.

### C7 — Rollback evidence retention

**Binds:** the remediation path — wraps `git checkout --`, `git restore`,
`git clean`, and `rm -rf` on tracked paths.

**Does:** refuses to discard a modified tracked file until its current content
is captured to the checkpoint store. Directly prevents §3.4.

**Fails:** closed. Refusing a revert is safe; losing evidence is not.

**Cannot:** help if remediation happens outside the wrapper. Its real value is
inverting the default: today capture is a thing you remember, and it becomes a
thing you would have to bypass.

### C8 — Signed mutation receipt

**Binds:** the mutation record.

**Does:** for every M3+ mutation, emits a receipt binding actor, tool, class,
targets, decision, and checkpoint into the existing hash-chained audit store, so
local mutations become first-class governed events rather than a parallel log.

```json
{
  "schema": "acgs.mutation.receipt/v1",
  "receipt_id": "mrec-01JQ...",
  "checkpoint_id": "ckpt-01JQ...",
  "mutation_class": "M3",
  "actor": { "kind": "human", "id": "...", "auth": "unauthenticated-local" },
  "tool": { "name": "npm", "version": "10.9.2", "attested": false },
  "action": "dependency.install",
  "arguments_hash": "sha256:...",
  "decision": "deny",
  "policy_id": "dep-gate-v1",
  "policy_hash": "sha256:...",
  "reason": "non-canonical package manager: repo declares pnpm@9.15.4",
  "audit_ref": "sha256:<chain-head>",
  "signature": null
}
```

**Fails:** closed for M4+ — unsigned means unpermitted, with no downgrade path.

**Cannot:** be claimed as equivalent to the kernel's Decision Receipt until the
field alignment in §5.4 is implemented and tested. Until then this is a proposed
schema, not a kernel capability.

### Implementation sequence

Ordered by prevented-risk per unit of effort, not by architectural elegance.

| Order | Control | Effort | Would it have prevented the incident? |
|---|---|---|---|
| 0 | **Migrate the hook to `UniversalGateway.handle_claude_hook`** (§5.4a) | hours-days | No — but it converts the agent path from passive telemetry to policy-decision and audit mediation using code that already exists and is tested. Cheapest real capability gain available. |
| 1 | **C3 first row only** — deny non-canonical package manager | hours | **Yes, completely.** One read of `package.json`. |
| 2 | C5 provenance sidecar for declared M4 surfaces | days | Converts the silent rewrite into a CI failure |
| 3 | C2 control-surface inventory with owners | days | Yes — the file had no owner |
| 4 | C7 rollback capture wrapper | days | Prevents the self-inflicted evidence gap |
| 5 | C1 full checkpoint store | weeks | Makes §1.3's unknowns knowable |
| 6 | C4 SBOM delta in CI | weeks | No — lockfile was gitignored. Backstop only. |
| 7 | C8 signed receipts | weeks | Not prevention; makes it auditable |
| 8 | C6 attestation | ongoing | No — improves attribution only |

The ordering carries the argument: **the highest-value control is also the
cheapest.** A one-line manager check would have stopped this outright. That is
the strongest available evidence that the gap is architectural rather than
resource-bound — nobody was blocked by cost. The class of mutation had simply
never been modeled as governable.

---

## 7. Incident report template

Reusable structure for incidents involving AI coding agents, developer tools,
package managers, and autonomous workflows. Ordered deliberately: **evidence
before timeline, timeline before authority, authority before impact.** Writing
the narrative first is how inference gets promoted to fact.

Store as `docs/audits/YYYY-MM-DD-<slug>.md`.

### §1 Evidence

Capture before analyzing, and before any remediation.

- Artifact inventory: every file/tree, with SHA256 and mtime
- Command evidence: exact text, source (shell history / CI log / agent
  transcript), timestamp with timezone and its derivation
- Environment evidence: mounts, sandbox restrictions, tool versions
- **Explicit unknowns**: what evidence does not exist and why. Never omit.
- **Evidence-gap ledger**: anything destroyed during response, and by which command

### §2 Timeline

- One row per event: time, event, actor, evidence class
- Mark each **proven / inferred / unknown** — no unmarked rows
- State detection latency and *how* detection occurred
- Separate causally independent events explicitly; note where correlation was
  tested and rejected

### §3 Authority

The five-way decomposition (§1.2). Never collapse these.

- **Attribution** — who/what performed it, and how that is known
- **Authorization** — which control evaluated it. "None — never asked" is the
  most common and most important answer
- **Intent** — benign / negligent / adversarial / unknown, with support
- **Authority held** — what the actor *could* have done, not only what it did
- **Governance failure** — which control should have applied and why it did not

### §4 Impact

- Mutation classes touched (§4.A)
- Blast radius in counts, not adjectives
- **Reversible vs irreversible**, split explicitly
- Release/production reach, with the verification that establishes it
- Second-order impact: control surfaces, provenance, trust signals

### §5 Containment

- Actions taken, in order, each with its verification command and result
- What was deliberately **not** done, and why (evidence preservation, missing
  authority, scope)
- Residual hazards that survive containment, with owners

### §6 Decision

- Disposition per artifact: unauthorized / quarantined / approved
- **Two signatures for anything at M4+.** Self-signing is disallowed.
- Open decisions with named owners

### §7 Verification

- Every claim of "fixed" carries its command and literal output
- Gates re-run against the **final** state, not an intermediate one
- Explicit statement that no test, fixture, or datum was modified to make a gate pass
- **Exact reproduction procedure**, including environment prerequisites

### §8 Lessons learned

- Systemic causes, not operator error (§3)
- Which control class would have prevented it
- Proposed controls with owners and a gate they attach to
- **Benchmark scenario**, if the failure is reproducible

### Anti-patterns this template exists to prevent

| Anti-pattern | Guard |
|---|---|
| Narrative written before evidence captured | §1 precedes §2 |
| Inference presented as fact | Per-row proven/inferred/unknown marking |
| "Fixed" without command output | §7 requires literal output |
| Independent events merged into one story | §2 requires explicit separation |
| Evidence destroyed by remediation, unrecorded | §1 evidence-gap ledger |
| Author signs own disposition | §6 two-signature rule |
| Blast radius stated in adjectives | §4 requires counts |

---

## 8. Strategic value analysis

### 8.1 Why this incident class is becoming structurally important

Three shifts compound.

**Volume.** AI coding agents raise the rate of repository mutation by roughly an
order of magnitude. Controls that relied on a human reading every diff degrade
smoothly until they stop working, and there is no alarm at the transition.

**Actor opacity.** A repository now receives mutations from agents, agent-invoked
tools, IDE extensions, package managers, and humans — often within one minute of
each other, as this incident shows. `git blame` answers *which commit*; it does
not answer *which actor, under what authority*. This incident needed 14 hours
and forensic archaeology to answer a question that should be a lookup.

**Authority inversion.** The most dangerous actor in this repository is not the
AI agent. It is `npm` — which fetches unreviewed code from the internet and
executes it under full operator privilege, with no approval point. AI agents
arrived into an ecosystem where unmediated execution was already normal, and
inherited it. The agent did not create the hole; it multiplied traffic through it.

The general form: **as the number of high-agency actors grows, governance bound
to any single actor becomes proportionally less effective**, because the
ungoverned share grows with every new actor.

### 8.2 Why existing tooling does not close it

Not a criticism of these tools — a statement about what they were built to answer.

| Category | What it does | Why it misses this |
|---|---|---|
| SCA / dependency scanners | Find known CVEs in a resolved dependency set | Answers *is this package known-bad*, not *was this install authorized*. A clean scan of 103 unauthorized packages is a clean scan. |
| SBOM tooling | Inventory what is present | Descriptive, not authorizing. An SBOM would have listed all 103 — accurately, after the fact. |
| Secret scanners | Find credentials in source | Wrong artifact class entirely |
| Pre-commit hooks | Gate content at commit time | The damage occurred at **install** time. Nothing was ever committed. |
| Branch protection / CODEOWNERS | Gate merges | Same: applies at the wrong end. Local mutation and execution already happened. |
| SLSA / provenance | Attest how a build artifact was produced | Governs the build pipeline, not the developer workstation where this occurred |
| EDR / endpoint | Detect malicious process behavior | `npm install` is not anomalous. Intent was benign. Nothing to detect. |
| AI agent guardrails | Constrain what the agent may do | **Governs the one actor that was not involved.** |

The pattern: every mature control sits at **commit time, merge time, build time,
or runtime**. The incident occurred at **local mutation time** — a stage with
essentially no governance tooling, which is precisely the stage AI agents and
their tools operate in most heavily.

Second gap: all of these are *detective*. They tell you what happened. None
produce a *decision record* — an authenticated statement that this actor was
permitted this mutation at this time under this policy. That is the artifact an
auditor needs and the one nothing above emits.

### 8.3 Where ACGS differentiates

Stated honestly, because this is the section most likely to be overclaimed.

**What exists today**, in the repository's own approved wording: a **local
receipt-gated kernel** with a **tamper-evident JSONL audit chain** and an
**opt-in Ed25519 signing mode** (`AGENTS.md:154-161`). The core invariant —
*no valid Decision Receipt, no side effect* — is `tested` (`CLAIMS.md:8`), with
the limitation stated in the same row: *"Only true for paths wired through the
governed executor."* That limitation is exactly what this incident exercised.
It is not deployed, not multi-tenant, not externally anchored, and — per
`CLAIMS.md:35-42` — explicitly not production-certified, compliance-certified,
or regulator-approved.

**What this incident shows** is that the same primitives — authorization before
side effect, receipt as evidence, fail-closed default, tamper-evident audit —
are not agent-specific. They are the correct primitives for *any* high-agency
actor. The kernel was built one abstraction level too narrow.

The strategic move is to widen the actor model, not to build a second product:

> ACGS governs **high-agency software actors**. AI agents are the newest and most
> visible; package managers, developer tools, and CI automation are the
> incumbent, larger, and currently ungoverned majority.

Three reasons this is defensible rather than merely broader:

1. **The primitives already generalize.** Receipt, gate, audit chain, fail-closed
   are actor-agnostic. Widening is a matter of where the gate is bound (§4.0),
   not new cryptography.
2. **It answers a question no incumbent answers.** SCA answers "is it
   vulnerable." ACGS answers "was it authorized, by whom, under what policy, and
   can you prove it." That is the auditor's question.
3. **The competitive framing changes.** "Another AI guardrail" is a crowded
   category with unclear buyers. "The authorization and evidence layer for
   everything with write access to your codebase" is adjacent to controls
   regulated buyers already must demonstrate.

**What must not be claimed.** ACGS has not governed a package manager, has not
deployed this framework, and did not prevent this incident in its own
repository. The credible claim is: *we found this class of gap in our own
repository, using our own governance discipline, and the control model follows
from primitives we have already built and tested locally.* That is a strong
claim precisely because it is not a product claim.

**The roadmap consequence.** The A-Lite pilot thesis — one customer, one
mutation surface, dispatcher-mediated, recoverable — is unchanged. Dependency-
graph mutation (M3) is a strong candidate for an *early* action class: it is
high-value, bounded, universally understood, and the customer already feels the
pain. Section 6 defines the controls that would make it a governed surface.

---
