# Adopting an Agent-Skill Trust Pipeline

Status: proposal
Date: 2026-08-01
Scope: `.claude/skills/**`, `.agents/skills/**`, and the governance story around them

## Why this document exists

Agent skills are executable policy. A skill can tell an agent to run commands, read
files, call tools, or make decisions on a user's behalf, and in this repo at least one
is eligible for automatic invocation: `.agents/skills/govern-zone/agents/openai.yaml`
sets `allow_implicit_invocation: true`. (The `SKILL.md` body loads on trigger, not as
standing context in every run.) In the reviewed tree that flag is a latent risk rather
than a live one: the skill body itself is unparseable (see the scan findings below),
so there is no evidence the host can currently register or load it. The moment step 1
repairs the frontmatter, the skill becomes implicitly invocable without anyone opting
in; that is why the repair and the controls proposed here belong together.

The repository tracks six `SKILL.md` paths across the two trees: `govern-zone` mirrored
in both, plus `maintain-acgs`, `phase-gate`, `pr-evidence`, and
`source-driven-development` under `.claude/skills/`. The working tree where the scan
below was run carried 24 skill directories, most of them local-only and untracked, so
counts and findings involving untracked skills are recorded evidence, not reproducible
from a clean checkout. None of these skills has an owner record, a declared permission
set, an eval, or an integrity check. For a repository whose product is governed
execution, that is the least governed surface we own.

NVIDIA published a four-layer trust pipeline for exactly this problem
([NVIDIA/skills](https://github.com/NVIDIA/skills), Apache-2.0 + CC-BY-4.0, 324 skills).
This note records what is worth adopting, what is not, and what we found when we ran
their scanner against our own skills.

## Their model

| Layer | Question it answers | Artifact |
|---|---|---|
| SkillSpector scan | Does the content look safe to ship? | report (markdown / JSON / SARIF) |
| Skill card | What does it claim, who owns it, what are the limits? | `skill-card.md` |
| OMS signature | Is what I received what was reviewed? | `skill.oms.sig` |
| Eval set | Does it still behave as described? | `evals/evals.json`, `BENCHMARK.md` |

The docs are not aspirational. The four skills sampled for this note, re-verified at
upstream commit `ea1d5b5c6753b9de34326f49099fc02c03707e4b`
([skill-card-generator](https://github.com/NVIDIA/skills/tree/ea1d5b5c6753b9de34326f49099fc02c03707e4b/skills/skill-card-generator),
[cuopt-server-api-python](https://github.com/NVIDIA/skills/tree/ea1d5b5c6753b9de34326f49099fc02c03707e4b/skills/cuopt-server-api-python),
[data-designer](https://github.com/NVIDIA/skills/tree/ea1d5b5c6753b9de34326f49099fc02c03707e4b/skills/data-designer),
[deepstream-dev](https://github.com/NVIDIA/skills/tree/ea1d5b5c6753b9de34326f49099fc02c03707e4b/skills/deepstream-dev)),
each ship the complete set: `SKILL.md`, `skill-card.md`, `skill.oms.sig`,
`evals/evals.json`, and `BENCHMARK.md` are present at every one of those paths, which a
directory listing at that commit reproduces. (At the same commit, 323 of the 324
`SKILL.md` directories in the catalog carry all three sidecar artifacts.) Signing
uses the OpenSSF Model Signing format — Sigstore-style bundles extended to cover a
**directory tree** rather than a single file — with a pinned trust anchor and offline
verification:

```bash
model_signing verify certificate SKILL_DIR \
  --signature SKILL_DIR/skill.oms.sig \
  --certificate-chain nv-agent-root-cert.pem
```

Strict by default: files added after signing fail verification.

## What we found running their scanner on our own skills

SkillSpector (`github.com/NVIDIA/SkillSpector`, 64 patterns / 16 categories) was run
locally against both trees with `--no-llm`, so nothing left the machine.

```
skillspector scan .claude/skills --recursive --no-llm --format markdown
skillspector scan .agents/skills --recursive --no-llm --format markdown
```

**Reported: 7 HIGH, 6 MEDIUM.** One reproducibility limit applies to the whole run,
beyond the untracked-skill caveat above: the scanner's exact revision was not recorded,
no installation lock was kept, and the full report artifact was not preserved. Pinning
the NVIDIA skill-catalog sample (previous section) does not pin SkillSpector, whose
rule set and CLI evolve independently, so the 7-HIGH/6-MEDIUM totals — including the
rows against tracked skills — are recorded evidence from an unpinned scanner build,
not independently re-derivable. Any future scan whose findings feed a gate or a claim
must record the exact scanner commit or release, lock the installed dependencies, and
preserve the full output artifact (or at minimum its hash) alongside the findings.
Six of the seven HIGH findings were captured in the
notes below; each was verified as a heuristic misfire on one of this repo's own idioms
by reading the flagged line. The seventh HIGH was not preserved when these notes were
written, so the zero-true-positive verdict is claimed only for the six itemized here:

| Rule | Where | Verdict |
|---|---|---|
| AS1 "Agent Config Directory Access" | `maintain-acgs:27` | False positive — the skill's *purpose* is maintaining `.claude`; reading `settings.json` is its job |
| AS1 | `worktree-lanes:82` | False positive — a documentation cross-reference to `.claude/rules/headless-delegation.md`, not access |
| P6 "Direct Prompt Extraction" | `pr-evidence:32` | False positive — "paste literal commands and literal outputs" is our verification-discipline rule |
| P6 ×3 | `imagegen-frontend-web:3,6,399` | False positive — fires on emphatic rule blocks ("HARD OUTPUT RULE — READ FIRST") |

Of the flagged skills, `maintain-acgs` and `pr-evidence` are tracked in this
repository; `worktree-lanes` and `imagegen-frontend-web` were local-only untracked
skills, so those rows cannot be re-derived from a clean checkout.

The finding list was not the value. **The structural output was.** SkillSpector reported
`.claude/skills/govern-zone` as `Skill: unknown`, because it cannot parse a name from a
file whose first line is a ` ```markdown ` fence instead of YAML frontmatter. That proves
the file is malformed by the scanner's parsing rules, not how either host handled it:
as noted above, no host-load evidence exists either way, so the skill is best described
as malformed and unverified-loadable rather than as one the hosts demonstrably skipped.
(A real host registration test is exactly what the step-2 loadability gate below adds.)
The defect existed in *two* copies, the same blob mirrored at
`.claude/skills/govern-zone/SKILL.md` and
`.agents/skills/govern-zone/SKILL.md`. It went unnoticed indefinitely because nothing
checks that a skill is loadable, let alone correct.

That is the argument for this proposal in one example: a governance repository shipped an
implicit-invocation-enabled but unverified-loadable skill that was malformed *and*
factually wrong about its own conventions, and no gate noticed.

## What to adopt

### 1. Declared permissions in frontmatter — highest value

NVIDIA's `skill-card-generator/SKILL.md`:

```yaml
permissions:
  file_read:  ["target_skill_directory", "references/", "scripts/"]
  file_write: ["target_skill_directory", "/tmp/"]
  shell:
    allowed_scripts: ["scripts/discover_assets.py", "scripts/render_card.py"]
```

Two observations. First, it is not universal in their catalog — documentation-only skills
omit it, so the trust-pipeline doc's claim that capabilities "are declared in the
`SKILL.md` frontmatter" is aspirational for a good share of their own skills. Second, and
more important: **nothing enforces it at runtime.** It is documentation.

That gap is precisely where gove-zone fits, with a caveat the design must own: the
`permissions:` block is declared by the skill itself, so a compromised or unreviewed
skill (the very thing this pipeline exists to constrain) can simply declare the broader
access it wants. Binding the declaration into a receipt makes it tamper-evident, not
trustworthy. Enforcement therefore needs two inputs the declaration cannot supply: a
trusted skill identity (name, version, and artifact digest, which is why an integrity
mechanism must precede this step), and an independently reviewed maximum permission set
held outside the skill. The declared block then operates only as an additional deny
gate: it can narrow the approved ceiling, never widen it. With those in place, the
kernel's existing actor/action/argument/policy binding extends naturally. They declare;
we authenticate, cap, and enforce, for the calls that are actually routed through the
receipt-gated executor boundary (step 6 records how narrow that routing is today). This
is the one item that is both borrowable and differentiating.

### 2. Skill cards

Per-skill governance record: owner, license, use case, deployment geography, credential
type with a least-privilege note, actionable risk/mitigation pairs, output schema, and a
version tied to the signing identifier. We have `docs/CLAIMS.md` at repo level and nothing
per capability.

Their "good risk statements" guidance is the same instinct as the safe/unsafe claim
wording boundaries this repo tracks in `AGENTS.md` ("Claim boundaries") and
`docs/CLAIMS.md`: vague risks rewritten as testable ones:

| Weak | Stronger |
|---|---|
| The skill could make mistakes. | The skill may generate incorrect remediation steps; users must review proposed code changes before execution. |
| The skill writes files. | The skill may overwrite generated reports in the configured output directory; it must not write outside that directory. |

Worth pointing skill cards at those tracked claim boundaries rather than maintaining a
separate vocabulary.

### 3. Per-skill eval sets

`evals/evals.json` carries behavioural cases with an `expected_behavior` checklist,
including negative assertions:

```json
"expected_behavior": [
  "Selects LP (not MILP or QP) given continuous variables and a linear objective",
  "Does not invent method names that are not in the skill"
]
```

We have zero evals for our skills. The govern-zone skill asserted that Python filenames
use camelCase, in a tree that is snake_case throughout; a single eval asserting "states
snake_case for Python modules" would have caught it.

### 4. Directory-tree signing

OMS signs a whole directory tree: detached signature, pinned trust anchor via a
certificate chain, offline verification, strict rejection of files added after signing.
The closest artifact in this repo, `packages/acgs-proofpack-verifier`, is a useful
conceptual contrast rather than a reusable implementation: it signs only the receipt (a
pack-level signature over the evidence manifest and other artifacts is explicitly
documented as requiring a format change), verifies against an operator-supplied public
key with no PKI, certificate chain, or trust-store bootstrap, and does not treat extra
directory files as unsigned additions. If we sign our own skill directories, adopt OMS
rather than extending the verifier or inventing a format: it interoperates and already
solves the directory-signature problem. The trust-anchor and key-distribution work
remains ours either way.

## What not to adopt

Their pipeline governs the **artifact at install time**. It says nothing about the
**action at execution time**. A correctly signed, scanned, carded skill can still
instruct an agent to do something policy forbids — signing proves provenance, not
behaviour.

That is not a criticism of their design; it is the boundary of it, and it is where ACGS
sits. Adopt their supply-chain layer; do not let it be mistaken for runtime enforcement,
and do not describe our adoption of it as making skills "verified" in the behavioural
sense.

Note also that their blog frames this as "capability governance for AI agents," which
overlaps our positioning language even though the mechanism does not overlap. Worth
tracking alongside the Microsoft AGT comparison as a narrative competitor.

## Proposed sequence

1. **Fix what is broken.** Both `govern-zone` skill copies (in flight). One
   placement constraint first: these are generated, managed artifacts, not
   hand-maintained files. Their bodies identify themselves as auto-generated,
   `.claude/ecc-tools.json` lists both copies and `agents/openai.yaml` under
   `managedFiles`, and `docs/CLAIM_AUDIT.md` already defers wording fixes in this
   skill to the skill-extraction generator rather than its output. Hand-patching
   the outputs would therefore last only until the next ECC regeneration, which
   could restore the malformed body, the camelCase falsehood, and
   `allow_implicit_invocation: true` in one pass, silently invalidating the
   step-2 parity gate and the step-5 digest. The repair, including the invocation
   flags below, must land in the generator or its canonical source, with the
   host copies regenerated from it; if the generator cannot be fixed on this
   timeline, replace the generated skill with a hand-owned canonical source and
   remove the copies from the generator's managed set, so no automated pass can
   overwrite the repaired artifacts. One ordering
   constraint: repairing the frontmatter is exactly what arms the
   `allow_implicit_invocation: true` flag, so shipping the repair alone would turn a
   previously inert, unowned, unsigned skill into an automatic instruction source
   before any control below exists. The repair must therefore set
   `allow_implicit_invocation: false` in `agents/openai.yaml`, and that flag alone
   covers only the Codex host. Repairing the frontmatter equally makes the Claude
   mirror at `.claude/skills/govern-zone/SKILL.md` model-selectable, so the repair
   must also set `disable-model-invocation: true` in that copy's frontmatter, the
   same flag this repository already uses on its manual Claude skills. Both flags
   stay disabled through the phased rollout until the skill is authenticated and its
   actions are actually constrained: the step-5 identity/digest and approved ceiling
   plus the step-6 host interception and enforcement. The flags alone cannot carry
   that hold, because they live in the same writable checkout that ordinary agent
   tool calls can edit: a prompt-injected agent or another acting skill can clear
   `disable-model-invocation` or restore `allow_implicit_invocation` and make the
   skill selectable during exactly the interval when no identity or interception
   exists to catch it. During the phased interval the hold must therefore also be
   enforced in host policy held outside agent write authority, and that
   hold must be default-deny over the repository's skills, not a denylist
   enumerating the known held names: the same checkout write authority that
   could clear the in-repo flags can equally create a new loadable skill,
   or copy or rename a held skill's directory under a different name, and
   once the host reloads its skill registrations that replacement is
   selectable and directs the same unrestricted tool calls before steps 5-6
   exist, while every flag-tampering and explicit-invocation test for the
enumerated entries still passes. The host policy must therefore deny
    every repo-local skill by default, enabling a skill only when its
    identity has been externally admitted through the step-5 review *and*
    the step-6 host interception and enforcement routing for its actions
    is active, and it must reject *every* invocation path for skills not
    meeting both conditions (model selection, implicit
    invocation, and explicit user invocation alike), not
    only the two automatic paths. Admission alone must not lift the hold:
    when step-5 admission lands before step-6 interception, the newly
    admitted skill's actions are not yet constrained by anything (the
    in-repo flags block only the automatic paths), so an explicit user
    invocation can load the admitted skill and direct unrestricted tool
    calls during exactly the rollout interval between admission and
    enforcement; invocation and instruction ingestion for an admitted
    skill therefore stay denied until the step-6 routing that constrains
    its actions is enforcing. The in-repo flags only remove automatic
   selection, and a user who explicitly loads a held or manual skill during
   the interval loads the same instructions with the same power to direct
   unrestricted tool calls before the step-5 identity and step-6 interception
   exist, so a hold scoped to automatic invocation leaves the exact exposure
   it was created to close (step 6 already applies the same
   loadability-not-invocation-path reasoning to the governed set). The
   negative tests must prove that modifying the in-repo frontmatter or
   companion-manifest flags does not make a held skill invocable while the
   host-policy hold is in force, that (an explicit-invocation case)
   a user's explicit invocation of a held skill is refused while the hold is
    in force, that (a default-deny case) a loadable skill newly created
    or renamed in the checkout during the interval is not invocable by any
    path until its identity has been externally admitted and the step-6
    interception is active, and that (a step-5-before-step-6
    explicit-invocation case) a skill whose identity is externally
    admitted while the step-6 interception and enforcement routing is not
    yet active has an explicit user invocation refused, with no
    instruction ingestion and no side effect, until that routing is
    enforcing. The hold gates
   invocation, and invocation gating cannot reach contexts that predate it:
   a skill already loaded into a live model session before the hold is
   enabled needs no new invocation, so its retained instructions keep
   directing unrestricted tool calls during exactly the interval the hold
   was created to close while every invocation-path test above passes.
   Enabling the hold must therefore also drain preexisting contexts:
   rollout terminates or taints every live model context that has loaded a
   not-yet-admitted skill, or the hold is re-enforced on every tool request
   rather than only at invocation time, denying requests from contexts
    whose loaded skills are unadmitted, with a preexisting-context negative
    test that loads a skill before hold activation and proves that skill's
    subsequent tool call is denied while the hold is in force. Draining
    contexts and denying later tool requests still does not stop work those
    contexts set in motion before the hold: a detached child process, file
    watcher, scheduled task, or queued operation launched by a
    not-yet-admitted skill needs no further tool call, so it keeps producing
    unrestricted effects throughout the interval while the
    preexisting-context test passes. Activating the hold must therefore
    also terminate or revoke the process trees, scheduled tasks, and
    pending queued work attributable to unadmitted skill contexts, or
    restart the execution boundary into a state where none of them
    survive, with a pre-hold background-work negative test that launches a
     detached child (or schedules deferred work) from a skill context
     before hold activation and proves it produces no further effects once
     the hold is in force. Invocation and tool-request gating still governs
     only formal skill activation, and ordinary ingestion is neither: during
     the interval a non-skill context can read a held `SKILL.md` through an
     ordinary `Read` or `cat` (none of the three denied invocation paths),
     and every later tool call that follows those instructions retains the
     context's unrestricted non-skill authority, while the
     activation-on-read rule that would catch this is exactly the step-6
     machinery the interval lacks (this design defers direct-read handling
     to step 6). The hold must therefore also deny ordinary ingestion and
     extraction of unadmitted skill artifacts during the interval (reads,
     copies, and transformations of their instruction files by non-loader
     contexts are refused), or taint the consuming context so that its
     subsequent tool requests are denied while the hold is in force, with a
     read-then-call negative test that reads a held `SKILL.md` through an
     ordinary file read before any invocation and proves either the read
     itself is refused or the reading context's subsequent tool call is
     denied while the hold is in force. The step-2 loadability gate and
   a step-3 card are prerequisites but not sufficient, because neither prevents an
   automatically selected skill from directing actions beyond its intended
   authority; a schema-valid, well-described skill can still instruct anything.
2. **Add a loadability gate.** A root test that every `SKILL.md` under `.claude/skills/**`
   and `.agents/skills/**` parses `---`-delimited frontmatter with a `name` and
   `   description`, and enforces the host's skill schema (see step 4 for why the generic
   check alone is not enough). The host validators do not ship in this repository or as
   a pinned dependency: Codex's `quick_validate.py`, for example, lives only inside the
   agent installation, so an ordinary checkout or CI runner cannot invoke it. The gate
   must therefore vendor a pinned copy of the validator (license permitting) or encode
   the same schema rules as a repo-local check, with a recorded upstream version to diff
   against on host upgrades. A recorded version alone is documentation: nothing runs
   that diff, so when the installed Claude or Codex host is upgraded to a version whose
   skill schema diverges from the vendored validator, this repo-local gate keeps
   passing while the active host rejects the skill outright or interprets its security
   metadata (the `permissions:` declaration, invocation flags) differently than the
   gate validated. The gate must therefore also pin the host/schema version its
   vendored validator corresponds to, and host deployment/admission (step 5) must
   verify that the active host's skill-schema version matches that pinned version
   before enabling the skill, failing closed (the skill held un-invocable) on
   mismatch until a validator matching the active host version has revalidated the
   tree and the pin is updated, with a negative test proving a skill validated only
   against a stale schema version is not enabled on an upgraded host. The gate must also cover host companion manifests, not
   only `SKILL.md`: Codex registration of `govern-zone` additionally depends on
   `.agents/skills/govern-zone/agents/openai.yaml`, and `quick_validate.py` reads only
   `SKILL.md`, so a malformed or schema-incompatible companion manifest keeps the
   skill unloadable while a frontmatter-only gate passes. Validate each companion
   manifest against a pinned schema and check that it belongs to (and correctly
   references) the skill directory that contains it. And because `govern-zone` is
   maintained as two host-facing copies, per-file checks can pass while the copies
   drift apart, so a later repair could govern the Codex copy while Claude keeps
   loading stale or differently permissioned instructions. The gate must therefore
   enforce mirror parity for the shared skill body and security metadata (the
   permission declaration and semantics), but as a *normalized* comparison, not
   a raw byte diff, because the two copies legitimately diverge in host-specific
   representation: once step 4 applies host schemas, the Codex copy carries its
   `permissions:` declaration under `metadata:` or in a sidecar while the Claude
   copy may hold it in frontmatter, and only the Codex copy ships an
   `agents/openai.yaml` adapter. That same intentional divergence means the
   step-5 artifact digest is *not* a parity value: the canonical tree manifest
   binds every path and entry, so two compliant host mirrors necessarily
   produce different full-tree digests, and requiring digest equality across
   mirrors would either fail compliant mirrors permanently or force hashing a
   normalized view that omits host-specific bytes the host actually loads.
   Each host copy therefore carries its own full-tree digest computed over
   exactly the bytes that host loads, both digests are tied to a common
   canonical-source/release identity recorded alongside them, and parity is
   checked separately on the normalized instruction body and the permission
   semantics, never on digest equality. The parity check therefore compares a
   canonical instruction body and the security values after normalizing each
    copy's host-specific encoding, and allows host adapter files to exist only
    on their host's side; either generate both copies from one canonical source
    or fail on divergence of the normalized body, the permission semantics, or
    the shared canonical-source identity the per-host digests are tied to.
    Body, permissions, and release identity are still not the whole
    enforcement surface: step 4 makes `deny_behavior` an enforcement input
    that decides per skill whether a denied action stops, escalates, or
    enters a human-approval flow, and the invocation flags decide whether the
    model may select the skill at all, so two mirrors that agree on the
    normalized body, permissions, and canonical-source identity but encode
    different `deny_behavior` values or invocation semantics would pass the
    parity check above while the two hosts enforce different outcomes for
    the same denial. The parity comparison must therefore cover every
    canonical enforcement field, `deny_behavior` and the normalized
    invocation semantics (model-invocation and implicit-invocation flags)
    included, each compared after normalizing its host-specific encoding,
    with a mismatched-mirror negative test proving copies identical in body,
    permissions, and release identity but divergent in `deny_behavior` or
     invocation semantics fail parity rather than both being enabled.
     Parseability and schema bound a skill's shape, not its size: an
     otherwise schema-valid `SKILL.md` or companion file can be arbitrarily
     large, and implicit or model selection loads those bytes into the host
     and the model context before the dispatcher-ingress, pure-operation, or
     execution budgets elsewhere in this design ever apply, so a single
     oversized skill can exhaust host memory or the model's context window
     without a single tool call. The gate and host admission/load must
     therefore also enforce per-skill instruction and artifact ceilings
     (maximum instruction-file bytes, maximum bytes for each companion
     artifact the host ingests, and maximum instruction tokens where skill
     content enters a model context), refusing admission or load of an
     over-limit skill before any of its bytes reach the model, with an
     oversized-skill negative test proving a schema-valid skill exceeding
     its instruction byte or token ceiling is refused by the host at
     admission/load time rather than ingested into the model context.
     Cheap, deterministic, catches the entire class.
   One repo-hygiene prerequisite: the root `.gitignore` ignores `.agents` wholesale, so
   only the two already-tracked `govern-zone` files survive; any new skill or sidecar
   under `.agents/skills/**` is invisible to a CI checkout (`git check-ignore` confirms
   this for a new `SKILL.md` and for a `skill-card.md` beside the tracked skill).
   Before relying on this gate, un-ignore the shared `.agents/skills/**` source tree
   while selectively re-ignoring runtime state, mirroring the `.claude/` whitelist
   pattern already in the same file; otherwise the gate silently covers only skills
   someone remembered to force-add.
3. **Skill cards for the skills that can act.** Start with the tracked skills that
   direct governed capabilities — command execution, privileged-path or manifest
   reads, and network fetches (`govern-zone` in both tracked copies, `maintain-acgs`,
   `phase-gate`, `pr-evidence`, and `source-driven-development` today: `govern-zone`
   directs agents to create files, edit CI and manifests, and execute shell commands;
   `maintain-acgs`, `phase-gate`, and `pr-evidence` direct git, test, lint, or
   hash-check commands; and `source-driven-development` directs reads of package
   manifests and `.github/workflows/**` and fetches of external documentation URLs,
   with no `disable-model-invocation` flag, so it is model-selectable like the rest.
   File reads and network access are inside the governed capability set this proposal
   opened with, not exempt from it. The step-1 invocation hold therefore applies to
   this whole set, not only to the repaired mirror: a card and a loadability gate do
   not constrain what a selected skill directs, so every acting skill above must set
   `disable-model-invocation: true` (and its Codex counterpart must not set
   `allow_implicit_invocation: true`) until the step-5 authenticated identity and
   ceiling and the step-6 interception land; otherwise `phase-gate` and
   `source-driven-development` stay model-selectable through the phased rollout
   while directing shell commands and network reads with no enforcement behind
   them. The skill step 1 restores must
   not sit outside the controls this proposal exists for), and make a card the entry
   ticket for any currently untracked local skill (`worktree-lanes`,
   `headless-delegation`, `deploy-drift-check`, `pr-queue`, `codex-execution-workflow`)
   before it lands in the repository.
4. **Declared `permissions:` on the same set**, initially documentation-only. Where the
   block lives is host-specific: Codex's bundled skill validator (the skill-creator
   system skill's `quick_validate.py`) rejects frontmatter keys other than `name`,
   `description`, `license`, `allowed-tools`, and `metadata`, so for
   `.agents/skills/**` the declaration must sit under the supported `metadata:` key or
   in a sidecar manifest, not beside `name` as in NVIDIA's catalog. That is also why
   the step-2 gate must enforce the host schema via its vendored validator or
   equivalent repo-local check: a frontmatter-parses check alone would approve a skill
   the host itself rejects. This repository also already documents a governed-skill
   metadata contract in `docs/skills/skill-schema.md` (`allowed_tools`, `risk_level`,
   `requires_governance_gate`, `deny_behavior`, `evidence_outputs`, `owner`), and
   introducing `permissions:` beside it would create two sources of truth with no
   precedence rule (`allowed_tools` could permit shell while `permissions.shell`
   denies it).    This step therefore includes reconciling the two before rollout:
   `permissions:` supersedes `allowed_tools` as the capability declaration; the
   descriptive `skill-schema.md` fields (owner, risk, gate, evidence outputs) fold
   into the step-3 skill card; and `deny_behavior` (enforcement input, not card
   prose: it distinguishes per skill whether a denied action stops, escalates,
   or requires human approval) is carried into the canonical replacement alongside
   `permissions:`, with a defined fail-closed mapping (an absent or unrecognized
   value means stop, never proceed) before the old field is removed.
   Reconciliation fixes where the declaration lives, not what its terms mean:
   path patterns, network origins, and script identifiers only carry one
   authority if every component that reads them parses them identically, and
   nothing above defines or versions that grammar. One component can
   interpret `/tmp/**` recursively while another treats `**` literally or
   falls back to prefix matching, so the ceiling and the signed receipt can
   bind identical declaration bytes while the executor grants different
   authority than admission approved. The canonical replacement must
   therefore define one versioned permission-language grammar and
   canonicalization — a single parser (or a conformance-tested equivalent)
   shared by the step-2 gate, host admission, receipt issuance, and the
   executor — with every declaration reduced to its canonical form before
   use, the language version and the canonical effective permission set bound
   into ceiling records and receipts, unknown or noncanonical forms rejected
   fail-closed rather than interpreted best-effort, and parser-differential
   negative tests proving a declaration whose pattern is interpreted
   differently by two components (recursive-glob versus literal or
   prefix-match readings) is rejected or yields identical granted authority
   at every consumer, never a wider grant at the executor than at
   admission. The
   `require human approval` value needs one more rule, because this repository
   already forbids treating `DENY` or `ESCALATE` receipts as executable: approval
   never revives the original receipt. A granted approval triggers a freshly
   evaluated request through the full policy path, producing a new `ALLOW` or
   `TRANSFORM` receipt that is the only thing the executor will accept, and a
    negative test must prove the original denied or escalated receipt can never
    run, approved or not. Approval is also not a general override of denial:
    a grant can respond only to an explicit `ESCALATE`, or to a decision the
    policy itself marks approvable, so `deny_behavior: require human approval`
    selects escalation as a skill's deny handling rather than making every
    denial grantable. A hard `DENY` (an absolute control such as tenant
    isolation or a forbidden destructive action) remains denied regardless of
    any grant: the fresh post-approval evaluation must deny it again, and a
    real-handler negative test must prove a hard-denied request accompanied by
    an otherwise valid approval grant yields no executable receipt and no side
    effect. Approval is also bounded below the permission ceiling,
   never a way over it: a grant can resolve only policy-level escalation for
   requests whose final arguments remain inside every effective permission
   ceiling (the step-5 approved ceiling intersected with the declaration and,
   under composition, every stacked skill's set). When the denial came from the
   declared/approved permission intersection itself, the fresh evaluation must
   deny again (the independently reviewed maximum is not an overridable
   suggestion), and an above-ceiling-with-valid-approval negative test through
   the real handler must prove a request outside the ceiling yields no
   executable receipt and no side effect even when it carries an otherwise
   valid approval grant. The approval grant is itself a credential and must be
    bound to the exact request it approves: authenticated to the granting human,
    tied to the actor, skill identity/digest, action, and final arguments the new
     receipt represents, single-use, and bounded by an expiry, with the grant
     recorded as evidence in that receipt. That tuple alone does not identify a
     decision: the same actor, skill, action, and arguments can recur in another
     tenant, under another policy bundle/version, or in a later request, and
     single-use plus expiry prevent a second use, not first use against a
     different decision than the one the human saw. The grant must therefore
      also be bound to the originating request/audit hash of the escalated or
      explicitly approvable decision it responds to, plus the tenant, execution boundary,
      and policy bundle/version in force, and mismatch negative tests must prove
        a grant presented in a different tenant, under a different policy
        bundle/version, across a different execution boundary, or against a
          request whose audit hash differs is rejected without a side effect.
          Tenant, execution boundary, and policy version still leave the
          deployment dimensions unbound: staging and production
          deployments can share a tenant, execution boundary, policy
          bundle/version, actor, skill, action, and final arguments,
          differing only in project and environment, and the originating
          audit hash does not close that gap in the current model because
          `DecisionRecord.to_dict()` contains neither field, so a grant
          collected against the staging decision is consumable against
          the production one while every mismatch test above passes. The
          grant's explicit scope and the originating decision record must
          therefore both bind `project_id` and `environment_id` (the
          decision serialization extended to carry both deployment
          dimensions so the bound audit hash covers them), the trusted
          approval channel must render both dimensions to the approving
          human alongside the other bound fields, and cross-project and
          cross-environment grant-substitution negative tests must prove
          a grant collected in one project or one environment, presented
           against an otherwise identical decision in a different project
           or a different environment, is rejected without a side effect.
           Single-use and expiry are also the only lifecycle terminations
           stated so far: when the approving human discovers a grant was
           mistaken, coerced, or compromised before it is consumed, nothing
           above lets them withdraw that one grant short of revoking their
           whole credential or role, so the known-bad unconsumed grant
           remains consumable until its expiry and can still mint a fresh
           executable receipt. The rollback-protected grant ledger must
           therefore track a per-grant revoked/cancelled state that the
           granting human or an authorized administrator can set for an
           unconsumed grant, with grant consumption and the execution gate
           both rechecking that state under the same fresh, monotonic,
           rollback-refusing discipline as the other freshness domains,
           failing closed when the grant is revoked or the state is
           unavailable, and a revoked-grant negative test proving an
           unconsumed, unexpired grant revoked after issuance is rejected
           at consumption without a side effect, and that a receipt already
           minted from a grant revoked before that receipt's first
           presentation is refused at the execution gate without a side
           effect.
           Single-use and expiry bound a grant only as reliably as the clock
         that evaluates them: `docs/SECURITY_MODEL.md` and ADV14 record that
         expiry today is host-clock-bound with no built-in trusted time
         source, so a verifier whose host clock is set backward or frozen
         accepts an otherwise expired but unused approval grant, invocation
         context, or receipt, and every rollback-resistant ledger in this
         design still passes because the artifact was never consumed. Expiry
         evaluation at issuance, at grant consumption, and at execution must
         therefore consult a trusted time source (a trusted monotonic clock
         or a signed time attestation of the same trust class as the ceiling
         and grant freshness state, held and validated outside agent and
         child-process write authority), fail closed when that source is
         unavailable rather than falling back to the mutable host clock, and
         a clock-rollback negative test must let an approval grant, an
         invocation context, and a receipt expire unused, set the verifier's
          host clock back before their expiry, and prove each is still
          rejected without a side effect.
          A trusted monotonic clock also has no persistent epoch: a host
          restart resets or rebases it, so a durable unused grant,
          invocation context, or receipt whose deadline was recorded
          against the pre-restart monotonic value can compare against the
          new lower reading and remain usable past its intended lifetime,
          while the wall-clock rollback test above still passes because no
          wall clock moved. Monotonic timestamps must therefore be bound
          to a non-reusable boot or time-source epoch identifier, with
          expiry evaluation failing closed across any epoch discontinuity
          rather than comparing raw readings across it (or the verifier
          must instead require fresh, non-replayable signed absolute
          time), and a restart negative test must let an approval grant,
           an invocation context, and a receipt expire unused, restart the
           host so the monotonic clock resets or rebases, and prove none of
           the pre-restart artifacts regains validity or yields a side
           effect.
           An epoch-bound monotonic clock still measures only running
           time: on hosts where the monotonic reading stops during
           system suspension or VM pause, the pause produces no epoch
           discontinuity and no rollback, so an unused grant, invocation
           context, or receipt does not age while the host is suspended
           and remains executable long after its intended real-time
           expiry while both the clock-rollback and restart tests pass.
           The trusted elapsed-time source must therefore be
           suspend-aware, counting suspended and paused intervals (a
           boottime-class clock or equivalent held in the same trust
           class), or expiry evaluation must require fresh,
           non-replayable signed absolute time, failing closed when
           neither is available, with a pause/resume expiry negative
           test suspending or pausing the host until an unused approval
           grant, invocation context, and receipt pass their intended
           real-time expiry and proving each is rejected after resume
           without a side effect.
           Authenticating the approver and binding the grant to the canonical
        request fields still does not prove those fields are what the human
        saw: when the requesting agent or a compromised skill supplies the
        label or summary the approval prompt displays, the prompt can
        describe a benign staging action while the signed payload names
        production, and every binding, role, expiry, and replay test above
        passes. The approval must therefore be collected through a trusted
        approval channel that renders the decision directly from the payload
        being signed (the actor, skill identity/digest, action, final
        arguments, resolved target, and referenced-content digests taken
        from the canonical bound fields, never from caller-supplied prose),
        with a mismatched-display negative test proving an approval prompted
        with a caller-supplied label or summary that disagrees with the
        bound request fields yields no consumable grant and no side effect.
        Rendering only those request fields still lets bound-but-unrendered
        fields be signed unseen: the requirements below bind the effective
        credential principal, the resolved ambient target context, the
        versioned enforcement and implementation identities, and the
        handler's or allowed script's security-relevant ambient
        configuration values (such as `DEPLOY_MODE`) into the approval, so
        a compromised requester can obtain a signature over a destructive
        value in any of those fields while every canonical-binding and
        mismatched-label test above passes, because nothing requires the
        channel to display them. The trusted approval channel must
        therefore render every security-relevant field bound into the
        payload being signed (or a trusted semantic representation derived
        from those bound values, never from caller-supplied prose) and
        refuse to collect a signature over a payload carrying a bound
        behavior-defining field it did not render, with a hidden-field
        substitution negative test that binds a destructive ambient
        configuration value, credential principal, or enforcement identity
        into an approval payload whose rendered request fields all match
        and proves an approval collected without that field rendered
        yields no consumable grant and no side effect.
        The trusted-semantic-representation alternative is itself a
        rendering escape hatch unless it is complete: for a structured
        bound field, inline final arguments carrying a manifest, a GraphQL
        operation, or deployment options, a renderer can show a benign
        summary that omits a destructive nested value, collect a valid
        signature over the exact hidden payload, and still satisfy the
        hidden-field test because the field was rendered in some form.
        Every bound field must therefore be rendered either as full
        escaped content or through a schema-validated, behavior-complete
        semantic rendering held to the same completeness guarantees
        required of referenced-content summaries below (validated against
        the field's schema, proven to represent every behavior-affecting
        value, refused and falling back to escaped full content
        otherwise), with an omitted-nested-value negative test binding a
        destructive nested value inside a structured field whose semantic
        rendering omits it and proving collection is refused or falls back
        to full escaped rendering with the destructive value unambiguously
        visible, and that a signature collected over the incomplete
        rendering yields no consumable grant and no side effect.
        Rendering every bound field faithfully still lets the bound bytes
        lie to the eye: a bound argument, resolved target, or skill name can
        carry terminal control sequences, newlines, or Unicode
        bidirectional-control code points that, rendered verbatim from the
        canonical payload, hide or visually reorder the destructive value
        while the signed bytes and every caller-prose mismatch check above
        remain exact. The trusted approval channel must therefore reject
        bound fields carrying such display-control code points, or render
        every unsafe code point as an unambiguous visible escape without
        changing the bound value the signature covers, with an approval-
        spoofing negative test proving a bound field carrying ANSI terminal-
        control and Unicode bidirectional-control payloads either fails
        collection or is displayed with the destructive value unambiguously
        visible, and that a signature collected over a spoofed rendering
        yields no consumable grant and no side effect.
        Rendering the canonical final arguments faithfully also discloses
        what they contain: when an argument field carries an inline
        credential (an `Authorization` header, a password field, a
        `--token` value), the trusted channel renders the secret to the
        approver's display and the receipt and audit argument bindings
        serialize it into longer-lived evidence, while the secret
        classifications elsewhere in this design cover only by-reference
        and ambient inputs. Secret-bearing argument fields must therefore
        be classified exactly as secret-classified ambient inputs are and
        bound through a secret-store reference or a keyed commitment
        verified inside the trusted gate, with the approval channel
        rendering only a non-disclosing designator of the secret (its
        store identity and version, never its value) and receipts,
        ceiling records, and audit events carrying the same non-disclosing
        binding, with non-disclosing rendering and serialization negative
        tests proving an approval collected over an inline-credential
        argument, its receipt, its ceiling record, and its audit events
        emit neither the secret value nor an offline-guessable digest of
        it, while a substituted or mismatched secret reference still
        yields no consumable grant and no side effect.
        A non-disclosing binding also authorizes nothing: it proves which
        secret version was used, not that this actor or skill may use it,
        so a malicious skill that can name a production token or signing
        credential by store identity gets the trusted gate to resolve and
        pass that secret while every serialization and substitution test
        above passes. Every caller-supplied or caller-selected
        secret-store reference must therefore pass an ACL or capability
        check before resolution, scoped to the requesting actor, the full
        skill stack, the deployment (tenant, `project_id`,
        `environment_id`, and execution boundary), and the requested
        action/operation, evaluated against the same fresh, monotonic,
        rollback-protected authorization state as the other freshness
        domains and failing closed when that state is unavailable, with an
        unauthorized-secret-reference negative test proving a request
        naming a secret the actor and skill are not entitled to use for
        that operation is refused before the secret is resolved, with no
        disclosure and no side effect.
        Binding the final arguments and the originating audit hash pins the
        references the human saw, not the bytes they designate: when the
        approved request names a mutable manifest or configuration file, an
        attacker can replace that file's content after the human approves
        it but before the grant is consumed: the actor, action, final path
        arguments, audit hash, and every bound enforcement identity still
        match, and the fresh evaluation snapshots the replacement, minting
        a valid receipt for bytes the human never reviewed (the
        authorization-to-handler content-binding requirement below closes
        only the subsequent authorization-to-execution window). The grant
        and its approval evidence must therefore also bind the content
        digest or immutable snapshot identity of every mutable file or
        security-relevant by-reference input the reviewed request
        designates, and grant consumption must re-resolve each reference
        and reject the grant when the current content no longer matches
        what was reviewed, with a reviewed-content substitution negative
        test that approves a request naming a mutable manifest, replaces
        that file's content before presenting the grant, and proves
        consumption is refused without a side effect. Re-resolving the
        digest and then letting the fresh evaluation read the path again
        leaves a check-to-snapshot gap when another workload can mutate
        the reviewed file concurrently: the reviewed bytes can match at
        the consumption check, be replaced immediately afterward, and be
        snapshotted into a valid executable receipt for content the human
        never reviewed, an interleaving the sequential substitution test
        above cannot catch. Consumption must therefore be atomic with
        capture: each reviewed reference is resolved once into an
        immutable verified snapshot (or read and verified through a
        protected handle), and exactly that verified snapshot or handle
        is what the fresh evaluation binds into the receipt and the
        execution consumes, never a second independent read of the
        mutable path, with a concurrent replace-versus-consume negative
        test racing a content replacement against grant consumption and
        proving no interleaving yields a receipt or side effect over
        bytes that differ from what was reviewed.
        Binding and atomically capturing the reviewed content still shows
        the approver only its digest: when the approved request names a
        mutable manifest or configuration file, the trusted channel
        renders an opaque hash for that reference, so a compromised
        requester can supply destructive content before the approval
        prompt is generated, no post-approval substitution ever occurs,
        every digest-binding, substitution, and replace-versus-consume
        test above passes, and the human approves bytes they were never
        shown. The trusted approval channel must therefore render, for
        each referenced-content binding in the payload being signed, the
        referenced content itself, a trusted semantic summary, or a
        reviewable diff, each derived by the trusted channel from exactly
        the verified bytes the bound digest names (never from
        caller-supplied prose or requester-computed renderings), and
        refuse to collect a signature over a referenced-content binding
        it did not render in one of those forms, with a
        destructive-referenced-content negative test that supplies a
        destructive manifest before the prompt is generated, presents
        only its digest to the approver, and proves an approval collected
        without the content, summary, or diff rendered yields no
        consumable grant and no side effect.
        A reviewable diff authenticates the rendering process, not the
        comparison base: when the referenced artifact is new or its
        prior version is attacker-controlled, the trusted channel can
        satisfy the diff alternative by computing an empty or benign
        diff against an identical or attacker-staged unreviewed
        baseline, so the bound digest names destructive content the
        approver never sees while every destructive-referenced-content
        test above passes. A diff rendering must therefore be computed
        only against an independently approved baseline, with that
        baseline's digest and approval provenance bound into the
        payload being signed and displayed alongside the diff, and when
        no such approved baseline exists (a first approval, or a
        baseline whose approval provenance cannot be authenticated) the
        trusted channel must fall back to rendering the full content or
        a trusted semantic summary rather than any diff, with a
        first-approval/substituted-baseline negative test proving a
        diff computed against a new, unreviewed, or attacker-substituted
        baseline is refused as approval evidence and only a
        full-content rendering, trusted summary, or approved-baseline
        diff yields a consumable grant.
        Deriving the summary inside the trusted channel authenticates
        its source, not its semantic completeness: when the referenced
        input uses a schema or version the summarizer does not fully
        support, or carries behavior the summarizer's rendering omits, a
        lossy trusted semantic summary hides a destructive field while
        the channel still signs the exact content digest, so the
        approver approves bytes whose destructive behavior the rendering
        never showed and every destructive-referenced-content test above
        passes. A trusted semantic summary is therefore admissible as
        approval evidence only when the trusted channel schema-validates
        the referenced content against a schema whose behavior-relevant
        fields and sections the summarizer provably renders completely
        (every element that can cause or parameterize an operation is
        rendered, or its unrendered presence is explicitly and visibly
        surfaced), and the channel must refuse summary rendering and
        fall back to the safely escaped full content whenever the
        content fails schema validation, uses an unsupported schema or
        version, or contains sections the summarizer cannot account
        for, with an omitted-section negative test supplying a manifest
        whose destructive operation lives in a section the summarizer
        omits and proving the lossy summary is refused as approval
        evidence and only the safely escaped full-content rendering or
         a behavior-complete rendering yields a consumable grant.
         Schema-validating the summary and deriving renderings from the
         verified bytes still presume the rendering reaches the approver
         whole: when a referenced manifest exceeds the trusted channel's
         display, transport, or model-token limits, the channel can sign
         the exact bound digest while delivering a truncated full-content
         or diff rendering, so a destructive tail beyond the truncation
         point is never reviewed and every destructive-referenced-content,
         baseline, and omitted-section test above passes. Full-content and
         diff renderings must therefore carry a maximum reviewable size
         and a complete-delivery check verifying the rendering presented
         to the approver covers the entire verified bytes the bound digest
         names, and when the content exceeds what the channel can
         completely render and the approver can review, the channel must
         fall back only to a behavior-complete trusted summary admissible
         under the schema-validation rule above or refuse to collect the
         approval, never a truncated rendering, with a
         large-referenced-content negative test supplying a manifest whose
         destructive operation lies beyond the channel's rendering limit
         and proving an approval collected over a truncated rendering
         yields no consumable grant and no side effect.
         Rendering the verified bytes faithfully re-opens for content the
        display-spoofing gap the bound-field escaping rule above closes
        for fields: a referenced manifest or configuration can carry
        ANSI terminal-control sequences, label-overwriting newlines, or
        Unicode bidirectional-control code points, so rendering the
        exact reviewed content, a summary quoting it, or a diff of it
        verbatim hides or visually reorders a destructive operation
        while the bound digest and the displayed bytes remain exact and
        every destructive-referenced-content test above passes. The
        trusted channel's content, summary, and diff renderings must
        therefore apply the same display-safety discipline as bound
        fields: reject referenced content carrying unsafe
        display-control code points, or render every such code point as
        an unambiguous visible escape without changing the verified
        bytes the bound digest names, with a referenced-content
        spoofing negative test proving a referenced manifest carrying
        ANSI terminal-control, label-overwriting newline, and Unicode
        bidirectional-control payloads either fails rendering or is
        displayed with the destructive operation unambiguously visible,
        and that an approval collected over a spoofed rendering yields
        no consumable grant and no side effect.
        Rendering and digest-binding the referenced content presume the
        content is safe to show and to commit to: when a reviewed
        by-reference input is itself a credential, a private key, or
        another low-entropy secret, binding its ordinary content digest
        into the grant evidence publishes an offline-guessable
        commitment through artifacts that travel beyond the trusted
        boundary, and rendering the content or a diff on the approval
        channel discloses the secret to the approver and to every
        surface the prompt reaches; the secret ambient-input handling
        later in this design covers only ambient inputs an admitted
        handler consumes, never the explicit referenced inputs reviewed
        here. Reviewed by-reference inputs must therefore also be
        classified for secrecy, and a secret-classified referenced
        input bound through a secret-store version identifier or a
        keyed commitment (a MAC or salted commitment whose key never
        leaves the trusted gate) verified against the captured bytes
        inside the trust boundary rather than through an ordinary
        content digest, with the trusted approval channel rendering a
        non-disclosing trusted description for that reference (the
        secret's identity, store version, and relevant metadata, never
        its value, an unkeyed digest of it, or a content diff), grant
        evidence, receipts, and ceiling records carrying only the
        non-disclosing binding, and a secret-reference serialization
        negative test proving that for a secret-classified referenced
        input no approval prompt, grant evidence, receipt, or ceiling
        record emits the value or any offline-guessable digest of it,
        while substitution of the referenced secret between review and
        consumption is still detected and refused without a side
        effect.
        Binding the policy bundle id/version detects substitution, not
       rollback: when an older, more permissive policy bundle and its
       active tenant binding are restored together, receipt issuance,
       grant consumption, and execution all observe the same stale
       policy, every bound identifier matches what those checks consult,
       and an action the current policy newly denies can execute if it
       remains inside the skill ceiling; `docs/SECURITY_MODEL.md` already
       records that no active/stale/revoked policy lifecycle registry
       exists today to catch this. The currently active policy bundle
       identity and version must therefore be held in monotonic,
       rollback-refusing freshness state outside agent and child-process
       write authority (the same trust class as the ceiling freshness
       records and the grant ledger), with receipt issuance, grant
       consumption, and execution each validating the policy bundle in
       force against that state and failing closed when the bundle is
        older than the recorded active version or the state is
        unavailable, and a matched bundle-and-binding rollback negative
         test that restores an older permissive bundle together with its
         active tenant binding and proves a request the current policy
          denies yields no executable receipt and no side effect.
          Rollback-refusing freshness names the newest bundle, not where it
          applies: when one tenant hosts staging and production with
          different active policy bundles, freshness state keyed only to the
          tenant lets a staging bundle and its active binding be selected
          while issuing or executing a production receipt whose `project_id`
          and `environment_id` fields still verify, because nothing scopes
          the active-bundle record to the deployment dimensions the receipt
          binds. Active policy freshness and its validation must therefore
          be keyed by tenant, `project_id`, `environment_id`, and execution
          boundary, with receipt issuance, grant consumption, and execution
          each validating the policy bundle in force against the freshness
          record for exactly the deployment context the receipt binds and
          failing closed on mismatch or missing scope, and cross-project and
          cross-environment policy-substitution negative tests proving a
          bundle active for one project or environment cannot validate
          issuance or execution of a receipt bound to another.
          Identity and version name the bundle, not its bytes: a policy
         bundle or custom policy implementation mutated in place while
         retaining its id and version satisfies every freshness and
         lease check above, so the changed policy can mint a valid
         receipt for an action the reviewed bytes denied; the current
         tenant path demonstrates the gap by assigning
         `policy_hash=policy.version` rather than hashing the loaded
         implementation or serialized bundle. The freshness record and
         the receipt must therefore bind a content digest computed over
         the policy's code, configuration, dependencies, and applicable
         runtime (not its declared identity and version alone), and
         evaluation must run only over immutable verified bytes matching
         that digest, with a same-version mutation negative test that
         mutates a policy bundle in place while retaining its id and
           version and proves an action the reviewed bytes denied yields
           no executable receipt and no side effect.
           A digest over the policy's configuration also publishes a
           commitment to what that configuration contains: when a policy
           construction input carries a credential, token, private
           allowlist value, or another low-entropy secret, binding an
           ordinary content digest of the configuration into the
           freshness record and the receipt exposes an offline-guessable
           commitment to anyone who knows the surrounding code and the
           non-secret configuration, and the secret-handling rules
           elsewhere in this design cover argument fields, reviewed
           by-reference inputs, and handler ambient inputs, never policy
           construction inputs. Secret-classified policy configuration
           must therefore be bound through a secret-store version
           identifier or a keyed commitment (a MAC or salted commitment
           whose key never leaves the trusted gate) verified against the
           captured bytes inside the isolated evaluator, with freshness
           records, receipts, and ceiling records carrying only that
           non-disclosing binding alongside the ordinary digest over the
           non-secret remainder, and a policy-secret serialization
           negative test proving that for a policy whose configuration
           carries a secret no freshness record, receipt, or ceiling
           record emits the value or any offline-guessable digest of it,
           while substitution of the secret configuration between review
           and evaluation is still detected and refused without a side
           effect.
           A content digest binds the bytes, not the heap: the kernel
          accepts an arbitrary `Policy` instance and invokes it
          repeatedly, and an implementation can retain mutable in-memory
          state that changes its decisions between evaluations without
          any change to its code, configuration, dependencies, or
          version (the fail-closed test suite's flip-flop policy already
          demonstrates decisions alternating across calls), so a
          stateful policy whose digest was approved while it denied a
          call can later mint an `ALLOW` receipt for the same call while
          every digest, freshness, and immutable-verified-bytes check
          above passes. Policy evaluation must therefore be isolated
          from mutable runtime state: each evaluation runs against a
          stateless or freshly instantiated policy constructed only from
          the verified bytes and bound configuration, or any persistent
          evaluation state is treated as policy input, captured in an
          authenticated state snapshot whose identity is bound into the
          freshness record and the receipt and validated at issuance,
          consumption, and execution, failing closed on mismatch, with a
           state-mutation negative test that mutates a policy instance's
           in-memory state between evaluations while retaining its code,
           configuration, dependencies, and version and proves an action
           the approved state denied yields no executable receipt and no
           side effect.
           Statelessness isolates the heap, not the environment: a
           policy's `evaluate` can read an environment variable, file,
           database row, clock, or network service, and a freshly
           constructed instance built only from the verified bytes and
           bound configuration still consults that external input, so the
           input can change between approval and evaluation without
           changing the content digest, the constructor configuration, or
           any authenticated heap-state snapshot, and the altered policy
           mints an executable `ALLOW` receipt while every digest,
           freshness, and state check above passes. Policy evaluation
           must therefore run in a capability-isolated environment where
           every input is explicit and authenticated (no ambient
           environment, filesystem, database, clock, or network reads
           reachable from `evaluate`), or every external input the policy
           consults must be captured in an authenticated snapshot whose
           identity is bound into the policy freshness record and the
           receipt and validated at issuance, consumption, and execution,
           failing closed on mismatch or on any external read outside the
           snapshotted set, with an external-state substitution negative
           test that alters an environment variable, file, or other
           external input the policy reads between approval and
           evaluation while retaining its code, configuration,
           dependencies, and version and proves an action the approved
           external state denied yields no executable receipt and no side
           effect.
           Validating policy freshness at issuance, consumption, and execution
        still leaves a check-to-launch race the rollback test does not
        cover: the gate validates a receipt against the then-active policy
        version, a policy transition then installs a version that denies
        the action, and the already-validated request still launches
        afterward under the superseded policy. Unlike the ceiling and
        invocation transitions elsewhere in this design, nothing above
        serializes policy-freshness validation with receipt consumption and
        launch, so that validation must be made atomic with the
        active-policy transition: launch holds a policy-version lease or
        epoch check acquired atomically with the freshness validation and
        consumed with the receipt (one transaction, or an epoch recheck at
        launch that fails closed when the active policy changed since
        validation), with a concurrent policy-update-versus-launch negative
        test racing a policy transition that newly denies the action
        against an in-flight validated request and proving no interleaving
        lets the side effect run under the superseded policy. A lease that
        ends at launch still stops short of the effect: an admitted handler
        can queue work and an allowed script can perform its governed write
        after spawning, so the launch commits under policy v1, the lease
        ends, and policy v2 denies the action before the actual side effect
        occurs, a gap the shell containment section below makes explicit by
        distinguishing launch from the launched process's transitive
        effects, which a launch-scoped test therefore cannot close. The
        policy-version lease must be held until the governed effect commits
        or completes, or the launched work must remain revocable or
        brokered so a policy transition revokes or re-validates in-flight
        work before its effect commits (the same revocable-lease discipline
        the ceiling-revocation requirement applies to running work), with a
        delayed post-launch effect negative test racing a policy transition
        that newly denies the action against a launched process whose
        governed effect occurs after launch and proving the effect never
        commits under the superseded policy.
        The decision identity above still omits the enforcement context the
      fresh evaluation will run under: while a grant sits unconsumed, the
      active ceiling record, the executor profile, the permission-language
      version, or an admitted handler's deployment can be re-approved or
      upgraded, every bound request field and the originating audit hash
      still match, and the fresh evaluation then mints a receipt under
      versioned enforcement and implementation identities the approving
      human never saw. The grant must therefore also bind the versioned
      enforcement and implementation identities in force at approval (the
      active ceiling record and version, the executor profile identity and
      version, the permission-language version, and the admitted handler
      deployment digest the request resolves to), and consumption must
      recheck each of them against the identities active at fresh
      evaluation, failing closed on any change, with a context-substitution
      negative test that approves a request and then substitutes the active
      ceiling or the admitted handler before presenting the grant, proving
      the stale grant is rejected without a side effect. Those identities
      version the enforcement machinery, not the handler's ambient inputs:
      an unnamed feature flag, environment value, configuration default,
      or service-discovery record the admitted handler depends on can
      change after human approval but before grant consumption while
      every identity above stays unchanged, the fresh evaluation then
      issues a receipt bound to the new configuration, and the
      launch-time pinned-configuration rule faithfully executes behavior
      the approver never reviewed. The grant and its approval evidence
      must therefore also bind the handler's security-relevant ambient
      configuration snapshot (the resolved values or content digests of
      those flags, environment values, configuration defaults, and
      service-discovery records, as enumerated at handler admission), and
      consumption must recheck the currently resolved configuration
      against that binding, failing closed on any change, with an
      approval-to-consumption configuration-substitution negative test
      that approves a request, changes an ambient flag or
      service-discovery record before presenting the grant, and proves
      the grant is refused without a side effect. Those versioned
      identities still do not pin the principal the handler will act as:
      the admitted handler resolves a mutable ambient credential or default
      context, so while the grant sits unconsumed that credential can be
      repointed from the approved staging role to a production role with
      the ceiling record, executor profile, permission-language version,
      and handler deployment digest all unchanged; consumption then passes,
      the fresh evaluation mints a receipt bound to the new principal, and
      the execution-time principal re-resolution also passes because
      production is now the current designation. The grant and its approval
      evidence must therefore also bind the effective credential principal
      (the stable principal, account, or role identifier, with its scope
      and trust epoch) that the handler's ambient credential resolved to at
      approval, and consumption must recheck that binding against the
      currently resolved principal, failing closed on any change, with a
      credential-substitution negative test spanning approval to grant
      presentation: approve a request while the handler resolves the
      staging principal, repoint the ambient credential to production, and
      prove the grant is refused without a side effect. Rechecking the
      principal at consumption still does not recheck where the effect
      lands: the same principal can remain valid for multiple clusters,
      projects, regions, or namespaces, so while the grant sits unconsumed
      a mutable default target can move from the approved staging context
      to production with the principal, ceiling record, configuration
      snapshot, and handler deployment digest all unchanged; consumption
      then passes, the fresh evaluation mints a receipt bound to the newly
      current production target, and the launch-time target check also
      passes because the receipt already names that target. The grant and
      its approval evidence must therefore also bind the resolved ambient
      target context (the endpoint, cluster or project, region, namespace,
      and equivalent target identifiers) the admitted footprint resolved
      to at approval, and consumption must recheck that binding against
      the currently resolved target, failing closed on any change, with an
      approval-to-consumption target-substitution negative test that
      approves a request while the default target designates staging,
      repoints the target context to production before presenting the
      grant, and proves the grant is refused without a side effect.
      Binding the
      originating audit hash also presumes the bound event persists: when a
      governed skill can write the local audit store, it can delete or
      truncate the recorded escalation after the grant is issued, and the
      grant still consumes and the freshly issued receipt still executes
      while the decision evidence the approval was predicated on is gone
      (the protected grant and receipt ledgers record the grant and the
      receipt, not the escalated decision, so they do not restore it). The
      originating audit state must therefore be held or anchored in
      authenticated, rollback-resistant storage outside agent and
      child-process write authority (the same trust class as the grant
      ledger below), and both grant consumption and execution must confirm
      the bound audit event remains present and anchored there, failing
      closed when it does not, with a negative test that deletes or
      truncates the bound audit event before presenting the grant and
      proves consumption is refused without a side effect.
      Anchoring the originating escalation event protects grants, not
      ordinary receipts: a non-approval `ALLOW` receipt binds the hash
      of its own decision event, the local audit store is then deleted
      or truncated, and the signed receipt still consumes and executes
      because the retention requirement above is scoped to the
      escalation event a grant originates from and the universal
      consumption rule does not require the bound event to remain
      anchored. Authenticated, rollback-resistant audit retention and
      execution-time presence verification must therefore apply to
      every executable receipt: the decision event each executable
      receipt binds must be held or anchored in the same trust class of
      storage, and receipt presentation must confirm that event remains
      present and anchored there, failing closed when it does not, with
      a negative test that truncates an ordinary receipt's decision
      event after issuance but before presentation and proves execution
      is refused without a side effect.
      Binding alone does not establish
    separation of duties: exact-request binding proves *what* was approved, not
    that an independent authority approved it, so when the requesting actor is
    itself an authenticated human, nothing above stops that same principal from
    granting its own approval. The grant must therefore be issued by an
    authorized approver distinct from the requesting actor — the separation the
    existing `escalation.py::approve_escalation` path already enforces by
    rejecting a validator whose identity equals the proposer — and a
    self-approval negative test through the real handler must prove a grant
    issued by the requesting principal for its own request is rejected without
     a side effect. Comparing credential or opaque principal identifiers is
     not comparing humans: `docs/CLAIMS.md` already records that two
     identities controlled by one person are distinct principals to the
     kernel and that no built-in IAM closes that gap, so a single human
     holding two credentials can submit the request under one and approve it
     under the other while the inequality check and the self-approval test
     both pass. An independent-human approval claim must therefore compare
     requester and approver by an authoritative stable human-subject
     identifier bound into both credentials at authentication from the
     organization's identity provider or an equivalent authoritative
     directory, failing closed when that mapping is unavailable, with a
     same-human negative test proving a request submitted under one
     credential and approved under a second credential mapped to the same
     human subject is rejected without a side effect; where no authoritative
     human-subject mapping exists, the check provides principal-level
     separation only, that limitation must be recorded explicitly in the
     ceiling record, the approval evidence, and the receipt, and the design
     must not represent the check as independent-human approval.
     Distinctness and human authentication are verified against
     the credential that signed the grant, not against the approver's current
     standing: when an approver's role or credential is revoked after
     compromise, an unconsumed grant signed with the retired credential still
     satisfies every check above, and the signer-trust requirements later in
     this design protect the receipt-issuance key, not the human approval
     credential, so a post-revocation approval can still yield a freshly
     signed executable receipt. The grant must therefore bind the approver's
     credential and role identifiers, and grant consumption must revalidate
     both against fresh, monotonic, rollback-protected approver-authorization
     and credential-revocation state (the same trust class as the grant
     ledger below), failing closed when the credential is revoked, the role
     is withdrawn, or that state is unavailable, with a post-revocation
       negative test proving a grant signed by a since-revoked approver
       credential, or issued under a since-withdrawn approver role, is rejected
       at consumption without a side effect. An active credential and a held
       role still say nothing about scope: a role authorized only for another
       project, environment, tenant, or action class remains active, so a
       staging-only or read-only approver can sign a production or destructive
       approval payload while the credential and role identifier checks above
       pass. Approver revalidation at consumption and at the execution gate
       must therefore check the approver's authorization state against the
       exact bound request scope, the tenant, `project_id`, `environment_id`,
       execution boundary, and the action/effect class rendered to that
       human, failing closed when the approver's authority does not cover
       that scope, with an out-of-mandate approver negative test proving a
       grant signed by an approver whose active role is authorized only for a
       different project, environment, tenant, or action class is rejected at
       consumption without a side effect. Revalidation alone still leaves a
      validate-then-consume race: the consumer can validate the old active
      authorization state, the revocation can then commit, and the
      already-validated grant can still be consumed to mint a fresh executable
      receipt after the approver lost authority, while the sequential
      post-revocation test above passes. Approver-state validation, the
      grant's compare-and-consume, and receipt issuance must therefore be
      serialized against approver credential and role transitions (for
      example, via an approver-authorization epoch or lease acquired
      atomically with consumption and rechecked at issuance commit), so that
      issuance either commits before the revocation takes effect or fails
      closed, with a concurrent revoke-versus-consume negative test racing an
       approver credential or role revocation against grant consumption and
       proving either the executable receipt was issued before the revocation
       committed or consumption is refused without a side effect, never both.
       Serialized consumption still ends the approver's accountability at
       issuance: when an approver compromise is discovered after grant
       consumption has minted the executable receipt but before that receipt
       is first presented, revoking the credential or role has no effect,
       because the execution gate revalidates the policy, signer, and handler
       freshness domains but not the approver, so an attacker can pre-mint an
       unused receipt with the compromised credential and execute it after
       revocation while the revoke-versus-consume test passes (the revocation
       there races consumption, not execution). Approval-gated receipts must
       therefore bind the approver's credential and role identifiers and the
       approver-authorization epoch under which the grant was consumed, and
       the execution gate must revalidate that state against the same fresh,
       monotonic, rollback-protected approver-authorization and
       credential-revocation store, serialized with receipt consumption and
       launch under the same epoch-or-lease discipline as the other freshness
       domains, failing closed when the credential is revoked, the role is
       withdrawn, or the bound epoch is superseded, with a negative test
        revoking the approver credential after receipt issuance but before the
        receipt is first presented and proving the receipt is refused at the
        execution gate without a side effect. Execution-gate revalidation
        still ends the approver's accountability at launch: an approved
        handler that queues work or an allowed script that defers its side
        effect can commit launch while the approver is still authorized, this
        launch-scoped lease can end, and the approver credential can then be
        revoked before the deferred effect occurs, so a grant forged during a
        subsequently discovered approver compromise still takes effect after
        revocation, unlike the effect-held actor, signer, policy, profile,
        and handler-admission leases elsewhere in this design, while the
        pre-presentation revocation test above passes because it races
        revocation against presentation, not against a deferred effect. The
        approver-authorization lease must therefore be held until the
        governed effect commits or completes, or the launched work kept
        revocable or brokered so approver credential or role revocation
        revokes or re-validates in-flight and queued work before its effect
        commits, with a delayed-effect approver-revocation negative test
        revoking the approver credential after launch but before a deferred
        side effect and proving the effect either committed before the
        revocation or never occurs.
        Single-use must hold under concurrency:
    marking the grant used at execution time is too late, because two
    evaluations presenting the same still-unused grant could each validate it
    and mint separate executable receipts before either execution burns it, so
    both side effects run while a second-execution replay test still passes.
    Consuming the grant must therefore happen at receipt issuance as an atomic
    compare-and-consume (or an idempotent issuance operation keyed on the
    grant) against shared durable state, so at most one executable receipt can
    ever be minted from one grant. Atomic consumption presumes the grant
    ledger's own integrity: if a governed skill or child process can write or
    restore that shared state, it can delete a consumed grant's consumption
    record or roll the ledger back to an earlier snapshot, resurrecting a
    consumed, unexpired grant so a second distinct signed receipt is minted
    from it — and because the receipt-consumption ledger accepts each distinct
    receipt once, the promised one-grant/one-side-effect bound is lost while
    every grant-race test above still passes. The grant ledger must therefore
    itself be authenticated, monotonic and rollback-refusing, and held outside
    agent and child-process write authority — the same trust class required of
    the receipt-consumption store below — with a grant-ledger tamper/rollback
    negative test proving that deleting or rolling back a consumed grant's
    record before re-presenting that grant does not allow a second executable
    receipt to be minted from it. Issuance-time consumption bounds minting,
    not execution: the one minted `ALLOW` receipt is itself a bearer
    credential, and an execution gate that is stateless across calls — as
    `execute_with_receipt` is without a shared receipt-consumption ledger —
    would execute that same receipt's side effect repeatedly while every
    grant-race test above still passes. Approval-gated receipts must therefore
    also be consumed atomically at the execution gate, against shared durable
    state of the same class as the grant ledger, so one grant yields at most
    one executable receipt and that receipt yields at most one execution.
    Negative tests must prove a grant
    presented for altered arguments or a different skill, an expired grant, and a
    grant replayed for a second execution are all rejected without a side effect,
    and a concurrent-use test must prove that two evaluations racing on the same
    grant yield exactly one executable receipt and at most one side effect —
    plus a concurrent-replay test of the issued receipt itself, presenting the
    one minted receipt to the execution gate in parallel and proving the side
    effect runs at most once.
   `docs/skills/skill-schema.md` is then updated to record that mapping so cards,
   validators, and the future executor read exactly one contract.
5. **Skill identity and permission ceiling.** A trusted name/version/artifact digest per
   skill, plus an independently reviewed maximum permission set held outside the skill.
   Without these, step 6 would enforce a caller-controlled declaration. Before OMS
   signing lands, that artifact digest is the security identity everything below binds
   to (the ceiling's version-binding, the executed snapshot, the loader-issued origin
   context, and the receipt), so its computation must itself be defined, not left to
   the implementation. Hashing file contents in traversal order while omitting paths,
   entry types, modes, or unambiguous length boundaries lets structurally different
   skill trees collide on the same digest without breaking the underlying hash (the
   same bytes redistributed across files or paths), while every listed single-file
   mutation test still passes. The digest must therefore be computed over a versioned,
   collision-resistant canonical tree manifest that binds, for every entry, its
   normalized relative path, entry type, relevant mode bits, and content length and
   hash under an unambiguous, length-delimited encoding, with the manifest scheme
   version bound into ceiling records and receipts so a verifier rejects a digest
   computed under an unknown scheme, and a structural-substitution negative test
   proving a tree that permutes the same content across different paths or entry
   boundaries yields a different digest and is rejected. Normalized relative
   paths that are distinct on the case-sensitive filesystem where verification
   runs can still collide on the admitted host: a case-folding or
   Unicode-normalizing host filesystem resolves entries such as
   `scripts/run.py` and `Scripts/run.py` (or NFC/NFD variants of the same
   name) to the same file, the digest validly binds both entries, and
   installation order then decides which entry's bytes execute under the
   allowlisted path — so the bytes of a nominally unapproved entry can run
   under an approved name while every digest check passes. Manifest
   validation must therefore define path canonicalization for each supported
   host filesystem (case folding and Unicode normalization form included) and
   reject any manifest whose entries collide after canonicalization for the
   target host, with a cross-platform path-collision negative test proving a
   manifest containing case-folded or Unicode-normalization-equivalent path
   pairs is rejected rather than installed. Canonicalization and collision
   rejection still authenticate names rather than confine them: when snapshot
   construction consumes an archive or installer manifest, an entry can be
   syntactically relative yet normalize to a parent traversal (`../...`), or
   be absolute, and the canonical manifest then merely authenticates that
   escaping name; extraction materializes or overwrites a host file outside
   the skill root before any runtime receipt enforcement, while the
   structural-substitution, path-collision, and symlink tests all pass
   because each checks the manifest, never where entries land. Manifest
   validation and snapshot construction must therefore reject any entry that
   is absolute or whose normalized path does not remain strictly beneath the
   skill root, and extraction must be confined descriptor-relative to the
   skill root (openat-style resolution that cannot follow `..` or absolute
   names out of it) rather than trusting the normalized string, with
   absolute-path and parent-traversal negative tests proving an archive or
   manifest entry naming an absolute host path or a `../`-escaping path is
    rejected rather than materialized outside the snapshot root. Confined
    extraction bounds where entries land, not what extracting them costs:
    an attacker-supplied compressed archive can expand a tiny input into
    enormous regular files, sparse entries that materialize to huge sizes,
    or millions of individually valid entries before any runtime executor
    budget applies, exhausting the admitting host's storage, memory, or
    inodes while every path stays beneath the root, every entry has an
    allowed type, and every digest verifies. Snapshot admission must
    therefore impose resource limits on extraction itself (a maximum entry
    count, per-entry and total-uncompressed-size ceilings, sparse-file
    materialization limits, and a maximum decompression ratio), failing
    admission closed when any limit is exceeded, with an archive-bomb
    negative test proving a high-ratio or many-entry archive is rejected
     during admission without exhausting the admitting host. Those extraction
     limits bound what admission materializes, not what admission itself
     spends deciding: an attacker can supply an enormous container holding
     few small entries, trailing padding, or parser-pathological metadata,
     so the entry-count, uncompressed-size, sparse-file, and
     decompression-ratio limits all remain satisfied while merely reading
     and parsing the archive exhausts the admitting host's CPU, memory,
     disk, or wall-clock time, making rejection itself the exhaustion
     vector. Admission must therefore also impose a maximum
     compressed/container input size and run snapshot parsing and
     extraction under enforceable CPU, memory, temporary-storage, and
     deadline budgets, failing admission closed when any budget is
     exhausted, with a parser-resource negative test proving an oversized
     container or one carrying parser-pathological metadata is rejected
     within those budgets and the admitting host's CPU, memory, storage,
     and responsiveness are preserved. Paths, entry types,
   mode bits, lengths, and content hashes still leave security-relevant
   filesystem metadata unbound: a skill installed from a privileged archive can
   carry ownership, POSIX ACLs, security labels, or extended attributes such as
   a Linux `security.capability`, and changing that metadata changes what
   identical file bytes may access or execute with while the manifest digest is
   unchanged; the read-only snapshot below then preserves rather than
   authenticates whatever metadata existed at authentication time, so every
   listed content-mutation test can pass for an artifact carrying unapproved
   execution authority. Snapshot construction must therefore strip and
   normalize security-relevant metadata to a fixed approved baseline (no
   setuid/setgid or capability bits, canonical ownership, no ACLs or
   security-relevant extended attributes), or every security-relevant
   ownership, ACL, and extended-attribute value must be bound into the manifest
   digest and rechecked when the snapshot is constructed, with a
   metadata-substitution negative test proving an artifact whose bytes match
   the approved digest but whose ownership, ACL, or `security.capability`
   metadata differs is rejected rather than executed with that authority.
   "Outside the
   skill" is necessary but not sufficient: if the agent, or any skill it runs, can
   write the location holding the ceiling record, the caller can widen the ceiling
   before issuance, the receipt then faithfully binds the tampered value, and the
   executor accepts capabilities nobody approved. The ceiling record must therefore
   live outside agent write authority entirely, be authenticated (integrity-protected
   under a key or review path the agent cannot exercise), and be version-bound to the
   specific skill digest it approves. Authenticity and version-binding alone cannot
   detect rollback: an authentic older ceiling remains correctly version-matched to
   its authentic older skill digest, so reverting both together satisfies every
   signature and binding check while restoring capabilities that were since
   narrowed. Validation must therefore also consult trusted freshness state — an
   active-version/revocation record or monotonic counter held outside agent write
   authority that identifies the currently approved ceiling-and-skill pair — and
   reject any pair that is not the active one, with tamper and rollback tests at
   both issuance and execution proving that a widened, digest-mismatched, or
   reverted ceiling record is rejected, including the rollback of a previously
   valid ceiling-and-skill pair as a matched set. Authenticity, version
   binding, and freshness still authenticate only the ceiling-and-skill pair
   and its currency, not where that pair applies: when the same skill digest
   is installed in multiple tenants or execution boundaries, a ceiling
   approved for tenant A can be selected as the active pair while issuing a
   tenant-B receipt, and binding tenant B into that receipt does not prove
    the ceiling was ever approved there. Tenant, execution boundary, and
    executor profile are also not the finest applicability scope: project
    and environment are distinct trust dimensions in this repository's v2
    receipt model, and staging and production can share a tenant,
    execution boundary, and executor profile, so a ceiling-and-skill pair
    approved for one project or environment could otherwise be selected
    as the active pair while authorizing a receipt in the
    other. Every ceiling record and active-pair
    entry must therefore also be bound to the tenant, `project_id`,
    `environment_id`, execution boundary, and
    applicable host or executor profile it was approved for, with those
    fields rechecked against the requesting deployment context at both
    issuance and execution, and cross-tenant, cross-project,
    cross-environment, and cross-boundary substitution
    negative tests proving a ceiling approved in one tenant, project,
    environment, or execution
    boundary cannot authorize a receipt issued or executed in
    another. Freshness checks at issuance
   and execution bound only work that has not yet launched: a long-running or
   detached process started under a then-active pair has already passed both
   checks, so revoking or narrowing the pair afterward leaves that process's
   ambient file and network capabilities intact, and the rollback and
   revocation tests above can pass while stale authority keeps producing side
   effects. Revocation must therefore either be made effective against running
   work (process trees and brokered resources launched under a
   ceiling-and-skill pair are tied to a revocable capability lease that the
   host closes when the active pair changes; lease acquisition must itself be
   atomic with the revocation transition, because closing "every currently
   registered lease" leaves a race in which execution validates the outgoing
   pair, revocation switches the active pair and closes the registered
   leases, and the already-validated request then registers a fresh lease and
   launches after revocation — active-pair validation and lease registration
   must be serialized against the pair-change transition (one transaction, or
   an epoch check at registration that fails closed when the pair changed
   since validation), with negative tests proving a still-running child
   process's file and network effects are cut off after revocation and a
   concurrent revoke-versus-launch race proving no stale process survives or
   starts regardless of interleaving) or be explicitly scoped to future
   launches only, with that
   residual risk recorded in the ceiling record and receipt and a test
   documenting that a pre-revocation process retains its capabilities until it
   exits. A pinned
   digest proves what was approved, not what executes: if a bundled script or
   resource changes after the loader authenticates the artifact digest but before
   the tool runs, the loader context and receipt still carry the old trusted
   digest while the shell reads the modified bytes. Identity must therefore be
   bound to what actually executes by running skills — scripts and bundled
   resources alike — from a read-only, immutable content-addressed snapshot taken
   at authentication time. Atomic pre-launch digest revalidation is not an
   acceptable substitute: it leaves a window between the recheck and `exec`, and
   says nothing about resources a script reads after launch, so authenticated
   bytes could still change while the receipt carries the approved digest. The
     executed snapshot digest is bound into the receipt, with tests mutating skill
     bytes both between load and launch and after launch (a bundled resource read
     mid-execution) proving the mutated content is never executed or read.
     A read-only snapshot authenticates the bytes behind a name, not the
     binding of the name itself: when the content-addressed snapshot is
     stored beneath a directory the agent or another workload can rename,
     replace, or mount over, the snapshot's directory entry can be swapped
     after authentication, and a later loader or launcher that reopens the
     same snapshot path consumes attacker-controlled instructions or
     scripts while the receipt still carries the approved digest. The
     snapshot and every ancestor directory used to resolve it must
     therefore be outside attacker namespace-mutation authority (rename,
     replace, bind-mount, and mount-over included), or loaders and
     launchers must retain protected descriptors to the verified tree
     acquired at authentication time and load exclusively through those
     descriptors rather than re-resolving paths, with a snapshot-root
     substitution race negative test swapping the snapshot's directory
     entry or an ancestor mount between authentication and a later load
     and proving no unverified byte is executed or read.
     Immutability of the snapshot is not containment of what it references: a
     read-only content-addressed directory can still preserve a symlink such as
     `scripts/run.py -> /tmp/run.py`, whose digest and link entry are unchanged
     while the external target is replaced after authentication, so unapproved
     bytes execute while every in-snapshot mutation test passes. Snapshot
      construction and resource loading must therefore reject symlinks and other
      references that escape the snapshot, or materialize their targets inside
      the confined snapshot and include those bytes in the hashed content, with a
      negative test that mutates an external link target between authentication
      and use and proves the mutated target is never executed or read.
      Materialization is itself a read, so the permitted alternative must
      never be applied to external targets: an attacker-supplied skill can
      bundle a symlink to a host file outside the skill root, and a
      materializing admission process that follows it copies the target's
      bytes into the authenticated snapshot, disclosing any file readable
      by the admission process even though subsequent mutation is
      prevented. Materialization is therefore permitted only for link
      targets that resolve descriptor-relative to paths inside the source
      skill tree; absolute targets and targets whose resolution escapes
      the skill root are rejected at admission without ever being opened
      or read, with a negative test bundling a symlink to an out-of-root
      secret and proving admission fails with no byte of the target
      disclosed into the snapshot, no authenticated snapshot, no receipt,
      and no side effect.
      Descriptor-relative resolution constrains lexical paths, not mount
      topology: another mount-capable workload can bind-mount an
      out-of-root directory beneath the source skill tree, so the
      manifest and materialization walk stays descriptor-relative and
      lexically inside the tree while the ordinary directories and files
      it sees are out-of-root content, and a materializing admission
      process copies secrets readable only by its privileged identity
      into the authenticated snapshot without following any symlink. The
      walk must therefore pin the source root's filesystem identity and
      refuse to cross any mount boundary encountered beneath it for the
      entire manifest and materialization traversal (failing admission
      closed when a walked entry resides on a different mount than the
      pinned root), or run the whole traversal inside an immutable
      private mount namespace constructed before authentication that no
      outside workload can alter, with a mounted-subtree disclosure
      negative test bind-mounting an out-of-root directory containing a
      secret beneath a candidate skill tree and proving admission fails
      with no byte of that content disclosed into the snapshot, no
      authenticated snapshot, no receipt, and no side effect. The
      symlink rule does not cover special inodes: a bundled FIFO, Unix
      socket, or device node is neither a symlink nor a reference whose
      target can be materialized into content, so the unchanged entry can
      receive attacker-controlled bytes or reach external state after
      authentication while the manifest digest and the read-only directory
      both remain valid (the regular-file-only rule later in this design
      restricts directory capabilities, not the construction of this
      snapshot). Snapshot admission must therefore reject every entry that
      is not a regular file or directory unless that specific entry is
      separately brokered and content-bound as its own reviewed capability,
       with a bundled-FIFO negative test proving a skill bundling a FIFO or
       other special inode fails snapshot construction and yields no
       authenticated snapshot, no receipt, and no side effect.
       The regular-file rule still admits hard links: a writable source
       tree can contain a hard link to an out-of-root inode, which
       appears to this admission walk as an ordinary regular file,
       resides on the pinned filesystem, and traverses no symlink or
       mount boundary, so a privileged admission process hashes and
       copies otherwise inaccessible host content into the authenticated
       snapshot before any receipt gate runs; the hard-link controls
       later in this design govern runtime directory capabilities, not
       snapshot construction. Snapshot admission must therefore reject
       any source entry whose link count exceeds one, or safely vet
       multiply linked entries before reading them (proving every link
       to the inode resolves inside the source skill tree, or
       materializing the entry only from a private single-linked copy
       whose content the submitting identity could already read), with a
       hard-linked-secret disclosure negative test bundling a hard link
       to an out-of-root secret in a candidate skill tree and proving
       admission fails with no byte of the target disclosed into the
       snapshot, no authenticated snapshot, no receipt, and no side
       effect. That
    snapshot bounds the guarantee to bundled skill content, and the claim must
    say so: a snapshotted script still resolves its interpreter, imports
    installed packages, and invokes binaries through `PATH`, and those
    executable bytes live outside the skill directory, so they can change while
    the skill-directory digest stays identical and every skill/resource
    mutation test passes even though unapproved code controls the side effect.
    The identity guarantee is therefore explicitly scoped to bundled skill
    content, and the ambient runtime the skill executes under (interpreter,
    installed packages, `PATH`-resolved binaries) is recorded in the approval
    and receipt as an unverified boundary. Extending the guarantee over that
    runtime requires binding a content-addressed runtime image or
    interpreter/dependency closure into the approval and receipt; no broader
    identity claim may be made without that binding.
6. **Wire `permissions:` into the kernel** as a deny-only policy input bound into the
   receipt and checked against the step-5 identity and ceiling. Deny-only narrowing
   presumes a declaration exists, and absence must not be an escape hatch: the host
   schema accepts a skill with no `permissions:` block, and if absence is read as
   "no additional restriction" the implementation falls back to the full approved
   ceiling, so a new or partially migrated skill widens its authority by omitting
    the declaration while the outside-declaration tests still pass on skills that
    do declare. For skills in the governed set, a missing, malformed, or
    unrecognized permission declaration must therefore fail admission (no
    ceiling fallback, no receipt), with a real-handler negative test proving a
    governed skill lacking a valid declaration produces no receipt and no side
    effect. The governed set itself must not be decided by content
    classification: step 3 seeds it from the skills whose current prose directs
    governed capabilities, but a model-selectable skill classified as
    documentation-only can later be compromised or emit a tool instruction
    without ever entering that list, and its loader origin would then be
    accepted with no declared/approved permission intersection while the
    missing-declaration test above still passes for the skills that are listed.
    Membership is therefore defined by loadability, not prose and not the
    invocation path: every loadable skill is in the governed set regardless of
    who invokes it. Scoping the set to model-selectable or implicitly invoked
    skills would leave explicit user invocation ungoverned, and
    `disable-model-invocation: true` makes a skill unselectable by the model,
    not unloadable: a user who explicitly invokes a manual skill (the
    checked-in `maintain-acgs` and `pr-evidence` skills are exactly this
    shape) loads the same instructions with the same power to direct tool
    calls, so that path needs the same mandatory declaration and ceiling
    checks. A documentation-only skill carries an explicit
    deny-by-default/no-capability declaration (an empty permission set) rather
    than being exempted by classification, so admission fails closed for any
    loadable skill without a declaration and a tool instruction emitted
    from a nominally documentation-only skill is denied against its empty
    declared set, with real-handler negative tests proving a tool call
    originating from a documentation-classified skill with a no-capability
    declaration produces no receipt and no side effect rather than being
    governed under the agent's non-skill ceiling, and an explicit-invocation
    case proving a tool call directed by a manual skill the user explicitly
    invoked (its `disable-model-invocation` flag notwithstanding) is governed
    under that skill's declaration and ceiling, and denied when the skill
    lacks a valid declaration, rather than executing under the agent's
    non-skill ceiling. Binding is only as
   strong as receipt authentication: hash-binding the skill digest and permission
   fields makes them part of the receipt's content hash, but with an unsigned
   receipt a caller can alter those fields and recompute the hash, so mutation
   tests that change fields without rehashing prove nothing. The deployed hook
   path is exactly that unsigned case — `.claude/settings.json` selects
   `GOVE_ZONE_PROFILE=dev` and `integration.py::emit_receipt_for_hook` has no
   signer path — so this step requires signed receipt issuance for the
   skill-trust stage (the kernel's opt-in Ed25519 signing mode is the starting
   point) with verification by a trusted verifier at the executor gate against
    key material held outside agent write authority, and a recomputed-forgery
    negative test proving a receipt whose skill digest, ceiling, or permission
    fields were altered and re-hashed (and, absent the issuance key,
    re-signed) is rejected without a side effect. Write protection on key
    material is not enough, because that forgery test only holds while the
    issuance key is actually out of the attacker's reach: a shell-enabled
    skill whose grant includes ambient credentials (an option the containment
    contract below explicitly permits when documented) could read a
    filesystem-resident issuance private key and mint correctly signed
    receipts with widened skill bindings without modifying anything. The
    issuance private key must therefore also be held outside agent and
    child-process read authority: receipt signing happens through an isolated
    signer (a separate process or service boundary, or a non-exportable key in
    an OS keystore or hardware-backed store) that governed agents and their
    spawned processes can neither read nor invoke directly, reachable only
    through the issuance path that performs the checks above, and a
     key-exfiltration/unauthorized-signing negative test must prove a
     shell-enabled skill granted ambient credentials can neither read the
     issuance key material nor obtain a validly signed receipt outside the
     issuance path. Protecting the key bounds forgery only while the key is
     trusted: when an issuance key is rotated after compromise, a stale
     executor whose local trust store still honors the retired key accepts
     newly forged `ALLOW` receipts minted with the exfiltrated key, and the
     key-exfiltration test above still passes because it assumes the active
     key is unavailable. Verification must therefore not rely on a static
     verifier alone: every skill-trust receipt must bind the identity of the
     key that signed it and that key's purpose (skill-trust issuance, not any
     other signing role) into the signed content, and the execution gate must
     consult fresh, rollback-protected signer-trust state — a monotonic
     revocation/active-key record held outside agent write authority, of the
     same trust class as the ceiling freshness records — at execution time,
     rejecting any receipt whose signing key is retired or whose purpose does
     not match (`execute_with_receipt` already exposes a `revoked_keys`
     parameter at `packages/gove-zone/src/gove_zone/executor.py` as the
     starting point for that check). A retired-key negative test must prove a
     receipt minted after its signing key was retired is rejected without a
     side effect, including by an executor whose local signer-trust state is
     stale or rolled back (the rollback-refusing store, not the executor's
      memory, is what the gate must consult). Key identity and purpose scope
      what a key may sign, not where its signatures are trusted: when
      staging and production share a tenant but use different
      receipt-signing roots, a signer-trust record keyed only by key
      identity and issuance purpose lets a staging signing key authorize a
      production receipt whose `project_id` and `environment_id` fields
      otherwise verify. The v2 receipt trust model already carries a full
      tenant/project/environment trust scope (`ReceiptTrustScope`), so the
      signer active/revocation state and the execution-time lookup must be
      scoped the same way: each active-key record binds the tenant,
      `project_id`, `environment_id`, and execution boundary the key is
      trusted for, and the gate rejects any receipt whose signing key is not
      active for exactly the deployment context the receipt binds, with
      cross-project and cross-environment signing-key substitution negative
      tests proving a key trusted for one project or environment cannot
      authorize a receipt bound to another. Consulting fresh signer-trust
     state is still a point-in-time read, and key retirement can race an
     in-flight request: the gate can observe a compromised key as active,
     the retirement can then commit, and the already-validated forged
     receipt can launch afterward even though the signer is now retired,
     an interleaving the sequential retired-key test above (which mints
     the receipt after retirement) never exercises. Signer-trust
     validation, receipt consumption, and launch must therefore be
     serialized against the active-key transition: the gate acquires a
     signer-trust lease or epoch atomically with validation and holds it
     through launch, revalidating or failing closed when the epoch changes
     before the launch commits, with a concurrent revoke-versus-launch
     negative test racing key retirement against an in-flight receipt
     validated under that key, proving the launch either commits before
      the retirement takes effect or is refused without a side effect,
      never runs after it. Launch is not the effect: an allowed script or
      admitted handler can defer its governed effect, so a forged receipt
      minted under a compromised key can launch just before the key is
      retired, release a launch-scoped lease, and commit the effect
      afterward even though the signer is no longer trusted,
      contradicting the never-runs-after-it outcome above. The
      signer-trust lease must therefore be held until the governed effect
      commits or completes, or the launched work kept revocable or
      brokered so key retirement revokes or re-validates in-flight work
      before its effect commits, with a delayed-effect retirement
      negative test retiring the signing key after launch but before a
      deferred side effect and proving the effect either committed before
      the retirement or never occurs. Signing and hash-binding prove
   integrity, not that the verifier understands the new fields: during a rolling
   deployment or on a stale executor worker, skill fields encoded into an existing
   extensible receipt field would let an older gate validate the signature and the
   actor/action/argument bindings while silently ignoring the skill ceiling, and
   every new-executor test above would still pass. Skill-governed receipts must
   therefore carry a new receipt schema version or a critical purpose/extension
   marker that a verifier must reject when it does not support it, and a
   compatibility test must prove the current pre-skill executor fails closed on a
   skill-governed receipt rather than executing it under pre-skill semantics.
   Until signed issuance and
   trusted verification exist on the hook path, the skill-trust result is
   explicitly limited to non-adversarial unsigned development use and must
   never be described as enforcement. Deny-only is not a
   one-shot pre-check: existing policies can return `TRANSFORM`, and
   `kernel.py::dispatch` then executes `record.transformed_args`, so a request that
   entered within the ceiling can be rewritten into a path, command, or endpoint
   outside the declared/approved set while the receipt correctly binds those final
   arguments. The permission intersection must therefore be evaluated against the
    final executable arguments, re-running after any policy transformation and
    denying (fail closed) when the transformed request crosses the ceiling, with the
    post-transform check recorded in the receipt. Checking and binding the
    final arguments still authorizes only the argument strings, not the
    state they point at: when a final argument names mutable input outside
    the immutable step-5 skill snapshot (an allowed deployment manifest
    path, a configuration file the ceiling permits), another permitted
    writer can replace that content after the post-transform check and
    before the admitted handler reads it, so a different operation executes
    while the receipt still binds the approved path string, and the
    symlink, path-race, skill-resource, and handler-identity tests all pass
    because the pathname and the handler are unchanged. Every
    security-relevant by-reference input must therefore be bound by
    content, not by name: hashed or snapshotted at authorization time, with
    that digest or snapshot identity recorded in the receipt, and the
    handler made to consume exactly those verified bytes, either from a
    sealed or copy-on-write byte snapshot materialized at authorization
    time, or with writes to the underlying object provably excluded (an
    immutable seal or exclusive write lease held from authorization
    through the handler's read). An already-resolved descriptor alone is
    not such an exclusion: it pins the inode, not the bytes, so another
    permitted writer can overwrite the object in place after
    authorization and the same descriptor exposes the newly written
    content while every pathname-replacement and descriptor-identity
    check passes. This requires a negative test that replaces an
    authorized by-reference input's content between authorization and
    handler read, and an in-place overwrite race test that writes the
    authorized inode through another permitted descriptor (a `pwrite` on
     the same object) in that window, proving in both cases the handler
     consumes the authorized bytes or the execution is
     denied, never the swapped content. Bytes are not the whole behavior:
     when a handler's behavior depends on metadata of a by-reference
     input, its executable mode bits, extended attributes, ACLs, symlink
     status, behavior-relevant timestamps, or archive entry metadata,
     hashing only the file content lets that metadata change after
     authorization while the content digest and path still match, so the
     handler executes behavior the receipt never bound. The
     authorization-time binding must therefore capture security- and
     behavior-relevant metadata together with the bytes (snapshotted or
     digested into the same receipt binding and consumed from the same
     sealed snapshot or write-exclusion window as the content), or
     admitted handlers must be required, and verified at admission, to
     ignore any metadata the receipt does not capture, with a
     metadata-substitution negative test flipping an authorized input's
     executable mode, xattr/ACL, or symlink status between authorization
     and handler read while its content digest still matches, proving the
     handler consumes the authorized metadata or the execution is denied,
     never behavior derived from the swapped metadata. Argument-level checks are also
   insufficient for the direct filesystem capabilities: a `file_read` or
   `file_write` ceiling scoped to a directory is not enforced by validating the
   final path argument, because an allowed path can traverse a symlink to a
   location outside the ceiling, or a path component can be swapped for a symlink
   after the check and before the host opens it. Directory ceilings must be
   enforced at filesystem resolution — descriptor-relative opens with no-follow
   semantics (`openat2`-style `RESOLVE_BENEATH`) or an equivalent filesystem
    sandbox that confines the resolved target — with negative tests proving both a
     symlink escape inside an allowed path and a check-to-open path race fail to
     touch the outside location. Confinement beneath the approved root still
     leaves name matching host-naive: on a case-insensitive or
     Unicode-normalizing target filesystem, a request naming
     `.GITHub/workflows/x.yml` resolves to the same file as
     `.github/workflows/x.yml`, so a permission pattern or a consumer-registry
     carve-out expressed as `.github/workflows/**` fails to match the alias
     while descriptor-relative resolution stays beneath the approved root and
     opens the denied control artifact anyway; the host-specific
     canonicalization and collision rule above applies only to snapshot
     manifest validation, never to runtime matching. Runtime permission
     matching and every consumer-path exclusion must therefore evaluate
     patterns against the target filesystem's canonical path identity (case
     folding and Unicode normalization form included), canonicalizing the
     requested name under the target host's rules before matching, or
     matching against the resolved filesystem object's canonical identity,
     with a path-alias negative test proving a case-folded or
     Unicode-normalization-equivalent alias of an excluded path is denied on
     an aliasing host rather than admitted beneath the root. Resolution-time checks validate where a name
    pointed at open, not where the open file lives when it is written: when
    another workload can rename an already-open in-ceiling file (or one of
    its ancestor directories) into a denied directory, the skill retains the
    descriptor from the validated open and writes after the relocation, so
    the written content materializes in the denied location while every
    symlink, check-to-open, mount, and hard-link test passes because the
    open itself was clean. Writable directory ceilings must therefore either
    place writable targets in a private, immutable-to-outsiders namespace or
    view whose entries no other workload can rename or relocate (with
    results exposed to shared locations only through a controlled publish
    step), or serialize the governed write against relocation so no
    outside workload can rename or relocate the target or an ancestor
    directory while any written byte remains unpublished; a commit step
    that merely revalidates, on the still-open descriptor, that the
    target remains beneath the ceiling before each subsequent write is
    not sufficient, because bytes already written reside in the inode and
    relocate with it, becoming visible through the denied directory even
    though every later write is blocked. Written content must therefore
    land in private staging that outsiders cannot relocate and be
    published to the shared location only through a commit step that
    revalidates the destination's identity beneath the ceiling, or the
    target must be held under serialization that excludes outside
    relocation for the duration of the write, with a rename-after-open
    negative test proving that when the target is renamed into a denied
    directory after a validated open, no written content, bytes already
    written before the relocation included, ever becomes visible at the
    denied location. Resolution, rename, mount, and hard-link controls
    govern where names resolve and where written content lands, not what
    an in-ceiling object's metadata grants: with `file_write` authority
    over an in-ceiling directory, an admitted metadata operation or an
    allowed script can run `chmod`, `setfacl`, or `setxattr` on an
    in-ceiling file to expose its contents to outside principals or to
    change how another process executes it (a newly executable or setuid
    mode, a widened ACL, an altered security label or extended
    attribute), while every no-follow, beneath-resolution, mount,
    rename, and hard-link check here passes because the pathname never
    escapes the ceiling; the snapshot metadata normalization above
    applies only while constructing the immutable skill snapshot, never
    to runtime mutation of files the ceiling permits. Runtime changes to
    ownership, mode, ACLs, security labels, and extended attributes must
    therefore be defined as distinct deny-by-default capabilities, never
    implied by `file_write` or any other filesystem capability, granted
    only through explicit declaration and review and brokered under
    reviewed constraints naming the permitted targets and attribute
    transitions, with an ACL/mode escalation negative test proving a
    skill holding `file_write` over a directory cannot change an
    in-ceiling file's mode, ACL, ownership, label, or extended
    attributes to expose it to an outside principal or alter how another
    process executes it unless the metadata-mutation capability was
    explicitly declared and approved. Beneath-style resolution is a pathname
   property, not a mount property: an allowed directory can contain a bind
   mount or another mounted subtree that exposes a denied location, and
   `RESOLVE_BENEATH` still permits the access because the pathname remains
   lexically beneath the ceiling root (Linux provides the separate
   `RESOLVE_NO_XDEV` control precisely for mount-point crossings, bind mounts
   included), so the symlink, race, and hard-link tests here can all pass
   while a read or write reaches the denied tree. Directory-ceiling
   resolution must therefore also refuse to cross mount points within the
   ceiling (`RESOLVE_NO_XDEV`-style no-cross-mount resolution) or run under
   an equivalent isolation that guarantees no mounted subtree inside an
   allowed directory exposes out-of-ceiling content, with a bind-mount escape
   negative test proving an access through a mount point inside an allowed
    directory fails to reach the denied tree. No-cross-mount resolution still
    presumes the ceiling root itself is authentic: a mount-capable workload
    can bind-mount a denied tree over the allowed ceiling root before the
    broker opens that root, so traversal begins inside the substituted
    mount, `RESOLVE_NO_XDEV` observes no mount crossing, and the bind-mount
    escape test above passes because it exercises only a mounted subtree
    beneath the root, never replacement of the root itself. The ceiling must
    therefore be bound to a protected root descriptor whose mount and inode
    identity is established and verified before execution, with every
    resolution performed descriptor-relative to that pinned root, or
    resolution must run inside a private, immutable mount namespace no
    other workload can alter, with a root-replacement negative test proving
    an access attempted after a denied tree is bind-mounted over the
    ceiling root itself fails closed rather than resolving inside the
    substituted mount. No-follow, descriptor-relative resolution still
   cannot see hard links: an allowed directory can contain a hard link to a
   denied file on the same filesystem, so the allowed pathname resolves
   beneath the ceiling root while reading or writing it accesses the same
   inode as the outside file, and both tests above pass while an
   out-of-ceiling side effect runs. Directory ceilings must therefore also
   handle hard links explicitly, and an unspecified isolated filesystem view
   is not sufficient: a mount namespace or bind-mounted allowed directory
   hides the outside pathname but preserves the hard-linked inode, so writing
    the visible in-ceiling name still mutates the denied file. Copying is not
    a sufficient remediation either: materializing the allowed directory onto
    a copied or copy-on-write filesystem gives the sandbox fresh inodes, so
    later writes no longer reach the outside file, but the copy is produced by
    reading every in-ceiling entry, so an entry that is a hard link to a
    denied file is read during materialization and its contents are disclosed
    into the sandbox; fresh inodes prevent mutation of the outside file, not
    disclosure of it, and the required unreadability outcome fails even though
    the write-isolation outcome holds. Cross-boundary hard links must
    therefore be rejected, or individually vetted and explicitly approved,
    before any copy or materialization is taken: a multi-linked entry whose
    link count shows the inode is shared beyond the ceiling boundary fails the
    ceiling closed unless specifically vetted, and only the vetted tree may
     then be materialized onto fresh inodes. Vetting that runs before a
     separate materialization step is itself a check-to-use race: when the
     source tree stays live between the two operations, another permitted
     writer can replace a vetted regular file with a hard link to a denied
     file after the link-count check passes and before the copy reads it, so
     materialization reads the denied inode and discloses its contents even
     though the sequential vetting succeeded. Vetting must therefore be
     atomic with materialization: either the materialized view is
     constructed from a frozen, immutable snapshot of the source taken
     before vetting, with both the vet and the copy reading only that
     snapshot, or each entry is validated and copied through the same opened
     descriptor (the link-count and inode-identity check performed on the
     descriptor whose bytes are actually copied), with concurrent
     substitution of any entry prevented or detected and failed closed. The
     cross-boundary hard-link
      negative test must prove that a hard link inside an allowed directory to a
      denied file fails to read or write the outside content, that no copy or
      snapshot of the denied content ever becomes readable inside the
      materialized view, and that this holds when the capability runs inside a
      mount-namespace or bind-mount view of the allowed directory, and a
      concurrent swap-versus-materialization negative test must prove that
       replacing a vetted entry with a hard link to a denied file between
       vetting and materialization fails closed rather than disclosing the
       denied content into the materialized view. Vetting bounds the links
       that exist when the tree is admitted, not the links outsiders add
       afterward: when a writable target lives on a filesystem another
       workload can access, that workload can create an out-of-ceiling hard
       link to a previously single-linked target after this
       pre-materialization vetting but before the governed write commits, so
       the open descriptor and its in-ceiling parent remain valid, the
       rename-after-open and destination revalidation checks pass, and the
        committed write becomes visible through the newly created denied
        path. A recheck performed at write or commit closes only the
        pre-commit window: once the governed write commits, the
        capability's participation ends and no further recheck ever
        runs, so a hard link created afterward by a same-filesystem
        workload immediately exposes the committed bytes through the
         denied path. The writable target must therefore reside, for its
         entire lifetime, in storage where outsiders cannot create links
         to it, and a private mount namespace is not that storage: mount
         namespaces isolate mount topology, not inode link operations,
         so when the namespace exposes the same underlying filesystem
         that another workload's namespace also maps, that workload can
         hard-link the inode through its own mount after commit while
         the target's private view never shows it. The no-outside-link
         property requires a distinct or access-controlled filesystem
         whose link operations are exclusively broker-owned (an
         equivalent broker-private store), or the governed write must
         land in such broker-private
         storage and be published only through a broker-controlled copy
         whose destination also has that no-outside-link property for the
         published object's lifetime, with the link-after-open negative
         test extended to race hard-link creation both before commit and
         after commit, the post-commit attack issued from a different
         mount namespace that maps the same underlying filesystem, and
         proving a link added to the target at any
         point in its lifetime never makes the governed content
         readable through the out-of-ceiling path. All
     of these path-escape defenses share an assumption the filesystem does not
    guarantee: that an inode genuinely beneath the ceiling only carries
    in-ceiling effects. A FIFO or device node inside an allowed directory
    resolves cleanly under descriptor-relative, no-follow, no-cross-mount
    resolution — no symlink, mount point, or hard link is traversed — yet
    writing the FIFO delivers commands to whatever more-privileged process
    reads the other end, and opening the device node reaches kernel or
    hardware state that has nothing to do with the directory, so every
    symlink, race, bind-mount, and hard-link test above can pass while an
    out-of-ceiling side effect runs. Directory capabilities must therefore be
    restricted to regular files and directories, failing closed on any other
    inode type (FIFOs, device nodes, sockets) unless a specific special inode
    is explicitly brokered as its own reviewed capability, with FIFO and
    device-node negative tests proving the external effect itself does not
    occur: a write to an in-ceiling FIFO is denied and no command reaches the
    privileged reader, and an open of an in-ceiling device node is denied
    rather than reaching the device. Direct network capabilities have the same
   resolution gap: a network ceiling scoped to allowed origins is not enforced
   by validating the requested endpoint or the post-policy arguments, because
   an allowed URL can redirect to a forbidden origin, and a hostname can
   resolve — or rebind between check and connect — to an address outside the
   ceiling, so a different network side effect runs than the one bound into
   the receipt. Network ceilings must therefore be enforced through a
   direct-network broker that re-validates every redirect hop against the
   ceiling before following it, validates the actual resolved destination
   address, and connects using that approved resolution rather than
   re-resolving afterward, with negative tests proving an allowed URL
   redirecting to a forbidden origin and a hostname rebinding to an
    out-of-ceiling address both fail to reach the outside destination; the
    spawned-process denied-socket test below covers only shell containment,
    not this direct network capability. Validating and pinning the resolved
    socket destination still governs only the first network hop: when an
    allowed origin is itself a forwarding endpoint (an HTTP CONNECT proxy,
    a SOCKS proxy, or an equivalent relay), the broker observes and
    approves the proxy's address while the process asks that proxy to
    reach an arbitrary forbidden origin, and the redirect, DNS-rebinding,
    and denied-connect tests all pass because the local connection never
    leaves the allowlisted proxy. Permission to use a forwarding endpoint
    must therefore be treated as authority over every destination that
    endpoint can relay to, granted only when that transitive reach is
    itself reviewed and intended, or the connection must run through a
    protocol-aware broker that parses the tunnel or relay request and
    validates and binds the logical tunnel destination against the ceiling
    before establishing it, with a proxy-tunnel negative test proving an
    attempt to tunnel through an allowed proxy to a denied origin fails to
    reach that origin.
     Pinning the resolved address still binds only the transport peer, not
     the logical authority: when an allowed origin shares an IP address,
     load balancer, or reverse proxy with a denied origin, a contained
     process can connect to the pinned approved address while presenting a
     TLS SNI value or an application-level HTTP Host header naming the
     denied virtual host, and the redirect, DNS-rebinding, and proxy-tunnel
     tests all pass because no redirect is followed, no resolution changes,
     and no tunnel is requested, yet the logical network effect lands on an
     origin the ceiling never named. The direct-network broker must
     therefore bind and enforce the logical network authority at connection
     use (the scheme, authority, TLS SNI, and application-level host
     presented on the wire must match the allowed origin), or permission to
     reach a shared endpoint must be treated as authority over every virtual
     host that endpoint serves, granted only when that transitive reach is
     itself reviewed and intended, with a shared-address virtual-host
     negative test proving a connection to an allowed origin's address that
     presents a denied origin's SNI or Host value fails to reach the denied
     virtual host.
     Matching the presented identity authenticates nothing about the peer:
     when an allowed HTTPS authority resolves to an attacker-controlled
     peer or the traffic is intercepted on path, the scheme, authority,
     SNI, and application-level host can all name the allowed origin even
     though the peer presents an invalid or mismatched certificate, and a
     contained caller that disables or mishandles certificate verification
     then discloses data or performs the effect against an unauthenticated
     service while every broker check above passes. For TLS and equivalent
     authenticated-channel origins the broker itself must therefore
     validate the peer's certificate chain and hostname against a trusted
     anchor set or a pinned identity for the allowed origin, independently
     of caller-controlled verification settings, refusing the connection
     when peer authentication fails, with an invalid-certificate/MITM
     negative test proving a connection to an allowed origin whose peer
      presents an invalid or mismatched certificate is refused by the
      broker even when the caller disables verification, and no request
       data reaches the unauthenticated peer.
       Chain validation is only as trustworthy as the clock it consults:
       when the broker evaluates certificate validity periods and
       revocation status against the mutable host clock, rolling that clock
       backward makes an expired or revoked certificate chain appear valid
       while the request still satisfies every scheme, authority, SNI, and
       Host check above, so data reaches a peer whose credentials are no
       longer trustworthy. The broker must therefore evaluate certificate
       validity and revocation freshness against the same trusted,
       rollback-refusing time source the receipt-expiry and freshness
       checks elsewhere in this design consult (never a host clock writable
       by governed workloads), or bind the allowed origin to a non-expiring
       pinned peer identity whose verification does not depend on
       wall-clock validity, with a clock-rollback certificate negative test
       proving a connection validated under a rolled-back clock against an
       expired or revoked certificate is refused and no request data
       reaches the stale peer.
       Authenticating the peer still grants the whole service: one allowed
      origin can expose both benign and privileged operations (a readable
      `GET /docs` and an authenticated destructive `DELETE /admin/...` on
      the same API), and the broker admits both because their scheme,
      authority, resolution, presented host, and TLS identity are
      identical, while the ambient-credential and external-effect budget
      requirements only authenticate the caller and bound aggregate
      counts, so a single destructive same-origin request remains inside
      the stated ceiling. Network authority must therefore be bound to
      protocol-specific operations where the protocol expresses them (for
      HTTP, the allowed methods and resource/path constraints recorded in
      the ceiling and enforced by the broker on every request), or an
      origin grant must be explicitly treated as authority over every
      operation the entire service exposes, granted only when that
      full-service reach is itself reviewed and intended, with a
       same-origin disallowed-operation negative test proving a request to
       an allowed origin whose method or resource falls outside the
       recorded operation constraints is refused by the broker rather than
       sent. Method and resource/path constraints still under-specify APIs
       that select the logical operation elsewhere: a `POST /graphql` body
       carrying a mutation or a `POST /api` payload with `action=delete`
       stays within an allowed method and path while performing a
       destructive out-of-ceiling operation encoded entirely in query
       parameters or the request body, so the broker passes the
       same-origin negative test while sending it. For endpoints whose
       operation semantics are carried in the query or body, the recorded
       operation constraints must therefore extend to canonical
       query/body/schema/operation constraints the broker parses and
       enforces on every request (the allowed GraphQL operations, the
       allowed action values, the schema of permitted payloads), or
       permission to such an endpoint must be explicitly treated as
       authority over every operation the endpoint accepts, granted only
       when that full reach is itself reviewed and intended, with a
       payload-encoded operation negative test proving a request to an
       allowed endpoint whose method and path match but whose query or
       body encodes an operation outside the recorded constraints is
       refused by the broker rather than sent. Even then, argument-level checks
   govern only the launch, not the launched process: an allowed
   `shell.allowed_scripts` entry spawns a process that inherits the host's ambient
   file and network capabilities, so a declaration that permits that script while
   denying network access or writes outside a directory promises containment that
   rechecking the command and its transformed arguments cannot deliver. Nor is
   the allowlist itself enforced by inspecting a general shell command string:
   `sh -c 'scripts/approved.sh; unapproved-command'` mentions the approved
   path yet executes additional code, and wrappers, command substitution, and
   redirection give the same bypass, so a sandbox that bounds transitive file
   and network effects still does not preserve the allowed-script restriction.
   `shell.allowed_scripts` must therefore be enforced by an argv-based
   launcher that directly resolves and executes the approved executable from
   the immutable step-5 snapshot with caller-supplied arguments, never through
   shell interpretation of a command string, or by a parser that rejects
   wrappers, substitutions, redirections, and command chaining outright, with
   a negative test proving a command string that references an allowed script
   with an appended command is denied rather than launched. An argv launch
   still hands caller-supplied arguments to the reviewed executable, and
   arguments can themselves carry code: an `--eval` expression, or a module,
   plugin, or configuration path the approved script loads and executes, lets
   the caller run unapproved code inside a reviewed process while the
   allowed-script check on the top-level executable passes, and hashing
   by-reference inputs at authorization proves which bytes were supplied, not
   that those bytes were admitted as executable content. Each allowed script
   must therefore either carry a per-script argument schema, reviewed at
   admission, that rejects command-, code-, and plugin-bearing arguments
   outright, or every executable input its arguments can name (scripts,
   modules, plugins, and any configuration the script evaluates as code) must
   itself be recursively admitted and content-bound the same way as the
   top-level executable before the receipt is issued, with a negative test
   proving an allowed script invoked with a code-bearing argument (an eval
   expression, or a path to an unadmitted plugin or module) is denied rather
    than launched. Argument admission governs argv, not the input channel:
    when the launcher leaves the spawned process's standard input connected
    to caller-controlled data, an admitted script or interpreter can read
    and evaluate code delivered on stdin while its executable and every
    argument satisfy the argument schema, so the appended-command and
    code-bearing-argument tests both pass because no shell syntax and no
    argument carries the payload. The launcher must therefore close
    standard input by default (or connect it to a null source), and any
    allowed script that legitimately consumes standard input must have
    that input bound and validated as exact bytes under its per-script
    input schema, content-bound the same way as by-reference inputs, with
    a stdin-code negative test proving code delivered on standard input to
    an allowed script is never evaluated: the launch is denied or the
    input never reaches the process. This step
   therefore defines shell containment semantics explicitly: a shell grant is
   treated as granting the process's ambient file and network capabilities unless
   the launch runs under an OS-level sandbox or capability-brokered executor that
   materially enforces the narrower ceilings. Even an enforced network ceiling
   is directional: a grant that names only selected outbound origins constrains
   where the process may connect, but says nothing about `bind()` or `listen()`,
   so an executor can satisfy every redirect, DNS-rebinding, and denied-connect
   test above while still letting the approved script expose a TCP service that
   other workloads reach and drive through arbitrarily many externally initiated
   operations under the one launch receipt. Inbound listener authority must
   therefore be defined as its own capability, distinct from outbound origin
   authority and denied by default for any declaration that names only outbound
   origins, with the executor profile required to enforce that distinction
   (and the grant rejected when it cannot), and a negative test proving that
   a process launched under an outbound-only grant cannot create a reachable
   listener: another workload's attempt to connect to a socket the sandboxed
   process binds and listens on fails.
     Declaring inbound listener authority admits the listener, not its
     traffic: the grant still authorizes only the launch, so once an allowed
     listener is reachable, external peers can drive arbitrarily many
     operations through the process under that one launch receipt, and the
     per-transitive-effect reservation requirement below applies only to
     admitted handlers, leaving a declared shell listener outside it. Each
     request an allowed listener accepts, or each externally visible effect
     that service performs, must therefore pass through the dispatcher and
     the same scoped external-effect and rate budgets as directly issued
     requests, or the listener grant must reserve a verified maximum
     accepted-operation count with the executor profile terminating the
     listener when that bound is reached, with a declared-listener
      amplification negative test driving many externally initiated requests
      at an allowed listener and proving the operations it performs are
      bounded and accounted rather than unlimited under the single launch
      receipt. Bounding accepted operations bounds admissions, not their
      fan-out: one accepted listener request can trigger many downstream
      external operations, so a listener capped by accepted-operation
      count can still amplify a single request into unbounded messages,
      resource creations, or charges under one launch receipt, and the
      per-transitive-effect reservation requirement below is explicitly
      limited to admitted handlers. Every operation an allowed listener
      accepts must therefore debit the scoped external-effect and rate
      budgets per downstream effect it triggers, or carry a verified
      maximum downstream effect count and value enforced by terminating
      the work when that bound is reached, with a single-request fan-out
       negative test driving one accepted listener request that attempts
       many downstream external effects and proving those effects are
       bounded and accounted rather than unlimited under the single
       launch receipt. Count bounds also authorize contents they never
       inspect: when an allowed listener is reachable by arbitrary peers,
       those peers choose which operations the service performs under the
       launch receipt, so a client can drive an unauthorized or
       destructive request that stays comfortably inside the
       accepted-operation and fan-out counts. Each request an allowed
       listener accepts must therefore be individually authenticated and
       policy-checked before the service acts on it (the accepted
       operation validated against the ceiling exactly as a directly
       issued request would be), or the listener grant must be explicitly
       treated as authority over every operation any peer can trigger
       through that listener, granted only when that reach is itself
       reviewed and intended, with an out-of-intent listener-request
       negative test proving a single well-formed request asking an
       allowed listener for an operation outside the reviewed intent is
       refused or has no effect even though it stays within every
       accepted-operation and fan-out bound. Ambient capability is not only
   files and sockets: the spawned process also inherits the host environment and
   open handles (cloud tokens, API keys, credential-agent sockets), and file and
   network ceilings alone do not stop an allowed script from using or
   exfiltrating those credentials. The containment contract must therefore treat
   inherited credentials explicitly: either the shell grant is defined as
   granting the ambient credentials the process inherits (and the declaration
   documents that), or the sandboxed/brokered launch must run with an
    allowlisted environment (secrets stripped) and inherited descriptors and
    credential-agent handles closed, with negative tests proving the spawned
      process can neither read a denied environment token nor use an inherited
      credential handle. Documenting that ambient credentials are granted
      names the credential channel, not the principal: an allowed script
      that inherits a mutable ambient credential or default context (a
      Kubernetes context, a cloud default role) executes as whatever that
      credential designates at launch, so between authorization and launch
      the credential can be repointed from the approved staging principal
      to production while the script, its arguments, and the receipt all
      remain unchanged, and the handler-principal binding later in this
      design covers only admitted handlers, not spawned scripts. Shell
      grants, their approvals, and their receipts must therefore bind the
       effective credential principal (the stable principal, account, or
       role identifier, with its scope and trust epoch) that each granted
       ambient credential resolved to at authorization, and the launcher
       must, atomically with launch, re-resolve each granted credential,
       fail closed when any designates a different principal, scope, or
       epoch, and materialize the verified result as an immutable
       credential instance (a materialized session, token, or
       non-reswitchable handle) that is the only credential the spawned
       process inherits or consumes; a launcher that re-resolves, checks,
       and then launches leaves a check-to-use gap in which the ambient
       credential can designate the approved staging principal during the
       check and be repointed to production before the child inherits or
       uses it, exactly the race the admitted-handler path below closes by
       pinning. This requires a shell credential-substitution negative
       test proving an allowed script authorized while the ambient
       credential resolved to the staging principal is refused launch,
       without a side effect, after that credential is repointed to
       production, and a concurrent switch-versus-use negative test racing
         an ambient-credential repoint against script launch and use,
         proving the spawned process only ever acts as the pinned verified
         principal. Materializing an immutable credential instance also
         decouples it from revocation: when an allowed script or admitted
         handler materializes a bearer session or token at launch, revoking
         the ambient service credential or its role after launch does not
         necessarily invalidate the pinned instance before a deferred write
         or downstream call occurs, and the actor lease covers the
         requesting actor, not this distinct cloud, cluster, or service
         principal, so the effect can run under authority whose trust epoch
         has since been retired while every substitution and
         switch-versus-use test above passes. The pinned credential
         instance, on the shell path here and on the admitted-handler path
         later in this design alike, must therefore be tied to a revocable
         authorization lease held until the governed effect commits or
         completes, revoked or re-validated when the source credential or
         role is revoked, or the executor profile must require and verify
         that the downstream service enforces revocation of the
         materialized instance itself, with post-launch
         credential-revocation negative tests for both the shell and
         admitted-handler paths revoking the source credential or role
         after launch but before a deferred effect and proving the effect
         either committed before the revocation or never occurs.
         Pinning the shell credential's principal verifies who
        the spawned process acts as, not where its effects land: the same
        principal, scope, and trust epoch can remain valid while the
        credential's resolved target changes (a Kubernetes context can keep
        its user credential while its current cluster or namespace moves
        from staging to production, and one cloud principal can address
        multiple projects or regions), and the resolved-target binding
        required for admitted handlers later in this design covers only
        that path, not spawned scripts, so a repointed default target lets
        an allowed script authorized against staging run against production
        while every principal check above passes. Shell grants, their
        approvals, and their receipts must therefore also bind the resolved
        ambient target context (the endpoint, cluster or project, region,
        namespace, and equivalent target identifiers each granted
        credential resolves to) at authorization, and the launcher must
        resolve the effective target atomically with launch, fail closed on
        mismatch, and pin the verified target into the same immutable
        credential instance the spawned process inherits or consumes rather
        than leaving the child to re-read mutable defaults, with a shell
        target-substitution negative test proving an allowed script
        authorized while its credential's target designated staging is
         refused launch, without a side effect, after that target is
         repointed to production under an unchanged principal, scope, and
         epoch. Binding the principal and target still authorizes only who
         the spawned process acts as and where its effects land, not the
         configuration that selects the operation: an allowed script that
         consumes a permitted non-secret environment value or an unnamed
         default configuration (a `DEPLOY_MODE` variable, a feature flag, a
         configuration file the script reads by convention) executes
         whatever operation that value selects at launch, so changing the
         value after authorization alters the executed operation while the
         script, its arguments, the credential principal, the target, and
         the receipt all remain unchanged; the allowlisted-environment rule
         above names which variables survive (secrets stripped), never
         which values were authorized, and the admitted-handler
         ambient-configuration rule later in this design covers only
         admitted handlers, not spawned scripts. Each allowed script's
         security-relevant ambient inputs must therefore be enumerated at
          admission (the environment values, configuration files and
          defaults, and feature flags its operation depends on), bound by
          resolved value or content digest into the shell grant, its
          approvals, and its receipts at authorization, and resolved
          atomically with launch into the same pinned immutable snapshot the
          spawned process consumes (the allowlisted environment and
          configuration materialized from the bound values, never re-read
          from mutable host state), failing closed on mismatch. Binding by
          resolved value or ordinary content digest is safe only for
          non-secret ambient inputs: when an allowed script consumes an
          unnamed secret-bearing configuration file, a private feature
          value, or another non-credential ambient secret, serializing its
          resolved value into the grant, approval, or receipt discloses the
          secret, and an unkeyed content digest of a low-entropy secret is
          an offline-guessable commitment, while the secret-ambient-input
          rule later in this design is explicitly scoped to admitted
          handlers. Secret-classified shell ambient inputs must therefore
          be represented in shell grants, approvals, and receipts by the
          same secret-store identity-and-version or keyed-commitment
          representation that rule requires for admitted handlers (the
          commitment verifiable only inside the trusted resolver that holds
          the key, never offline from the evidence alone), with the raw
          value still resolved atomically with launch into the pinned
          immutable snapshot and mismatches failing closed, with a shell
          ambient-configuration substitution negative test proving an
          allowed script authorized while `DEPLOY_MODE` (or an equivalent
          flag or default) held its reviewed value is refused launch,
          without a side effect, or cannot have its executed operation
          altered by the change, after that value is modified between
          authorization and launch, and a shell secret-ambient-input
          serialization negative test proving the shell grant, approvals,
          and receipts for a script consuming a secret-bearing ambient
          input never contain the secret's value or an unkeyed digest of
          it while substitution of that input is still refused.
        Files, sockets, environment, and credentials still do
     not exhaust ambient authority: a launch that shares the host's PID or
     IPC namespace lets the spawned process signal or trace same-UID
     processes, connect over abstract Unix-domain sockets, and read or write
     shared IPC (shared-memory segments, message queues) belonging to other
     host workloads, while every file, network, credential, and
     resource-budget test in this contract passes. The containment contract
     must therefore treat process-control and IPC channels explicitly:
     either the shell grant is defined as granting that ambient
     process-control and IPC authority (and the declaration documents it),
     or the executor profile must isolate or broker those channels (separate
      PID and IPC namespaces, or equivalent brokering of signals, tracing,
      and shared IPC). Separate PID and IPC namespaces alone do not close the
      abstract-socket channel: Linux abstract Unix-domain sockets are scoped
      to the network namespace, not the IPC namespace, so a sandbox that
      shares the host network namespace still lets the launched process reach
      host services over abstract sockets while satisfying that stated
      isolation profile. The isolation profile must therefore also include a
      separate network namespace or explicit brokering of abstract-socket
      access, with an end-to-end negative test exercising that exact profile
      and proving the launched process cannot signal, trace, connect to a
      host abstract Unix-domain socket, or otherwise affect another host
      process through those channels. Namespaces, descriptors, and ceilings also
      assume the process keeps the identity it was launched with: when the
      execution host exposes a setuid or setgid helper, retains
      supplementary groups or Linux capabilities, permits `sudo`, or
      offers an exploitable user-namespace path, an allowed script can
      acquire authority outside the sandbox's declared ceiling, and every
      listed file, network, credential, PID/IPC, and resource test passes
      because none of them exercises escalation. OS identity and privilege
      controls must therefore be an enforceable executor-profile
      requirement: the sandboxed or brokered launch runs with a fixed
      non-privileged UID/GID and supplementary group set, drops Linux
      capabilities, sets `no_new_privs` (or the platform equivalent), and
      denies or brokers access to setuid/setgid helpers, `sudo`, and
      user-namespace creation, with shell grants rejected at admission and
      at execution when the executor profile cannot impose these controls,
      and an end-to-end privilege-escalation negative test proving a
      launched process that attempts each escalation path the host exposes
      fails to acquire the elevated identity and the resulting
      out-of-ceiling effect does not occur. File, network, environment, and credential containment
    still leave shared host resources ungoverned: an allowed script handed an
    adversarial workload size, or one that spawns unbounded children, can
    exhaust host CPU, memory, process slots, wall-clock runtime, or disk
    while satisfying every containment test above, and that exhaustion
    disrupts other work inside the same execution boundary even though no
    file, network, or credential ceiling is crossed. The containment
    contract must therefore also record enforceable resource budgets (CPU
    time, memory, process/PID count, wall-clock runtime, and storage) in the
    ceiling and executor profile, imposed by the sandboxed or brokered
    launch on the spawned process and its entire descendant tree, with shell
    grants rejected at admission and at execution when the executor profile
    cannot impose the recorded budgets, and an end-to-end
    resource-exhaustion negative test proving a launched process that
    attempts to exceed its budget (an unbounded fork loop, allocation, or
    disk write) is terminated or denied and the host-level exhaustion does
    not occur. Those budgets still leave two shared substrates
    ungoverned: an allowed script that repeatedly opens files or sockets
    can exhaust the host-wide descriptor table, and one that saturates an
    allowed disk or network endpoint can starve other workloads of I/O
    bandwidth, all without exceeding any CPU, memory, PID, wall-clock, or
    storage quota, so the exhaustion test above passes while another
    workload is still denied service. The recorded budgets must therefore
    also include enforceable open-file/socket (descriptor) limits and
    disk and network I/O bandwidth quotas imposed on the spawned process
    and its entire descendant tree, or the executor profile must
    explicitly isolate those shared resources (a per-launch descriptor
    allocation and an I/O-scheduling or bandwidth class separating the
    launch from other workloads), with descriptor-exhaustion and
    I/O-bandwidth-exhaustion negative tests proving a launched process
    that opens descriptors or sockets in a loop, or saturates an allowed
     disk or network endpoint, is throttled, denied, or terminated and
     other workloads' descriptor and bandwidth availability is preserved.
     Byte-based storage quotas, descriptor limits, and bandwidth classes
     still leave shared filesystem object capacity ungoverned: a spawned
     process tree or admitted handler that repeatedly creates and closes
     zero-length files exhausts a shared filesystem's inode or
     directory-entry capacity while never exceeding any storage-byte quota,
     simultaneous-descriptor limit, or I/O-bandwidth class listed here, and
     the archive-admission entry-count limit bounds extraction, not runtime
     creation, so every exhaustion test above passes while other workloads
     can no longer create files. The recorded budgets must therefore also
     include per-invocation and aggregate filesystem-object (inode and
     directory-entry) quotas imposed on spawned process trees and admitted
     handlers, or the executor profile must confine their writes to an
     isolated filesystem with a bounded inode pool, with a sequential
     empty-file exhaustion negative test proving a governed process or
     handler that creates and closes zero-length files in a loop is denied
     or terminated and the shared filesystem's object capacity is
     preserved.
     Per-launch budgets bound each process tree, not their sum: a skill
    that issues many distinct allowed script invocations concurrently
    keeps every launch within its recorded per-launch limits while the
    aggregate CPU, memory, PID, storage, descriptor, or bandwidth use of
    those launches exhausts the host, and single-use receipts prevent
    replaying one receipt, not issuing many separately authorized calls,
    so every exhaustion test above passes while other workloads are still
    denied service. The containment contract must therefore also impose
    shared admission control and aggregate resource quotas scoped to the
    skill, tenant, and execution boundary, enforced across all concurrent
    and queued launches attributed to that scope (a launch whose admission
    would exceed the aggregate quota is denied, queued, or throttled
    rather than run), with a concurrent many-launch exhaustion negative
    test proving that many simultaneous individually-within-budget
    launches from one skill are collectively bounded and other workloads
    retain CPU, memory, PID, storage, descriptor, and bandwidth capacity.
     Per-skill aggregates bound each skill's sum, not the boundary's:
     when several admitted skills share one execution boundary, each can
     remain within its own aggregate quota while their combined CPU,
     memory, PID, storage, descriptor, bandwidth, or filesystem-object
     use exhausts the
     shared host (several skills each within their own aggregate inode
     and directory-entry quota can still jointly exhaust a shared
     filesystem's object pool with zero-length files), and a many-launch
     test driven from a single skill never
     exercises that combination. The aggregate quotas, the
     filesystem-object (inode and directory-entry) quotas above
     included, must therefore be
     hierarchical: per-skill totals nest under tenant-wide and
     execution-boundary-wide totals for every budgeted resource (CPU,
     memory, PID, storage bytes, descriptors, bandwidth, and
     filesystem objects alike), each enforced at admission across
     every concurrent and queued launch attributed to that tenant or
     boundary regardless of originating skill (a launch whose admission
     would exceed any enclosing total is denied, queued, or throttled
     rather than run), with a cross-skill shared-boundary exhaustion
     negative test proving simultaneous individually-within-quota
     launches from distinct skills sharing one execution boundary are
     collectively bounded by the boundary-wide limit and other workloads
     retain capacity, including a cross-skill empty-file exhaustion
     variant proving distinct skills each within their own
     filesystem-object quota cannot jointly exhaust the shared
     filesystem's inode or directory-entry capacity.
    A permitted `queued` outcome moves the exhaustion rather than
    removing it: every quota above bounds admitted execution, and the
    ingress and per-call budgets below bound each request and active
    governance work, so a skill (or several) can submit arbitrarily
    many individually valid launches that each land in the queue,
    exhausting dispatcher memory or durable queue storage while no
    queued launch ever consumes its execution budget. Queue admission
    must therefore be governed by its own hierarchical queue-length
    and queued-byte budgets, per-skill totals nesting under
    tenant-wide and execution-boundary-wide totals of the same shape
    as the aggregate quotas they guard, enforced before a launch is
    enqueued, with a submission whose enqueueing would exceed any
    enclosing queue budget rejected fail-closed or held behind
    backpressure that blocks the submitter rather than buffering the
    submission, with a sustained over-quota submission negative test
    driving continuous individually valid launches from multiple
    skills against one shared boundary and proving dispatcher memory
     and durable queue storage stay within the declared queue budgets
     while other workloads' submissions still make progress.
     Hierarchical queue budgets cap what the queue stores, not who can
     use it: one skill, or coordinated skills submitting under several
     child scopes, can fill the tenant-wide or execution-boundary-wide
     queue allowance with individually valid submissions and reclaim
     each slot the moment it drains, so unrelated workloads never find
     free capacity even though every declared queue budget holds and
     the promise that other submissions make progress goes unenforced.
     Queue admission must therefore apply the same sybil-resistant
     capacity partitioning the audit quotas below require: the
     concurrently admitted child-scope queue allocations must
     collectively leave a protected reserve of each enclosing allowance
     (their sum bounded strictly below the enclosing total, with
     creation of new child scopes itself a governed,
     allocation-consuming admission rather than a free identity), or
     scheduling must guarantee each submitter a minimum reserved queue
     capacity no set of other scopes can consume, with backpressure
     landing only on the exhausting scopes, and the sustained
     over-quota submission test must also drive a continuous submitter
     and coordinated submissions spread across child scopes whose
     shares would sum to the enclosing allowance, proving unrelated
     submitters still enqueue and make progress out of the protected
     reserve.
     Host-resource quotas bound what a launch consumes locally, not what
    it effects remotely: an admitted action that is cheap on the host but
    high-impact externally (sending a message, creating a cloud
    resource, charging an account) lets a skill issue many distinct
    allowed requests while every process stays within all of the CPU,
    memory, storage, descriptor, and bandwidth quotas above, and each
    request receives its own valid receipt and executes exactly once, so
    receipt idempotency and host-resource admission control never bound
    the aggregate external effect or spend. The containment contract
    must therefore also impose atomic count, rate, and (where the action
    carries a quantifiable magnitude) value budgets on externally
    visible actions, scoped to the skill, actor, tenant, and action,
    enforced at admission across all concurrent and queued requests
    attributed to that scope (a request whose admission would exceed the
    aggregate external-effect budget is denied, queued, or escalated
    rather than run), with a concurrent many-request negative test
    driving a low-host-resource but externally effectful handler and
     proving the aggregate count, rate, or value of its external effects
     is bounded even though every individual request is allowed and every
     host-resource quota is respected. A budget keyed by the combined
     skill/actor/tenant/action scope gives each combination its own
     allowance: when several skills or actors operate in the same tenant
     or downstream account, every individual counter can pass while their
     aggregate cloud spend, messages, or resource creations exceed the
     tenant-wide bound, the same gap the hierarchical host-resource quotas
     above close for local consumption. External-effect budgets must
     therefore be hierarchical as well: per-skill and per-actor counters
     nest under tenant-wide, target-account-wide, and
     execution-boundary-wide action totals, each enforced at admission
     across every concurrent and queued request attributed to that
     enclosing scope regardless of originating skill or actor (a request
     whose admission would exceed any enclosing total is denied, queued,
     or escalated rather than run), with a concurrent
     cross-skill/cross-actor negative test proving simultaneous
     individually-within-budget requests from distinct skills and actors
     sharing one tenant or target account are collectively bounded by the
     enclosing total.
     Hierarchical totals keyed by action still leave the effect itself
     aliased: when the same external effect is reachable through multiple
     admitted actions (both `create_resource` and `apply_manifest` can
     create billable cloud resources), each action's target-account total
     is a separate allowance, so the combined spend or resource count
     across those actions exceeds the promised enclosing budget while
     every action-specific counter stays within bounds. Admission must
     therefore also debit a canonical target/effect-class budget shared
     across every admitted action and alias that can produce the same
     class of external effect against the same target, with the mapping
     from admitted actions to canonical effect classes declared and
     reviewed at admission and unmapped externally effectful actions
     failing admission closed, in addition to the action-specific
     counters, with a concurrent cross-action negative test proving
     simultaneous individually-within-budget requests through distinct
     actions producing the same effect class against one account are
     collectively bounded by the shared effect-class total.
     Atomic admission presumes the budget
     state's own integrity: when a governed skill or descendant process can
     write or restore the backing state for these count, rate, and value
     budgets, it can reset its recorded usage after each admitted request
     and obtain an unlimited sequence of individually valid receipts and
     external effects, because atomicity orders concurrent updates but
     neither authenticates the counters nor prevents rollback, protections
     the receipt-consumption and grant ledgers above already require.
     External-effect budget accounting must therefore be kept in
     authenticated, monotonic, rollback-refusing state held outside agent
     and child-process write authority, the same trust class as those
     ledgers, with a counter-reset/rollback negative test proving that
     deleting or rolling back budget state between admitted requests does
     not allow the aggregate count, rate, or value bound to be exceeded.
      Rollback-refusing counters authenticate the accounting state, not the
      clock that windows it: when rate budgets are evaluated against the
      mutable host clock, advancing the clock opens a fresh fixed window or
      refills a token bucket repeatedly, admitting additional valid receipts
      and external effects while the authenticated counter state is
      untouched, the same host-clock manipulation the grant, invocation-
      context, and receipt expiry requirements above already treat as a
      threat. Rate reservations must therefore be evaluated against the same
      trusted, epoch-bound, rollback-resistant time source those expiry
      checks require, failing closed across any clock or epoch discontinuity
      rather than opening a fresh window, with a host-clock manipulation
      negative test proving that advancing or rolling the host clock between
      admitted requests does not admit requests beyond the aggregate rate
      bound.
     Admission must also charge the request that actually executes: policy
     can return `TRANSFORM`, and the permission intersection is
     re-evaluated against the final executable arguments, but a budget
     debit reserved from the original request's magnitude lets a transform
     that increases the request's quantity or value execute the larger
     final operation against the smaller reservation while staying inside
     the permission ceiling, so the aggregate effect budget is exceeded
     while every admission and ceiling test passes. The external-effect
     budget must therefore be reserved atomically against the final
     transformed action and arguments, recomputed after any policy
     transformation, with that reservation bound into the receipt the
     executor validates, and a transform-that-increases-value negative
      test proving a transform that raises a request's count or value
      beyond the remaining aggregate budget is denied, queued, or escalated
      rather than run.
      Reservation without release converts denial of effect into denial
      of budget: a count or value debit reserved at admission against a
      tenant- or target-account-wide total stays charged when its
      receipt is abandoned, expires unconsumed, or is rejected by a
      later freshness, liveness, or consumption check before any
      external effect occurs, so a low-privileged requester can exhaust
      the shared budget by minting reservations it never executes while
      every admission and accounting test above passes. Reservations
      must therefore follow a two-phase lifecycle recorded in the same
      authenticated rollback-refusing state as the counters: a
      reservation is committed only when its effect becomes irrevocable
      (the per-effect debit points defined below), and it is released
      atomically, by explicit abort or by an expiry bounded to the
      mapped receipt's own lifetime, on every provable pre-effect
      failure (receipt expiry without consumption, denial at the
      execution gate, revocation of the underlying lease), while any
      outcome whose effect status is ambiguous (a downstream operation
      already issued with no authoritative evidence it failed before
      taking effect) conservatively retains the charge, with an
       abandoned-receipt exhaustion negative test proving a requester
       that repeatedly reserves budget and abandons, expires, or
       invalidates its receipts before execution cannot durably exhaust
       the shared tenant or target-account budget.
       Release restores capacity, not fairness: one actor, or
       coordinated skills submitting under several child scopes, can
       continuously reserve the tenant- or target-account-wide
       allowance and abandon each receipt, and because every release
       returns the capacity to an open pool the same submitters reclaim
       it immediately, indefinitely starving unrelated valid effects
       while every two-phase lifecycle and abandonment test above
       passes. Enclosing external-effect budgets must therefore
       preserve capacity for unrelated submitters through the same
       sybil-resistant protected-share or fair-scheduling rule required
       below for queue and audit capacity: the concurrently admitted
       child-scope reservations must collectively leave a protected
       reserve of the enclosing allowance (with child-scope creation
       itself a governed, allocation-consuming admission rather than a
       free identity), or scheduling must guarantee each submitter a
       minimum reserved share that no set of other scopes can consume,
       with the abandoned-receipt exhaustion test extended to sustained
       reserve-and-abandon submissions coordinated across multiple
       actor scopes and proving unrelated requesters in the same
       enclosing scope still obtain reservations and execute their
       effects out of the protected reserve.
       Admission charges the outer request, not its transitive effects: an
    admitted handler that batches operations, fans one request out to
    many downstream calls, or retries after an ambiguous downstream
    timeout consumes one admission and one single-use receipt while
    creating multiple messages, resources, or charges behind the
    dispatcher, so atomic request admission and receipt idempotency
    bound the requests observed at admission, not the external effects
    that actually occur, and the many-request test above passes while
    the promised aggregate bound does not hold. The handler path must
    therefore reserve and commit external-effect budget per transitive
    effect (each downstream message, resource creation, or charge debits
    the scoped budget before it is issued), propagate a downstream
    idempotency identity so an ambiguous-timeout retry cannot
    double-effect, or conservatively reserve a verified maximum effect
    count and value for the invocation at admission and refuse
    invocations whose maximum cannot be established, with a
    retry-or-batch negative test driving an admitted handler that
    batches downstream operations and retries after an ambiguous
    downstream timeout and proving the aggregate count, rate, and value
    of its actual external effects stay within the reserved budget even
    though admission observed a single request.
    That per-transitive-effect rule must not be scoped to admitted
    handlers alone: an allowed script whose launch is admitted once can
    batch outbound calls to a permitted network origin through the
    direct-network broker (creating many cloud resources or charges), so
    the outer launch debits one admission while the broker permits every
    downstream call under the same receipt and the aggregate count and
    value budget is exceeded on the shell path. Brokered shell effects
    must therefore be governed identically: each externally effectful
    brokered operation debits the scoped external-effect budget
    individually before it is issued, or the script invocation reserves
    at admission a verified maximum downstream effect count and value
    that the broker enforces, refusing invocations whose maximum cannot
    be established, with a batching-script negative test driving an
    allowed script that issues many brokered calls to a permitted origin
    under one receipt and proving the aggregate count and value of its
    brokered external effects stay within the reserved budget.
    Count and value debits charge an effect at creation, not over its
    lifetime: when an allowed action creates a persistent billable
    resource without an enforced end time, the count budget is debited
    once and the value-budget clause is inapplicable because the
    resource's total lifetime cost is not yet quantifiable, so after
    creation commits the resource accrues unbounded spend while every
    admission, receipt, and aggregate-count check above passes.
    Persistent external effects must therefore carry an enforceable
    bound on lifetime cost at admission: either the creation reserves
    the resource's maximum total lifetime value against the scoped
    value budget (an enforced end time or hard spend cap the target
    honors), or the resource is held under a revocable budget lease
    whose renewal debits the scoped budget on a trusted-time schedule
    and whose expiry or revocation triggers enforced teardown of the
    resource, with creations whose maximum lifetime or total value
    cannot be established refused admission fail-closed, and a
    persistent-resource negative test driving an admitted creation of
    a resource that continues charging after its creation receipt
    completes and proving the accrued spend stays within the reserved
    value or the lease's exhaustion tears the resource down.
    Whether such a mechanism exists is
   a property of the execution host, not of the checkout, so the static step-2
   gate cannot decide enforceability: it could reject a declaration a production
   sandbox would enforce, or accept one under an assumed sandbox that is absent
   where the skill actually runs. The split is therefore: schema validation at
   the step-2 gate records the containment capabilities a declaration requires
   (a shell grant paired with narrower file or network denials requires a
   sandbox or broker able to enforce them) as machine-readable requirements;
   host deployment/admission fails closed when the executor profile it is
   admitting the skill into cannot supply the recorded requirements; and the
   executor fails closed again at execution time when the active profile does
   not provide them, so a profile downgraded after admission cannot silently
   turn the denials into unenforceable promises. Those checks are only as
   trustworthy as the profile they consult: if the active executor profile is
   represented by writable configuration, a skill can edit it to claim
   sandbox or broker capabilities the executor does not actually provide,
   and both the admission and execution checks then pass before the process
   launches with ambient authority — the proposal protects ceilings and
   signer state from agent writes, and the executor profile needs the same
   trust requirement. The profile must therefore be derived from the actual
   dispatching executor's own capabilities, or be an authenticated,
   versioned record held outside agent and child-process write authority,
   with the profile identity and version bound into the receipt and
   rechecked at execution, and a profile-tampering negative test proving a
   forged or edited profile cannot satisfy the containment requirements: the
   launch is denied rather than run uncontained. Authentication and version
   binding admit any profile that was ever validly issued, not the one
   currently in force: when the executor is downgraded (its sandbox or
   resource controls removed), an older, correctly authenticated profile
   record can be restored and still pass the version-binding and
   execution-time checks while claiming containment capabilities the
   dispatching executor no longer provides. The active profile version must
   therefore be held in monotonic, rollback-refusing freshness state of the
   same trust class as the ceiling and signer freshness state, with any
   profile older than the recorded active version rejected at admission, at
   grant consumption, and at execution, and a matched profile/configuration
    rollback negative test that downgrades the executor's actual
    configuration, restores the older authenticated profile that claims the
    removed capabilities, and proves the launch fails closed rather than
    running uncontained. Rollback-refusing freshness still leaves the
    execution-time recheck a point-in-time read: a sandbox or profile
    downgrade can race an in-flight launch, so the gate validates the
    capable profile, the downgrade then removes its controls, and the
    process spawns with ambient authority even though no stale profile
    record was ever restored, an interleaving the matched rollback test
    cannot catch because nothing is rolled back. Profile validation, the
    containment-requirement check, and launch must therefore be serialized
    against profile transitions: the gate acquires a capability lease or
    profile epoch atomically with validation and holds it through launch,
    revalidating or failing closed when the epoch changes before the
    launch commits, with a concurrent downgrade-versus-launch negative
     test racing a profile or capability downgrade against an in-flight
     launch and proving the process either launches under the
     still-enforced capable profile or is refused, never uncontained.
     A profile lease that ends at launch still stops short of the effect:
     a spawned process or contained handler can defer its governed write
     or connection until after launch, so the launch commits under the
     capable profile, the lease is released, and a profile downgrade then
     removes the broker, network, resource, or sandbox controls from the
     in-flight work before the effect occurs, running it uncontained even
     though the downgrade-versus-launch test passes (the same
     launch-versus-effect gap the policy-version and actor-authorization
     leases close elsewhere in this design). The selected containment
     must therefore remain immutable for the entire descendant and effect
     lifetime, or the profile lease must be held, revocably, until the
     governed effect commits or completes so a profile or capability
     downgrade revokes or re-validates in-flight work before its effect
     commits, with a delayed post-launch effect negative test downgrading
     the profile or its capabilities after launch but before a deferred
     write or connection and proving the effect either runs under the
     still-enforced containment or never occurs, never uncontained.
     Wherever sandboxed or
   brokered enforcement is claimed it must be proven by end-to-end negative tests
   on the transitive effects themselves (the spawned process's denied write
   outside the allowed directory, its denied socket, its denied environment
   token and credential-handle use) rather than on the launch
   arguments. Receipt binding governs
   only actions that reach the executor, and today's host coverage is narrow:
   `.claude/hooks/acgs-emit-receipt.py::_classify` intercepts the edit tools and a few
   orchestration commands, so ordinary `Read` and general `Bash` calls bypass the
   receipt path entirely, and the `.agents` tree has no runtime gate at all. This step
   therefore includes the host-side interception that routes every governed capability
   through `execute_with_receipt`; until that wiring exists, the enforcement claim is
   limited to calls already routed through that boundary. Routing "through" the
   gate must mean the gate performs the side effect, not that it observes it:
   on the Claude path the interceptor is a `PreToolUse` hook, and
   `.claude/hooks/acgs-emit-receipt.py` only emits evidence and returns before
   the host performs the original tool call, so calling `execute_with_receipt`
   around validation or a no-op inside that hook would pass every receipt and
   positive-handler test while the real host side effect still runs outside the
   executor. Interception must therefore take the form of a dispatcher or proxy
   in which the downstream host operation itself is the `tool_fn` the gate
   executes, so the host performs the side effect only as the gate's callee,
   with a test proving that when the gate denies, no subsequent direct host
   execution path performs the operation. "Every governed
   capability" must be closed-world, not a curated mapping: `_classify` today
   returns `None` for any action it does not recognize and the hook exits
   successfully, so a newly exposed side-effectful MCP or plugin tool, or an
   alias absent from the mapping, executes with no ceiling decision at all, and
   adding mappings for today's Read/Bash/Edit cases would satisfy every listed
   test while future tools bypass the pipeline. Interception must therefore
   resolve every side-effectful action, regardless of origin class, against an
   exhaustive admitted-tool registry and fail closed on any tool or alias not
   in it: the authenticated non-skill origin required below establishes who is
   calling, not what is called, so scoping exhaustive resolution to
   skill-originated actions would leave ordinary authenticated calls on
   today's `_classify` behavior and let a newly exposed side-effectful tool
   run without a receipt despite the repository-wide invariant. Real-handler
   negative tests must prove an unknown or newly exposed tool is denied rather
   than silently passed through both when invoked from a skill and when
   invoked from an authenticated non-skill context. Scoping that closed
   world to side-effectful actions leaves the disclosure half of the ceiling
   unenforced: a newly exposed read-only MCP or plugin tool is absent from
   the registry, performs no write, and can still read files or secrets far
   outside a skill's `file_read` ceiling, so unknown-tool tests that
   exercise only effectful tools pass while data leaves the boundary
   ungoverned. Every capability-bearing tool, reads, queries, and listings
   included, must therefore resolve against an admitted registry entry whose
   declared capability class the ceiling decision covers, with only
   operations explicitly proven pure (computing over inputs already supplied
   in the request, touching no host state and disclosing nothing beyond it)
    eligible for exemption, and the unknown-tool negative tests must include
    an unrecognized read-only tool proving it is denied rather than silently
    passed through. Purity bounds disclosure and host state, not
    computation: an operation exempted as pure (a parser, solver,
    decompressor, or regex evaluator over caller-supplied input) sits
    outside the admitted-tool registry while the resource-budget
    requirements below apply only to admitted handlers, so a skill can
    exhaust CPU, memory, or dispatcher time through one pathological
    call or many concurrent calls without touching host state or
    violating the purity definition. Pure exemptions must therefore
    retain enforceable per-call and aggregate resource budgets (CPU,
    memory, and wall-clock or dispatcher time, enforced across all
    concurrent calls attributed to the skill, actor, tenant, and
    execution boundary), with the exemption refused and the operation
    falling back to registry admission when those budgets cannot be
    imposed, and a pathological-input exhaustion negative test proving a
      pure-exempt operation driven with pathological input, alone or
      concurrently, is throttled, denied, or terminated and other
      workloads retain CPU, memory, and dispatcher capacity.
      Those budgets bound what a pure operation consumes, not what it
      emits: a decompressor, expander, or generator over a small
      caller-supplied input can stay within its CPU, memory, and
      wall-clock budgets while streaming a hugely expanded result that
      exhausts response buffers, transport bandwidth, downstream model
      context, or durable result logging. Pure exemptions must therefore
      also carry per-call and aggregate output-byte limits (and
      output-token limits where results enter a model context) with
      declared expansion bounds relative to input size, enforced through
      streaming backpressure or termination of the operation at the
      bound rather than unbounded buffering of an over-limit result, and
      the pathological-input exhaustion test must also drive a
      high-expansion input and prove the emitted output is bounded and
      other workloads retain response-channel, transport, model-context,
      and result-logging capacity.
      A purity classification is a decision about code, and code moves:
      the exempted operation sits outside the admitted-tool registry,
      so when the alias or implementation behind a proven-pure parser,
      solver, or evaluator is upgraded or rebound to code that reads
      host state or performs an effect, the implementation-digest and
      admission-freshness checks below never apply to it and the
      operation retains its bypass while executing effectful code.
      Every purity decision must therefore be bound to the immutable
      implementation and runtime identities it was proven against (the
      resolved handler or server identity, its implementation digest,
      and the relevant runtime version), with the execution path
      rechecking that binding on every call and failing closed into
      ordinary registry admission whenever the resolved implementation,
      digest, or runtime differs from the one the purity decision
      names, and a pure-to-effectful substitution negative test proving
      that rebinding a pure-exempt alias or upgrading its
      implementation to code that reads host state or performs an
      effect loses the exemption and is routed through registry
      admission rather than executed under the stale purity decision.
      Per-call budgets attach to the dispatched operation, but the
     governance path computes first: canonicalization, permission
     matching, policy evaluation, and audit serialization all run over
     caller-supplied arguments before the pure operation or any handler
     or shell budget applies, so oversized or pathological arguments
     can exhaust the dispatcher inside the governance path itself while
     every budget above is never reached; the current kernel defaults
     `policy_timeout` to `None`, and even the optional watchdog leaves
     a timed-out evaluation thread running rather than cancelling it.
     The dispatcher must therefore enforce ingress size and
     structural-depth limits on requests before governance work begins,
     and the entire pre-dispatch governance path must run under
     cancellable per-call and aggregate resource budgets whose
     exhaustion terminates the work rather than abandoning the thread,
      with a denied-request exhaustion negative test driving oversized
      or pathological arguments that are ultimately denied and proving
      the governance path itself is bounded and other workloads retain
      dispatcher capacity.
      Ingress limits enforced by the dispatcher arrive after the host
      has already parsed: when the host or framework fully deserializes
      a tool payload before invoking the dispatcher, a deeply nested or
      parser-pathological request exhausts parser CPU or memory before
      any ingress check or cancellable governance budget begins. The
      execution boundary must therefore cap raw transport bytes before
      any parsing occurs, and request deserialization itself must run
      under the same structural-depth, CPU, memory, and deadline limits
      as the governance path, terminated at the bound rather than
      completed and then measured, with the denied-request exhaustion
      negative test delivering its oversized and parser-pathological
      payloads through the real transport endpoint rather than passing
      an already-materialized request object to the dispatcher, proving
      the pre-dispatch parse itself is bounded and other workloads
      retain parser and dispatcher capacity.
      Bounding active governance work bounds computation, not durable
     evidence: every denied request still appends its durable audit
     event, the active budget is released after each denial, and a
     sustained stream of small individually denied requests stays
     within the ingress and per-call budgets while the accumulated
     audit bytes and filesystem objects grow without bound, eventually
     exhausting the audit volume so unrelated governed requests can no
     longer record their required evidence (and, because audit precedes
     execution, fail closed into a denial of service). Durable audit
     growth must therefore be governed by its own hierarchical
     audit-event and audit-byte quotas, per-skill and per-actor totals
     nesting under tenant-wide and execution-boundary-wide totals,
       backed by authenticated rotation and checkpointing or a bounded
       authenticated remote sink, with fail-closed backpressure applied
       to the submitting scope when its quota is reached (never dropped
        events and never execution without a recorded event). Those two
        rules bind admitted requests, and they cannot both hold for the
        over-quota stream itself: appending a durable event for every
        backpressure denial grows the exhausted scope's storage without
        bound, while refusing the attempt with no evidence at all
        contradicts the stated evidence rule. Requests arriving after a
        scope's quota is exhausted must therefore be refused at a
        pre-admission rejection boundary that is explicitly outside the
        per-request audit obligation (nothing is admitted, so no
        per-request event is owed and no execution can occur), with the
        rejected attempts kept auditable through bounded authenticated
         aggregation: a fixed-size, tamper-evident per-scope record of
         over-quota attempt counts, byte totals, and first/last
         timestamps, updated in place rather than appended per attempt.
         An in-place record that is only tamper-evident is still
         rewindable: restoring an older authenticated copy of the
         aggregate hides later over-quota attempts without appending
         anything or exceeding the quota, erasing sustained abuse while
         the bounded-growth test passes. The over-quota aggregate must
         therefore be held behind the same monotonic, rollback-refusing
         watermark/epoch discipline as the other freshness stores in
         this design, each update advancing an authenticated watermark
         and reads and updates failing closed when the record regresses
         below it or the state is unavailable, with an aggregate-rollback
         negative test restoring an earlier authentic copy of a scope's
         over-quota record and proving the rollback is refused or
         detected rather than the later attempts silently vanishing.
         The
        enclosing tenant-wide and execution-boundary-wide allowances must
       preserve capacity for unrelated submitters through a
       sybil-resistant partition or scheduling rule: bounding each child
       scope's share individually below the enclosing total is not
       sufficient, because coordinated skills submitting under several
       child scopes can keep every scope within quota while their shares
       sum to the entire enclosing allowance, and rotation then finds no
       over-quota events to reclaim. The admitted child allocations must
       therefore collectively leave a protected reserve of the enclosing
       allowance (the sum of all concurrently admitted child shares
       bounded strictly below the enclosing total, with the creation of
       new child scopes itself a governed, allocation-consuming admission
       rather than a free identity), or scheduling must guarantee each
       submitter a minimum reserved capacity that no set of other scopes
       can consume, while events
       still required by unexpired receipts are retained through their
       receipts' retention obligations, with a many-small-denials
        storage-exhaustion negative test driving a sustained stream of
        small denied requests, including coordinated submissions spread
        across multiple actor scopes whose combined shares would sum to
        the enclosing allowance and continued submissions after the
        exhausting scope's quota is already full, and proving audit
        storage stays
        within its declared quotas, fail-closed backpressure lands only on
        the exhausting scopes, the post-exhaustion attempts add no
        per-request audit growth while remaining visible in the bounded
        aggregate record, and unrelated governed requests in the same
        enclosing scope still record their required evidence and execute
        out of the protected reserve.
     Admission by name is still
   not admission of code: the registry authenticates that a tool or alias is
   admitted, not which implementation the name resolves to, so an admitted MCP
   alias rebound to a different server, or a plugin or host handler upgraded
   to code with broader side effects, executes different code while the same
   skill identity, action, and arguments pass every registry and receipt
   check. Each admitted registry entry must therefore bind the implementation
   it was reviewed against (the resolved server or handler identity and its
   compatible schema or implementation version) into the ceiling record and
   the receipt, and the execution gate must recheck that binding against the
   implementation actually resolved at execution time, failing closed on
    mismatch, with a handler-substitution negative test proving that rebinding
    an admitted alias to a different server, or swapping the handler behind an
    admitted tool name, is denied rather than executed under the stale
    admission. Logical identity and version are themselves aliases: when an
    admitted handler lives in mutable storage or loads a mutable deployment,
    its code can be replaced in place while the alias, server/handler
    identity, and advertised schema or version are all preserved, so the
    identity/version recheck passes and unreviewed code runs with broader
    side effects — the handler-substitution test passes because nothing it
    checks changed. The admission binding must therefore be to immutable
    code, not names: each admitted entry must bind a content-addressed
    deployment digest (or an equivalent signature) computed over the
    handler's executable and dependency closure, held and verified outside
    agent and handler write authority, and the execution gate must recheck
    that digest against the implementation bytes actually resolved and loaded
     at execution time, failing closed on mismatch, with an in-place mutation
     negative test proving a handler whose code is replaced in place while its
     name, identity, and advertised schema/version remain unchanged is denied
     rather than executed. Rechecking the digest and then loading from mutable
     storage still leaves a check-to-load race: an agent-controlled writer can
     replace a dependency after verification but before a lazy import or
     execution-time load, so unreviewed code performs the side effect while
     the sequential in-place-mutation test passes. The gate must therefore
     execute the handler only from verified bytes: either the verified handler
     and its dependency closure are materialized into an immutable snapshot
     from which every load (lazy imports included) resolves, or loading and
     verification go through the same protected handles so the bytes verified
     are exactly the bytes executed, with a concurrent swap-versus-load
      negative test racing a dependency replacement against a lazy or
      execution-time load and proving the swapped code never runs.
      The handler digest covers the handler's own executable and
      dependency closure, not the runtime that executes it: an admitted
      handler running under a mutable Python or Node interpreter,
      dynamic loader, or native shared library outside that closure
      executes whatever code a replaced runtime supplies, so unreviewed
      code controls the side effect while every handler-byte,
      immutable-snapshot, and lazy-import check still passes, the same
      ambient-runtime boundary the skill-snapshot identity claim above
      records explicitly. The admission record and receipt must
      therefore extend the content-addressed binding over the handler's
      execution runtime (the interpreter binary, dynamic loader, and
      native shared libraries it loads, or an equivalent
      content-addressed runtime image), verified and loaded from the
      same immutable snapshot or protected handles as the handler bytes,
      with a runtime-substitution negative test proving a handler whose
      interpreter or shared library is replaced while its own bytes
       remain unchanged is denied rather than executed; where a
       deployment cannot yet supply a verifiable runtime closure, the
       admission and receipt must record the runtime as an explicitly
       unverified boundary, and no implementation-identity claim may
       extend over it.
       An explicitly unverified runtime also disqualifies the
       reviewed-footprint alternative below: footprint-based admission
       accepts a handler on the strength of its recorded effect
       footprint, and a substituted unverified interpreter, loader, or
       shared library can drive that same bound handler to filesystem
       or network effects absent from the reviewed footprint while the
       gate still accepts the recorded boundary. Footprint-based
       admission must therefore require a verifiable runtime closure,
       and any handler whose runtime remains explicitly unverified must
       execute only under OS-level containment or a capability broker
       that independently enforces the invoking skill's effective
       ceiling on its transitive effects, with a substituted-runtime
       footprint negative test proving a footprint-admitted handler
       whose unverified interpreter or shared library is replaced
       cannot perform a filesystem or network effect absent from its
       reviewed footprint.
       Verified bytes are verified against whichever admission record the
      gate consults, and admissions are retired as well as granted: when an
      ordinary authenticated non-skill call uses this registry after a
      handler has been retired, restoring the previously valid registry
      entry together with its old immutable handler snapshot makes every
      identity, digest, receipt, and loaded-byte recheck succeed against the
      same stale admission, so retired code executes while the
      handler-substitution, in-place-mutation, and swap-versus-load tests
      all pass because nothing they check changed. Unlike the policy,
      ceiling, signer, and executor-profile state elsewhere in this design,
      a registry alone has no rollback-refusing active-version state, so the
      admitted-tool registry must carry the same discipline: the active
      handler admission is held as monotonic, rollback-refusing freshness
      state (a registry version or admission epoch) scoped to its tenant
      and execution boundary and held outside agent and handler write
      authority, validated at receipt issuance and rechecked at the
      execution gate, so a superseded or retired admission fails closed
      even when its registry entry and deployment snapshot are
      byte-identical to a formerly valid state, with a matched
        registry-and-deployment rollback negative test restoring a retired
        registry entry together with its old handler snapshot and proving
        execution is refused rather than run under the stale admission.
        Tenant and boundary scoping still span deployments: when staging
        and production share the same tenant and execution boundary, a
        handler admission reviewed for one project or environment can be
        selected while issuing or executing a receipt bound to the other,
        the receipt's `project_id` and `environment_id` fields verify, and
        nothing proves the admitted registry entry and deployment digest
        were approved for that deployment context. The active
        handler-admission freshness state must therefore also bind the
        `project_id` and `environment_id` the admission was approved for,
        with receipt issuance and the execution-gate recheck validating the
        admission against exactly the deployment context the receipt binds
        and failing closed on mismatch, and cross-project and
        cross-environment admission-substitution negative tests proving a
        handler admission approved for one project or environment cannot
        validate issuance or execution of a receipt bound to another.
        Rollback-refusing admission state still leaves the gate's recheck
       a point-in-time read: a retirement can commit after the gate
       observes the admission as active and validates the immutable
       handler snapshot, and the already-validated invocation then
       launches under the retired authority, an interleaving the matched
       rollback test cannot catch because nothing is restored. Admission
       validation, receipt consumption, and launch must therefore be
       serialized against active-admission transitions the same way
       policy freshness and executor-profile validation are serialized
       elsewhere in this design: the gate acquires an admission epoch or
       lease atomically with the validation and holds it through launch,
       revalidating or failing closed when the admission state changes
        before the launch commits, with a concurrent retire-versus-launch
        negative test racing a handler-admission retirement against an
        in-flight validated invocation and proving no interleaving lets
        the retired handler perform the side effect. An admission lease
        that ends at launch still stops short of the effect: an admitted
        handler can queue asynchronous work or defer its side effect, so
        the launch commits under the active admission, the lease is
        released, retirement then commits, and the queued effect runs
        under the retired admission even though the launch-scoped race
        test passes (the same launch-versus-effect gap the
        policy-version, actor-authorization, and executor-profile leases
        close elsewhere in this design). The admission lease must
        therefore be held until the governed effect commits or
        completes, or the handler's in-flight and queued work must
        remain revocable or brokered so a retirement revokes or
        re-validates it before its effect commits (the same effect-held
        lease discipline the other freshness leases apply), with a
        delayed post-launch effect negative test retiring a handler
        admission after launch but before a queued or deferred effect
        and proving the effect never commits under the retired
        admission.
      Binding the reviewed implementation receipts only the outer
   tool call, not what the handler does to fulfill it: an admitted MCP
   server, plugin, or host handler internally performs its own filesystem,
   network, and process effects, those nested effects need not pass back
   through the dispatcher, and so an unchanged, correctly bound handler can
   exceed the invoking skill's file or network ceiling from inside — the
   handler-substitution test passes because no substitution occurred. This is
   the same ambient-authority gap the shell containment contract closes for
   spawned processes, and it needs the same treatment: either each admitted
   handler's ambient effect footprint (the filesystem paths, network origins,
   credentials, and process capabilities its implementation exercises
   internally) is reviewed at admission and recorded in the ceiling record
   and receipt as authority the admission itself grants, so invoking the
   handler from a skill whose ceiling is narrower than that footprint is
   denied at issuance, or the handler executes under OS-level containment or
   a capability broker that gates its transitive filesystem, network, and
   process effects to the invoking skill's effective ceiling. Either way, a
   negative test analogous to the shell containment tests must prove the
   transitive effect itself is contained: an admitted, unmodified handler
   whose internal behavior attempts a write outside the invoking skill's
   file ceiling or a connection outside its network ceiling fails to perform
    that effect (or the invocation is denied at issuance under the recorded
     footprint), rather than passing because only the outer call was
     checked. Filesystem, network, credential, and process capabilities
     enumerate where a handler's effects land, not every channel a shared
     host exposes: an admitted local plugin or per-invocation handler
     sharing the host's namespaces can signal or trace same-UID
     processes, write shared memory segments or message queues, connect
     to an abstract Unix-domain socket, receive inbound connections on a
     listener it opens, use an inherited open descriptor or credential
     handle, or acquire privilege through a setuid/setgid helper, `sudo`,
     or user-namespace creation, all without attempting the
     out-of-ceiling filesystem write or network-origin connection the
     footprint test above exercises, the same channels the shell
     containment contract already treats as separate containment
     surfaces for spawned processes. The handler footprint review and
     the broker or containment alternative must therefore cover those
     channels with the same explicitness: process-control and IPC access
     (signals, tracing, shared memory, message queues, abstract
     Unix-domain sockets) either recorded as authority the admission
     grants or isolated/brokered by the executor profile, inherited
     descriptors and credential handles closed at handler launch or
     explicitly recorded in the footprint, inbound listeners denied or
     recorded as declared listener authority subject to the same review,
     and OS identity and privilege controls (a non-privileged identity,
     `no_new_privs` or the platform equivalent, and denied or brokered
     setuid/setgid helpers, `sudo`, and user-namespace creation)
     enforced for handler execution exactly as for shell launches, with
     end-to-end negative tests proving an admitted, unmodified handler
     attempting each channel (a same-UID signal or trace, a
     shared-memory or message-queue write, an abstract-socket
     connection, use of an inherited credential handle, an undeclared
     inbound listener, and each privilege-escalation path the host
     exposes) fails to affect another process, use the handle, receive
     the connection, or acquire elevated identity, rather than only the
     filesystem-write and network-origin cases being
     tested. That footprint records where the handler's effects may land,
    not how much it may consume: an admitted local plugin, MCP server, or
    host handler fed adversarial arguments can allocate unbounded memory,
    fork descendants, exhaust the descriptor table, or saturate shared
    disk and network I/O without ever attempting a denied write or
    connection, and the CPU, memory, PID, wall-clock, storage,
    descriptor, and I/O-bandwidth budgets above apply only to shell
    launches, so both footprint tests pass while the host is denied
     service. Handler admission must therefore also record enforceable
     per-invocation resource budgets (CPU, memory, a wall-clock execution
     deadline, process/thread count, open-file/socket descriptor limits,
     storage, and disk and network I/O bandwidth) imposed on the handler
     and any work it spawns, or the handler must execute as isolated or
     rate-limited service capacity whose exhaustion cannot starve other
     workloads, with admission failing closed when the active executor
     profile cannot supply the recorded budgets or isolation, and a
     handler-driven exhaustion negative test proving an admitted handler
     that allocates memory, forks, opens descriptors or sockets, or
     saturates an allowed disk or network endpoint in a loop is throttled,
     denied, or terminated while other workloads' capacity is preserved,
     rather than only shell exhaustion being tested. The wall-clock
     deadline is required independently of the consumption budgets: an
     admitted handler that sleeps, deadlocks, or waits forever consumes
     almost no CPU or I/O yet occupies a dispatcher worker indefinitely,
     and the shell wall-clock budget above does not apply to handler
     invocations, so every listed exhaustion test can pass while dispatch
     capacity is starved; a non-terminating-handler negative test must
     prove an admitted handler that never returns is terminated at its
     deadline and its dispatcher capacity reclaimed. Per-invocation
     budgets bound each call, not their sum: a skill that submits many
     concurrent admitted-handler invocations keeps every call within its
     recorded per-invocation limits while their aggregate memory,
     threads, descriptors, or I/O exhausts the host, so, exactly as the
     shell containment contract requires for launches, handler execution
     must also run under shared admission control with aggregate resource
     quotas scoped to the skill, tenant, and execution boundary, enforced
     across all concurrent and queued handler invocations attributed to
     that scope (an invocation whose admission would exceed the aggregate
     quota is denied, queued, or throttled rather than run), and neither
     per-invocation budgets nor isolated service capacity alone satisfies
     this requirement without the aggregate bound, with a concurrent
      many-handler-call exhaustion negative test proving many simultaneous
       individually-within-budget handler invocations from one skill are
       collectively bounded and other workloads' capacity is
       preserved.
       Consumption budgets bound what execution takes from the host, not
       what it emits: an admitted handler that returns or streams a huge
       result, or an allowed script that continuously writes stdout and
       stderr, can exhaust dispatcher serialization buffers, response
       transport, downstream model context, or durable result logging
       while staying within every listed CPU, memory, process,
       descriptor, storage, I/O-bandwidth, and execution-deadline budget,
       and the output-byte and output-token bounds above are scoped to
       pure-operation exemptions, so neither this handler budget list nor
       the shell budget contract bounds result output. Shell and handler
       execution must therefore also carry per-invocation and aggregate
       output-byte limits (and output-token limits where results enter a
       model context), enforced through streaming backpressure or
       termination of the workload at the bound rather than unbounded
       buffering of an over-limit result, with a result-output exhaustion
       negative test proving an admitted handler or allowed script that
       streams an oversized result is throttled or terminated at its
       recorded output bound while other workloads retain
       response-channel, transport, model-context, and result-logging
       capacity.
       The enumerated budgets cover host CPU, memory, processes,
      descriptors, storage, and I/O, not accelerators: on a GPU- or
      accelerator-equipped execution host, an admitted handler or
      allowed script can allocate all device memory or saturate
      accelerator compute while remaining within every listed budget,
      starving other experiments or production workloads even though
      every exhaustion test above passes. Admission for shell and
      handler workloads on accelerator-equipped hosts must therefore
      also record and enforce accelerator budgets (device-memory
      allocation and accelerator compute time or utilization), imposed
      per invocation and as aggregate quotas scoped to the skill,
      tenant, and execution boundary exactly like the host-resource
      quotas above, with admission failing closed when the active
      executor profile cannot enforce or isolate accelerator
      consumption on that host, and a shared-GPU exhaustion negative
      test proving an admitted workload that attempts to allocate all
      device memory or saturate accelerator compute is throttled,
      denied, or terminated while other workloads' accelerator capacity
      is preserved.
       Containment bounds where a handler's effects land and what it
      consumes, not what it remembers: an admitted long-lived MCP server,
      plugin, or pooled handler that serves multiple invocations or tenants
      can retain a secret or request payload from one scope in its process
      state and return it to another without performing any new filesystem,
      network, credential, or process effect, its implementation digest
      unchanged and both calls holding valid receipts within the recorded
      footprint, so every containment test above passes despite a cross-
      scope disclosure. Tenant partitioning alone is also too coarse:
      staging data returned in production, or one project's payload
      returned in another, crosses a trust boundary the receipt model
      treats as first-class (`project_id` and `environment_id` are receipt
      trust dimensions) even when both scopes share a tenant. Handler
      execution must therefore partition state by invocation and full
      deployment scope (at least tenant, `project_id`, `environment_id`,
      and execution boundary) with verified teardown between scopes (a
      fresh process or isolate per scope, or a verified reset of all
      retained state), or persistent handler state and response disclosure
      must themselves be treated as brokered capabilities recorded in the
      ceiling record and mediated by the dispatcher, with cross-tenant,
      cross-project, and cross-environment state-retention negative tests
      proving a secret submitted in one invocation, tenant, project, or
      environment scope is never observable in a later invocation
      from a different scope served by the same admitted handler. Recording that a handler's footprint includes credentials
    identifies the channel, not the principal: an admitted handler that
    resolves a mutable ambient credential or default context (a Kubernetes
    context, a cloud role, a default account) executes as whatever that
    credential currently designates, so swapping it can make identical
    approved tool arguments run against production instead of staging while
    the handler deployment digest, executor profile, and receipt all still
    verify. The ceiling record and receipt must therefore bind the stable
    principal, account, or role identifier (with its scope and trust epoch)
    that the handler was admitted to act as, and the execution gate must,
    atomically with launch, resolve the handler's effective credential,
    fail closed when it designates a different principal, scope, or epoch,
    and pin the verified result as an immutable credential instance (a
    materialized session, token, or non-reswitchable handle) that is the
    only credential the handler consumes; a gate that merely re-resolves
    and checks, leaving the handler to re-read the mutable ambient
    credential afterward, reopens the window, because the context can
    designate the approved principal during the check and be repointed
    before the handler resolves or uses it. This requires a
     credential-substitution negative test proving a swapped ambient
     credential or context is denied rather than executed against a
     principal the admission never named, and a concurrent
     switch-versus-use negative test racing an ambient-credential repoint
     against handler launch and use, proving the side effect only ever runs
     as the pinned verified principal. Pinning the principal verifies who
     acts, not where the side effect lands: the same credential principal,
     scope, and epoch can remain valid for multiple targets (a Kubernetes
     context can keep the same user credential while its current cluster
     or namespace changes from staging to production, and one cloud
     principal can address multiple projects or regions through the same
     network origin), so a repointed default target passes every principal
     check while identical approved arguments land somewhere the admission
     never named. The ceiling record, approvals, and receipts must
     therefore also bind the resolved ambient target context (the
     endpoint, cluster or project, region, namespace, and equivalent
     target identifiers the admitted footprint resolves to), and the
     execution gate must resolve the effective target atomically with
     launch, fail closed on mismatch, and pin the verified target into the
     immutable credential instance the handler consumes rather than
     leaving the handler to re-read mutable defaults, with a
      target-substitution negative test proving a retargeted context or
      default (an unchanged principal whose current cluster, project,
      region, or namespace now designates production) is denied rather
      than executed against a target the admission never named.
      Principal and target pinning govern who acts and where the effect
      lands, not what the handler is told to do: an admitted handler that
      reads a mutable default configuration file, environment value,
      feature flag, or service-discovery record not named in the final
      arguments executes a different operation when that input changes
      after authorization, while the handler deployment digest, the outer
      action and arguments, and the recorded path/origin footprint all
      still verify; the by-reference content binding above covers only
      inputs the final arguments name, and the allowlisted-environment
      rule applies only to spawned shell processes, not admitted handlers.
      Handler admission must therefore enumerate every security-relevant
      ambient input the implementation consumes (configuration files and
      defaults, environment values, feature flags, service-discovery
      records), bind their resolved values or content digests into the
      ceiling record and the receipt, and have the execution gate resolve
      them atomically with launch into a pinned configuration snapshot
      that is the only configuration the handler consumes rather than a
      re-read of mutable state, failing closed on mismatch, with an
       ambient-configuration substitution negative test proving that
       changing an unnamed default (a repointed service-discovery record
       or flipped feature flag) after authorization is denied or cannot
       alter the executed operation, never silently changes it. Binding
       resolved values or plain content digests is safe only for
       non-secret configuration: when an enumerated ambient input is a
       credential, token, or other sensitive value, serializing its
       resolved value into the ceiling record and receipt discloses it
       through evidence artifacts that travel beyond the trusted
       configuration boundary, and even an ordinary content digest
       discloses a low-entropy secret to offline enumeration. Secret
       ambient inputs must therefore be bound by reference through a
       secret-store version identifier or a keyed commitment (a MAC or
       salted commitment whose key never leaves the trusted gate) that
       the execution gate verifies against the pinned resolved value
       inside the trust boundary, with the value itself redacted from
       receipts, ceiling records, and approval rendering, and a
       secret-serialization negative test proving that for a
       secret-classified ambient input neither the resolved value nor
       any offline-guessable digest of it is emitted in any receipt,
       ceiling record, or approval-rendering artifact while substitution
       of the secret is still detected and denied.
      Interception alone is still
   not sufficient, because an agent issues ordinary tool calls outside any skill
   invocation and the current hook cannot tell the difference:
   `.claude/hooks/acgs-emit-receipt.py::main` receives only the tool payload and
   assigns `PAPERCLIP_AGENT_ID` or a generic actor, with no skill digest or
   loader-issued invocation identity. A compromised skill could direct a normal
   Bash/Edit call that is then governed only as an unscoped agent action, bypassing
   its ceiling. Every intercepted request must therefore carry an unforgeable,
   host-bound    origin. For requests the host identifies as skill-originated, that
   origin is the loader-issued invocation context (the step-5 identity and digest,
   not self-reported in the payload), which selects the skill's ceiling.
   Unforgeability authenticates the issuer, not freshness: a context minted for a
   previously active broader skill, if cacheable or replayable, lets a later call
   select that skill's ceiling after its invocation has ended. Each context must
   therefore be bound to the host session and to the exact tool-call/request
   digest it authorizes, carry a short lifetime and a nonce or be held as a
    non-exportable live handle, and be validated before any receipt is issued,
     with stale-context and cross-call replay negative tests proving a context
     from an ended invocation, or one minted for a different tool call, is
     rejected before receipt issuance. Validating the context without
     consuming it still admits duplication at issuance: when issuance for
     one live tool call is retried or raced, each attempt can validate the
     same session-bound nonce and mint its own signed receipt anchored to
     a distinct decision event, and because the execution-gate ledger
     below consumes each distinct receipt once, one invocation context
     then runs its side effect multiple times while the replay tests for
     any individual receipt pass. Receipt issuance must therefore
     atomically compare-and-consume the invocation context (or be
     idempotent, keyed on the session, nonce, and request digest,
     returning the already-issued receipt rather than minting another)
     against shared durable state of the same trust class as the grant
     ledger, so one origin context yields at most one signed receipt, with
     a concurrent multi-issuance negative test racing retried issuance on
     the same context and proving at most one executable receipt is ever
     minted and the side effect runs at most once. One-shot consumption,
     read strictly, conflicts with the approval path above: a
     skill-originated request that returns `ESCALATE` consumes its
     invocation context when the signed non-executable escalation receipt
     is issued, yet a granted approval requires a fresh evaluation to issue
     the executable `ALLOW`/`TRANSFORM` receipt for that same request, so
     strict one-receipt consumption rejects the approved issuance while
     minting a new context for it would abandon the one-context/one-receipt
     protection. Context consumption must therefore be modeled as an atomic
     state transition rather than a single-shot flag: issuing the
     non-executable escalation receipt atomically transitions the bound
     context into an escalated state tied to that decision's approval
     grant, from which consuming the matching grant may issue at most one
     executable approved receipt under the same bound context, after which
     the context is terminally consumed, and every other issuance path out
     of either state fails closed. A negative test must race retried
     post-approval issuance on the same escalated context and prove one
     origin context never yields more than one non-executable escalation
     receipt followed by at most one executable receipt, with the side
     effect still running at most once.
     Validating the context protects only up to
    issuance: a skill-issued `ALLOW` that involves no human approval yields a
    valid signed receipt whose planned bindings carry no session, nonce, or live
    handle, and the shared consumption ledger above is scoped to approval-gated
    receipts, so against a stateless `execute_with_receipt` that same bearer
    receipt can be presented repeatedly for matching actor/action/arguments and
    run the side effect multiple times while every stale-context test still
    passes. The live invocation must therefore be bound into the receipt itself
    (the origin context's session binding and its nonce or handle identity), and
    every executable receipt, regardless of origin class (skill-originated,
    approval-gated, or an ordinary authenticated non-skill tool call), must be
    consumed atomically at the execution gate against shared durable state of
     the same class as the grant ledger. Consumption scoped only to
     skill-originated receipts leaves the non-skill receipt a reusable
     bearer credential: a retried or replayed authenticated non-skill call
     presents the same signed `ALLOW` receipt and runs its matching side
     effect repeatedly, while the closed-world non-skill routing
     requirement only ensures each presentation carries a receipt, not
     that each receipt executes once. This requires concurrent-replay
     negative tests presenting an ordinary non-approval skill receipt and
     an ordinary authenticated non-skill receipt to the execution gate in
      parallel and proving each side effect runs at most once.
      Execution-gate consumption makes each issued receipt run at most
      once, not each request yield at most one receipt: the
      invocation-context compare-and-consume above protects
      skill-originated issuance, but an ordinary authenticated non-skill
      request retried at issuance rather than replaying the already-issued
      receipt mints a distinct signed receipt per retry, and each of those
      receipts individually passes atomic consumption, so one logical
      request runs its side effect once per retry. Non-skill issuance must
      therefore be atomic and idempotent over a trusted request identity:
      the issuance path derives a nonce or idempotency key from the
      authenticated request (carried by the caller's authenticated
      transport or minted and returned on first issuance, never freely
      re-choosable by the retrying caller), binds it into the receipt, and
      answers a retry carrying the same key by replaying the
      already-issued receipt rather than minting a new one, with a
      concurrent retry-to-issuance negative test presenting parallel
      retries of one authenticated non-skill request to issuance and
      proving at most one executable receipt exists and its side effect
      runs at most once. A key minted and returned only on first issuance
      does not close the initial race: a transport can duplicate the
      first authenticated attempt before either copy has received the
      server-minted key, so both attempts arrive keyless, each mints a
      distinct executable receipt, and replay deduplication that matches
      only retries already carrying the returned key never fires. The
      trusted request identity must therefore exist before any first
      attempt is admitted, and it must be a per-operation identity, not a
      content digest: deduplicating solely on a digest of the
      authenticated actor, action, and arguments conflates two distinct
      intentional operations that happen to carry identical content, so
      the durable mapping answers the second operation with the first
      issuance, whose receipt may already be consumed, and the second
      legitimate operation can never obtain an executable receipt, while
      evicting the mapping to recover instead lets a delayed duplicate of
      the first operation mint another. The caller's authenticated
      transport must supply a stable per-operation idempotency identity
      with every first attempt (a message, sequence, or delivery identity
      that is unique per intentional operation even when actor, action,
      and arguments are identical), and the issuance path atomically maps
      that identity to at most one issuance (compare-and-swap on that
      identity against shared durable state of the same trust class as
      the consumption ledger) before minting; a request whose transport
      supplies no per-operation identity is rejected at admission rather
      than deduplicated by content digest. The identity-to-issuance
      mapping must carry a defined retry lifetime, retained at least as
      long as the mapped receipt remains executable, with any duplicate
      presented within that lifetime replaying the already-issued receipt
      and never minting a new one, with a keyless initial-attempt
      negative test presenting duplicate authenticated first attempts
      carrying no per-operation identity and proving they are denied
      without minting any executable receipt, and a distinct-operation
      negative test presenting two intentional operations with identical
      actor, action, and arguments but distinct per-operation identities
       and proving each obtains its own executable receipt while a
       duplicate of either within its retry lifetime replays rather than
       re-mints. A retry lifetime that ends when the mapped receipt
       stops being executable leaves the identity reusable afterward:
       once the mapping is evicted, a transport that redelivers the same
       per-operation identity after the mapped receipt has expired
       presents an identity the compare-and-swap no longer recognizes,
       so the delayed duplicate is treated as a new issuance and mints a
       second executable receipt for an operation that already ran.
       Receipt expiry must therefore never make the operation's identity
       reusable: the identity-to-issuance mapping must decay into a
       non-reusable tombstone retained beyond receipt expiry, or the
       per-operation identity must be drawn from a monotonic delivery
       sequence whose already-consumed positions are permanently
       refused, with the tombstone or delivery watermark held in the
       same authenticated, rollback-refusing trust class as the
       consumption ledger, and a delayed-duplicate negative test
        presenting the same per-operation identity after the mapped
        receipt has expired and its retry lifetime has elapsed and
        proving no new executable receipt is minted and no side effect
        runs. A per-operation tombstone retained beyond expiry is sound
        only if it is bounded: when the transport supplies unordered
        identities, permanently refusing every already-seen identity
        means retaining one non-reusable record per intentional
        operation indefinitely, so ordinary distinct traffic grows the
        authenticated store without bound, while evicting tombstones to
        cap it recreates the delayed-duplicate mint. The replay
        protection must therefore be representable in bounded
        authenticated state: per-operation identities drawn from a
        monotonic delivery sequence whose consumed positions collapse
        into a bounded watermark (plus at most a bounded reordering
        window of individual records), or a transport-enforced maximum
        redelivery horizon after which the transport verifiably never
        redelivers an identity so tombstones older than that horizon
        can be safely discarded, or another authenticated replay
        structure whose size is bounded independently of operation
        count, with transports that can supply neither ordering nor a
        verified redelivery horizon rejected at admission, and a
        replay-store growth negative test proving the authenticated
        replay state stays within its declared bound under sustained
        distinct-operation traffic while a duplicate identity at or
        before the watermark or horizon is still refused without
        minting a receipt. Atomic
     consumption presumes the ledger's own integrity: if a governed skill can
     write the consumption store, it can delete a consumed receipt's key or
     restore an earlier ledger snapshot, making a still-valid signed receipt
     unused again so its side effect runs repeatedly while every
     concurrent-replay test passes. Consumption state must therefore be kept
     in an authenticated, monotonic store — one that refuses rollback to an
     earlier state — held outside agent and child-process write authority, of
     the same trust class as the ceiling and freshness records, with a
     negative test proving that tampering with or rolling back the ledger
      before replaying a consumed receipt does not make that receipt
      executable again.
      A ledger that retains one record per consumed receipt forever is
      bounded by lifetime request count, not by exposure: each consumed
      receipt eventually reaches its trusted expiry and can never again
      replay successfully, yet its consumption record remains, and the
      bounded replay structure above covers only per-operation
      transport identities, not these consumption entries, so ordinary
      sustained distinct executable traffic grows the authenticated
      store without bound and an actor can exhaust the protected ledger
      through nothing but unique requests. The consumption state must
      therefore also be representable in bounded authenticated form:
      authenticated, rollback-refusing compaction that discards a
      consumption record only after the receipt's trusted, suspend-aware
      expiry has verifiably passed and expiry alone suffices to refuse
      it, a bounded expiry-window structure retaining individual records
      only within the maximum receipt lifetime, or another
      rollback-refusing representation whose size is independent of
      lifetime request count, never compaction that forgets a
      still-executable receipt's consumption, with a consumption-store
      growth negative test driving sustained unique receipt issuance
      and consumption and proving the authenticated consumption state
      stays within its declared bound while a still-valid consumed
      receipt replayed after compaction and an expired receipt are both
      refused without a side effect. Binding and
     consumption authenticate origin and prevent reuse, not liveness: a
     receipt minted just before its invocation ends and first presented
     afterward is still unused in the consumption ledger, its session and
     nonce bindings prove where it originated, the short context lifetime
     constrains only the origin context before issuance, and the receipt's
     own expiry can outlive that context, so a delayed first use executes
     while every stale-context and concurrent-replay test above passes. The
      execution gate must therefore revalidate invocation liveness at
      consumption, verifying that the bound session or handle is still active,
      and receipt expiry must be capped to the originating invocation's
      lifetime, with a negative test proving a receipt first presented after
      its originating invocation has ended is denied without a side
      effect. That recheck closes only the sequential case, not the race:
      liveness validation, receipt consumption, and launch are separate
      steps, so the gate can observe the handle as active, invocation
      termination can mark it ended, and the already-validated request can
      then consume the receipt and launch the side effect after the bound
      authority expired, while the first-presentation-after-end test passes
      because its presentation began before termination. Liveness
      validation, receipt consumption, and launch must therefore be
      serialized against the invocation-termination transition, the same
      way step 5 serializes active-pair validation and lease registration
      against ceiling revocation: the launch holds a revocable lease tied
      to the invocation handle, acquired atomically with the liveness check
      (one transaction, or an epoch check at consumption that fails closed
      when the invocation ended since validation) and closed by
      termination, with a concurrent end-versus-launch negative test
      proving that racing invocation termination against receipt
      consumption never launches the side effect after the invocation has
      ended, regardless of interleaving. A lease closed by termination
      bounds when work launches, not when it takes effect: a receipt can
      launch an allowed script or handler while its invocation is live,
      that work can defer its side effect until after the invocation
      ends, and closing a bookkeeping lease at termination removes
      nothing from an already-launched process unless its work and
      brokered resources are themselves tied to the lease. The invocation
      lease must therefore be effect-held, the same discipline the
      ceiling, signer, approver, and executor-profile leases above
      already follow: the launched work's brokered capabilities and any
      not-yet-committed effects remain bound to the lease through effect
      completion, and invocation termination revokes them or forces
      revalidation before the effect commits, with a deferred-effect
      negative test terminating the invocation after launch but before a
      deferred side effect and proving the effect is revoked or
      revalidated rather than produced under the ended invocation's
      authority. Context freshness bounds the credential,
   not the influence: rejecting a stale context does not remove the skill's
   instructions from the conversation, so a skill can direct the model to defer
   a tool call until after its invocation is marked ended, and the later call is
   honestly labeled with the authenticated non-skill origin and governed under
   the agent's broader ceiling. Because the host cannot reliably attribute a
   later model action to the prior prompt that caused it, skill execution must
   either run in an isolated capability-scoped context whose ceiling governs
   everything the model does within it, or the host must conservatively retain
   and intersect every loaded skill's ceiling until that model context is
   discarded, with a delayed-call negative test proving a tool call deferred
   until after invocation end, issued from a context that loaded the skill, is
    still governed by the skill's ceiling rather than the broader non-skill
    ceiling. Retention ends when the context is discarded, and compaction is
    not discard: when the host summarizes, compacts, or migrates a live model
    session, the original context is deleted while skill-derived instructions
    survive in the successor context, which never itself loaded the skill, so
    a tool call deferred into the summarized context is governed under the
    broader non-skill ceiling despite being influenced by the restricted
    skill, and the delayed-call test above passes because the originating
    context no longer exists. The retained skill stack and its intersected
    ceiling must therefore propagate through every context-summarization,
    compaction, and migration output into each successor context, intersected
    and retained until that successor is itself discarded (and propagated
    onward through any further summary or migration), or the host must refuse
    to summarize, compact, or migrate a context that has loaded a skill, with
    a compaction-laundering negative test proving a tool call issued from a
    summarized, compacted, or migrated successor of a skill-loaded context is
    still governed by the originating skill's ceiling rather than the broader
    non-skill ceiling. Retain-and-intersect constrains the skill's later tool calls, not
   its reading of the context: when a skill is loaded into a model session
   that already contains another tenant's data, credentials, or confidential
   instructions, the permitted retain-and-intersect alternative leaves the
   skill's instructions in that same context, and the skill can direct the
   model to reproduce an existing secret in its ordinary response without
   invoking any intercepted capability, so every receipt and delayed-call
   test passes while the disclosure leaves through the response channel.
   Untrusted skills must therefore be loaded only into least-data isolated
   contexts containing no data beyond what their invocation requires, with
   the isolated context's response passing a governed output boundary before
   reaching any broader recipient, or the claim must explicitly exclude
   response-channel confidentiality and the host must refuse to load
   untrusted skills into model contexts holding data classified above the
   skill's clearance, with a shared-context disclosure negative test proving
   a skill loaded alongside sensitive foreign data either cannot cause that
   data to appear in the response delivered to the skill's requester or is
   refused loading into that context. Isolation holds only as far as its output boundary: when the
   isolated context returns generated output into the caller's broader model
   context, a malicious skill can encode a delayed tool instruction in that
   output, and the receiving caller (which is not part of the delegation
   stack) performs the requested action under its non-skill ceiling while the
   delayed-call test inside the isolated context still passes. Output returned
   from an isolated skill context must therefore either be terminal (delivered
   to the user or a non-model sink, never re-entering any model context as
   consumable instructions), or taint its recipient: the full skill stack of
   the isolated context propagates into every model context that consumes the
   output, intersected as above and retained until that recipient context is
   discarded, with a negative test proving a tool call issued by a caller
   after consuming isolated-context output is still governed by the
   originating skill's ceiling rather than the caller's broader ceiling. That
   propagation rule covers only output returned directly into another model
   context; persistence is a second return path. A restricted skill can write
   delayed instructions into an artifact its ceiling permits (an allowed
   file, a queue entry, any durable store), and after the isolated context is
   discarded a broader non-skill context that later reads the artifact would
   perform the requested above-ceiling action without inheriting the skill
   stack, while every direct-output and delayed-call test above still passes.
   Skill-produced persistent artifacts must therefore carry origin metadata
   recording the producing skill stack, and that metadata must be
   host-assigned and held outside the producing skill's write authority — a
   mandatory label applied by the host or write broker at write time, or an
   authenticated out-of-band provenance record keyed to the artifact — never
   a self-carried marker, because a restricted skill that controls an
   allowed file, queue entry, or adjacent sidecar can omit or forge
   provenance it writes itself, letting a later broader context consume the
    artifact without inheriting the restricted ceiling; the provenance must
     also be preserved across copies and updates of the artifact.
     Copies and updates preserve the label on the same artifact, not on
     what is computed from it: when a broader non-skill process
     transforms a labeled skill-produced artifact (a `sed` pipeline
     writing a new file, template rendering, compilation, archive
     extraction), the output is neither a copy nor an update of the
     original, so this preservation rule never attaches provenance to
     it, and the copy-and-transform rule below is scoped to registered
     skill instruction files, so the broader context can read the
     derived output, or obtain a fresh receipt over it, under its
     broader ceiling while every preservation and mixed-writer test
     passes. Every output an operation derives from a
     provenance-labeled input must therefore inherit the intersection
     of every labeled input's contributing origin stacks, assigned by
     the host or write broker at output-commit time exactly as
     write-time labels are and accumulated with any label the output
     already carries, and operations whose input-to-output derivation
     the broker cannot track must be refused read access to labeled
     inputs or have every artifact they can write conservatively
     labeled with those inputs' contributors, with a derived-artifact
     laundering negative test proving a non-skill transformation of a
     restricted-labeled artifact yields an output whose next reader,
     and any receipt minted over that output, is governed at or below
     the restricted intersection, never the transformer's broader
     ceiling. Under
     multiple writers, preservation alone is not enough: a restricted skill
    can append instructions to an artifact previously labeled as non-skill
    or broader-skill output, or a later broad writer can replace the
    restricted writer's label, and the next reader then inherits authority
    the most restricted contributor never had. Every update must therefore
    accumulate provenance rather than overwrite it, recording every
    contributing origin stack across the artifact's write history, and
    consumers must be governed by the intersection of all contributors'
    ceilings, with a mixed-writer negative test proving an artifact written
    first by a broader (or non-skill) context and then modified by a
    restricted skill governs its next reader at the restricted
    intersection; the provenance-stripping test below does not cover this
    case. Accumulation must not mean unbounded append: a skill that
    repeatedly updates one permitted artifact (especially across distinct
    skill versions or composed origin stacks) would grow a
    record-every-contributor history without bound even though the file
    stays tiny and no new filesystem object is created, sidestepping the
    byte and inode exhaustion bounds elsewhere and eventually exhausting
    the out-of-band provenance store or making provenance reads and the
    atomic update commit below impractical. The accumulated provenance
    must therefore be a bounded authenticated representation: the set of
    deduplicated effective origin stacks, whose intersection governs
    consumers exactly as above so a repeat contributor never grows the
    record and the intersection stays non-amplifying, plus a compact
    authenticated history commitment (a running hash or accumulator over
    the full write history) in place of an enumerated per-write history,
    under a declared retention policy for any auditable history detail,
    with a repeated-update growth negative test proving the protected
    provenance record for an artifact updated arbitrarily many times by
    the same origin stacks stays within its declared bound while its next
    reader is still governed at the restricted intersection.
    Deduplication bounds repeat contributors, not distinct ones: an
    artifact updated by many distinct skill versions or composed
    delegation stacks retains one entry per new stack, so the
    deduplicated set itself grows without bound under exactly the
    distinct-stack traffic identified above. The governing record must
    therefore be bounded independently of contributor count: store the
    running effective intersection itself, which only narrows
    monotonically and is bounded by the ceiling representation while
    governing consumers identically because intersection is
    order-insensitive, alongside the compact history commitment, in
    place of any enumerated stack set; or, where enumerated stacks
    must be retained for audit, impose and enforce a hard bound on
    distinct retained contributors beyond which further updates are
    denied or the artifact's effective ceiling collapses to the most
    restrictive contributor and the artifact is quarantined from
    consumption pending review, with a distinct-stack growth negative
    test proving the protected provenance record for an artifact
    updated by an unbounded sequence of distinct origin stacks stays
    within its declared bound while its next reader is still governed
    at (or below) the restricted intersection.
    Storing the effective intersection compresses identity out of the
    record: once contributor stacks are replaced by their previously
    computed intersection, no identity or freshness handle remains from
    which a reader can detect that a contributing skill version was
    later revoked or its ceiling narrowed, so an artifact written under
    a broad skill ceiling keeps granting its stale broader intersection
    and a delayed instruction it carries can enter a new context and
    obtain a fresh receipt for an action the current ceiling denies,
     while every growth and mixed-writer test above passes. The bounded
     provenance record must therefore remain revalidatable against live
     authority, and revalidation requires enumeration, not merely a
     commitment: an opaque running hash or accumulator over compacted
     contributor identities neither enumerates which skills contributed
     nor supplies their current ceilings, so a consumer holding only
     that commitment cannot detect that a contributor was narrowed or
     recompute the new intersection, and the artifact retains its stale
     broader effective ceiling. Alongside the stored intersection,
     retain a bounded authenticated contributor index: the deduplicated
     contributing skill identities and their ceiling epochs, kept within
     the same hard distinct-contributor bound above (updates beyond it
     denied or the artifact quarantined exactly as that bound requires),
     or an equivalent verifiable index/proof structure whose proofs let
      the consumer enumerate every contributor and check each against
      live revocation and ceiling state. Revalidation must only ever
      retain or narrow artifact authority, never restore or broaden it:
      recomputing solely from contributors' current ceilings would let a
      later broadening of a contributing skill's ceiling grant an
      existing artifact authority none of its writers had when producing
      it, so a delayed instruction in that artifact could obtain a fresh
      receipt for an action outside the original write-time
      intersection. The stored write-time effective intersection is
      therefore preserved as an immutable upper bound, and consumption
      must check the contributor
      index against the live revocation and ceiling state, recompute the
      effective ceiling as the intersection of that immutable write-time
      bound with the enumerated contributors' current
      ceilings, or quarantine the artifact, when any contributor has been
      revoked or narrowed, and fail closed when the index cannot be
      enumerated or verified; or the artifact's effective ceiling must be
      recomputed on every consumption as the intersection of the stored
      write-time bound with live contributor
      state, with a write-then-narrow negative test writing an
      artifact under a broad skill ceiling, then revoking or narrowing
      that skill's ceiling, and proving a later reader is governed at (or
      below) the narrowed ceiling and a delayed instruction in the
      artifact cannot obtain a receipt for an action the current ceiling
      denies, including when the provenance record has already been
      compacted to its bounded representation before the narrowing, and
      a write-then-broaden negative test writing an artifact under a
      narrow skill ceiling, then broadening that contributor's ceiling,
      and proving a later reader remains governed at (or below) the
      write-time effective intersection and a delayed instruction in the
      artifact cannot obtain a receipt for an action outside that
      write-time intersection.
    Accumulation "at write time" still leaves two stores: when a
    restricted skill updates an artifact whose existing label records a
    broader or non-skill origin, publishing the new content before the
    host label or out-of-band provenance record commits lets a concurrent
    reader consume the restricted instructions under the old broader
    ceiling, because nothing serializes content visibility against
    provenance visibility. Content visibility and the accumulated
    provenance must therefore commit as one atomic transition (the
    updated content becomes readable only in the same commit that records
    the contributing origin stack, or the artifact is held unreadable,
    locked or unpublished, until the provenance record commits), with a
    concurrent update-versus-read negative test racing a restricted
    skill's update against a broader reader and proving the reader
    observes either the old content under the old provenance or the new
    content under the accumulated provenance, never the restricted
    content under the broader ceiling.
    The atomic commit serializes visibility, not history: when the
    out-of-band provenance store is restored to an earlier authentic
    record after a restricted skill's update has committed, the
    artifact's current content carries a stale broader label that
    authentication and writer isolation both accept, because the
    restored record is genuinely host-assigned and validly
    authenticated for an earlier version of the same artifact, so a
    later reader consumes the restricted instructions without
    inheriting the restricted contributor's ceiling while every
    atomicity, mixed-writer, and provenance-stripping test above
    passes. Each provenance record must therefore be bound to the
    exact artifact version it labels (the content identity or a
    monotonic version counter of the bytes it governs) and held in
    monotonic rollback-refusing storage of the same trust class as the
    other freshness records in this design, with consumption failing
    closed, the reader refused or the artifact quarantined, whenever
    the artifact's current content has no provenance record matching
    its version at or above the recorded version watermark, and a
    matched content/provenance rollback negative test restoring an
    earlier authentic provenance record after a restricted skill's
    update (with and without the matching earlier content) and proving
    a later reader either observes matched content and provenance
    governed at the restricted intersection or is refused, never the
    current content under the stale broader label. The host
    must then either propagate
   the originating ceiling (intersected as above) into every model context
   that consumes such an artifact, retained until that context is discarded,
   or prevent skill-written artifacts from re-entering any model context as
   consumable instructions at all, with negative tests proving a tool call
   issued by a context after reading a skill-written artifact is still
   governed by the producing skill's ceiling rather than the reader's broader
   ceiling, and that a skill write attempting to strip, omit, or forge an
   artifact's provenance is denied or still yields a host-assigned record
   identifying the producing skill stack. Model contexts are not the only consumers of persisted artifacts:
   a write the ceiling permits can target a machine-consumed control artifact
   (a CI workflow, a host hook, a package script, any executable that CI or
   another host process later runs directly), and that consumer never enters
   a model context, so neither remedy above ever fires while the machine
   consumer executes the artifact's embedded instructions with its own
   broader network, credential, and filesystem authority; every
   model-consumption test passes while the escape runs in CI. Writes to
   machine-consumed control artifacts must therefore be treated as authority
   delegation: either denied by default (control-artifact paths carved out of
   every skill-writable ceiling), or origin-gated at the consumer's execution
   point (the CI/host runner verifies the artifact's recorded producing skill
   stack before executing it and refuses, or confines execution within the
   originating ceiling), and where neither write-time denial nor
   consumer-side origin gating or confinement is enforceable for a given
   consumer, admission must fail closed for that write capability: the
   skill-writable ceiling is narrowed to exclude the control-artifact
   paths that consumer executes (or the skill is held un-invocable),
   never the gap recorded as a permitted residual boundary, because a
   recorded-but-unenforced boundary still lets the later consumer execute
   the artifact's embedded instructions with its broader authority and no
   receipt. Negative tests must prove
   a skill-written modification to a machine-consumed control artifact is
   either rejected at write time or is not executed by that consumer with
   authority beyond the producing skill's ceiling, and that a declaration
   whose control-artifact write capability no reachable consumer can
   enforce is denied admission rather than admitted with a recorded
   residual boundary.
    That admission decision is evaluated against the consumer topology in
    force when the ceiling is approved, not the topology in force when the
    write's consequences land: when a new CI runner, host hook, or other
    machine consumer later begins executing a path an already-admitted
    ceiling leaves skill-writable, the earlier reachable-consumer check
    remains valid only for the old topology, so the skill can populate that
    path and the new consumer executes it with its broader authority without
    ever participating in origin gating, and artifacts written before the
    change carry the same exposure. Control-artifact admissions must
    therefore be bound to a freshness-protected registry of consumer-to-path
    mappings (or the executor profile that encodes them), of the same trust
    class as the other freshness records in this design, with any change to
    consumer mappings revoking or forcing revalidation of every admission
    whose writable ceiling intersects the new consumer's executed paths,
    including re-vetting or quarantining artifacts already written to those
    paths before the new consumer first executes them, or skill writes must
     be confined to storage that can never later become executable by a
     machine consumer, with a consumer-addition negative test proving a path
      written under an admitted ceiling and later mapped into a new consumer's
      executed set is not executed with the new consumer's authority until the
      admission and the existing artifacts are revalidated.
      Mapping changes are not the only authority changes: an existing CI
      runner, hook, worker, or live endpoint can keep the same path or
      namespace mapping while its implementation, credentials, or
      interpretation rules are upgraded to trigger broader operations, so
      the mapping-keyed invalidation above never fires while previously
      admitted skill-writable artifacts are interpreted by the same named
      consumer with new authority. The consumer-topology registry must
      therefore also bind each consumer's implementation identity and
      effective authority (its implementation digest or version epoch and
      its principal/credential epoch), with any change to those bound
      epochs forcing the same revocation or revalidation of every
      intersecting admission and the same re-vetting or quarantine of
      artifacts already written, before the changed consumer first
      executes or interprets them, with a consumer-upgrade negative test
      proving that upgrading a mapped consumer's implementation or
      broadening its credentials, with its path and namespace mappings
      unchanged, blocks interpretation of previously written skill
      artifacts under the new authority until the admission and the
      existing artifacts are revalidated.
     That registry and its admission invalidation are defined through
     consumer-to-path mappings and writable-path intersections, which
     cover only consumers that execute filesystem artifacts: a write the
     ceiling permits can produce a durable non-file artifact (a queue
     message, topic event, database row, or other durable object) whose
     later interpreter is a privileged worker rather than a
     path-executing consumer, and because such an artifact has no path to
     intersect, the worker executes its embedded instructions with its
     own broader authority and no receipt while every path-based
     admission and consumer-addition test above passes. The consumer
     topology must therefore name every durable namespace a machine
     consumer interprets, durable object namespaces, topics, queues,
     subscriptions, and tables alongside filesystem paths, with
     skill-writable ceilings intersected against those namespaces under
     the same admission, mapping-change revalidation, and consumer-side
     origin-gating or confinement rules (and the same fail-closed
     narrowing where none is enforceable), and a non-file consumer
     negative test proving a message, row, or object written under an
     admitted ceiling into a namespace a privileged worker consumes is
     not interpreted with that worker's broader authority, and that a
     newly subscribed worker triggers the same revalidation of the
     admission and of artifacts already written to that namespace before
     it first consumes them.
     Direct returns and persistent artifacts are not the only paths into
    another model context: a restricted skill can send delayed
    instructions over an allowed live channel (a brokered network
    connection, an IPC or inherited-handle channel, a streaming
    handler's output) to a receiver whose broader model context
    consumes the payload, and because that payload is neither an
    isolated-context return nor a persistent artifact, neither
    propagation rule above fires while the receiver executes the
    instruction under its broader non-skill ceiling. Every brokered
    communication payload that can enter another model context must
    therefore be treated as origin-carrying output: the broker or host
    labels the payload at transmission with the sending context's full
    skill stack (host-assigned, held outside the sender's write
    authority, exactly as artifact provenance is), and every model
    context that consumes it inherits the intersected ceiling as for
    isolated-context returns, retained until that context is
    discarded, or the channel must be constrained so its payloads can
    never become model-consumable instructions (delivered only to
    non-model sinks), with a live-channel laundering negative test
    proving a tool call issued by a broader context after consuming a
    restricted skill's live-channel payload is still governed by the
     sending skill's ceiling rather than the receiver's broader
     ceiling.
     Model contexts are not the only live receivers: a restricted skill
     can send instructions over an allowed live channel to a privileged
     machine consumer that never enters a model context (an RPC worker,
     an event-driven daemon, an orchestration service), and because the
     origin-carrying rule above gates only payloads entering model
     contexts while the machine-consumer topology covers only durable
     artifacts and namespaces, the worker interprets the live payload
     with its own broader filesystem, credential, and network authority
     and no receipt. Live machine-interpreted endpoints must therefore
     be governed exactly as durable consumer namespaces are: the
     consumer topology names every live endpoint a privileged machine
     consumer interprets, skill-connectable channels are intersected
     against those endpoints under the same admission, mapping-change
     revalidation, and consumer-side origin-gating or confinement rules
     (the consumer verifies the payload's host-assigned sending skill
     stack and refuses or confines interpretation within the sending
     ceiling), or permission to send to such an endpoint must be
     admitted and reviewed as carrying the full transitive authority of
     every operation its payloads can trigger, with the same
     fail-closed narrowing where neither is enforceable, and a live
     machine-consumer negative test proving a payload sent under an
     admitted ceiling to a privileged worker endpoint is not
     interpreted with that worker's broader authority, and that a newly
     attached privileged consumer on a live endpoint triggers
     revalidation of the admission before it first interprets skill
     payloads. A single
   origin identity is not enough once skills compose: when one skill invokes
   another, or several are active concurrently, attributing the request to any
   single skill would let a restricted outer skill route an action through a
   broader inner skill and escape its own ceiling. The loader-issued context must
   therefore carry the authenticated origin/delegation stack of every skill
   contributing to the request, and the effective permission set is the
   intersection of every stacked skill's approved ceiling *and* every stacked
   skill's own declared permissions, not the ceilings intersected with a single
   declaration: if an outer skill's ceiling permits network while its own
   declaration omits it, and an inner skill both declares and is approved for
   network, applying only the inner declaration would let the call through an
   authority the outer skill explicitly declined. Nested- and concurrent-skill
    negative tests must include that narrower-outer-declaration case, proving
    that invoking or overlapping with another skill can only narrow authority,
    never amplify it. Composition also crosses session boundaries: an acting
    skill can use an admitted orchestration tool to launch a subagent or team,
    and that child normally receives a fresh host session and model context, so
    the parent's session-bound origin cannot be reused there and the
    retained-ceiling rule for the parent context does not carry over; the child
    could then issue the requested action under its broader non-skill ceiling
    while every nested-skill and delayed-call test passes. Agent delegation from
    a skill context must therefore either be denied, or every child session must
    be minted a non-amplifying origin derived from the full parent skill stack,
    with that intersection retained for the child's lifetime and propagated to
    any further descendants, with a negative test proving a child agent launched
    from a skill context is denied when it attempts an action above the parent
    skill's ceiling. Child agent sessions are not the only descendants that
    can re-enter the gate: an allowed shell process launched from a skill
    context can, when its declared containment permits the host tool
    gateway's transport and it inherits an authenticated agent or tool
    credential (both of which this design permits when declared), invoke an
    admitted tool directly, and the gateway then authenticates that request
    as ordinary non-skill traffic governed by the broader agent ceiling; the
    shell sandbox contains the process's own local effects, not the remote
    handler's, so a restricted skill can launder an out-of-ceiling action
    through its descendant process while every child-agent and nested-skill
    test passes. Skill origin must therefore propagate to spawned processes
    exactly as it does to child agent sessions: every tool request
    originating from a descendant process of a skill-launched shell must
    carry the full parent skill stack (host-derived from the launch, never
    self-reported) and be governed by the same non-amplifying intersection,
    or descendant processes must be denied the gateway transport and any
    inheritable gateway credential at launch, with an end-to-end
    subprocess-to-tool negative test proving a tool call issued by a process
    spawned from a skill's allowed script is either governed by the parent
    skill's ceiling or refused at the gateway, never executed under the
    broader non-skill ceiling. For ordinary
   tool use outside any skill invocation, the host must authenticate an explicit
   non-skill origin, governed by the agent's normal policy ceiling; demanding a skill
   digest on every request would block all governed non-skill tool use. The gate
   fails closed when a request carries no authenticated origin at all, or when a
   skill-originated request arrives without its loader-issued context.
   Authenticating the non-skill origin proves only who issued the request,
   and only at issuance: revoking the requesting actor's credential, role,
   or session after receipt issuance but before first presentation
   invalidates nothing, because the execution gate's freshness rechecks
   cover the skill invocation context, approver, signer, policy, and
   handler admission while never re-examining the requesting actor's
   current authorization state, so the signed receipt still executes under
   a principal that has lost authority. Every receipt must therefore bind
   the requesting actor's credential and session identifiers and the
   actor-authorization epoch under which it was issued, and the execution
   gate must revalidate that state against fresh, monotonic,
   rollback-protected actor-authorization and credential-revocation state
   (the same trust class as the approver-authorization store), serialized
   with receipt consumption and launch under the same epoch-or-lease
   discipline as the other freshness domains, failing closed when the
   credential, role, or session is revoked or that state is unavailable,
   with a post-issuance actor-revocation negative test proving an unused
   receipt is refused at the execution gate after the requesting actor's
   credential, role, or session is revoked, and a concurrent
   revoke-versus-execute negative test racing an actor revocation against
   receipt presentation and proving either the side effect committed
   before the revocation took effect or execution is refused without a
   side effect, never both. Serializing the actor recheck with consumption
   and launch bounds only the launch: an admitted handler can queue work
   and a shell process can delay its write, so the launch commits while
   the actor is authorized, a launch-scoped lease then ends, and the actor
   is revoked before the governed side effect occurs; the delayed effect
   runs under a revoked principal while the post-issuance and concurrent
   revoke-versus-execute tests pass because both settle at launch. The
   actor-authorization lease must therefore follow the same discipline as
   the policy-version lease: held until the governed effect commits or
   completes, or the launched work kept revocable or brokered so an actor
   revocation halts or re-vets in-flight work before its effect, with a
    delayed-effect actor-revocation negative test revoking the requesting
    actor after launch but before a deferred side effect and proving the
    effect either committed before the revocation took effect or does not
    occur. Revalidating the issuing actor's standing still never asks who
    is presenting: a leaked or copied unused receipt can be presented once
    by a different authenticated principal while the bound actor's
    credential and session remain active, so one principal executes
    another's still-valid receipt before any revocation and every
    actor-revocation test above passes. The execution gate must therefore
    authenticate the presenting principal and session outside the
    receipt's own contents and require them to match the receipt's bound
    actor (`expected_actor`) and session identifiers, the executor-gate
    `expected_actor` comparison this repository already mandates, or
    receipts must be issued as non-exportable handles bound to the
    issuing principal's authenticated channel so possession cannot be
    transferred, failing closed when presenter authentication is
    unavailable, with a wrong-presenter negative test proving a valid
    unused receipt presented by a different authenticated principal,
    while the bound actor's credential and session remain active, is
    refused at the execution gate without a side effect. The
    non-skill origin rule authenticates how a request was issued, not what
   influenced it: a user or the model can load a registered `SKILL.md`
   through an ordinary `Read` call or `cat` rather than the host's skill
   loader, and every later tool call that follows those instructions is
   then honestly authenticated as non-skill origin and governed under the
   broader normal ceiling with no loader-issued skill stack, while the
   explicit-, implicit-, and delayed-invocation tests all pass because no
   formal invocation ever occurred. Ingestion of a registered skill
   artifact into a model context must therefore itself count as activating
   that skill: the host either treats a read of a registered skill's
   instruction files as a skill activation that propagates the skill's
   identity and ceiling into the consuming context (intersected and
   retained until that context is discarded, exactly as the
   isolated-context output and skill-written artifact rules above
   require), or prevents ordinary non-loader contexts from consuming
   registered skill artifacts as instructions at all, with a negative test
   proving a tool call issued by a context that read a registered
   `SKILL.md` through an ordinary file read is governed by that skill's
   ceiling rather than the reader's broader non-skill ceiling, or that the
   read itself is refused. Activation on read covers only registered
   artifacts: a non-skill context can first copy or transform a
   registered `SKILL.md` through an admitted shell or file operation,
   without ingesting the content into any model context, and then read
   the unregistered destination, which is neither a registered artifact
   nor labeled skill-produced (the copying context was non-skill, so the
   provenance rules above assign it no skill stack), so the instructions
   enter the model while subsequent calls retain the broader non-skill
   ceiling and the direct-read test still passes. Registered-skill
   identity must therefore propagate through copies and transformations:
   any artifact whose content derives from a registered skill's
   instruction files carries that origin (host- or broker-assigned at the
   copying or transforming operation, the same mandatory
   outside-writer-authority provenance mechanism as skill-written
   artifacts, never a self-carried marker) and reading it counts as
   ingesting the originating skill, propagating that skill's identity and
   ceiling exactly as a direct read does, or such extraction must be
   prevented outright (registered skill artifacts refused as the source
   of ordinary non-loader copy and transform operations), with a
    copy-then-read negative test proving a tool call issued by a context
    that read a copied or transformed registered `SKILL.md` is governed by
    the originating skill's ceiling rather than the reader's broader
    non-skill ceiling, or that the copy itself is refused.
    Copy and transform tracking covers operations whose source is the
    registered artifact path: a non-skill context can instead extract the
    same instructions from version-control storage (`git show
    HEAD:.claude/skills/x/SKILL.md`, `git archive`, or an equivalent
    history or object read), which reads `.git/objects` rather than any
    registered path and can stream the content directly into the model
    context without ever creating the copied artifact the rule above
    labels, so the direct-read and copy-then-read tests pass while
    subsequent calls remain authenticated under the broader non-skill
    origin. Registered-skill origin must therefore also propagate through
    VCS, history, and archive extraction: content extracted from
    repository objects that corresponds to a registered skill's
    instruction files carries that skill's origin (host- or
    broker-assigned at the extracting operation, matched against the
    registered artifacts' content identities), whether the output lands
    in a file or streams directly into a model context, or such
    extraction paths must be refused as instruction sources for ordinary
    non-loader contexts, with a VCS-extraction negative test proving a
    tool call issued by a context that obtained a registered `SKILL.md`
    through a history or archive read is governed by the originating
     skill's ceiling rather than the reader's broader non-skill ceiling,
     or that the extraction itself is refused.
     Matching extracted content against the registered artifacts'
     content identities covers only the currently registered bytes:
     `git show <old-commit>:.claude/skills/x/SKILL.md` extracts a
     former version whose bytes no longer match any active registered
     artifact's content identity, so the matching rule attaches no
     skill origin and the superseded instructions stream into the model
     as non-skill content governed under the broader non-skill ceiling,
     obtaining a fresh receipt while the VCS-extraction test above
     passes for current versions. Origin attachment for history and
     object reads must therefore be keyed by registered path and
     version lineage, not current content alone: an extraction whose
     historical repository path corresponds to a registered skill's
     instruction files propagates that skill's identity and ceiling
     regardless of whether the extracted bytes match the currently
     registered version, backed by an authenticated index of the
     skill's registered historical versions and superseded blob
     identities where per-version identity is required, or historical
     extractions matching no registered artifact identity must be
     refused as instruction sources for ordinary non-loader contexts,
     with a historical-version extraction negative test proving a tool
      call issued by a context that obtained a superseded `SKILL.md`
      version through a history or object read is governed by the
      originating skill's ceiling rather than the reader's broader
      non-skill ceiling, or that the historical extraction is refused.
      Path, copy, and repository-object tracking all key on local
      storage: a network-enabled non-skill context can instead fetch
      the same registered or superseded `SKILL.md` from a raw
      repository URL, a mirror, or an artifact service, where the
      broker observes an ordinary HTTP response rather than a
      registered local path or a VCS object read, so none of the
      propagation rules above attaches skill origin, the instructions
      enter the model context as untrusted network content, and later
      calls that follow them execute under the broader non-skill
      ceiling while the direct-read, copy-then-read, VCS-extraction,
      and historical-version tests all pass. Ingestion tracking must
      therefore extend to network-fetched instruction artifacts:
      content entering through a network capability whose bytes match
      a registered skill's instruction files (current or superseded
      versions, matched through the same authenticated index of
      registered historical versions and superseded blob identities
      the history-read rule uses) carries that skill's origin and
      propagates its identity and ceiling exactly as a local read
      does, or untrusted network content entering a model context must
      be conservatively tainted so the consuming context's subsequent
      calls are governed no more broadly than the untrusted
      network-content class permits rather than trusted as ordinary
      non-skill instructions, or such fetches must be refused as
      instruction sources for ordinary non-loader contexts, with a
      network-fetch laundering negative test proving a tool call
      issued by a context that obtained a registered or superseded
      `SKILL.md` through a raw URL, mirror, or artifact-service fetch
      is governed by the originating skill's ceiling (or by the
      conservative network-content taint) rather than the reader's
      broader non-skill ceiling, or that the fetch itself is refused. The
      interception layer is itself inside the threat model: the current hook is
   executed directly from its working-tree path (`.claude/hooks/acgs-emit-receipt.py`,
   selected by `.claude/settings.json`) on each intercepted call, so a skill whose
   `file_write` ceiling covers the checkout can edit the hook or its
   configuration to disable routing or forge the supposedly host-bound origin
   context for every subsequent tool call — a permitted write silently
   dismantling the gate. The interceptor and its configuration must therefore
   live outside agent write authority (host-installed, not resolved from the
   writable checkout), or be authenticated against a pinned digest with the
   host then executing the verified bytes themselves, from an immutable
   snapshot or protected copy materialized at verification time, never
   re-opened from the writable path after verification: revalidating the
   digest and then reloading the file leaves the same check-to-use window
   step 5 already rejects for pre-launch digest revalidation of skill
   artifacts, in which a skill replaces the hook after the check passes but
   before the host loads it, bypassing routing or forging the origin context.
    The hook-tampering negative test must prove both that a modified hook or
    settings file yields fail-closed denial of subsequent governed calls, not
    silent bypass, and that a hook swapped in after verification is never the
    code that executes. Verified hook bytes are not the whole executable
    surface: the hook runs under an interpreter resolved from the writable
    checkout (the project `.venv`) and imports `gove_zone.integration` and the
    rest of the governance package on each call, so a skill whose write
    ceiling covers the checkout can leave the verified hook and settings
    untouched while modifying an imported gate dependency — the governance
    package, the permission parser, or the executor implementation — and every
    subsequent intercepted call then executes compromised gate code that can
    bypass receipt validation while every hook-tampering test above passes.
    The interceptor's interpreter and its complete governance dependency
    closure must therefore be protected the same way as the hook itself:
    host-installed immutable code outside agent write authority, or
    authenticated against pinned digests with the host executing the verified
    bytes from the same immutable materialization (never re-imported from the
    writable checkout after verification), with a negative test that mutates
    an imported gate dependency while preserving the hook bytes and proves
    subsequent governed calls fail closed rather than execute the compromised
    gate. This is the
    differentiating step and should get a design of its own.
7. **Evals** for the skills that encode repo conventions, where drift is silent.
8. **Full OMS-style signing** can come last; step 5 needs only a pinned digest and an
   approval record, not the complete certificate-chain apparatus, though the two should
   converge.

Steps 2 and 3 are small and independently useful. Steps 5 and 6 are a real design task
and should not be bundled with the rest; they, together with step 4's enforcement
path (the `deny_behavior` fail-closed mapping and the approval-grant issuance,
binding, expiry, atomic consumption, and original-receipt-rejection requirements),
are recorded as a planned stage in
[`docs/ROADMAP.md`](../ROADMAP.md) ("Skill trust: identity, permission ceilings, host
interception") so the roadmap of record carries the gap, not just this note.

## References

- [NVIDIA/skills](https://github.com/NVIDIA/skills) — catalog, Apache-2.0 + CC-BY-4.0
- [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) — scanner
- `docs/agent-skill-trust-pipeline.mdx`, `docs/signing-agent-skills.mdx`,
  `docs/skill-cards.mdx` in the NVIDIA/skills repo
- OpenSSF Model Signing (OMS), `model-signing` on PyPI
- Local counterparts: `AGENTS.md` (claim boundaries and the security-sensitive file
  list), `docs/CLAIMS.md`, `packages/acgs-proofpack-verifier`
