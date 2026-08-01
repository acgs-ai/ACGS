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
implicitly-invocable skill that was malformed *and* factually wrong about its own
conventions, and no gate noticed.

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
   enforced in host policy held outside agent write authority (a host-level
   denylist of the held skills for model selection and implicit invocation), with
   a negative test proving that modifying the in-repo frontmatter or
   companion-manifest flags does not make a held skill invocable while the
   host-policy denylist is in force. The step-2 loadability gate and
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
   against on host upgrades. The gate must also cover host companion manifests, not
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
   value means stop, never proceed) before the old field is removed. The
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
    a side effect. Single-use must hold under concurrency:
    marking the grant used at execution time is too late, because two
    evaluations presenting the same still-unused grant could each validate it
    and mint separate executable receipts before either execution burns it, so
    both side effects run while a second-execution replay test still passes.
    Consuming the grant must therefore happen at receipt issuance as an atomic
    compare-and-consume (or an idempotent issuance operation keyed on the
    grant) against shared durable state, so at most one executable receipt can
    ever be minted from one grant. Issuance-time consumption bounds minting,
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
   boundaries yields a different digest and is rejected. "Outside the
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
   valid ceiling-and-skill pair as a matched set. Freshness checks at issuance
   and execution bound only work that has not yet launched: a long-running or
   detached process started under a then-active pair has already passed both
   checks, so revoking or narrowing the pair afterward leaves that process's
   ambient file and network capabilities intact, and the rollback and
   revocation tests above can pass while stale authority keeps producing side
   effects. Revocation must therefore either be made effective against running
   work (process trees and brokered resources launched under a
   ceiling-and-skill pair are tied to a revocable capability lease that the
   host closes when the active pair changes, with a negative test proving a
   still-running child process's file and network effects are cut off after
   revocation) or be explicitly scoped to future launches only, with that
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
     Immutability of the snapshot is not containment of what it references: a
     read-only content-addressed directory can still preserve a symlink such as
     `scripts/run.py -> /tmp/run.py`, whose digest and link entry are unchanged
     while the external target is replaced after authentication, so unapproved
     bytes execute while every in-snapshot mutation test passes. Snapshot
     construction and resource loading must therefore reject symlinks and other
     references that escape the snapshot, or materialize their targets inside
     the confined snapshot and include those bytes in the hashed content, with a
     negative test that mutates an external link target between authentication
     and use and proves the mutated target is never executed or read. That
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
    Membership is therefore defined by invocability, not prose: every
    model-invocable skill (anything a host can select or implicitly invoke)
    is in the governed set, and a documentation-only skill carries an explicit
    deny-by-default/no-capability declaration (an empty permission set) rather
    than being exempted by classification, so admission fails closed for any
    model-invocable skill without a declaration and a tool instruction emitted
    from a nominally documentation-only skill is denied against its empty
    declared set, with a real-handler negative test proving a tool call
    originating from a documentation-classified skill with a no-capability
    declaration produces no receipt and no side effect rather than being
    governed under the agent's non-skill ceiling. Binding is only as
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
    issuance path. Signing and hash-binding prove
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
   post-transform check recorded in the receipt. Argument-level checks are also
   insufficient for the direct filesystem capabilities: a `file_read` or
   `file_write` ceiling scoped to a directory is not enforced by validating the
   final path argument, because an allowed path can traverse a symlink to a
   location outside the ceiling, or a path component can be swapped for a symlink
   after the check and before the host opens it. Directory ceilings must be
   enforced at filesystem resolution — descriptor-relative opens with no-follow
   semantics (`openat2`-style `RESOLVE_BENEATH`) or an equivalent filesystem
   sandbox that confines the resolved target — with negative tests proving both a
   symlink escape inside an allowed path and a check-to-open path race fail to
   touch the outside location. No-follow, descriptor-relative resolution still
   cannot see hard links: an allowed directory can contain a hard link to a
   denied file on the same filesystem, so the allowed pathname resolves
   beneath the ceiling root while reading or writing it accesses the same
   inode as the outside file, and both tests above pass while an
   out-of-ceiling side effect runs. Directory ceilings must therefore also
   handle hard links explicitly, and an unspecified isolated filesystem view
   is not sufficient: a mount namespace or bind-mounted allowed directory
   hides the outside pathname but preserves the hard-linked inode, so writing
   the visible in-ceiling name still mutates the denied file. The remediation
   must either materialize the allowed directory onto a copied or
   copy-on-write filesystem whose entries are fresh inodes sharing no storage
   with any file outside the ceiling, or reject (or specially vet)
   multi-linked entries whose link count shows the inode is shared beyond the
   ceiling boundary, with a cross-boundary hard-link negative test proving
   that a hard link inside an allowed directory to a denied file fails to
   read or write the outside content, including when the capability runs
   inside a mount-namespace or bind-mount view of the allowed directory. Direct network capabilities have the same
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
   not this direct network capability. Even then, argument-level checks
   govern only the launch, not the launched process: an allowed
   `shell.allowed_scripts` entry spawns a process that inherits the host's ambient
   file and network capabilities, so a declaration that permits that script while
   denying network access or writes outside a directory promises containment that
   rechecking the command and its transformed arguments cannot deliver. This step
   therefore defines shell containment semantics explicitly: a shell grant is
   treated as granting the process's ambient file and network capabilities unless
   the launch runs under an OS-level sandbox or capability-brokered executor that
   materially enforces the narrower ceilings. Ambient capability is not only
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
   credential handle. Whether such a mechanism exists is
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
   turn the denials into unenforceable promises. Wherever sandboxed or
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
   resolve every skill-originated action against an exhaustive admitted-tool
   registry and fail closed on any tool or alias not in it, with a real-handler
   negative test proving an unknown or newly exposed tool invoked from a skill
   is denied rather than silently passed through. Admission by name is still
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
   admission. Interception alone is still
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
    rejected before receipt issuance. Validating the context protects only up to
    issuance: a skill-issued `ALLOW` that involves no human approval yields a
    valid signed receipt whose planned bindings carry no session, nonce, or live
    handle, and the shared consumption ledger above is scoped to approval-gated
    receipts, so against a stateless `execute_with_receipt` that same bearer
    receipt can be presented repeatedly for matching actor/action/arguments and
    run the side effect multiple times while every stale-context test still
    passes. The live invocation must therefore be bound into the receipt itself
    (the origin context's session binding and its nonce or handle identity), and
    every skill-originated receipt, not only approval-gated ones, must be
    consumed atomically at the execution gate against shared durable state of
    the same class as the grant ledger, with a concurrent-replay negative test
    presenting an ordinary non-approval skill receipt to the execution gate in
    parallel and proving its side effect runs at most once. Context freshness bounds the credential,
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
   ceiling. Isolation holds only as far as its output boundary: when the
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
   recording the producing skill stack, and the host must either propagate
   the originating ceiling (intersected as above) into every model context
   that consumes such an artifact, retained until that context is discarded,
   or prevent skill-written artifacts from re-entering any model context as
   consumable instructions at all, with a negative test proving a tool call
   issued by a context after reading a skill-written artifact is still
   governed by the producing skill's ceiling rather than the reader's broader
   ceiling. A single
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
    skill's ceiling. For ordinary
   tool use outside any skill invocation, the host must authenticate an explicit
   non-skill origin, governed by the agent's normal policy ceiling; demanding a skill
   digest on every request would block all governed non-skill tool use. The gate
   fails closed when a request carries no authenticated origin at all, or when a
   skill-originated request arrives without its loader-issued context. The
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
   code that executes. This is the
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
