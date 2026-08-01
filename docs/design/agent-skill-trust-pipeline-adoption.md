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
   every repo-local skill by default, enabling only identities externally
   admitted through the step-5 review, and it must reject *every*
   invocation path for unadmitted skills (model selection, implicit
   invocation, and explicit user invocation alike), not
   only the two automatic paths. The in-repo flags only remove automatic
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
   in force, and that (a default-deny case) a loadable skill newly created
   or renamed in the checkout during the interval is not invocable by any
   path until its identity has been externally admitted. The hold gates
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
   subsequent tool call is denied while the hold is in force. The step-2 loadability gate and
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
      the stale grant is rejected without a side effect. Those versioned
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
      prove the grant is refused without a side effect. Binding the
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
     a side effect. Distinctness and human authentication are verified against
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
     at consumption without a side effect. Single-use must hold under concurrency:
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
   pairs is rejected rather than installed. Paths, entry types,
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
   the ceiling was ever approved there. Every ceiling record and active-pair
   entry must therefore also be bound to the tenant, execution boundary, and
   applicable host or executor profile it was approved for, with those
   fields rechecked against the requesting deployment context at both
   issuance and execution, and cross-tenant and cross-boundary substitution
   negative tests proving a ceiling approved in one tenant or execution
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
     memory, is what the gate must consult). Signing and hash-binding prove
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
    handler made to consume exactly those verified bytes or the
    already-resolved descriptors rather than re-reading the mutable path
    after authorization, with a negative test that replaces an authorized
    by-reference input's content between authorization and handler read and
    proves the handler consumes the authorized bytes or the execution is
    denied, never the swapped content. Argument-level checks are also
   insufficient for the direct filesystem capabilities: a `file_read` or
   `file_write` ceiling scoped to a directory is not enforced by validating the
   final path argument, because an allowed path can traverse a symlink to a
   location outside the ceiling, or a path component can be swapped for a symlink
   after the check and before the host opens it. Directory ceilings must be
   enforced at filesystem resolution — descriptor-relative opens with no-follow
   semantics (`openat2`-style `RESOLVE_BENEATH`) or an equivalent filesystem
   sandbox that confines the resolved target — with negative tests proving both a
   symlink escape inside an allowed path and a check-to-open path race fail to
   touch the outside location. Beneath-style resolution is a pathname
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
   directory fails to reach the denied tree. No-follow, descriptor-relative resolution still
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
      denied content into the materialized view. All
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
   not this direct network capability. Even then, argument-level checks
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
   than launched. This step
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
   process binds and listens on fails. Ambient capability is not only
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
     credential handle. Files, sockets, environment, and credentials still do
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
     and shared IPC), with an end-to-end negative test proving the launched
     process cannot signal, trace, or otherwise affect another host process
     through those channels. File, network, environment, and credential containment
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
    not occur. Whether such a mechanism exists is
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
   running uncontained. Wherever sandboxed or
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
   invoked from an authenticated non-skill context. Admission by name is still
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
    rather than executed. Binding the reviewed implementation receipts only the outer
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
    checked. Recording that a handler's footprint includes credentials
    identifies the channel, not the principal: an admitted handler that
    resolves a mutable ambient credential or default context (a Kubernetes
    context, a cloud role, a default account) executes as whatever that
    credential currently designates, so swapping it can make identical
    approved tool arguments run against production instead of staging while
    the handler deployment digest, executor profile, and receipt all still
    verify. The ceiling record and receipt must therefore bind the stable
    principal, account, or role identifier (with its scope and trust epoch)
    that the handler was admitted to act as, and the execution gate must
    re-resolve the handler's effective credential at execution time and
    fail closed when it designates a different principal, scope, or epoch,
    with a credential-substitution negative test proving a swapped ambient
    credential or context is denied rather than executed against a
    principal the admission never named. Interception alone is still
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
     parallel and proving its side effect runs at most once. Atomic
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
     executable again. Binding and
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
      ended, regardless of interleaving. Context freshness bounds the credential,
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
   recording the producing skill stack, and that metadata must be
   host-assigned and held outside the producing skill's write authority — a
   mandatory label applied by the host or write broker at write time, or an
   authenticated out-of-band provenance record keyed to the artifact — never
   a self-carried marker, because a restricted skill that controls an
   allowed file, queue entry, or adjacent sidecar can omit or forge
   provenance it writes itself, letting a later broader context consume the
    artifact without inheriting the restricted ceiling; the provenance must
    also be preserved across copies and updates of the artifact. Under
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
    case. The host
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
   originating ceiling), and where neither is enforceable for a given
   consumer that residual boundary must be recorded explicitly in the ceiling
   record and receipt rather than left implied, with a negative test proving
   a skill-written modification to a machine-consumed control artifact is
   either rejected at write time or is not executed by that consumer with
   authority beyond the producing skill's ceiling. A single
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
   read itself is refused. The
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
