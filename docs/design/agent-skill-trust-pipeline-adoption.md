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
file whose first line is a ` ```markdown ` fence instead of YAML frontmatter. That is a
real defect — the skill silently never loaded — and it existed in *two* copies, the same
blob mirrored at `.claude/skills/govern-zone/SKILL.md` and
`.agents/skills/govern-zone/SKILL.md`. It went unnoticed indefinitely because nothing
checks that a skill is loadable, let alone correct.

That is the argument for this proposal in one example: a governance repository shipped an
implicitly-invocable skill that was broken *and* factually wrong about its own conventions,
and no gate noticed.

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
   plus the step-6 host interception and enforcement. The step-2 loadability gate and
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
   enforce mirror parity for the shared skill body and security metadata (permission
   declaration, pinned digest), but as a *normalized* comparison, not a raw byte
   diff, because the two copies legitimately diverge in host-specific
   representation: once step 4 applies host schemas, the Codex copy carries its
   `permissions:` declaration under `metadata:` or in a sidecar while the Claude
   copy may hold it in frontmatter, and only the Codex copy ships an
   `agents/openai.yaml` adapter. The parity check therefore compares a canonical
   instruction body and the security values after normalizing each copy's
   host-specific encoding, and allows host adapter files to exist only on their
   host's side; either generate both copies from one canonical source or fail on
   divergence of the normalized body or security metadata. Cheap, deterministic,
   catches the entire class.
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
   opened with, not exempt from it. The skill step 1 restores must
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
   run, approved or not. The approval grant is itself a credential and must be
   bound to the exact request it approves: authenticated to the granting human,
   tied to the actor, skill identity/digest, action, and final arguments the new
   receipt represents, single-use, and bounded by an expiry, with the grant
   recorded as evidence in that receipt. Negative tests must prove a grant
   presented for altered arguments or a different skill, an expired grant, and a
   grant replayed for a second execution are all rejected without a side effect.
   `docs/skills/skill-schema.md` is then updated to record that mapping so cards,
   validators, and the future executor read exactly one contract.
5. **Skill identity and permission ceiling.** A trusted name/version/artifact digest per
   skill, plus an independently reviewed maximum permission set held outside the skill.
   Without these, step 6 would enforce a caller-controlled declaration. "Outside the
   skill" is necessary but not sufficient: if the agent, or any skill it runs, can
   write the location holding the ceiling record, the caller can widen the ceiling
   before issuance, the receipt then faithfully binds the tampered value, and the
   executor accepts capabilities nobody approved. The ceiling record must therefore
   live outside agent write authority entirely, be authenticated (integrity-protected
   under a key or review path the agent cannot exercise), and be version-bound to the
   specific skill digest it approves, with tamper and rollback tests at both issuance
   and execution proving that a widened, reverted, or digest-mismatched ceiling record
   is rejected. A pinned
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
6. **Wire `permissions:` into the kernel** as a deny-only policy input bound into the
   receipt and checked against the step-5 identity and ceiling. Deny-only is not a
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
   touch the outside location. Even then, argument-level checks
   govern only the launch, not the launched process: an allowed
   `shell.allowed_scripts` entry spawns a process that inherits the host's ambient
   file and network capabilities, so a declaration that permits that script while
   denying network access or writes outside a directory promises containment that
   rechecking the command and its transformed arguments cannot deliver. This step
   therefore defines shell containment semantics explicitly: a shell grant is
   treated as granting the process's ambient file and network capabilities unless
   the launch runs under an OS-level sandbox or capability-brokered executor that
   materially enforces the narrower ceilings. Whether such a mechanism exists is
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
   outside the allowed directory, its denied socket) rather than on the launch
   arguments. Receipt binding governs
   only actions that reach the executor, and today's host coverage is narrow:
   `.claude/hooks/acgs-emit-receipt.py::_classify` intercepts the edit tools and a few
   orchestration commands, so ordinary `Read` and general `Bash` calls bypass the
   receipt path entirely, and the `.agents` tree has no runtime gate at all. This step
   therefore includes the host-side interception that routes every governed capability
   through `execute_with_receipt`; until that wiring exists, the enforcement claim is
   limited to calls already routed through that boundary. Interception alone is still
   not sufficient, because an agent issues ordinary tool calls outside any skill
   invocation and the current hook cannot tell the difference:
   `.claude/hooks/acgs-emit-receipt.py::main` receives only the tool payload and
   assigns `PAPERCLIP_AGENT_ID` or a generic actor, with no skill digest or
   loader-issued invocation identity. A compromised skill could direct a normal
   Bash/Edit call that is then governed only as an unscoped agent action, bypassing
   its ceiling. Every intercepted request must therefore carry an unforgeable,
   host-bound origin. For requests the host identifies as skill-originated, that
   origin is the loader-issued invocation context (the step-5 identity and digest,
   not self-reported in the payload), which selects the skill's ceiling. A single
   origin identity is not enough once skills compose: when one skill invokes
   another, or several are active concurrently, attributing the request to any
   single skill would let a restricted outer skill route an action through a
   broader inner skill and escape its own ceiling. The loader-issued context must
   therefore carry the authenticated origin/delegation stack of every skill
   contributing to the request, and the effective ceiling is the intersection of
   all stacked skill ceilings (before intersecting with the declaration as
   above), with nested- and concurrent-skill negative tests proving that invoking
   or overlapping with another skill can only narrow authority, never amplify
   it. For ordinary
   tool use outside any skill invocation, the host must authenticate an explicit
   non-skill origin, governed by the agent's normal policy ceiling; demanding a skill
   digest on every request would block all governed non-skill tool use. The gate
   fails closed when a request carries no authenticated origin at all, or when a
   skill-originated request arrives without its loader-issued context. This is the
   differentiating step and should get a design of its own.
7. **Evals** for the skills that encode repo conventions, where drift is silent.
8. **Full OMS-style signing** can come last; step 5 needs only a pinned digest and an
   approval record, not the complete certificate-chain apparatus, though the two should
   converge.

Steps 2 and 3 are small and independently useful. Steps 5 and 6 are a real design task
and should not be bundled with the rest; they are recorded as a planned stage in
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
