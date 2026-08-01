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

**Reported: 7 HIGH, 6 MEDIUM.** Six of the seven HIGH findings were captured in the
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

1. **Fix what is broken.** Both `govern-zone` skill copies (in flight).
2. **Add a loadability gate.** A root test that every `SKILL.md` under `.claude/skills/**`
   and `.agents/skills/**` parses `---`-delimited frontmatter with a `name` and
   `   description`, and enforces the host's skill schema (see step 4 for why the generic
   check alone is not enough). The host validators do not ship in this repository or as
   a pinned dependency: Codex's `quick_validate.py`, for example, lives only inside the
   agent installation, so an ordinary checkout or CI runner cannot invoke it. The gate
   must therefore vendor a pinned copy of the validator (license permitting) or encode
   the same schema rules as a repo-local check, with a recorded upstream version to diff
   against on host upgrades. Cheap, deterministic, catches the entire class.
   One repo-hygiene prerequisite: the root `.gitignore` ignores `.agents` wholesale, so
   only the two already-tracked `govern-zone` files survive; any new skill or sidecar
   under `.agents/skills/**` is invisible to a CI checkout (`git check-ignore` confirms
   this for a new `SKILL.md` and for a `skill-card.md` beside the tracked skill).
   Before relying on this gate, un-ignore the shared `.agents/skills/**` source tree
   while selectively re-ignoring runtime state, mirroring the `.claude/` whitelist
   pattern already in the same file; otherwise the gate silently covers only skills
   someone remembered to force-add.
3. **Skill cards for the skills that can act.** Start with the tracked skills that run
   commands or touch privileged paths (`govern-zone` in both tracked copies,
   `maintain-acgs`, `phase-gate`, and `pr-evidence` today: `govern-zone` directs agents
   to create files, edit CI and manifests, and execute shell commands, and the other
   three direct git, test, lint, or hash-check commands; the skill step 1 restores must
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
   the host itself rejects.
5. **Skill identity and permission ceiling.** A trusted name/version/artifact digest per
   skill, plus an independently reviewed maximum permission set held outside the skill.
   Without these, step 6 would enforce a caller-controlled declaration.
6. **Wire `permissions:` into the kernel** as a deny-only policy input bound into the
   receipt and checked against the step-5 identity and ceiling. Receipt binding governs
   only actions that reach the executor, and today's host coverage is narrow:
   `.claude/hooks/acgs-emit-receipt.py::_classify` intercepts the edit tools and a few
   orchestration commands, so ordinary `Read` and general `Bash` calls bypass the
   receipt path entirely, and the `.agents` tree has no runtime gate at all. This step
   therefore includes the host-side interception that routes every governed capability
   through `execute_with_receipt`; until that wiring exists, the enforcement claim is
   limited to calls already routed through that boundary. This is the differentiating
   step and should get a design of its own.
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
