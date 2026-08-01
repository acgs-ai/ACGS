# Adopting an Agent-Skill Trust Pipeline

Status: proposal
Date: 2026-08-01
Scope: `.claude/skills/**`, `.agents/skills/**`, and the governance story around them

## Why this document exists

Agent skills are executable policy. A skill can tell an agent to run commands, read
files, call tools, or make decisions on a user's behalf, and in this repo several load
implicitly — `.agents/skills/govern-zone/agents/openai.yaml` sets
`allow_implicit_invocation: true`, so its content becomes standing context for every
Codex run without anyone opting in.

We have 24 skill directories across two trees. None of them has an owner record, a
declared permission set, an eval, or an integrity check. For a repository whose product
is governed execution, that is the least governed surface we own.

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

The docs are not aspirational. Four sampled skills each ship the complete set. Signing
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

**Findings: 7 HIGH, 6 MEDIUM. Zero true positives.** Every HIGH was a heuristic misfire
on one of this repo's own idioms, verified by reading each flagged line:

| Rule | Where | Verdict |
|---|---|---|
| AS1 "Agent Config Directory Access" | `maintain-acgs:27` | False positive — the skill's *purpose* is maintaining `.claude`; reading `settings.json` is its job |
| AS1 | `worktree-lanes:82` | False positive — a documentation cross-reference to `.claude/rules/headless-delegation.md`, not access |
| P6 "Direct Prompt Extraction" | `pr-evidence:32` | False positive — "paste literal commands and literal outputs" is our verification-discipline rule |
| P6 ×3 | `imagegen-frontend-web:3,6,399` | False positive — fires on emphatic rule blocks ("HARD OUTPUT RULE — READ FIRST") |

The finding list was not the value. **The structural output was.** SkillSpector reported
`.claude/skills/govern-zone` as `Skill: unknown`, because it cannot parse a name from a
file whose first line is a ` ```markdown ` fence instead of YAML frontmatter. That is a
real defect — the skill silently never loaded — and it existed in *two* copies, the same
blob mirrored at `.claude/skills/govern-zone/SKILL.md` and
`.agents/skills/govern-zone/SKILL.md`. It went unnoticed indefinitely because nothing
checks that a skill is loadable, let alone correct.

That is the argument for this proposal in one example: a governance repository shipped an
implicitly-loaded skill that was broken *and* factually wrong about its own conventions,
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

That gap is precisely where gove-zone fits. A declared permission set is a policy input.
The kernel already binds actor, action, arguments, and policy into a receipt; a skill's
declared `permissions` block is another binding, checkable at the executor gate. They
declare; we enforce. This is the one item that is both borrowable and differentiating.

### 2. Skill cards

Per-skill governance record: owner, license, use case, deployment geography, credential
type with a least-privilege note, actionable risk/mitigation pairs, output schema, and a
version tied to the signing identifier. We have `docs/CLAIMS.md` at repo level and nothing
per capability.

Their "good risk statements" guidance is the same instinct as our
`.claude/rules/claim-safety.md` safe/unsafe wording table — vague risks rewritten as
testable ones:

| Weak | Stronger |
|---|---|
| The skill could make mistakes. | The skill may generate incorrect remediation steps; users must review proposed code changes before execution. |
| The skill writes files. | The skill may overwrite generated reports in the configured output directory; it must not write outside that directory. |

Worth cross-linking the two rule sets rather than maintaining separate vocabularies.

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

OMS is close to what `packages/acgs-proofpack-verifier` already does for receipt bundles:
detached signature, pinned trust anchor, offline verification, strict about unsigned
additions. If we sign our own skill directories, adopt OMS rather than inventing a format
— it interoperates, and the verifier already exists as a pip package.

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
   `description`. Cheap, deterministic, catches the entire class.
3. **Skill cards for the skills that can act.** Not all 24 — start with those that run
   commands or touch privileged paths: `maintain-acgs`, `worktree-lanes`,
   `headless-delegation`, `deploy-drift-check`, `pr-queue`, `codex-execution-workflow`.
4. **Declared `permissions:` on the same set**, initially documentation-only.
5. **Wire `permissions:` into the kernel** as a policy input bound into the receipt. This
   is the differentiating step and should get a design of its own.
6. **Evals** for the skills that encode repo conventions, where drift is silent.
7. **Signing** last — it is the least valuable layer until the content is worth pinning.

Steps 2 and 3 are small and independently useful. Step 5 is a real design task and should
not be bundled with the rest.

## References

- [NVIDIA/skills](https://github.com/NVIDIA/skills) — catalog, Apache-2.0 + CC-BY-4.0
- [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) — scanner
- `docs/agent-skill-trust-pipeline.mdx`, `docs/signing-agent-skills.mdx`,
  `docs/skill-cards.mdx` in the NVIDIA/skills repo
- OpenSSF Model Signing (OMS), `model-signing` on PyPI
- Local counterparts: `.claude/rules/claim-safety.md`,
  `.claude/rules/security-sensitive-files.md`, `packages/acgs-proofpack-verifier`
