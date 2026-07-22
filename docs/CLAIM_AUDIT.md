# Claim Audit (Phase 5)

> Audit of reviewer-visible claims against the repository's own evidence and the
> claim-safety vocabulary in `.claude/rules/claim-safety.md` / `docs/CLAIMS.md`.
> Verdicts: **ALLOWED** (accurate, evidenced), **DOWNGRADE** (weaken wording),
> **REMOVE** (unsupported), **LEAVE** (already correct in context).

## Headline

The repository already has **strong claim discipline**: a `docs/CLAIMS.md`
ledger, a `claim-matrix.json` + static overclaim CI gate, and frontend copy that
explicitly disclaims certification ("Not production-ready / No compliance
certification"). The README carries a full "Scope and claim boundary" section
disclaiming production-certified / compliance-certified / regulator-approved /
formal-verification. **Almost every forbidden-phrase match in the tree is a
disclaimer, not a claim.** Only a few affirmative wording items needed action.

## Allowed (no change) — representative

| Claim | Where | Why allowed |
|---|---|---|
| "fail-closed execution gate", "Decision Receipts", "hash-chained audit" | README, docs | Evidenced by `kernel.py`, `receipt.py`, `audit.py` + tests |
| "tamper-evident audit chain" | README, CLAIMS | Matches implementation (SHA-256 chain detects edits) |
| "optional Ed25519 signing" | README, `signing.py` | Opt-in, accurately scoped |
| "Not production-ready / No compliance certification" | `acgi-ai/src/routes/*.tsx` | Correct disclaimer posture |
| "not production-certified, not compliance-certified, not regulator-approved" | README "Scope and claim boundary" | Correct disclaimer |
| "A **signed** Decision Receipt is an unforgeable token" | `ROADMAP-ENFORCEMENT-SUBSTRATE.md:119` | Already scoped to signing, under a "design targets, not current characterizations" heading — **LEAVE** |
| "reference monitor … **tamper-proof** … verifiable" | `docs/SECURITY_MODEL.md:39` | Quotes Anderson (1972) reference-monitor definition (term of art), not a product claim — **LEAVE** |
| "production-ready Helm/K8s" | `COMPARISON.md:45` | Describes a **competitor** (NeMo), not gove-zone |

## Actioned in this pass (DOWNGRADE) — completed

The chain is *tamper-evident* (detects modification), not *tamper-proof*
(prevents it). Signing makes tampering detectable, not impossible. Downgraded
three affirmative uses to the repo's canonical vocabulary:

| File:line | Before | After | Status |
|---|---|---|---|
| `docs/design/governance-aml-screening.md:155` | "contents are tamper-proof" | "contents are tamper-evident" | ✅ done |
| `docs/design/governance-legal-agent.md:163` | "contents are tamper-proof" | "contents are tamper-evident" | ✅ done |
| `docs/design/governance-vulnclaw-pentest.md:114` | "receipt contents are tamper-proof" | "receipt contents are tamper-evident" | ✅ done |

(`docs/design/acgs-lite-pep-closure-final-goal.md:66` also contains
"tamper-proof" but as an item in a **forbidden-words list** — left intentionally.)

## Deferred to the generator (not hand-edited)

| File:line | Item | Verdict | Why deferred |
|---|---|---|---|
| `.claude/skills/govern-zone/SKILL.md:8` | "keep the repository clean and **production-ready**" | DOWNGRADE → "release-ready" | File is **auto-generated** ("Auto-generated skill from repository analysis", line 4). Fix belongs in the skill-extraction generator, not the output. Low risk: internal agent-tooling doc, refers to repo hygiene not product certification. |

## Version-wording drift (tracked separately)

Many docs still describe the product as "Alpha `0.1.0.dev0`" / "`0.1.0a1`" while
canonical surfaces say `gove-zone 1.0.0rc1` / Beta. This is a **version**
consistency issue, not a safety-claim issue — see `docs/VERSIONING.md`. It is
already self-flagged as a reconcile-before-tag blocker in
`docs/gove-zone-pypi-readiness.md`.

## Conclusion

No REMOVE-class (fabricated) claims found on public surfaces. The forbidden
claims — formally verified, production/compliance certified, regulator-approved,
guaranteed-safe — appear only as **disclaimers**. Three affirmative
"tamper-proof" wordings were downgraded to "tamper-evident". Claim posture is
**launch-appropriate** after this pass.
