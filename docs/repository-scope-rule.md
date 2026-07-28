# The Repository Scope Rule

| | |
|---|---|
| **Applies to** | Every governance or security claim in this repository — docs, PR descriptions, commit messages, code comments, review verdicts |
| **Origin** | The WS-A adversarial verification pass, 2026-07-28 ([audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md)) |
| **Status** | Review rule. Not machine-enforced; see "Why this is not a lint rule". |

## The rule

> A governance or security claim must state its **component scope**, **runtime path**,
> **configuration assumptions**, and **verification evidence**. A claim missing any of the
> four is incomplete, regardless of whether it happens to be true.

## Why it exists

Three of the seven false statements found in the WS-A verification pass shared one shape:
**a true statement about `packages/gove-zone/` written as a statement about the repository.**

- "No shipped call site supplies an audit anchor" — true inside `packages/gove-zone/src/`,
  false of the repository, which has five such call sites and a persisted transactional sink.
- "No static scan and no CI job detects an ungoverned effect path" — false; one exists and is
  CI-enforced. The true claim is about its *assertion strength* and *coverage*, not its
  existence.
- "The 11-class manifest is the source of truth" — true on a branch commit, false at the ref
  the document itself cited.

None of these was a careless guess. Each was verified — against the wrong scope. The author
held the scope in their head and did not put it on the page, so the sentence that reached the
reader claimed more than the evidence supported.

A fourth, found while correcting the first three, ran the other way: "on a default v1 receipt
those four fields are not hash-bound" is literally true and reads as a live vulnerability,
because it omitted the validation that pins those fields empty. **Overstating a weakness is
the same defect as overstating a strength.** In a security document it misdirects a
reviewer's attention just as effectively, and it costs the document credibility it will need
for the claims that are real.

This monorepo makes the failure especially easy: "the repo" contains a kernel, a control
plane, a frontend, several research packages, and three nested repositories with their own
gates. There is almost no security statement that is true of all of them.

## The four required elements

| Element | Answers | Failure if omitted |
|---|---|---|
| **Component scope** | Which package, module, or path? | The claim silently generalizes to the monorepo |
| **Runtime path** | Which execution path reaches this control? | A control that exists but is never called reads as a control that runs |
| **Configuration assumptions** | Which defaults, profiles, or env vars must hold? | A guarantee true only under an opt-in posture reads as a default guarantee |
| **Verification evidence** | Which test, command, or file:line proves it? | The claim cannot be re-checked, so it rots silently |

## Examples

**Bad.** "ACGS prevents unauthorized actions."
Scope unstated, path unstated, configuration unstated, evidence absent. Also false: an
in-process library cannot prevent code in its own process from bypassing it.

**Good.** "The `gove-zone` executor path rejects a side effect that arrives without a valid
Decision Receipt: `execute_with_receipt` refuses before invoking `tool_fn`
(`executor.py:32`), under the default production profile
(`require_signature=True`), proven by
`test_executor_guard.py::test_executor_refuses_no_receipt`."

**Bad.** "Receipts are tamper-proof."
Overclaims the property (tamper-*evident*, not tamper-proof), and omits that detecting
truncation requires an operator-supplied external anchor.

**Good.** "A receipt whose fields are altered fails hash comparison at the gate
(`receipt.py:332-377`). The audit chain is tamper-**evident**: in-chain edits are detected by
re-walking, but truncation and full rewrite are detected only when the caller supplies
`expected_count` / `expected_last_hash` — which no call site inside `packages/gove-zone/src/`
does, though `acgs-control-plane` does (`governance.py:756-758`)."

**Bad.** "Single-use receipts prevent replay."
True only when a ledger is supplied, which is not the gate default.

**Good.** "Replay is blocked when a `consumption_ledger` is supplied. It defaults to `None`
at all three gate surfaces (`executor.py:56`, `:297`, `:354`), and is a **required** keyword
under `GovernanceProfile.production_strict` (`profile.py:134-141`)."

## How to apply it in review

1. For each security claim in the diff, ask the four questions. Any unanswered → request changes.
2. Check the scope against the evidence, not against intent. If the evidence is a test under
   `packages/gove-zone/tests/`, the claim is about `gove-zone` — say so in the sentence.
3. A negative claim ("nothing does X", "no call site supplies Y") needs a **repository-wide**
   search, not a package-wide one, or it needs the package named in the sentence. Negative
   existence claims are where this rule is broken most often, because a package-scoped grep
   feels conclusive.
4. Prefer narrowing the claim over broadening the implementation. A narrower true statement is
   worth more than a broader one a reviewer will disprove.

## Why this is not a lint rule

Scope correctness is a semantic property of a sentence against a codebase; no regex decides
it. What *is* mechanizable, and worth adding when the pattern recurs, is a check that
negative-existence claims in `docs/` cite a command that was run repository-wide. That is not
implemented today, and this document does not claim it is.

## Related

- [claims-map.md](./claims-map.md) — the SAY / SAY-WITH-CAVEAT / DO-NOT-SAY vocabulary.
- [ENFORCEMENT-BOUNDARY.md](./ENFORCEMENT-BOUNDARY.md) — the document this rule was written from.
- [audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md) — the findings that produced it.
