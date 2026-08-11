# ACGS vNext — Execution Governance Layer

**Governed mediation for execution-environment side effects.**

- **Status:** P11 accepted and partially implemented. Phase 0 and parts of
  Phases 1-2 are implemented; the remaining phases are proposals. Decision
  record: [ADR-0010](../adr/0010-execution-governance-layer.md)
- **Date:** 2026-08-09
- **Motivating incident:** [`docs/audits/2026-08-09-npm-artifact-incident.md`](../audits/2026-08-09-npm-artifact-incident.md)
- **Prior analysis:** [`developer-tool-mutation-governance.md`](developer-tool-mutation-governance.md) (§6 C8 superseded by ADR-0010 D3)
- **Vocabulary constraint:** this document uses only terms defined in
  `docs/GLOSSARY.md`, `docs/DECISION_RECEIPT_SPEC.md`, and
  `docs/SECURITY_MODEL.md`. No new governance concept is introduced. Where the
  prior analysis coined terms, this document replaces them — see §1.1.

---

## Executive summary

**The layer existed before P11; the repository hook is now wired to it.**

ACGS built `UniversalGateway` — a complete Policy → Receipt → Executor loop with
sealed-tool bypass detection, an always-on consumption ledger, and real
`DecisionReceipt` minting. The ledger applies to the strong `invoke` path.
Before P11, the repository hook called the passive auditor, whose default policy
returned `ALLOW` unconditionally and whose receipt type had no signature
field. The current hook calls `UniversalGateway.handle_claude_hook`.

So ACGS vNext is not a new kernel, a new receipt, or a new threat class. It is
**the existing gateway extended toward seven previously unmediated surfaces**: shell
commands, package-manager invocations, dependency installation, lifecycle
scripts, git mutations, artifact generation, and release publication.

**Three of those seven are not fully mediable, and the design says so rather
than papering over it.** Shell commands are gated only where an argv prefix
resolves to a known binary; arbitrary redirects and copies are recorded, not
classified (§2.2.1). Lifecycle scripts run inside the package manager's process
with no external callback — the only real control is disabling them at
invocation (§2.2.2). Artifact generation is a CI check, not mediation (§2.2.3).
Surfaces 2, 3, 5, and 7 are genuinely gated.

**What remains genuinely new work** is specific: a `PATH` shim so a package
manager invoked from an interactive terminal reaches a decision point, a policy
that evaluates dependency-set deltas, and authenticated
`allowed_actors`/`validator` identities. Structural classification and the
canonical-manager rule are implemented at integrated hooks.

**What cannot be closed** is stated plainly and repeatedly below: no hook can
observe an interactive terminal, and a `PATH` shim is bypassable by absolute
path or container. The layer's honest goal is to make bypass *deliberate and
detectable* rather than routine and invisible — and `bypass_attempts()` already
makes that measurable.

---

## 1. Governance gap analysis

### 1.1 Vocabulary correction

The prior analysis used six terms that are **not** ACGS vocabulary. This
document replaces them. Anyone carrying forward that analysis should apply this
mapping.

| Prior term (do not use) | Canonical replacement | Source |
|---|---|---|
| authority boundary | `authority` **and** `execution_boundary`, kept separate | `GLOSSARY.md:24`, `DECISION_RECEIPT_SPEC.md:30` |
| evidence graph | tamper-evident evidence; hash-chained JSONL audit chain | `GLOSSARY.md:38`, `ARCHITECTURE.md:17` |
| artifact lineage | `previous_audit_hash` / `audit_event_hash`; provenance | `DECISION_RECEIPT_SPEC.md:45-46` |
| credential lifecycle | key lifecycle; key custody, revocation | `SECURITY_MODEL.md:17-18` |
| trust anchor | trusted verifier; trusted key; scoped trust purpose | `DECISION_RECEIPT_SPEC.md:184-201` |
| autonomous execution control | receipt-gated execution; execution membrane | `GLOSSARY.md:36`, `ARCHITECTURE.md:3` |
| mutation class M0–M6 | risk tier, expressed through `RiskTierPolicy` | `policy.py:791-960` |

The last row matters most for implementation. The prior analysis proposed a
seven-level mutation taxonomy. ACGS already has `RiskTierPolicy`, which is
content-addressed, sealed, defaults unassigned tools to the **most restrictive**
declared tier (`policy.py:843-848`), and is tested. **The taxonomy becomes tier
configuration, not a new concept.**

### 1.2 Supported today versus missing wiring

> **Implementation status (2026-08-09).** P11 is accepted and partially
> implemented: Phase 0 and parts of Phases 1-2 are live. The matrix distinguishes
> current capability from the remaining proposal; §1.2a records what landed.

The decisive column is the last one.

| Capability | Status | Evidence | For this layer |
|---|---|---|---|
| Fail-closed executor gate, `expected_actor` required | **on-master, tested** | `executor.py:32-236`; `test_executor_guard.py` | reuse as-is |
| `DecisionReceipt`, 32 fields, hash-bound incl. signature triple | **on-master, tested** | `receipt.py:119-185,332-377` | reuse as-is |
| MACI validator ≠ proposer, self-validation rejected | **on-master, tested** | `receipt.py:850-886`; `test_maci_role_separation.py` | reuse as-is |
| Hash-chained audit + `verify_chain` | **on-master, tested** | `audit.py:99-400` | reuse as-is |
| Ed25519 signing over `receipt_hash` | **on-master, tested**, optional `crypto` extra | `signing.py:76-178` | reuse; key custody unresolved |
| Argument binding (receipt ↔ executed args) | **on-master, tested** | `receipt.py:1001-1032` | reuse as-is |
| Single-use consumption ledger | **on-master, tested**; always-on for `invoke` | `gateway.py:827` | reuse on the strong execution path; hook decisions do not consume receipts |
| Sealed-tool bypass detection + audited `BYPASS_ATTEMPT` | **on-master, tested** | `gateway.py:157-198`; `test_universal_gateway.py:253,270,290` | **the ADV9 primitive** — reuse |
| `bypass_attempts()` accessor | **on-master** | `gateway.py:730` | makes mediation completeness observable |
| Full Policy → Receipt → Executor loop | **on-master, tested** | `gateway.py:458-616` | the mediation path |
| `handle_claude_hook` minting real receipts | **on-master, tested and wired** | `gateway.py:1022-1109`; `.claude/hooks/acgs-emit-receipt.py` | Phase 0 delivered |
| `RiskTierPolicy`, content-addressed + sealed | **on-master, tested** | `policy.py:791-960` | expresses the risk taxonomy |
| `allowed_actors` fail-closed principal allowlist | **on-master** | `gateway.py:__init__` | **missing wiring** — no real identities exist |
| Four-verdict `Decision` incl. `TRANSFORM` | **on-master** | `decision.py:18-24` | `TRANSFORM` = "install, but pinned to this exact resolved set" |
| Byte-exact bundle replay | **on-master, tested**; needs `ReplaySideStore`, **off by default** | `replay.py:231-389`; `kernel.py:93` | must be enabled for this layer |
| Shell / package-manager mediation | **partial at integrated hooks** | `execution.py`; `test_execution_governance.py` | hook calls are classified and can be denied; interactive and outside-hook paths remain unmediated |
| Canonical-manager / dependency-set policy | **partial** | canonical-manager rule in `execution.py`; resolved-set delta absent | manager mismatch is implemented; resolved-set evaluation remains proposed |
| Interactive-terminal observation | **impossible via hooks** | — | **cannot be closed** |

**Nine of fifteen rows are reuse. Two are wiring. Two are net-new and small. One
is impossible and must be stated as such.**

### 1.2a What P11 actually implemented, and where the prediction was wrong

| Capability | Predicted | Delivered | Where |
|---|---|---|---|
| `handle_claude_hook` wired to the hook | wiring | **done** | `.claude/hooks/acgs-emit-receipt.py`; `test_execution_governance.py::test_gateway_factory_writes_to_the_existing_audit_chain` |
| Structural (non-substring) classification | not predicted as a component | **done — the one genuinely new mechanism** | `execution.py::classify_command` |
| `RiskTierPolicy` expressing the tiers | reuse | **done, as data** | `execution.py::EXECUTION_TIER_BUNDLE` |
| `allowed_actors` populated with real identities | wiring | **NOT done** | see §1.2b |
| Dependency-set delta policy | net-new | **partial** — the canonical-manager rule landed; resolved-set diffing did not | `execution.py::EXECUTION_RULE_BUNDLE` |
| `PATH` shim | net-new | **NOT done** | ADV-A stays open |
| `ReplaySideStore` enabled | must be enabled | **NOT done** | A3-3 unverified |
| Interactive-terminal observation | impossible | **still impossible** | unchanged |

Two rows changed shape against the prediction, and both changes were forced by
reading the code rather than by preference:

1. **A custom `Policy` subclass for the canonical-manager check is not
   possible.** `CompositePolicy.__init__` (`policy.py:981-1001`) rejects any
   member that is not a sealed built-in — it caches its version at construction
   but evaluates members live, so a mutable member could change decisions under
   a stable composite version. The error message names the remedy: express it as
   a `RuleSetPolicy` bundle. The classifier therefore emits structured *facts*
   and the bundle decides on them declaratively.

2. **`RiskTierPolicy` keys tiers off the tool name only** (`policy.py:937`), and
   a tier carries exactly one enforcement decision. The §2.3 claim that the
   `dependency` tier permits `ALLOW | TRANSFORM | ESCALATE | DENY` cannot come
   from the tier. It comes from ordering: `CompositePolicy` is
   first-non-ALLOW-wins, so the rule set runs first and a specific denial is
   recorded under its own `rule_id`, with the tier as the baseline behind it.

### 1.2b Attribution is improved but not solved — A1-1 is NOT met

The hook no longer emits the hardcoded `govern-zone-hook`. It resolves an actor
through a stated precedence and records *which* source produced it
(`execution.py::resolve_execution_actor`): explicit `GOVE_ZONE_ACTOR`, then
`PAPERCLIP_AGENT_ID`, then the POSIX login name as `local:<user>`, then the
literal `unattributed`.

**None of these is an authenticated identity.** They are environment variables,
and any process that can set one can choose its own actor string. What changed is
that the basis is now explicit, machine-readable, and carried into the receipt as
`attribution_source` — the weakness is auditable instead of hidden behind a
constant. A1-1 as written ("0 records with the fallback actor") is **not met**:
the live chain still holds 414 historical `govern-zone-hook` records, and the new
basis is not authentication. Closing it requires an authenticated principal from
the integrating surface, which this layer does not provide.

### 1.3 The three defects that made the incident invisible

Each is a specific line, and each has a specific fix.

1. **Classifier scope.** `_classify` (`.claude/hooks/acgs-emit-receipt.py:58-69`)
   returns `None` for everything outside four tool names and three substrings.
   `npm install` exits unaudited.

   It is a substring matcher, not a classifier, and fails in both directions:
   `git commit -m "fix team dashboard"` matches `" team "` and emits a spurious
   receipt. **This class of defect was observed live while writing this
   document** — the repository's `seal-block` guard fired on
   `docs/adr/0010-execution-governance-layer.md` because the prose contains the
   string `constitutional-hash`, though the file carries no seal marker. Two
   independent substring classifiers, two false positives, same root cause.

2. **Unconditional allow.** `_ObserverPolicy.evaluate`
   (`integration.py:583-600`) returns `Decision.ALLOW` for everything. The
   observed distribution is `decision: allow` at 100% of 381 records.

3. **Attribution.** `acgs-emit-receipt.py:111` falls back to the literal
   `govern-zone-hook` because `PAPERCLIP_AGENT_ID` is set nowhere; `run_id` is
   accepted at `integration.py:652,723` and never reaches the `Receipt`
   constructed at `:700-707`.

---

## 2. Architecture proposal

### 2.1 Position

The Execution Governance Layer sits at the same place the kernel always has —
*below reasoning, above side effects*. `AGENTS.md:13` defines ACGS as the
execution membrane below agent reasoning and above side-effectful tools. This
layer takes that definition literally: a dependency install is a side effect,
whoever requested it.

**This is not a scope expansion.** ADR-0001 already decided that ACGS "should
govern execution boundaries: tool calls, API calls, file writes, **shell
commands**, permissions, policy checks, separation-of-duties, audit trails, and
verifiable evidence," and that "prompt-level governance is advisory. Runtime
governance is authoritative." Shell commands have been in ACGS's declared scope
since ADR-0001 and have never been mediated. This layer closes the gap between
declared and implemented scope — which is also why no new governance concept is
required to describe it.

```
actor (agent | tool | CI | human at a terminal)
  → mediation point (hook | PATH shim | git hook | CI job)
  → UniversalGateway.invoke
      → policy evaluation           (RiskTierPolicy)
      → DecisionReceipt minted      (signed where a signer is configured)
      → execute_with_receipt        (expected_actor bound, receipt burned)
      → SealedTool                  (bypass audited as BYPASS_ATTEMPT)
  → side effect
  → hash-chained audit append
```

One `UniversalGateway` instance owns the `execution-environment` boundary: one
tenant contract, one policy, one audit chain, one consumption ledger.

### 2.2 The seven surfaces

`execution_boundary` = `execution-environment` for all seven. Actions follow the
existing `runtime.*` convention already present in the audit chain.

| # | Surface | `proposed_action` | Mediation point | Default verdict | Coverage |
|---|---|---|---|---|---|
| 1 | Shell command | `env.shell.exec` | agent hook only | record; tier via argv-prefix match | **partial — see 2.2.1** |
| 2 | Package-manager invocation | `env.package.invoke` | `PATH` shim | `DENY` if manager ≠ declared `packageManager` | full at the shim |
| 3 | Dependency installation | `env.package.install` | `PATH` shim, post-resolve pre-fetch | `ESCALATE` on new direct dependency | full at the shim |
| 4 | Lifecycle-script enablement | `env.package.lifecycle_enable` | decision at surface 3 | scripts **disabled**; enablement escalates | **not a mediated execution point — see 2.2.2** |
| 5 | Git mutation | `env.git.mutate` | `core.hooksPath` guard | tier-dependent; `ESCALATE` on control surfaces | full at commit time |
| 6 | Artifact generation | `env.artifact.generate` | CI check on declared generators | `DENY` if a tracked artifact declares generated with no generator | **detective only — see 2.2.3** |
| 7 | Release publication | `env.release.publish` | CI job | `ESCALATE` — always second-party | full |

**Surface 2 is the highest-value control in the entire proposal.** One read of
`package.json` for `packageManager`, compared against the invoked binary. It
would have denied the incident outright, before any network access and before
any lifecycle script ran. It is also the cheapest thing here.

#### 2.2.1 Shell commands are only partially governable — do not claim otherwise

ADR-0001 placed shell commands in ACGS's declared scope. Delivering that scope
honestly requires naming what a gate can and cannot resolve.

A shell command is an opaque string. Its side effects are not recoverable by
argument parsing: `> file`, `tee`, `cp`, `mv`, `install`, and any `$(...)`
substitution mutate tracked source without naming a tool. `.claude/policy/build.yaml:13-15`
already concedes exactly this and warns against writing rules that would be
"dead, not a gate."

Therefore surface 1 is scoped to what is decidable:

- **Decidable:** argv-prefix match against a declared table — the invoked binary
  and its first arguments. This routes `npm`/`pnpm`/`pip` to surfaces 2-3 and
  Git mutations to surface 5.
- **Not decidable:** the effect of an arbitrary command. Redirects, copies, and
  substitutions are recorded as `env.shell.exec` with an `argument_hash`, and
  are not promoted to a risk-bearing surface. The undecidable marker itself
  fails closed to `ESCALATE`, with no allow receipt.

Git inspection is also not decidable from argv alone. Repository and ambient
configuration can launch `core.fsmonitor`, `diff.external`, pager, signature,
and content-filter helpers from commands whose visible form is only
`git status`, `git diff`, or `git log`. The hook does not execute Git in a
sanitized environment or bind trusted Git configuration into a receipt.
Consequently every declared Git read-only command fails closed as undecidable;
only Git mutations retain their explicit control-surface classification.

**Consequence, stated rather than engineered around:** a shell command whose
effect is undecidable is recorded, attributed, and escalated without an allow
receipt. Detection of its actual mutation still falls to surface 5 at commit
time and to the control-surface inventory. Any claim that shell commands are
"governed" must carry this qualifier. Substring matching over command text is
explicitly rejected as the classifier — §1.3 documents two live false
positives from exactly that technique.

#### 2.2.2 Lifecycle scripts cannot be mediated at execution

Lifecycle scripts run **inside the package manager's own process**, after fetch,
with no callback to any external gate. There is no decision point between "the
manager decided to run this script" and "the script ran." A `PATH` shim decides
only *before* the manager is invoked.

So surface 4 is not a mediated execution point, and the design does not pretend
otherwise. The achievable control is a parameter of the surface-3 decision:

1. Install with scripts disabled by default (`--ignore-scripts` or equivalent).
2. Treat enabling them for named packages as a separate escalated decision,
   recorded as `env.package.lifecycle_enable` **before** the manager runs.

This is the `TRANSFORM` verdict doing real work — a governed downgrade of the
requested action, not a binary allow/deny. Execution remains irreversible:
deleting `node_modules` reverts artifacts, not execution. The incident's single
largest unknown is whether any of its 103 packages ran a lifecycle script, and
nothing recorded it.

#### 2.2.3 Artifact generation is detective, not preventive

Surface 6 exists because of the orphaned-generator finding: `.codex/config.toml`
was force-added past its own ignore rule, declares itself generated in its own
header, and has **no generator anywhere in the repository**.

There is no generic "generator wrapper" to build — generators are arbitrary
programs, and wrapping all of them is not a bounded task. What *is* bounded is
the inventory: a declared list of tracked artifacts with `status`
(authored / generated / generated-with-source), `generator`, and `owner`, checked
in CI. A tracked artifact declaring itself generated with a null generator fails
the check.

This detects the condition; it does not prevent the write. A tool rewriting such
a file still succeeds locally — it simply now fails a check instead of passing
silently. That is the whole delta, and it is worth having, but it is not
mediation.

### 2.3 Risk tiers

Expressed as `RiskTierPolicy` configuration, not a new taxonomy. Unassigned
tools default to the most restrictive declared tier
(`policy.py:843-848`) — fail-closed by construction.

| Tier | Actions | Verdicts permitted |
|---|---|---|
| `unclassified` | shell commands whose effect is not decidable from the argv prefix | `ESCALATE`; no allow receipt |
| `read-only` | inspection whose executable context is structurally bounded; excludes Git inspection | `ALLOW` |
| `workspace` | untracked/ignored writes | `ALLOW` + receipt |
| `source` | tracked source mutation | `ALLOW` + receipt |
| `dependency` | surfaces 2–4 | `ALLOW` \| `TRANSFORM` \| `ESCALATE` \| `DENY` |
| `control-surface` | CI, policy, hooks, tool config, tracked generated artifacts | `ESCALATE` minimum; self-approval rejected |
| `trust-root` | keys, approvers, enforcement mode, `allowed_actors` | `ESCALATE` by a distinct validator |
| `publication` | surface 7 | `ESCALATE` by a distinct validator |

`RuleSetPolicy` rules may only be `deny` or `escalate` (`policy.py:421-428`);
positive authorization is expressed as actor/trust-tier exemptions. The tier
table above respects that constraint.

**Correction from implementation.** A `RiskTier` carries exactly one
`enforcement` decision (`policy.py:743-748`), so the "verdicts permitted" column
is not a property of the tier. It is the range produced by the *composite*: the
rule set runs first (first-non-ALLOW-wins), then the tier as baseline. Concretely
for `dependency` — `DENY` comes from `deny-non-canonical-package-manager`,
`ESCALATE` from either `escalate-install-with-lifecycle-scripts-enabled` or the
tier baseline, and the tier alone would only ever escalate. As implemented, the
tiers are `EXECUTION_TIER_BUNDLE` and the rules are `EXECUTION_RULE_BUNDLE` in
`packages/gove-zone/src/gove_zone/execution.py`.

`default_tier` is deliberately left unset so `RiskTierPolicy` resolves an
unassigned tool to the most restrictive declared tier — `trust-root`, i.e. DENY
(`test_execution_governance.py::test_unassigned_tool_falls_to_the_deny_default`).
That is fail-closed by construction and it is also a self-lockout hazard: every
tool a hook matcher can deliver must carry an assignment, which is asserted
against the live `.claude/settings.json` by
`test_every_hook_matcher_tool_has_a_tier_assignment`.

### 2.4 What preserves the invariant

- **Fail-closed execution** is unchanged on paths wired through
  `UniversalGateway.invoke`: no valid Decision Receipt, no side effect. On the
  Claude hook path, policy timeout, policy error, and audit-append failure fail
  closed at the decision surface, but the host does not present the minted
  receipt to a gove-zone executor. Kernel failures synthesize `DENY` with
  distinct `policy_version` markers (`kernel.py:328,361,371,377-387`).
- **Self-validation** is structurally rejected: `validator_id == expected_actor`
  → `SELF_VALIDATION` (`receipt.py:850-869`). The two-signature rule for
  `control-surface` and above is the same rule the runtime already enforces.
- **Actor never comes from the request body** on any gateway surface
  (`gateway.py:1121-1126`, tested at `test_universal_gateway.py:502`).
- **One decision, at most one side effect on the strong execution path** — the
  consumption ledger is always on for `UniversalGateway.invoke`. Hook decisions
  mint receipts for a host executor and do not consume them.

---

## 3. Threat model deltas

No new `ADV*` number. Per `SECURITY_MODEL.md:52-55`, every control below is
`[proposed]` until it has cited tests in the checkout.

### ADV9 — out-of-gate executor bypass (scope extension)

Current row (`SECURITY_MODEL.md:73`) is tagged `[on-master, partial]` with the
residual: *"the kernel cannot stop code paths it is not wired into; gateway
conformance is partial."*

**Extension.** The attack surface includes execution-environment paths:
interactive shells, package managers invoked directly, and developer tools
writing tracked files. The incident is this residual realized against a real
repository.

**Proposed controls:** mediation points for all seven surfaces (§2.2);
`SealedTool` grants making direct invocation an audited `BYPASS_ATTEMPT`;
`bypass_attempts()` as a periodic completeness check.

**Residual that remains after all proposed controls** — state this wherever
ADV9 is described:

1. A `PATH` shim is bypassable by absolute path, by a container, or by
   unsetting `PATH`. Detectable after the fact via surface 5 and CI; not
   preventable.
2. An interactive terminal cannot be observed by any hook. This is a property
   of the harness, not a gap in ACGS.
3. `bypass_attempts()` returns an empty tuple both when there were no bypasses
   *and* when the gateway was never on the path. An empty result is evidence
   only alongside proof the gate is wired.

### ADV6 — supply-chain attacker (scope extension)

Current row (`SECURITY_MODEL.md:70`), `[on-master, partial]`, carries the
constitutional-hash caveat: the sealed-marker inventory is empty, so the gate
*"is real plumbing over a currently no-op gate."*

**Extension.** Named attack steps gain: dependency admission without approval;
lifecycle-script execution at install time; and non-canonical package-manager
use splitting lockfile resolution.

**Proposed controls:** surfaces 2–4; dependency-delta policy; SBOM delta as a
required CI check.

**Residual:** CI-side controls cannot see a local install. In the incident the
lockfile was gitignored, so no CI check would ever have fired. Surface 2 is the
control that covers this; SBOM delta is a backstop for what reaches shared
history, and the two are not substitutes.

### ADV2 — insider / malicious operator (relevance note)

The incident had **no adversary**. Intent was benign; the operator even ran
`npm audit` afterward. It is recorded here because ADV2's control — *"tamper-
evidence today… hash-chained JSONL"* — is precisely what did not apply: the side
effect never entered the chain, so there was nothing to make evident.

**This is the sharpest lesson in the threat model.** Tamper-evidence protects
records that exist. It offers nothing against a side effect that was never
recorded. Completeness of mediation (ADV9) is therefore a precondition for
ADV2's control to mean anything.

### ADV13 — availability (accepted cost)

Mediating shell commands and installs adds a fail-closed dependency to routine
developer work. ADV13 already names the inversion: fail-closed turns every
integrity attack into an availability attack. The degraded-mode policy ADV13
lists as `[proposed]` becomes more urgent, not less, under this layer.

---

## 4. Migration plan

Additive and observe-first. Each phase is independently valuable and
independently revertible. **`OBSERVE` on any surface is time-boxed with a named
owner** — an indefinitely-observing gate is the exact failure this work corrects.

**Status as of 2026-08-09:** Phase 0 **done** · Phase 1 **partial** (`run_id`
threaded, actor improved but not authenticated — §1.2b) · Phase 2 **partial**
(the canonical-manager rule is live at the hook; the `PATH` shim is not built) ·
Phases 3-6 **not started**.

Two deviations from the plan as written, both deliberate:

- Phase 0 said "no new code." That was wrong: `handle_claude_hook` normalizes a
  payload into `runtime.{tool}` calls carrying only a summary, so a shell command
  had no surface to be classified into. The new code is
  `gove_zone/execution.py` (the classifier and the policy bundles) plus one
  additive `call_factory` parameter on `handle_claude_hook`.
- Phase 2's `PATH` shim was skipped and the canonical-manager *rule* was
  implemented at the hook instead. The rule is what would have denied the
  incident; the shim is what extends it to the interactive terminal. Splitting
  them delivers the control now and leaves ADV-A explicitly open.

### Phase 0 — Wire the hook to the gateway *(completed; original estimate assumed no new code)*

Replace `integration.emit_receipt_for_hook` with
`UniversalGateway.handle_claude_hook` in `.claude/hooks/acgs-emit-receipt.py`.

- **Requires:** a `UniversalGateway` instance — `tenant_id`,
  `execution_boundary`, `policy`, `profile`, `validator`, `authority`. Note
  `profile.require_expiry` with no `receipt_ttl_seconds` raises at construction
  by design; supply a TTL.
- **Gains:** real policy evaluation; deny-wins batches; `TRANSFORM` → `"ask"`;
  a signable `DecisionReceipt` instead of the unsignable 5-field `Receipt`.
- **Exit:** `decision` is no longer 100% `allow`; receipt anchors present.
- **Revert:** restore the previous import. No data migration — the audit chain
  is append-only and both paths append to it.

### Phase 1 — Fix attribution *(days)*

Populate a real `actor`. Thread `run_id` into the persisted record — today it is
accepted at `integration.py:652,723` and dropped at `:700-707`. Populate
`allowed_actors` with the real principal set.

- **Exit:** zero records carrying the `govern-zone-hook` fallback.
- **Note:** this is a precondition for every later phase. A receipt naming an
  anonymous actor is an audit record, not an authorization.

### Phase 2 — Surface 2, the package-manager check *(days)*

`PATH` shim ahead of `npm`, `pnpm`, `pip`, `uv`, `cargo`. Initially the single
canonical-manager rule, in `OBSERVE` for two weeks, then `ENFORCE`.

- **Exit:** an `npm install` at repo root produces an `env.package.invoke`
  record with `decision: deny` and no `package-lock.json`.
- **This phase alone would have prevented the incident.**

### Phase 3 — Surfaces 3 and 4, dependency and lifecycle *(weeks)*

Resolve-without-installing, diff the resolved set, classify, decide. Scripts are
disabled at invocation by default; enabling them is a separate escalated
decision taken before the manager runs (§2.2.2).

- **Exit:** a new direct dependency escalates; every unattended install invokes
  the manager with scripts disabled.
- **Enable `ReplaySideStore`** here (`kernel.py:93`, off by default) — without
  it only the weak `replay_event` policy-version comparison is available, and
  dependency decisions are exactly the ones worth re-deriving.

### Phase 4 — Surfaces 5 and 6, git and artifacts *(weeks)*

`core.hooksPath` guard; declared control-surface inventory with owners; CI check
refusing tracked artifacts that declare themselves generated with a null
generator. Note surface 6 is detective, not preventive (§2.2.3) — no generic
generator wrapper is built, because generators are arbitrary programs and
wrapping all of them is not a bounded task.

- **Exit:** `.codex/config.toml` has a declared status and owner, or is
  untracked. A tool rewriting it fails a check instead of passing silently.

### Phase 5 — Surface 7, release publication *(weeks)*

CI-mediated, always `ESCALATE`, second-party approval, SBOM delta required.

### Phase 6 — Signing *(unscheduled — genuinely unsolved)*

Receipts on this layer stay unsigned until key custody is resolved.
`signing.py:20-32` names custody, distribution, and revocation distribution as
out of scope, and this layer does not solve them. **Do not fold this phase into
an implementation estimate.**

---

## 5. Acceptance criteria

**Status: partially implemented.** P11 delivered Phase 0 and part of Phases 1-2.
The tables below now carry real test names for what holds and an explicit
**NOT MET** for what does not. Criteria for unbuilt phases remain
specifications and are labelled as such.

Gate evidence, run 2026-08-09 from `packages/gove-zone/`:

```
$ .venv/bin/python -m pytest --tb=line -o addopts="--import-mode=importlib"
================= 1423 passed, 4 skipped, 1 xfailed in 25.28s ==================
$ .venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
All checks passed!
219 files already formatted
$ .venv/bin/python -m mypy src/gove_zone/execution.py
Success: no issues found in 1 source file
```

`mypy src/gove_zone` reports 7 pre-existing `import-not-found` errors in
`adapters/mcp_gateway.py` (the optional `mcp` extra is not installed). That file
is unmodified by this work.

### Implemented criteria

| ID | Criterion | Status | Test |
|---|---|---|---|
| A0-1 | Hook routes through the gateway | **met** | `.claude/hooks/acgs-emit-receipt.py` calls `handle_claude_hook`; `test_gateway_factory_writes_to_the_existing_audit_chain` |
| A0-2 | Decisions are no longer unconditionally allow | **met at the policy; unobserved live** | `test_non_canonical_package_manager_is_denied`, `test_canonical_manager_escalates_rather_than_denying`. The live chain is still 100% `allow` post-cutover **because no denied action has been attempted since** — not because the policy allows everything. The old distribution was 100% `allow` over 396 records under a policy that could return nothing else; that is the difference. |
| A0-3 | Receipt anchors minted | **met** | `test_unclassified_shell_command_is_allowed_and_receipted` asserts `receipt_hash` + `audit_hash` + `policy_hash` |
| A0-4 | Cutover does not fork the audit chain | **met** | `test_gateway_factory_writes_to_the_existing_audit_chain`; live `verify_chain()["valid"] is True` across 396 pre- and post-cutover records |
| A0-5 | Classification is bound into the receipt | **met** | `test_classification_appears_in_both_args_and_state`; `argument_hash` recomputes from the args carrying `facts`, and `DecisionReceipt.from_record` binds it into `receipt_hash` |
| A0-6 | The receipt is not an exfiltration channel | **met** | `test_raw_command_text_is_not_carried_into_the_receipt` — this test caught a real leak: the argv prefix was picking up the *value* of a value-taking option |
| A0-7 | Classification is structural, not substring | **met** | `test_quoted_argument_never_promotes_a_command`, `test_grep_pattern_containing_a_keyword_is_not_an_orchestration_event`, `test_operator_detection_ignores_quoted_operators` |
| A0-8 | Undecidable commands are not given a verdict | **met** | `test_shell_operators_make_the_effect_undecidable`, `test_unbalanced_quotes_are_undecidable_not_guessed` |
| A0-9 | No self-lockout: every matcher tool has a tier | **met** | `test_every_hook_matcher_tool_has_a_tier_assignment` (reads the live `.claude/settings.json`) |
| A0-10 | Option-bearing wrappers are not partially interpreted and are denied before receipt minting | **met** | `test_option_bearing_wrappers_are_undecidable_without_parsing_values`, `test_option_bearing_wrapper_is_denied_before_receipt_minting` |
| A0-11 | A call factory cannot replace the gateway actor | **met** | `test_call_factory_cannot_spoof_the_gateway_actor` |
| A1-2 | `run_id` persisted | **met** | `test_run_context_is_threaded_into_the_receipt_binding`, `test_run_context_reaches_non_shell_calls_too` |
| A2-1 | Non-canonical manager denied **at the hook** | **met, narrowed** | `test_non_canonical_package_manager_is_denied`. See the wording note below. |
| A2-2 | Canonical manager not denied (positive control) | **met, narrowed** | `test_canonical_manager_escalates_rather_than_denying` — it escalates rather than proceeding, which is the `dependency` tier baseline, not a silent allow |
| ADV10 | Production profile with no signer refuses to build | **met** | `test_production_profile_without_a_signer_refuses_to_build`; dispatcher-level `test_integration_gaps.py::test_hook_end_to_end_production_without_signer_blocks` |

**A2-1 wording.** The original criterion was "20/20 `deny`; 0 `package-lock.json`
created; 0 packages fetched." What is demonstrated is narrower and must be stated
as such: **the PreToolUse hook returns `deny` for an `npm install` payload before
the host decides whether to execute it.** The hook mediates the decision and
audit record; it does not run a receipt-gated executor. There is no `PATH` shim,
so an `npm install` typed into a terminal reaches no hook and is not prevented.
The incident's specific agent-hook decision path is mediated; the interactive
path and other outside-hook invocations are not. This is partial hook mediation,
not complete package-manager mediation.

### Not met

| ID | Criterion | Why not | Residual |
|---|---|---|---|
| A1-1 | 0 records with a fallback actor | Attribution is environment-derived, not authenticated; 414 historical `govern-zone-hook` records remain in the chain | §1.2b |
| A3-1 | New direct dependency escalates | Resolved-set diffing not built; every dependency surface escalates uniformly instead | over-escalation, not under |
| A3-2 | Installs run with lifecycle scripts disabled | The rule *escalates* an install that would run scripts; nothing yet invokes the manager with `--ignore-scripts` on the operator's behalf | §2.2.2 |
| A3-3 | Decisions re-derivable via `replay_bundle` | `ReplaySideStore` still off (`kernel.py:93`) | only weak policy-version comparison available |
| A4-1 | Tracked generated artifact without a generator refused | Phase 4 not started | `.codex/config.toml` still undeclared |
| A5-1 | Publication requires a distinct validator | `env.release.publish` escalates, but no second-party approval flow exists | Phase 5 |

### Coverage delta — a surface was removed

The retired `_classify` recognized three orchestration keywords (`autopilot`,
`ralph`, `team`). **Nothing in the new table replaces that concept**, and the
removal is deliberate: those branches matched substrings of command text and the
only such record in the live chain (`ev_de6629e1f60f41ea`) was a false positive —
a read-only `grep` whose *pattern* contained `autopilot`, audited as an autopilot
orchestration event.

Net effect is an increase in coverage, not a decrease. The old classifier
returned `None` for everything else and the hook exited **0 unaudited**, which is
why 396 records contained exactly one `runtime.Bash`. Every Bash call is now
classified and audited. If orchestration-command governance is wanted, it must be
re-added as declared argv-prefix entries, not as substrings.

Each remaining criterion states the workload and denominator, per the
gate-evidence rules.

### Per-phase gates

| ID | Criterion | Verification | Pass |
|---|---|---|---|
| A0-1 | Hook routes through the gateway | `grep handle_claude_hook .claude/hooks/acgs-emit-receipt.py` | non-empty |
| A0-2 | Decisions are no longer unconditionally allow | over ≥200 fresh records, `decision` distribution | at least one non-`allow`, and every `allow` traceable to a policy rule |
| A0-3 | Receipt anchors minted | sample 20 allowed hook decisions | 20/20 carry `receipt_hash`, `policy_hash`, `audit_hash` |
| A1-1 | No fallback actor | all records appended after cutover | 0 with `actor == "govern-zone-hook"` |
| A1-2 | `run_id` persisted | sample 20 records | 20/20 carry a non-empty run identifier |
| A2-1 | Non-canonical manager denied | `npm install <pkg>` at root, ≥20 trials | 20/20 `deny`; 0 `package-lock.json` created; 0 packages fetched |
| A2-2 | Canonical manager unaffected (positive control) | `pnpm install` with no delta, ≥20 trials | 20/20 proceed |
| A3-1 | New direct dependency escalates | ≥20 trials | 20/20 `escalate`; 0 unattended installs |
| A3-2 | Installs run with lifecycle scripts **disabled** unless separately escalated | ≥30 trials incl. ≥15 with script-bearing packages | 30/30 invoke the manager with scripts disabled; 15/15 script-bearing packages produce an `env.package.lifecycle_enable` escalation before any enabled run. **Not** "0 executions" — once enabled, execution is unmediated (§2.2.2). |
| A3-3 | Decisions re-derivable | ≥30 sampled decisions replayed via `replay_bundle` | 30/30 `re_derived=True` and matching |
| A4-1 | Tracked generated artifact without a generator is refused | fixture reproducing `.codex/config.toml` | refused |
| A5-1 | Publication requires a distinct validator | ≥10 trials incl. ≥5 self-approval attempts | 5/5 self-approvals rejected |

### Invariant tests — must hold at every phase

All seven are implemented in
`packages/gove-zone/tests/test_execution_bypass_adversarial.py` unless noted.

| ID | Property | Status | Test |
|---|---|---|---|
| INV-1 | Fail-closed when the decision cannot be recorded | **met** | `test_hook_denies_when_the_audit_chain_cannot_be_appended`, `test_hook_denies_a_payload_it_cannot_govern`, `test_hook_requires_an_actor` |
| INV-2 | `expected_actor` mismatch → `ACTOR_MISMATCH` | **met** | `test_receipt_for_one_actor_is_rejected_for_another`, `test_actor_outside_the_allowlist_is_denied` |
| INV-3 | Self-validation rejected | **met** | `test_an_actor_cannot_validate_its_own_execution_decision` |
| INV-4 | One decision authorizes at most one side effect | **met** | `test_receipt_is_single_use` |
| INV-5 | Direct call to a sealed environment tool is audited as `BYPASS_ATTEMPT` | **met** | `test_direct_call_to_a_sealed_execution_tool_is_refused_and_audited`, with positive control `test_the_governed_path_executes_the_same_tool` |
| INV-6 | Argument binding: executed args ≡ receipted args | **met** | `test_executed_arguments_must_equal_receipted_arguments`; boundary binding in `test_receipt_from_a_different_boundary_is_rejected` |
| INV-7 | Audit chain verifies against an **external** anchor | **met as a limitation** | `test_truncated_audit_tail_is_invisible_without_an_external_anchor` — asserts the internal walk passes on a truncated chain and only the anchored check fails |

### Adversarial cases — must be present, not optional

| ID | Attack | Status | Test |
|---|---|---|---|
| ADV-A | `npm` invoked by absolute path, bypassing a shim | **closed on the hook path; interactive path out of scope** | `test_absolute_path_invocation_fails_closed_but_a_path_shim_is_not_claimed` — a hook-visible path-qualified executable is undecidable; an interactive invocation that never reaches the hook remains outside this layer |
| ADV-B | Receipt for one actor replayed by another | **closed** | `test_receipt_for_one_actor_is_rejected_for_another` |
| ADV-C | A governed tool reaching a second governed tool mid-execution | **closed** | `test_a_governed_tool_cannot_reach_a_second_sealed_tool` — the grant is per-tool |
| ADV-D | Policy rewritten to allow all | **closed structurally** | `test_policy_is_content_addressed_and_sealed` — a rewritten bundle is a different content-addressed version, and the sealed policy rejects attribute rebinding |
| ADV-E | Audit tail truncated to hide an install | **NOT CLOSED, asserted as such** | `test_truncated_audit_tail_is_invisible_without_an_external_anchor` |

ADV-E remains *not closed*, and its test asserts the limitation rather than a
defense. ADV-A is closed only when the invocation reaches the hook; this layer
does not claim to mediate an interactive terminal. A third test,
`test_bypass_attempts_is_only_evidence_when_the_gate_is_on_the_path`, records
that an empty `bypass_attempts()` proves nothing on its own — a gateway nothing
was ever routed through reports zero too. An acceptance suite that claimed to
close any of these would be the overclaiming this repository's claim discipline
exists to prevent.

### Benchmark

Extend `acgs_benchmark`. Constraint: `CATEGORIES` (`schema.py:41-48`) is a
closed six-value vocabulary and `OUTCOMES` (`:64-83`) a closed frozenset — a new
category requires editing `schema.py`. File under `fail_closed` initially. Probes
are new `_probe_<name>` methods; dispatch is
`getattr(self, f"_probe_{scenario.probe}")` (`targets.py:394`). Every attack
scenario needs a positive control, per `authorization.json:5-25` — a
deny-everything gate otherwise scores perfectly.

---

## 6. Board and investor explanation

### What happened

A dependency install and a config rewrite reached a governance repository with
no authorization and no record, and took 14 hours and forensic reconstruction to
explain. No attacker was involved. That is the point: **the system had no way to
say no, and no way to say what happened.**

### Why it is strategically interesting rather than embarrassing

Three claims, in order of strength.

**1. We found it with our own discipline, and the fix is mostly wiring.** Nine
of fifteen required capabilities already exist, are tested, and are reused
unchanged. The single control that would have prevented the incident outright is
a one-line comparison. When the highest-value control is also the cheapest, the
gap is architectural, not resource-bound — nobody was blocked by cost. The
mutation class had simply never been modeled as governable.

**2. The gap is industry-wide and sits where no tooling lives.** Every mature
control — dependency scanning, SBOM, secret scanning, pre-commit, branch
protection, build provenance, endpoint detection, AI agent guardrails — operates
at commit, merge, build, or runtime. This incident happened at **local mutation
time**, which is exactly where AI coding agents and their tools do most of their
work. And every one of those controls is *detective*: they report what happened.
None issues an authorization decision. That decision record is what an auditor
asks for and what nothing above produces.

**3. The actor model was one level too narrow.** The most privileged actor in
this repository is not an AI agent. It is `npm` — which fetches unreviewed code
from the internet and executes it under full operator privilege with no approval
point, and has done so for a decade. AI agents arrived into an ecosystem where
unmediated execution was already normal. The defensible position is governing
**high-agency software actors**: agents are the newest and most visible; package
managers, developer tools, and CI are the larger, incumbent, ungoverned majority.
"Another AI guardrail" is a crowded category with unclear buyers. "The
authorization and evidence layer for everything with write access to your
codebase" is adjacent to controls regulated buyers already must demonstrate.

### What must not be claimed

Per `CLAIMS.md:46-48` and `AGENTS.md:152-171`:

- P11 governs package-manager-shaped calls only on the integrated agent-hook
  decision path. Actual package-manager execution, including interactive and
  other outside-hook invocations, remains unmediated.
- ACGS did **not** prevent this incident in its own repository.
- No claim here may reach public material without a `CLAIMS.md` row and a Safe
  public wording cell. Across all 44 existing rows, **none covers dependency
  governance, supply chain, SBOM, or local repository mutation** — that surface
  is unclaimed, which is both the honest gap and the genuine headroom.
- Approved wording for what exists: *local receipt-gated kernel*,
  *tamper-evident JSONL audit chain*, *opt-in Ed25519 signing mode*. Not
  production-certified, compliance-certified, or regulator-approved.
- This incident is **not** evidence that autonomous-development governance (R6)
  is implemented. It is evidence of the opposite.

### The credible sentence

> We found a class of ungoverned execution in our own repository using our own
> governance discipline, traced it to an adversary our threat model already
> named, and closed the integrated agent-hook decision path by wiring the gate
> we had already built and tested. Interactive and other outside-hook
> package-manager execution remains unmediated.

That is a stronger statement than a capability claim, because it is checkable —
and every citation in this document points at a file and a line.

---

## 7. Open questions

1. **Key custody** (Phase 6) is unsolved and gates every signing claim.
2. **Real identity** — `allowed_actors` needs a principal set. This layer
   assumes an identity source it does not provide.
3. **Latency budget** — the ≤100ms interactive p95 threshold is unmeasured for
   shell mediation.
4. **Degraded mode** — ADV13's `[proposed]` availability budget becomes load-
   bearing once developer workflows depend on a fail-closed gate.
5. **Reconciliation with `MUTATION_POLICY.md`** — its `T1–T5` tiers and §2.3's
   risk tiers must be mapped explicitly, or the repository ends up with two
   incompatible risk vocabularies.
