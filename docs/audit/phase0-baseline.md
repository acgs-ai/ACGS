# Phase 0 — Baseline survey

| | |
|---|---|
| **Spec** | ACGS Hardening Spec — Enforcement Boundary & Reference Enforcement Topology |
| **Phase** | 0 (PR-1, docs only) |
| **Surveyed ref** | `origin/master` @ `4459d849` ("Merge pull request #412 from acgs-ai/feat/gove-zone-full-digest-policy-identity") |
| **Date** | 2026-07-28 |
| **Method** | Direct read of a clean worktree cut from `origin/master`. No working-tree or branch state was consulted. |
| **Outcome** | **HALT** — three LOAD-BEARING assumptions REFUTED. See [deviation-report-2026-07-28.md](./deviation-report-2026-07-28.md). |

> **Survey hygiene note.** An earlier pass at this survey was performed against a
> long-lived feature worktree that is 565 commits behind `origin/master` and
> carries modules master does not track. It produced materially false verdicts and
> was discarded. Every finding below is re-derived from `4459d849`. Any future
> survey must state its ref and cut a clean worktree; "the repo" is not a
> well-defined object in this project.

---

## 1. Assumption verdicts (A1–A9)

| ID | Assumption | Load-bearing | Verdict | Evidence |
|----|------------|:---:|---|---|
| A1 | Single-use receipt consumption is opt-in, not default | **yes** | **CONFIRMED** | `executor.py:56` `consumption_ledger: ReceiptConsumptionLedger \| None = None`; same default at `:297`, `:354`. Docstring `executor.py:133` states it explicitly: "``consumption_ledger`` (opt-in) makes the receipt **single-use**". Enforcement is conditional: `executor.py:233-234` `if consumption_ledger is not None: consumption_ledger.consume(receipt)`. |
| A2 | Ed25519 signing is opt-in; unsigned mode runs without prominent runtime marking | **yes** | **REFUTED** (clause a) / **PARTIAL** (clause b) | Signing is **default-on**, not opt-in: `require_signature: bool = True` at `executor.py:50`, `executor.py:291`, and `contracts.py:272`. Clause (b) partially holds: an unsigned marker exists on the data (`signature="unsigned_local"`, `plan.py:74`, `workflow.py:158`; `signature_algorithm="none"`, `workflow.py:197`) and a rejection code exists (`errors.py:49 UNSIGNED_REJECTED`), but there is **no `signature_mode` field and no startup warning**. |
| A3 | Audit log is local JSONL chained via `previous_hash`; no external anchoring mechanism exists | **yes** | **REFUTED** (partially) | An external-anchor **verification** mechanism exists: `audit.py:308-341` `verify_chain(*, expected_count=None, expected_last_hash=None)`, checked at `:375` and `:385`. The docstring is explicit that the chain "alone therefore cannot detect rollback" (`:329`) and instructs the operator to "Persist whichever anchor you can … in a store the audit writer cannot rewrite" (`:339`). What does **not** exist is the *anchoring* half: no `AnchorSink`, no sink implementations, and **no shipped `src/` caller passes either argument** (7 call sites: `audit.py:72`, `cli.py:117`, `cli.py:710`, `proofpack.py:296`, `replay.py:272`, `smoke.py:87`, `verifier.py:410`). |
| A4 | Threat model enumerates adversaries as `ADV-n` entries | no | **REFUTED** | No `ADV-n` identifiers exist anywhere in `docs/` or `packages/gove-zone/tests/adversary/`. Adversaries are enumerated as eight named **classes** in the coverage manifest (§3 below). Per spec §5/A4, extend that taxonomy rather than introducing a parallel ID scheme. |
| A5 | The canonical one-liner appears in README in the assumed wording | **yes** | **REFUTED** | `README.md:32` reads: `> For every execution path wired through ACGS: **No valid Decision Receipt, no side effect.**` The assumed wording ("gove-zone is an alpha runtime governance plane for receipt-gated agent execution — …") does not appear. Note the shipped line **already carries a scope qualifier** ("For every execution path wired through ACGS"). |
| A6 | No brokered reference deployment exists in-repo | **yes** | **CONFIRMED** | No `deploy/` directory; no `docker-compose*` at repo root. |
| A7 | MACI roles instantiable single-process with string identities; no per-role key requirement | **yes** | **CONFIRMED** | `git grep -c validator_id` over `trust.py`, `authz.py`, `identity.py`, `verifier.py` returns **zero in all four** — no validator↔key binding exists. `trust.py` scopes keys to a *deployment* (`ReceiptTrustScope` = tenant/project/environment/purpose, `trust.py:42-56`), where `purpose` is the constant `"decision-receipt"` (`trust.py:25`); `resolve()` keys on `(scope, algorithm, key_id)` (`trust.py:212-245`) and never takes `validator_id`. Self-validation is a string comparison at issuance (`receipt.py:414-418`) and at the gate (`:865`, `:882`). |
| A8 | File locking relies on `fcntl` (POSIX-only); Windows unsupported | no | **REFUTED** | `_locking.py` already abstracts both platforms: "``fcntl`` on POSIX, ``msvcrt`` on Windows" (`_locking.py:5`, `:22-23`), with a `ModuleNotFoundError` fallback at `:30-35`. Guardrail §10.7 requires no action. |
| A9 | A claims map with SAY / SAY-WITH-CAVEAT / DO-NOT-SAY axes exists | **yes** | **REFUTED** | No `docs/claims-map.md`. `docs/CLAIMS.md` and `docs/CLAIM_AUDIT.md` exist, but a repo-wide grep for `DO-NOT-SAY`, `DO NOT SAY`, and `SAY-WITH-CAVEAT` returns nothing. Per §3/A9 the pre-authorised remedy applies: create `docs/claims-map.md` in WS-A. |

**Load-bearing refutations: A2, A3, A5.** Halt condition per spec §0.3 is met.

---

## 2. Side-effect path inventory

### 2.1 Effect-capable primitives inside the library

The library's own effect surface is deliberately narrow. Every occurrence of a
network, subprocess, or filesystem-mutating primitive in
`packages/gove-zone/src/gove_zone/`:

| Module | Line | Primitive | Governed? |
|---|---|---|---|
| `sandbox.py` | 13–14 | `shutil`, `subprocess` | This *is* the containment mechanism (see 2.3) |
| `gateway.py` | 942–943 | `urllib.request` / `urllib.parse` | Inside `http_json_tool` (`gateway.py:925`), the one governed HTTP helper |
| `cli.py` | 487 | `shutil` | Operator tooling, not an agent-reachable path |
| `setup.py` | 28 | `shutil` | Build tooling |

Only **two** modules import network or subprocess primitives. Nine modules call
`open()`. There are no database or cloud-SDK imports anywhere in the package.

### 2.2 Governed chokepoints

| Chokepoint | Location | What it enforces |
|---|---|---|
| `execute_with_receipt` | `executor.py:32` | The gate. Runs `tool_fn` only if the receipt is valid and matches `expected_tenant_id`, `execution_boundary`, action, actor, `audit_hash`, `policy_hash`, `policy_bundle_id`, `project_id`, `environment_id`, `validator_role`, `authority`. Defaults `require_signature=True`. |
| `GovernedExecutor` | `executor.py:239` | Class form of the same gate. |
| `Kernel.dispatch` | `kernel.py:137` | Policy decision + audit append before execution. |
| `Kernel._authz_check` | `kernel.py:309-330`, called at `:347-348` | Principal allowlist check **before** policy evaluation. Off by default (`authz_enforce=False`, `kernel.py:94-95`) with fail-closed pairing at `:107-108`. |
| `SealedTool.__call__` | `gateway.py:148` | Bypass detection; raises `BypassAttemptError` (`gateway.py:118`). Grant is identity-bound and spent before the side effect. |
| `ManagedAgent.register_tool` | `agent.py:87-99` | Wraps each tool in `sandbox.run_tool(fn, kwargs)` when a sandbox is configured; otherwise registers the raw callable. |

### 2.3 Effect channels — mediation status

| Channel | Status | Mechanism / gap |
|---|---|---|
| Filesystem | **PARTIAL** | Only via bwrap's read-only-except-sandbox-dir (`sandbox.py:186`), and only when enabled. No path capability, no per-call filesystem policy. |
| Subprocess | **PARTIAL** | Same mechanism (`sandbox.py:59 LocalProcessSandbox`). |
| HTTP | **PARTIAL** | bwrap `--unshare-all` (`sandbox.py:186`) blocks egress wholesale when enabled; `gateway.py:925 http_json_tool` is one governed helper. No host allowlist, no per-request egress policy. |
| Database | **MISSING** | No adapter, no mediation. |
| Cloud APIs | **MISSING** | No adapter, no mediation. |

**Load-bearing caveat — containment degrades to a warning by default.**
`sandbox.py:93-98`: when bwrap is absent and `require_bwrap` is unset, the
provider falls back to a plain subprocess that the docstring states explicitly
does **not** restrict network or filesystem, emitting only a `UserWarning`.
Containment is real only with bwrap installed **and** `require_bwrap=True`
(`sandbox.py:87-91` hard-fails otherwise). This directly substantiates the
spec's §1 premise.

### 2.4 Ungoverned-by-construction

Nothing constrains a raw `import requests` inside a tool body once that tool
runs, except bwrap when enabled. No static scan or CI job anywhere in the repo
detects an added uncontrolled side effect; all 33 workflows were swept.
`python-gove-zone.yml` runs Lint (`:69`), Test (`:74`), deny-path coverage
(`:93`), and an ADR-0005 budget check (`:109`) — none of which is an effect scan.

---

## 3. Current adversary list (verbatim)

Source: `packages/gove-zone/tests/adversary/test_coverage_manifest.py`. Eight
classes, quoted with both status fields:

| Class | `status` | `adaptive` |
|---|---|---|
| `forged-authorization` | `DEFENDED` | **`BYPASSABLE`** |
| `replayed-authorization` | `DEFENDED` | **`BYPASSABLE`** |
| `ledger-tampering` | `DEFENDED` | **`BYPASSABLE`** |
| `policy-downgrade` | `DEFENDED` | **`BYPASSABLE`** |
| `tenant-crossover` | `DEFENDED` | `STABLE` |
| `signature-stripping` | `DEFENDED` | `STABLE` |
| `validator-bypass` | `DEFENDED` | **`BYPASSABLE`** |
| `evidence-omission` | `DEFENDED` | `STABLE` |

**The manifest schema cannot express a gap.** `test_coverage_manifest.py:104`:

```python
_VALID_STATIC = frozenset({"DEFENDED"})
_VALID_ADAPTIVE = frozenset({"STABLE", "BYPASSABLE", "UNTESTED"})
```

Line 127 asserts every entry's `status` is in `_VALID_STATIC`. Every class
therefore reads `DEFENDED` **by construction** — the field admits no other
value. The only field that can express failure is `adaptive`, which currently
reads **5 BYPASSABLE to 3 STABLE**.

This is a governance-of-governance defect: the artifact that certifies adversarial
coverage is structurally incapable of reporting its absence. It is recorded here
as a Phase 0 finding and carried to the deviation report; it is not remediated in
this PR.

---

## 4. Configuration defaults

| Control | Default | Location |
|---|---|---|
| `require_signature` (standalone gate) | **`True`** | `executor.py:50` |
| `require_signature` (`GovernedExecutor`) | **`True`** | `executor.py:291` |
| `require_signature` (`ReceiptVerifier`) | **`True`** | `contracts.py:272` |
| `consumption_ledger` (single-use) | `None` — **opt-in** | `executor.py:56`, `:297`, `:354` |
| `max_clock_skew_seconds` | `DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS` — **already configurable** | `executor.py:55`, validated at `:156` via `validate_receipt_clock_skew_seconds` |
| `authz_enforce` | `False` — opt-in, fail-closed when paired | `kernel.py:94-95`, `:107-108` |
| `require_bwrap` | unset — **degrades to unrestricted subprocess with a warning** | `sandbox.py:87-98` |
| Audit anchor (`expected_count` / `expected_last_hash`) | `None` — **no shipped caller supplies either** | `audit.py:311-312` |
| Clock source | Host clock | `executor.py:25`, `:128`, `:227` |

No named deployment "profiles" exist as a first-class construct; defaults are
per-call keyword arguments.

---

## 5. Test-suite baseline

Command, run in a clean worktree at `4459d849`:

```bash
uv run --package gove-zone --extra crypto --extra dev \
  python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

Result (authoritative counts from JUnit XML, not from stdout):

```
tests=1189  failures=0  errors=0  skipped=5  time=15.562s
```

**Baseline is green.** For contrast, the same command in the stale feature
worktree reports 2587 tests with 2 failures — a different codebase, and further
evidence that the survey ref must always be stated.

### Governance-critical path coverage

Existing tests that exercise the controls this spec touches:

| Control | Test |
|---|---|
| Fake actor identity | `test_authz_enforcement.py:89::test_enforce_denies_unregistered_actor_through_dispatcher`; `:133::test_default_anonymous_actor_denied_when_unregistered` |
| Receipt replay | `test_receipt_consumption.py::test_resume_replay_blocked_with_ledger`; `::test_reminted_receipt_same_anchor_blocked` |
| Validator impersonation | `test_maci_role_separation.py::test_issuance_refuses_self_validation`; `::test_gate_refuses_validator_equals_caller` |
| Log deletion / truncation | `test_consumption_deletion_guard.py:48`, `:74`, `:121`; `test_audit_chain_corruption.py:155::test_verify_chain_detects_whole_event_truncation` (asserts **both** directions: keyless verify returns `valid=True` on a truncated prefix, anchored verify returns `length_mismatch` + `last_hash_mismatch`) |
| Unmanaged tool | `test_universal_gateway.py:162::test_unknown_tool_is_structurally_uncallable`; `test_kernel_dispatch.py:84::test_unknown_tool_raises_before_any_audit_append` |
| Direct call bypass (in-process) | `test_universal_gateway.py:253::test_direct_sealed_call_is_blocked_and_audited`; `:270::test_nested_sealed_call_inside_gated_tool_is_detected` |
| Gate wiring | `test_gate_wiring_matrix.py:159::test_shipped_example_routes_through_gate` |

**Not covered:** executor-compromise simulation — no taxonomy class and no test.
Network-layer egress bypass is untested because no topology exists to test it
(A6 CONFIRMED); this is precisely WS-C's deliverable.

---

## 6. Definition of done

- [x] Verdicts for A1–A9 with `file:line` evidence
- [x] Side-effect path inventory
- [x] Adversary list verbatim
- [x] Config-defaults table
- [x] Test-suite baseline executed and recorded
- [x] Halt-and-report triggered — see [deviation-report-2026-07-28.md](./deviation-report-2026-07-28.md)

Per spec §0.3 and §4, work stops here. WS-A through WS-D are **not** begun.
