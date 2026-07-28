# WS-A adversarial verification — findings

| | |
|---|---|
| **Subject** | `docs/ENFORCEMENT-BOUNDARY.md`, `docs/claims-map.md`, and the manifest change in `fc6b39c1` |
| **Method** | Three independent agents instructed to **refute**, not approve. Two wrote working exploit code. |
| **Date** | 2026-07-28 |
| **Verdict** | All three returned **PARTIALLY_REFUTED**. ~25 findings, several FALSE. |

**The WS-A documents are PROVISIONAL. Do not treat them as review-ready, and do not cite them
outward, until the FALSE items below are corrected.**

This file exists because the findings are more valuable than the documents that provoked them,
and because a governance project that hides its own failed verification has no business shipping
a claims map. Only item F-1 has been corrected so far.

## FALSE — must be corrected

### F-1 `receipt_hash` does not cover "every field" — **CORRECTED**
`ENFORCEMENT-BOUNDARY.md` claimed the hash is recomputed over every field except `receipt_hash`
and `signature`. `compute_hash` (`receipt.py:376`) hashes `_hash_payload()` (`:332-374`), a
**hand-enumerated dict**. `receipt_schema_version`, `project_id`, `environment_id`, and
`trust_epoch` are added only `if self.receipt_schema_version` (`:369-373`) — so on a default v1
receipt those four are **not hash-bound**. Verified directly. Corrected in the §1 table, along
with three related omissions found in the same pass:

- **`dev` profile opt-out**: `profile.py:18` defines a profile that is "explicitly unsigned
  (`require_signature=False`)", selected via `$GOVE_ZONE_PROFILE` (`:27-28`). The "signature
  required by default" row omitted it.
- **`require_expiry` defaults `False`** (`executor.py:51`, `:292`, `contracts.py:273`), so a v1
  receipt with an empty `expires_at` authorizes indefinitely.
- **Four binding anchors are caller-optional**: `expected_policy_hash`, `expected_project_id`,
  `expected_environment_id`, `expected_authority` all default `None` (`executor.py:32-58`).

### F-2 "no shipped call site supplies an audit anchor" is false
Asserted unscoped in `ENFORCEMENT-BOUNDARY.md` §3.4, `audit/phase0-baseline.md`, and
`audit/deviation-report-2026-07-28.md`. **Shipped in-repo code does supply both anchors** to
gove-zone's own store: `packages/acgs-control-plane/.../migration_recovery.py:32` imports
`ChainHashAuditStore` from `gove_zone.audit` and passes `expected_count` /
`expected_last_hash` at `:737-738`, `:988-990`, `:1129-1132`; also `app.py:1727-1732`, `:1788-1793`.

The "seven call sites, none supplying an anchor" figure is true **only within
`packages/gove-zone/src/`** and the sentence carried no such scope. This materially weakens the
framing that the anchor is an unexercised operator duty, and it undercuts the §5
`compromised-host` row that rests on it.

### F-3 "no static scan and no CI job" is false
Asserted in `ENFORCEMENT-BOUNDARY.md` §2 and §3.1, `README.md`, `audit/phase0-baseline.md` §2.4,
and `audit/ws-a-handoff.md` §5. A static AST check **exists and runs in CI**:
`packages/gove-zone/tests/test_gate_wiring_matrix.py:1` calls itself "the static 'is the gate
wired' check", operating "statically (AST only)" against ADV9 out-of-gate executor bypass, and
`saas-beta-required.yml:202` runs `pytest packages/gove-zone/tests`.

The accurate, narrower, still-useful statement: a static gate-wiring check exists and is
CI-enforced, but it covers only examples that `docs/INTEGRATION_MATRIX.md` claims are
"Shipped + tested", and its assertion is `imported & called` (`test_gate_wiring_matrix.py:170-173`)
— a gate symbol is imported and some call by that name occurs in the module. That is weaker than
proving the example's side effect is mediated, and it says nothing about integrator code.

### F-4 The documents cite a source of truth that does not exist at their pinned ref
Both docs pin "Evidence ref = `origin/master` @ `4459d849`". The 11-class manifest with the
widened vocabulary exists only on branch commit `fc6b39c1`. At `4459d849` the manifest has
`status: Literal["DEFENDED"]` and exactly 8 classes. So the §5 matrix's three placement rows and
the claims-map SAY row "11 classes … `UNKNOWN` may cite none" are **not true at the ref the
documents themselves cite**. Neither doc names `fc6b39c1`.

### F-5 The manifest invariants do not do what the docstring and commit message claim
Proven by working exploits against the real module:

- **"UNKNOWN must cite none, so a gap cannot be recorded while evidence exists"** — false.
  `test_unknown_may_not_cite_evidence` inspects only `entry["covering"]`, never the repository.
  Setting `tenant-crossover` to UNKNOWN with `covering: []` passes all five invariants while
  `test_tenant_safety.py` still defines the settling tests on disk.
- **"must cite ≥1 real test"** — "real" is not enforced. `_node_exists` is a substring scan for
  `def {name}(`, so it accepts private helpers (`::_record`) and **paths that traverse out of the
  test tree** (`../src/gove_zone/audit.py::...`).
- **No invariant discriminates DEFENDED from BYPASSABLE.** Flipping `compromised-host` from
  BYPASSABLE to DEFENDED with its `covering` list *completely unchanged* passes all five
  invariants and the full 25-test suite. Posture inflation is free.
- A recorded gap is erasable by citing unrelated evidence, or the manifest's **own** bookkeeping
  tests.

The widening genuinely made absence *expressible*; it did not make a posture *verifiable*. The
docstring must say so.

### F-6 The `compromised-host` covering comment is half wrong
It says the cited test "documents the bypass rather than asserting a boundary".
`test_audit_chain_corruption.py:155` asserts **both**: line 170 documents the keyless bypass, and
`:173-177` assert affirmative anchored detection (`length_mismatch`, `last_hash_mismatch`).

### F-7 `claims-map.md:26` — "editing or splitting row L19 reds the build"
The "splitting" half is false. `test_signing_default_doc_matches_code.py:107` reads CLAIMS.md as
one flat lowercased blob and asserts four substrings; nothing parses row identity or count.
Splitting L19 into two well-formed rows keeps every substring present and the build green. The
"editing" half is defensible — `does not auto-sign` occurs only at L19.

## OVERCLAIM — must be scoped

- **`ENFORCEMENT-BOUNDARY.md` §5 applies the `adaptive` qualifier asymmetrically, always
  favorably.** All 3 STABLE classes are labelled "adaptively stable", but only 2 of the 5
  BYPASSABLE ones are flagged — 7 lines after instructing the reader to read that exact column.
  `claims-map.md:90` states the correct 5-of-8 figure, so the two documents contradict each other
  and the boundary matrix is the version that reads better.
- **"out of scope" is not in the manifest vocabulary** (`DEFENDED/PARTIAL/BYPASSABLE/UNKNOWN`) and
  collapses two states the widening was built to distinguish.
- **The Mode 2 column is eleven cells of unmeasured projection** inside a table framed as
  machine-checked; the manifest models one deployment only.
- **"proven to route through the gate"** overstates `imported & called` (see F-3).
- **`claims-map.md:76` sandbox caveat is wrong in one branch**: `sandbox.py:86,102` use bwrap
  whenever it is present, with `require_bwrap=False` by default. `require_bwrap` controls
  hard-failure when bwrap is *absent* — it does not gate whether bwrap is used.

## IMPRECISE

- 32 workflows, not 33 (`.github/workflows/AGENTS.md` is a doc, not a workflow).
- "only `sandbox.py` and `gateway.py` import effect primitives" — `setup.py:28` and `cli.py:487`
  import `shutil` too.
- Expiry citations `executor.py:25`, `:128`, `:227` are an import, a docstring line, and a kwarg
  pass-through. The evaluation is at `receipt.py:1082-1096`.
- `AGENTS.md:166-167` should be `:165-167` — the range omits "production-certified".
- The `MODELLED` note claims the registry test pins what the harness "could model". It compares
  two hand-maintained lists; deleting a generator and marking the class UNTESTED in one edit
  stays green.

## Disagreement between verifiers

Verifier 3 reported `_hash_payload` "pops only receipt_hash+signature", contradicting verifier 2.
**Verifier 2 is correct** — confirmed by direct read of `receipt.py:362-374`, which shows the
hand-enumerated dict and the `if self.receipt_schema_version` conditional. Recorded because a
reviewer re-running these agents may see the same split.

## What this says about the process

Three of the seven FALSE items (F-2, F-3, F-4) share one shape: **a true statement about
`packages/gove-zone/` written as a statement about the repository.** The scope was in the
author's head and not on the page. That is the same failure mode as the earlier stale-worktree
incident in this program — a claim whose scope is assumed rather than stated.

Raw agent output: `/tmp/.../tasks/w3lg1zur1.output` (session-local, not durable).
