# WS-A adversarial verification — findings

| | |
|---|---|
| **Subject** | `docs/ENFORCEMENT-BOUNDARY.md`, `docs/claims-map.md`, and the manifest change in `fc6b39c1` |
| **Method** | Three independent agents instructed to **refute**, not approve. Two wrote working exploit code. |
| **Date** | 2026-07-28 |
| **Verdict** | All three returned **PARTIALLY_REFUTED**. ~25 findings, several FALSE. |

This file exists because the findings are more valuable than the documents that provoked them,
and because a governance project that hides its own failed verification has no business shipping
a claims map. **Nothing below has been deleted or softened.** Each finding now carries its
disposition; the original wording of every claim is preserved so the counterexamples stay
checkable.

## Remediation table

| Finding | Original claim | Reality | Action | Evidence |
|---|---|---|---|---|
| F-1 | `receipt_hash` covers "every field except `receipt_hash` and `signature`" | `_hash_payload` is hand-enumerated; four fields are gated on `receipt_schema_version` | **Narrowed** the §1 row — then narrowed again, see F-8 | `receipt.py:332-374` |
| F-2 | "no shipped call site supplies an audit anchor" | Five shipped call sites do, plus a transactional persisted sink | **Corrected + scoped** to `packages/gove-zone/src/`; WS-B4 scope withdrawn | `governance.py:756-758`, `models.py:57-58`, `app.py:1731`, `:1792`, `migration_recovery.py:738`, `:989`, `:1131` |
| F-3 | "no static scan and no CI job" detects an ungoverned path | One exists and is CI-enforced; its *assertion* and *scope* are the real limits | **Replaced** with the narrower true statement | `test_gate_wiring_matrix.py:1`, `:170-173`; `saas-beta-required.yml:202` |
| F-4 | Docs pin `4459d849` as the source of truth for an 11-class manifest | That manifest exists only on branch commit `fc6b39c1` | **Named the branch commit** at each citation | `git log fc6b39c1` |
| F-5 | Manifest invariants mean "a gap cannot be recorded while evidence exists" and "must cite ≥1 real test" | Invariants proved representability, not consistency; posture inflation was free; `_node_exists` accepted paths escaping `tests/` | **Implementation hardened** — posture↔evidence consistency check, evidence kind derived from the cited test, containment check on nodes | `91c7cb0e`; `test_posture_inflation_without_new_evidence_is_rejected` |
| F-6 | The `compromised-host` covering test "documents the bypass rather than asserting a boundary" | It asserts both halves | **Evidence corrected** — now cites the `xfail` residual that does document the bypass | `test_audit_chain_corruption.py:170-177`; `test_mutation_suite.py:438` |
| F-7 | "editing or splitting row L19 reds the build" | The gate reads CLAIMS.md as one lowercased blob and asserts substrings; splitting is safe | **Narrowed** to the editing half | `test_signing_default_doc_matches_code.py:105-112` |
| F-8 | *(new — this pass)* "on a default v1 receipt those four are **not** hash-bound" | Literally true, materially misleading: a v1 receipt is validated to carry empty values for all four | **Narrowed** and the reasoning stated | `receipt.py:250-256`, `:677-681`; `executor.py:208` |

Verification method for this pass: every claim above was read from source in the working tree
before being written, not carried over from an agent report. Two agent findings were themselves
wrong and are recorded under "Disagreement between verifiers".

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

### F-2 "no shipped call site supplies an audit anchor" is false — **CORRECTED**
Asserted unscoped in `ENFORCEMENT-BOUNDARY.md` §3.4, `audit/phase0-baseline.md`, and
`audit/deviation-report-2026-07-28.md`. **Shipped in-repo code does supply both anchors** to
gove-zone's own store: `packages/acgs-control-plane/.../migration_recovery.py:32` imports
`ChainHashAuditStore` from `gove_zone.audit` and passes `expected_count` /
`expected_last_hash` at `:737-738`, `:988-990`, `:1129-1132`; also `app.py:1727-1732`, `:1788-1793`.

The "seven call sites, none supplying an anchor" figure is true **only within
`packages/gove-zone/src/`** and the sentence carried no such scope. This materially weakens the
framing that the anchor is an unexercised operator duty, and it undercuts the §5
`compromised-host` row that rests on it.

### F-3 "no static scan and no CI job" is false — **CORRECTED**
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

### F-4 The documents cite a source of truth that does not exist at their pinned ref — **CORRECTED**
Both docs pin "Evidence ref = `origin/master` @ `4459d849`". The 11-class manifest with the
widened vocabulary exists only on branch commit `fc6b39c1`. At `4459d849` the manifest has
`status: Literal["DEFENDED"]` and exactly 8 classes. So the §5 matrix's three placement rows and
the claims-map SAY row "11 classes … `UNKNOWN` may cite none" are **not true at the ref the
documents themselves cite**. Neither doc names `fc6b39c1`.

### F-5 The manifest invariants do not do what the docstring and commit message claim — **CORRECTED (implementation hardened)**
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

### F-6 The `compromised-host` covering comment is half wrong — **CORRECTED**
It says the cited test "documents the bypass rather than asserting a boundary".
`test_audit_chain_corruption.py:155` asserts **both**: line 170 documents the keyless bypass, and
`:173-177` assert affirmative anchored detection (`length_mismatch`, `last_hash_mismatch`).

### F-7 `claims-map.md:26` — "editing or splitting row L19 reds the build" — **CORRECTED**
The "splitting" half is false. `test_signing_default_doc_matches_code.py:107` reads CLAIMS.md as
one flat lowercased blob and asserts four substrings; nothing parses row identity or count.
Splitting L19 into two well-formed rows keeps every substring present and the build green. The
"editing" half is defensible — `does not auto-sign` occurs only at L19.

### F-8 The F-1 correction was itself an overcorrection — **CORRECTED**
Found in the remediation pass, not by the agents. The §1 row written to fix F-1 said that on a
default v1 receipt `receipt_schema_version`, `project_id`, `environment_id`, and `trust_epoch`
are "**not** hash-bound". Every word is true and the row reads as a live vulnerability
disclosure. It is not one, and the row omitted the reason:

- `from_dict` **rejects** a v1 dict carrying any of the three v2-only fields
  (`receipt.py:250-256`).
- `verify` **rejects** a v1 receipt holding non-empty values for them (`:677-681`).
- The executor gate reaches that check — `executor.py:208` calls `receipt.verify(...)` — so the
  invariant is on the enforcement path, not merely defined on the class.

A v1 receipt is therefore pinned to empty values for all four, and their exclusion from the v1
hash payload is not an escalation vector. Cross-schema mutation is separately caught: adding or
stripping the fields changes the payload key set, so the recomputed hash no longer matches the
stored `receipt_hash`. `test_stripping_the_v2_scoped_fields_changes_receipt_identity` pins this.

Recorded rather than silently rewritten because it is the same failure the agents found, in the
opposite direction: **a claim stated without the scope that makes it meaningful.** Overstating a
weakness is not the safe direction of error — it is the same defect, and in a governance
document it misdirects a reviewer's attention just as effectively.

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
