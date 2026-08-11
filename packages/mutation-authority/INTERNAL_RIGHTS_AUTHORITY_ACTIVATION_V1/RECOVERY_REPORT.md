# CANONICAL COMMERCIAL RIGHTS WORKSPACE RECOVERY + AUTHORITY ACTIVATION — Report

Supersedes the disposition in `REPORT.md` (which concluded the substrate was
absent from every reachable location). It is not. It was located, identified,
and its baseline re-run. See "What changed since REPORT.md" at the end.

## Verdict

**`INTEGRATION_BLOCKED`.**

The canonical commercial-rights substrate **was found** and identified as
`EXACT_PRIOR_SUBSTRATE`. Authority cannot be activated against it — not because
of a filesystem detail, but because the one fact every sendable request needs is
an **external legal fact this task forbids fabricating**, and because the
substrate is a read-only, non-versioned corpus outside the assigned repository.
There is, in the strong sense, **nothing to activate**: the substrate already
encodes exactly the fail-closed state a correct authority layer would produce.

---

## Phase 1 — location & inventory (read-only; nothing modified)

Searched current-repo git history (all refs), `/tmp/claude-*`, and the operator home directory (`~`).

**Current repo (`/tmp/claude-1000/ACGS`, `docs/comparison-agt-permit`):** the
tokens (`COMMERCIAL_BUYER_READINESS_V1`, `verify_readiness.py`,
`RIGHTS_AUTHORITY_DETERMINATION_V1`, `REQUEST_REQUIRED`) appear in **0** files
and in **0 of 1694** commits (pickaxe `git log --all -S`). The subsystem has
never existed in this repository's history. Confirms REPORT.md's negative for
*this tree*; that negative was mistaken for a global one.

### Candidate inventory

| # | Path | Git? | mtime | Subsystems | `verify_readiness.py` | Upstream registry trees | Canonical? |
|---|---|---|---|---|---|---|---|
| 1 | `~/Downloads/traj_procurement_guideline_20260609 (2)/governance_trajectories/COMMERCIAL_BUYER_READINESS_V1` | **no** (loose bundle) | package files today | 9 layers incl. RESOLUTION V1–V5 | **yes** | **all 5 present** (`ACGS_DATA_ASSET_REGISTRY`, `AGEC_COMBINED_CORRECTED_v2`, `AGEC_GOVERNANCE_CORPUS_v1.1`, `AGEC_SYNTHETIC_ANNOTATIONS_v1`, `COMMERCIAL_VERIFICATION_PACKAGE`) | **YES** |
| 2 | `/tmp/claude-1000/cre-dbg-jxscxzjr/…/COMMERCIAL_BUYER_READINESS_V1` | no | 2026-08-10 11:38 | truncated (RESOLUTION_V1 only) | no | registry only | no — partial working copy |
| 3 | `/tmp/claude-1000/cre-dbgI-tzg7nzoj/…/COMMERCIAL_BUYER_READINESS_V1` | no | 2026-08-10 11:40 | truncated (V1+V2) | no | registry only | no — partial working copy |
| 4 | `/tmp/claude-1000/cre-dbgI2-6uaha71_/…/COMMERCIAL_BUYER_READINESS_V1` | no | 2026-08-10 11:41 | truncated (V1+V2) | no | registry only | no — partial working copy |

- Candidate **1** is the extraction of `~/Downloads/traj_procurement_guideline_20260609.zip` (the downloaded origin archive, dated 2026-06-09). **No non-`(2)` sibling directory exists** (a `find -maxdepth 4` would have surfaced one; only the zip and the `(2)` extraction are present).
- Candidates **2–4** are today-dated partial working copies missing the top-level verifier, RESOLUTION V3/V4/V5, and the corpus trees. They cannot self-verify and are **not canonical** — kept only for the record.

---

## Phase 2/3 — identity & continuity → `EXACT_PRIOR_SUBSTRATE`

Identity is asserted from the **artifacts**, not from filename or count
similarity (the trap the task names):

1. **Authorship path-binding.** `verify_readiness.py` line 17 hardcodes
   `ROOT = "~/Downloads/traj_procurement_guideline_20260609 (2)/governance_trajectories"`.
   The verifier was written to run **at this exact location** — authorship
   evidence, not coincidence.
2. **Exact count identity** (re-derived live from the files by the verifier,
   not quoted from the prompt): 12 requirements · 34 assets · **408 mappings** ·
   **340 `REQUEST_REQUIRED`** · **68 `BLOCKED`** · **340 requests / 340 coverage
   edges** · `ready_to_send 0` · `routing_required 340` split
   **`NO_EVIDENCED_COUNSEL_IDENTITY 306` / `NO_APPOINTED_CONTROLLER 34`** ·
   `evidenced_authority_identities 0` · `rights_assertions 0` ·
   `recipients_invented 0`. Q19 (rebuild-reproduces-artifacts) and the Case-M/Q
   gate family are present. Every figure the task treats as the "previously
   verified state" matches.
3. **Internal cryptographic coherence.** Each layer's manifest verifies and
   pins the tree below it by digest (attestation `8353a458…`, resolution
   `b572463b…`, request `035b6c48…`, collection `1cb11a70…`, determination
   `63aff0e8…`, scope `003a1b13…`, requirement `e608753f…`, request-exec
   `72129b81…`); all inter-layer "unmodified" gates pass.

**Continuity honesty:** identity rests on **path-binding + exact count identity**,
not on VCS lineage. The bundle is not version-controlled, so there is **no
commit chain binding it to a specific prior run**. This is the strongest
available claim and it is sufficient to classify `EXACT_PRIOR_SUBSTRATE`; it is
*not* commit-lineage continuity and is not claimed as such. It is not
`COMPATIBLE_BUT_UNPROVEN` (path-binding proves authorship here) and not
`SUBSTRATE_DIVERGED` (see Phase 5 — the only non-green signal is a read-only
write error, not a logic drift).

---

## Phase 5 — baseline re-run (current state, not the prompt's)

Command (from the bundle root):
`python3 COMMERCIAL_BUYER_READINESS_V1/verify_readiness.py --fast` → **exit 1**,
tail `6 FAILED`.

**The 6 "FAILED" lines are read-only-filesystem write errors, not gate
failures.** Every one is a wrapper of the form `FAIL <layer>: all gates pass —
N checks, 0 failed`, i.e. `0` gate failures but child `returncode != 0`. Probing
one child standalone shows why:

```
OSError: [Errno 30] Read-only file system:
  '.../COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1/verification_report.json'
  (verify_commercial_rights_requests.py line 1433)
```

`~/Downloads` is mounted **read-only** in this environment. Each child
runs every gate green, then exits 1 when it tries to emit its own
`verification_report.json`. **Zero named gates fail.** Full (non-`--fast`) mode
was also attempted and fails identically on the same write (and would additionally
hash 37,375 corpus files). All substantive gate output is `PASS`:

- All 13 rights-attestation, 18 resolution, 15 authority, request/collection/
  determination/scope/requirement/request-exec gate families: **PASS**.
- Upstream evidence re-derivation: **PASS** (controller `UNASSIGNED`, lawful
  basis `null`, rights columns all zero, 34/34 assets `UNKNOWN`, 0 determinations
  on file).
- Request-exec headline: `340 requests covering 340 mappings exactly once, none
  sendable`; `nothing is sendable because no authority identity is evidenced —
  340 routing required over 0 evidenced identities`.

**Baseline conclusion:** the substrate's **logic is fully green** and matches the
historical state; the only nonzero exit is report-emission against a read-only
mount.

### Scope caveats (or the report would overclaim)

- **`--fast` was used.** Content hashing is skipped and substituted with mtime,
  which the verifier's own comment says "proves nothing about content." The
  skipped gates include **`Q19` (a rebuild reproduces the shipped artifacts)**
  and each layer's deterministic-rebuild gate (`R1/V1/A1/C1/D1/S1/…`). Full mode
  is **not recoverable here** — it would still exit nonzero on the read-only
  write. So content-level reproduction is **INFERRED from manifest digests**,
  not **VERIFIED** by a clean rebuild this round.

---

## Phase 4 / Phase 6 — why authority cannot be activated

Ranked by durability (the read-only mount is contingent; the user could remount
and the first two blockers still stand):

### Blocker 1 (survives a writable filesystem) — zero evidenced authority identities

Every one of the 340 requests is fail-closed at `ROUTING_REQUIRED`:
`306 NO_EVIDENCED_COUNSEL_IDENTITY` + `34 NO_APPOINTED_CONTROLLER`,
`evidenced_authority_identities = 0`. The missing fact is an **external legal
fact** — a real counsel identity or an appointed data controller — which the
task explicitly forbids inventing ("do not invent lawyers, counsel identity,
controller identity, … appointment, engagement"). The substrate's own gates
**Q11/Q13/Q3** are built to fail any future build that raises `ready_to_send`,
routes a recipient, or sets a `rights_assertion` without evidencing an identity.
Fabricating one to reach `AUTHORITY_ACTIVATED` would trip the very gates that
define the substrate.

### Blocker 2 (survives a writable filesystem) — substrate is outside the assigned repo, non-git, path-hardcoded

The substrate lives in a loose 232 GB Downloads bundle, not in `/tmp/claude-1000/ACGS`,
with **no git history** and a **hardcoded absolute `ROOT`**. Phase 4's
"provenance-preserving Git transfer" is **impossible** — there is no source
lineage to preserve. Copying it into ACGS is out of scope and unsafe: the bundle
carries real AGEC corpus, credential-rotation logs, and session data, and the
verifier would not run there anyway (hardcoded path). That transfer is a
human-authorized decision, not an autonomous one.

### Blocker 3 (contingent, least important) — read-only mount

`~/Downloads` is read-only here, so the authority layer cannot even be
written *into* the substrate in this environment. Listed last because remounting
removes it while Blockers 1–2 remain.

### The stronger framing: there is nothing to activate

The substrate **already encodes exactly what a correct internal-authority layer
would output**: `340 ROUTING_REQUIRED` (306/34 split), `ready_to_send = 0`,
`rights_assertion = null` ×340, `recipients_invented = 0`,
`evidenced_authority_identities = 0`. Building the layer would add code and
**change no count**. And there is no internal authority to activate on the *other*
side of the task's distinction either: the data controller is `UNASSIGNED` and no
counsel is on file — so the "internally authorized sender" the task asks me to
represent has **no evidence establishing it**. Zero on both sides of
"authority to send ≠ evidence the right exists."

---

## Adversarial suite — split by what the baseline already proves vs. what is unrunnable

**Already answered by captured gate output (no new code needed):**

| # | Attack | Settled by |
|---|---|---|
| 1 | missing recipient | Q11 — `0 routed against 0 evidenced identities`, all 340 `ROUTING_REQUIRED` |
| 2 | invented recipient | Q11 — `recipients_invented = 0`; "no recipient derived from a label, brand or filename" |
| 3 | unknown counsel identity | 306 held fail-closed at `NO_EVIDENCED_COUNSEL_IDENTITY` |
| 4 | no appointed controller | 34 at `NO_APPOINTED_CONTROLLER`; upstream `controller UNASSIGNED` |
| 5 | duplicate request | Q8 — `340 edges, 0 missing, 0 duplicated`; Q8b exact reconstruction |
| 9 | change `rights_assertion` | Q3 — `340 requests carry null rights_assertion`; G7 `0 granting statuses` |
| 10 | send-authority → substantive evidence | Q13 — `sent, received and evidence-complete all still mean unanswered` |
| 11 | request absent from registry | Q6/Q8b — `340 mappings re-derived and matched` from upstream |

**Genuinely not runnable this round** (no authority-**receipt** layer exists in
the substrate to attack): #6 stale authority receipt, #7 receipt for a different
request, #8 receipt with changed payload, #12 cross-request receipt replay,
#13 mutation without valid authority receipt, #14 concurrent / at-most-once. These
require the receipt-gated authority layer that Blockers 1–3 prevent building.
Reported as unrunnable rather than as passed.

---

## Mutation-authority integration

**No repository mutation was performed**, so no mutation intent was raised, no
authority decision made, and **no receipt was required, requested, or issued**.
The `mutation-authority` kernel/integration baselines are unchanged and green
(`verify_mutation_governance.py`, `verify_mutation_integration.py`);
`verify_effect_authority_closure.py` remains `BLOCKED` (unchanged this round).
The Intent → Decision → receipt → effect → evidence path was **not exercised**
because there was no governed effect to gate.

---

## Evidence classification (per the task's requirement)

| Statement | Class |
|---|---|
| Substrate exists at the Downloads path; tokens absent from ACGS history | **repository fact** (grep / pickaxe) |
| Inter-layer "unmodified" bindings; manifest digests | **cryptographically bound fact** |
| All named gates PASS; 6 FAILs are read-only writes | **runtime-tested behavior** (this session) |
| Q19 / deterministic-rebuild reproduction | **INFERRED** (skipped under `--fast`; not re-verified) |
| "340 requests, 0 sendable" as the *prior* verified state | **historical statement** — now re-confirmed live |
| Whether a real controller/counsel exists in the world | **unresolved external fact** — cannot be created here |

Tests here prove **implementation behavior only**. They prove no legal right,
real-world identity, appointment, engagement, recipient ownership, or external
authority.

---

## Smallest concrete missing fact to unblock

A single real appointment recorded in
`ACGS_DATA_ASSET_REGISTRY/PRIVACY_OWNERSHIP.json`, field `data_controller`
(currently `"UNASSIGNED"`). A genuine value there unblocks the **34**
`NO_APPOINTED_CONTROLLER` requests from `ROUTING_REQUIRED` toward
`READY_TO_SEND`. (The larger 306 `NO_EVIDENCED_COUNSEL_IDENTITY` set needs an
evidenced counsel identity — a bigger, separate external fact.) Both must be
**recorded from real-world authority evidence, not fabricated**. Absence of
evidence must not be solved by creating evidence.

---

## Final verdict block

- **Primary verdict:** `INTEGRATION_BLOCKED`
- **Canonical path:** `~/Downloads/traj_procurement_guideline_20260609 (2)/governance_trajectories/COMMERCIAL_BUYER_READINESS_V1` (origin archive: `…/traj_procurement_guideline_20260609.zip`)
- **Continuity class:** `EXACT_PRIOR_SUBSTRATE` (path-binding + exact count identity; no VCS lineage)
- **Baseline:** `verify_readiness.py --fast` → exit 1, all named gates PASS; 6 non-gate FAILs = read-only-FS report writes (`Errno 30`)
- **Counts:** 12 requirements · 34 assets · 408 mappings · 340 `REQUEST_REQUIRED` · 68 `BLOCKED` · 340 requests / 340 edges
- **Authority records activated:** 0 · **requests transitioned:** 0 · **requests still blocked:** 340 (`ROUTING_REQUIRED`; 306 + 34)
- **`rights_assertion`:** null ×340 (unchanged) · **invented identities:** 0 · **invented recipients:** 0 · **substantive commercial-rights assertions created:** 0
- **Mutation-authority:** not exercised (0 mutations, 0 receipts); kernel/integration green; effect-closure `BLOCKED` unchanged
- **Files written this round:** this report + a superseded-by header on `REPORT.md`, both under `packages/mutation-authority/INTERNAL_RIGHTS_AUTHORITY_ACTIVATION_V1/`. Nothing written outside that scope; nothing written to the substrate (read-only) or the ACGS repo beyond this package.

## What changed since REPORT.md

`REPORT.md` concluded the substrate did not exist in any reachable location and
that the task should be repointed at "the real repository/branch where that
subsystem lives." That is now **falsified by direct evidence**: the substrate was
located in a downloaded trajectory bundle (not a repository/branch), identified as
`EXACT_PRIOR_SUBSTRATE`, and re-verified green. The verdict remains
`INTEGRATION_BLOCKED`, but for a **stronger and more specific reason**: the
substrate is found and correct, and it is the *external authority evidence* — not
the software — that is missing, exactly as the substrate's own fail-closed design
already records.
