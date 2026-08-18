---
title: "feat: Semantica compose adapter + positioning (case file vs. lock on the door)"
status: implemented (example + claims row; COMPARISON/POSITIONING deferred)
type: feat
date: 2026-08-17
owner: founder (Martin) / implementer TBD
target_repo: govern-zone monorepo — `examples/`, `packages/gove-zone/pyproject.toml` extras, docs. NOT the gove-zone kernel.
origin: Semantica investigation 2026-08-17 (live repo `semantica-agi/semantica` `main`, v0.6.5)
---

# feat: Semantica compose adapter + positioning

> **Do not implement until human approval.** This document is a plan, not a change. No file
> outside this plan was written in the run that produced it. Every phase below is gated on an
> explicit go from the owner.

---

## Summary

Semantica (`semantica-agi/semantica`, v0.6.5) is a post-hoc context graph / GraphRAG /
decision-intelligence layer. It records that a decision happened; it does not decide whether an
action may run. ACGS / gove-zone is the opposite: a local receipt-gated kernel whose executor
refuses a side effect without a valid `DecisionReceipt`
(`packages/gove-zone/src/gove_zone/executor.py:508` — `_REASON_RECEIPT_REQUIRED`). The two are
complementary, not competing implementations of the same thing, and the correct engineering
response is a thin one-way export adapter plus honest positioning — never a product merge and
never a knowledge graph inside the kernel. This plan sequences five tracks: an isolated
throwaway-venv spike (P0) that maps fixture receipts onto Semantica's `record_decision` and
`ProvenanceManager`, an in-repo example adapter outside `gove_zone` core with Semantica behind a
new optional extra (P1), an MCP compose note establishing that the Semantica MCP server is not a
PEP (P1), a positioning track that lists which docs should *later* carry a compose paragraph
(P1, docs untouched here), and two P2+ borrows (PROV-O export from the audit chain, operator
`verify` ergonomics). The load-bearing invariant across all five: Semantica never becomes a
security boundary, and nothing in ACGS's claim ledger moves without evidence.

The two negative demonstrations are as important as the positive mapping: Semantica will happily
record a decision with no ACGS receipt at all, and `add_causal_relationship` silently no-ops on a
missing or non-decision node. Both are proof that recording ≠ authorizing.

---

## Product boundary (non-negotiable)

`AGENTS.md:11`:

> ACGS is not an agent framework. It is the execution membrane below agent reasoning and above
> side-effectful tools. Agent frameworks may plan or request actions; ACGS decides whether an
> executor may actually run them.

This plan does not change that. Specifically:

- ACGS does **not** become a knowledge graph, a memory layer, a GraphRAG system, or a
  decision-intelligence product.
- Data flows **one way**: ACGS receipt → Semantica record. Nothing Semantica stores is ever read
  back into a gate, a policy evaluation, or a verification path.
- No Semantica code, model, or dependency enters `packages/gove-zone/src/gove_zone/**`.

---

## Non-goals (hard)

1. **No merge of products.** No vendoring, no fork, no shared schema negotiation with upstream.
2. **No kernel dependency.** `gove-zone` currently ships `dependencies = ["PyYAML>=6.0"]`
   (`packages/gove-zone/pyproject.toml:21`). Semantica goes into a *new* optional extra only —
   never `dependencies`, and never the `dev` extra (`pyproject.toml:46-59`), because `dev` is
   what the gates install and torch/spacy in the gate environment is self-inflicted damage.
3. **No Semantica in the trust path.** Semantica is not a PEP, not a PDP, not a verifier, not an
   audit root. A Semantica record is a downstream *view*.
4. **No claim inflation.** Nothing here makes ACGS certified, compliant, regulator-approved, or a
   complete IAM/PKI system (`docs/CLAIMS.md:44-50`). Composing with a graph product adds zero
   assurance.
5. **No edits to sealed / claim-bearing surfaces in the implementation phases without their own
   review lane:** `docs/CLAIMS.md`, `docs/SECURITY_MODEL.md`, `docs/DECISION_RECEIPT_SPEC.md`,
   `.github/workflows/**`, and any `Constitutional Hash` / `@generated` file.
6. **No nested-repo work.** `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`
   are independent repos; nothing here touches them.
7. **No console UI work.** See Track E.

---

## Deviations from the briefing (ACGS source wins)

Recorded because the implementer will hit each one:

| Brief said | Source says | Consequence |
|---|---|---|
| Map an ALLOW and a DENY receipt | `Decision` has **four** verdicts — `allow`, `deny`, `transform`, `escalate` (`decision.py:21-27`) | Mapping must cover all four; `transform` additionally carries `transformations` (`receipt.py:189`) |
| "fixture `DecisionReceipt` (ALLOW and DENY)" via the gate | `verify()` rejects DENY and ESCALATE outright (`receipt.py:554-557`), and `execute_with_receipt` runs `verify()` before anything else (`executor.py:527`) | A DENY/ESCALATE fixture **cannot** come out of the executor. Mint it directly with `DecisionReceipt.from_record(..., record=DecisionRecord(decision=Decision.DENY, ...))` (`receipt.py:268`) |
| Semantica `record_decision` takes `reasoning`, `outcome`, `confidence` | `DecisionReceipt` has **no** confidence field and **no** free-text reasoning. Closest are `declared_goal` and `matched_rules` (`receipt.py:133-138`); `reason` lives on `DecisionRecord` (`decision.py:116`) and is not carried onto the receipt | The adapter **must not synthesize** a confidence score or a reasoning narrative. Omit, or pass a documented constant with an inline comment stating ACGS emits none. A fabricated `confidence: 1.0` is fabricated evidence |
| `gove-zone` ships `dependencies=[]` (per the 2026-06-13 plan, `docs/plans/2026-06-13-001-…:52`) | `dependencies = ["PyYAML>=6.0"]` (`pyproject.toml:21`) | The stdlib-only mandate is stale; the "no new *runtime* dep" rule still holds |
| Preserve `receipt_id` if possible | `receipt_id = record.event_id` (`receipt.py:327`) — an arbitrary string, not a UUID | If upstream mints its own id, keep a one-way `receipt_id → semantica node id` map in the caller. `receipt_hash` (`receipt.py:253`) stays the only integrity anchor either way |

---

## Gate constraints discovered (these become the acceptance criteria)

`tests/docs/test_docs_and_examples.py` is the root documentation gate and it is unusually literal:

- `:134-158` runs each listed example with `sys.executable`, `cwd=ROOT`, and `PYTHONPATH` set to
  `packages/gove-zone/src` **only** (`:136-137`). A listed example may therefore import
  `gove_zone` + stdlib and **nothing else**.
- Each listed script must exit 0, print a **single line of JSON** with `status: "pass"`, within
  `timeout=30` (`:150-158`).
- Each listed README must contain the literal strings `Run:`, `Expected output`, `Failure case`,
  `What is proven` (`:141-144`).
- `:161-172` asserts every relative markdown link in the required docs and example READMEs
  resolves on disk.
- `REQUIRED_DOCS` (`:12-33`) includes `docs/COMPARISON.md` and `docs/POSITIONING.md`, and
  `:56-61` asserts every one of them contains the literal string
  `No valid Decision Receipt, no side effect`.
- `:81-101` bans specific portability phrasings in `README.md`, `docs/introduction.md`,
  `docs/POSITIONING.md` and requires `integration_matrix.md` to appear in the first two.

Consequence for Track B, stated as a hard requirement rather than a preference: **the example's
mapping function imports nothing from Semantica at module scope.** Emission lazy-imports inside a
function and is skipped when the package is absent. That is what makes the example listable in
`EXAMPLE_SCRIPTS` at all.

Risk note: root `tests/` has thin CI coverage (path-filtered workflows). Run the docs gate
locally; do not assume a green PR proves it ran.

---

## Track A — Isolated spike (P0)

**Goal.** Establish empirically what Semantica v0.6.5 actually accepts, what it returns, and what
it silently ignores — before a single line lands in the repo.

**Environment.** Throwaway venv **outside** the uv workspace (e.g. under `.tmp/`, already
ignored). Never `uv sync` Semantica into the workspace; never add it to any workspace manifest in
this track. Pin `semantica==0.6.5` (the release that patched the Critical unauthenticated
Explorer API, Cypher/SPARQL injection, and SSRF). Do **not** start the Explorer API, the MCP
server, or any listener from the spike — the spike is library calls only, offline. Check `df -i`
before installing: the transitive torch/spacy/transformers footprint is multi-GB and this box has
hit inode exhaustion before.

**Files to touch later.** None in-repo. Scratch scripts under `.tmp/semantica-spike/`; findings
land in this plan's follow-up notes or a new `docs/` note only if Track D is approved.

**Work.**

1. Build four fixture receipts in the spike venv (ACGS installed from source path, or the
   receipts serialized to JSON from a separate ACGS run and read as fixtures — the spike venv
   must not need the ACGS gate stack):
   - ALLOW — via `DecisionReceipt.from_record(...)` (`receipt.py:268`) with a `Validator`
     distinct from the proposer (`receipt.py:302-307` forbids self-validation).
   - DENY — minted directly; it can never leave the executor (see deviations table).
   - TRANSFORM — exercises the `transformations` list shape (`receipt.py:189`).
   - ESCALATE — the human-in-the-loop case; also non-executable.
2. Map each onto `ContextGraph.record_decision(...)` and record precisely which ACGS fields have
   no home and which Semantica fields have no ACGS source.
3. Call `ProvenanceManager.track_entity(...)` and `export_prov(...)` / `verify_chain()` on the
   result. Record whether `record_decision` writes provenance automatically (investigation says
   it does not — confirm).
4. **Negative demo 1 (recording ≠ authorizing):** call `record_decision` with a decision carrying
   no `receipt_id` and no `receipt_hash`. Confirm Semantica accepts it, returns a node, and
   nothing anywhere refuses it.
5. **Negative demo 2 (linkage is not enforced):** call `add_causal_relationship` with a bogus /
   non-decision node id. Confirm it raises nothing and creates no edge — therefore evidence
   linkage must never depend on it.

**Acceptance criteria (testable).**

- A1. A written field-mapping table: every `DecisionReceipt.to_dict()` key (`receipt.py:161-208`)
  is classified as *mapped*, *metadata-only*, or *dropped*, with the Semantica destination named.
- A2. All four verdicts round-trip into a Semantica node without an exception.
- A3. `verify_chain()` output captured verbatim for a provenance chain built from ACGS receipts,
  plus an explicit statement of what it does and does not attest.
- A4. Negative demo 1 reproduced: a Semantica decision node exists with no ACGS receipt, no error.
- A5. Negative demo 2 reproduced: bogus-node `add_causal_relationship` → no exception, no edge
  (assert edge count unchanged).
- A6. The workspace is unchanged: `git status --short` shows no new tracked path from the spike,
  and no workspace manifest gained a Semantica entry.

**Verification commands.** Spike-local only (throwaway venv):

```bash
# inside the throwaway venv, NOT the workspace
python .tmp/semantica-spike/map_receipts.py
python .tmp/semantica-spike/negative_demos.py
# workspace unchanged
git status --short
```

**Effort.** 0.5–1 day, dominated by the dependency install.

**Risks.** Heavy transitive deps (torch/spacy/transformers) — disk and inode pressure; upstream
API drift from the investigated shape (code wins, re-record); accidental workspace contamination
via a stray `uv add`.

**Must NOT change.** Anything under `packages/`, any workspace manifest, any lock file.

---

## Track B — In-repo adapter example (P1)

**Goal.** A thin, offline, example-tier adapter that turns a `DecisionReceipt` into a
Semantica-shaped payload, with Semantica strictly optional.

**Files to touch later.**

- `examples/semantica_evidence_export/receipt_to_semantica.py` — **new**, pure mapping. No
  Semantica import at module scope. No import of Semantica anywhere except inside the emit
  function.
- `examples/semantica_evidence_export/demo.py` — **new**, follows the shape of
  `examples/python_tool_gate/demo.py:74-139`: temp dir, strict fixture, single-line JSON report,
  exit code from `status`.
- `examples/semantica_evidence_export/README.md` — **new**, must contain the four literal gate
  strings.
- `packages/gove-zone/pyproject.toml` — add `[project.optional-dependencies] semantica = [...]`.
  Nothing else in that file changes.
- `tests/docs/test_docs_and_examples.py` — append the new script/README to `EXAMPLE_SCRIPTS`
  (`:35-41`) and `EXAMPLE_READMES` (`:43-49`) **only if** the demo runs green offline under the
  gate's `PYTHONPATH`-restricted environment.

**Design decisions.**

- `receipt_to_semantica(receipt: DecisionReceipt) -> dict[str, Any]` is a pure function over
  `receipt.to_dict()` (`receipt.py:161`). It returns a plain dict. It imports nothing beyond
  stdlib + `gove_zone`.
- A second function — e.g. `emit_to_semantica(payload, graph)` — lazy-imports Semantica **inside
  the function body** and raises a clear, actionable error when the extra is not installed. The
  demo skips this path when the import fails and still reports `status: "pass"`, because the
  proven invariant is the mapping and the boundary, not the presence of a third-party package.
- The mapping is **lossy by design and labelled as such**. `receipt_hash`, `audit_event_hash`,
  `previous_audit_hash`, `policy_hash`, `argument_hash`, `signature_algorithm`, `signing_key_id`
  travel as opaque metadata, never as anything Semantica interprets.
- **No fabricated fields.** No confidence score. No synthesized reasoning narrative. If upstream
  requires the parameter, pass a documented constant with an inline comment naming the absence.
- Non-executable verdicts (`deny`, `escalate`) export exactly like executable ones — a refused
  action is evidence too, and the mapping must not imply the action ran.
- `receipt_id` is preserved in the payload. If upstream mints its own node id, the demo keeps the
  one-way `receipt_id → node id` map in the caller and says so in the README.

**Acceptance criteria (testable).**

- B1. `python examples/semantica_evidence_export/demo.py` exits 0 and prints one line of JSON with
  `status: "pass"`, with `PYTHONPATH=packages/gove-zone/src` and Semantica **not** installed.
- B2. Same command, same result, in under 30 s (the gate's timeout, `:150`).
- B3. `grep -n "semantica" examples/semantica_evidence_export/receipt_to_semantica.py` shows no
  module-scope import — every Semantica reference is inside a function body.
- B4. The demo report includes a field proving the boundary, e.g.
  `"semantica_is_not_a_gate": true` alongside the existing-style invariant string; the ACGS gate
  behavior in the demo is unchanged whether or not the export runs.
- B5. The README contains the literal strings `Run:`, `Expected output`, `Failure case`,
  `What is proven`, and every relative link in it resolves (`:161-172`).
- B6. All four verdicts are exported in one demo run and appear in the JSON report by count.
- B7. `packages/gove-zone/pyproject.toml` diff adds **only** the `semantica` extra; `dependencies`
  (`:21`) and `dev` (`:46-59`) are byte-identical.
- B8. The full root docs gate is green with the new entries registered.

**Verification commands.**

```bash
# example, offline, gate-equivalent environment
PYTHONPATH=packages/gove-zone/src python examples/semantica_evidence_export/demo.py

# the authoritative root docs gate
uv run python -m pytest tests/docs --import-mode=importlib -q

# doc invariants
make lint-docs
```

(`make verify` is not required — this is a single-package + docs change.)

**Effort.** 1 day.

**Risks.** Registering the example in `EXAMPLE_SCRIPTS` makes it a hard gate for every future
contributor — if it can ever need the network or a heavy dep, do not register it; ship it
unlisted and say so. Upstream API drift breaks only the lazy path, by design.

**Must NOT change.** `packages/gove-zone/src/gove_zone/**` (any file), `docs/CLAIMS.md`,
`docs/SECURITY_MODEL.md`, `docs/DECISION_RECEIPT_SPEC.md`, existing example scripts, the `dev`
extra, `.github/workflows/**`.

---

## Track C — MCP compose note (P1)

**Goal.** Write down, once, how an agent config wires ACGS *then* Semantica, so nobody
accidentally treats the Semantica MCP server as a policy enforcement point.

**The ordering.** ACGS gate first, Semantica second, always:

```
agent → tool call
          │
          ▼
   ACGS gate  (validate_action / execute_with_receipt — executor.py:346)
          │  ALLOW + valid receipt ──► side effect runs
          │  DENY / ESCALATE / missing receipt ──► refused, audited (executor.py:508-520)
          ▼
   Semantica record_decision   ← observation only, after the fact, best-effort
```

**Facts that pin this.**

- ACGS's refusal happens before any adapter is entered; the gate appends a `DENY` audit record
  with reason `receipt.execution.receipt_required` (`executor.py:55`, `:508-520`) — exactly the
  behavior `examples/mcp_tool_gate/README.md:13` documents.
- Semantica ships **dual** MCP servers (`mcp/` vs `semantica.mcp_server`). Either way, an MCP
  server that records is not a gate. `docs/CLAIMS.md:39` already bounds ACGS's own neutrality
  claim to "the executor boundary"; a recording server sits outside it.
- A Semantica write failure must never block or alter an ACGS decision. Export is best-effort and
  its failure is logged, not fatal.

**Files to touch later.** One note only —
`examples/semantica_evidence_export/README.md` (a "Compose with MCP" section), or, if it grows
past a section, `docs/SEMANTICA_COMPOSE.md`. Prefer the README; a new required doc adds gate
surface for little gain.

**Acceptance criteria (testable).**

- C1. The note states in one sentence that the Semantica MCP server is not a PEP and never gates.
- C2. The note shows the ordering diagram above with ACGS strictly first.
- C3. The note names both Semantica MCP entrypoints and says which one the example assumed.
- C4. The note states the failure rule: Semantica unavailable → export skipped → ACGS decision and
  audit chain unchanged.
- C5. Every relative link in it resolves (docs gate `:161-172`).

**Verification.** `uv run python -m pytest tests/docs --import-mode=importlib -q`; manual read
against `.claude/rules/claim-safety.md`.

**Effort.** 0.5 day.

**Risks.** A reader skims the diagram and wires Semantica as an approval step — mitigate with the
explicit C1 sentence at the top, not buried.

**Must NOT change.** Any MCP source under `packages/gove-zone/src/gove_zone/mcp_*.py`; any
gateway authority constant.

---

## Track D — Positioning (P1, no doc edits in this plan's run)

**The pairing sentence.**

> **Semantica is the case file. ACGS is the lock on the door.**

Supporting copy, claim-safe (`.claude/rules/claim-safety.md`), for later use:

- "Semantica records what an agent decided. ACGS decides whether the agent's action may run at
  all — the local receipt-gated kernel refuses the side effect without a valid Decision Receipt."
- "They compose one way: a receipt can become a graph record; a graph record can never become an
  authorization."
- "Composing with a context-graph product adds context, not assurance. ACGS's claims are
  unchanged by it."

**Banned in this compose copy:** "production-certified", "regulator-ready", "compliance-ready",
"end-to-end governance stack", any phrasing implying Semantica enforces anything, and the
portability phrasings the gate already bans (`tests/docs/test_docs_and_examples.py:89-93`).

**Docs that should *later* get a short compose paragraph** — listed, not edited:

| Doc | Why | Constraint on the later edit |
|---|---|---|
| `docs/COMPARISON.md` | The natural home for "adjacent product, different layer" | Required doc; must keep the literal string `No valid Decision Receipt, no side effect` (`:56-61`) |
| `docs/POSITIONING.md` | Owns the layer story | Same invariant string; plus the banned-phrase and `integration_matrix.md` rules at `:81-101` apply to this file |
| `docs/INTEGRATION_MATRIX.md` | Where per-runtime/product tiers live; a Semantica row belongs here at *example* tier, not shipped tier | Required doc; invariant string |
| `examples/semantica_evidence_export/README.md` | Where the compose actually lives | Four literal gate strings |

**Ordering rule (do not skip).** `docs/CLAIMS.md:53-55` — "If a claim is not in this table, add it
here before using it in public docs." Any public compose sentence therefore needs a CLAIMS.md row
(status `implemented` / `partial` at best, evidence = the example + spike, limitation =
"local example; one-way export; Semantica is not a gate") **landed first**, in its own reviewed
change. That row is deliberately out of scope for this plan's authoring run.

**Acceptance criteria (testable).**

- D1. The compose paragraph exists in at most the four surfaces above, and nowhere else.
- D2. `rg -n "production-certified|regulator-ready|compliance-ready" <changed docs>` returns
  nothing.
- D3. Every edited required doc still contains `No valid Decision Receipt, no side effect`.
- D4. A CLAIMS.md row for the compose exists **before** the first public sentence ships.
- D5. `uv run python -m pytest tests/docs --import-mode=importlib -q` and `make lint-docs` green.

**Effort.** 0.5 day, plus a claim-review lane.

**Risks.** Copy drifts into "we have governance + memory" — the exact overclaim this plan exists
to prevent. Mitigation: D1's surface cap and the D4 ordering rule.

**Must NOT change.** `README.md` line 1 (gate-pinned, `:66-68`), any claim row's status, the
`Development Status :: 3 - Alpha` classifier (`pyproject.toml:15`).

---

## Track E — Optional later borrows (P2+)

Not scheduled. Recorded so they are not re-derived.

**E1 — PROV-O export from the ACGS audit JSONL.** Export, never gate. A PROV-O rendering of
`ChainHashAuditStore` events is a *view* over evidence that already exists; it establishes no new
trust and must not read stronger than `docs/CLAIMS.md:18` already allows — a bare JSONL chain
detects in-chain edits, reorders, and malformed tails, but a trusted full rewrite or truncation is
only detected against an external signed checkpoint. Any export must carry that limitation inline.
Candidate home: a new CLI verb or an example, never `receipt.py`/`audit.py` semantics.

**E2 — Operator UX for `verify`.** `cli.py:132` (`_replay`) and its `replay` subparser
(`cli.py:1865`) already print chain verification, and `_mcp_verify` / `_spend_verify` /
`_release_verify` exist alongside. So a `semantica provenance verify-chain`-comparable operator
experience is **ergonomics over existing capability**, not new capability. Scope it as naming and
output shape if it is ever picked up.

**E3 — Console receipt timeline: stays out of scope.** Checked:
`acgi-ai/src/routes/console/AuditProof.tsx:23` renders **one** receipt proof by `receiptId`
(hash chain, policy path, downloadable signed evidence packet). A per-receipt surface exists; a
*list/timeline* view does not. That makes a timeline net-new console work on a privileged origin
(`CLAUDE.md` hard constraint 4), so it stays P2+ and is not pulled forward by this plan.

---

## Phase order and gating

| Phase | Track | Gate to proceed |
|---|---|---|
| 0 | A — spike | Owner approves this plan |
| 1 | B — example + extra | A1–A6 recorded; field mapping reviewed |
| 2 | C — MCP note | B1–B8 green |
| 3 | D — positioning | C green **and** the CLAIMS.md row landed (D4) |
| — | E — borrows | Not scheduled |

Tracks B and C may run in one branch (same example directory). Track D is a separate branch and a
separate review lane, because it touches claim-bearing docs.

---

## Risks & fail-closed invariants that must not weaken

- **I1 — No valid Decision Receipt, no side effect.** `executor.py:508-520` refuses a missing
  receipt and audits the refusal. Nothing in this plan sits on that path.
- **I2 — DENY / ESCALATE are never executable.** `receipt.py:554-557`. Exporting a denied receipt
  to a graph must not read as "the action happened".
- **I3 — `expected_actor` is required at the gate** (`executor.py:471-483`,
  `GovernedExecutor.__init__` `executor.py:880-883`). Untouched.
- **I4 — Validator ≠ proposer.** `receipt.py:302-307` (issuance) and `receipt.py:481-506`
  (verification). Untouched.
- **I5 — `receipt_hash` is the only integrity anchor.** `receipt.py:253-257`. A Semantica node id,
  a PROV-O entity id, or a graph edge is not evidence of integrity.
- **R-A — Dependency weight.** torch/spacy/transformers in a gate environment would slow or break
  CI. Mitigation: new extra only, never `dev`; example must run with Semantica absent (B1).
- **R-B — Upstream security surface.** v0.6.5 patched a Critical unauthenticated Explorer API plus
  Cypher/SPARQL injection and SSRF. Mitigation: pin `0.6.5` minimum; no listener in the spike; if
  Semantica is ever run as a service that is a separate security review, not this plan.
- **R-C — Claim drift.** The single largest risk. Mitigation: Track D's surface cap (D1), banned
  phrases (D2), and the CLAIMS.md-first ordering rule (D4).
- **R-D — Silent-failure adoption.** `add_causal_relationship` no-ops on missing nodes (A5), so an
  integrator can believe evidence is linked when it is not. Mitigation: the example never depends
  on graph linkage for any assertion, and the README states the no-op explicitly.
- **R-E — Reverse dependency.** Someone later reads Semantica in a decision path. Mitigation: the
  one-way rule is stated in the product-boundary section and in the example README; a reviewer
  should treat any Semantica import under `packages/gove-zone/src/**` as an automatic block.

---

## Verification strategy (per phase)

| Phase | Command | Expected |
|---|---|---|
| A | spike scripts in the throwaway venv; then `git status --short` | mapping + negatives recorded; workspace clean |
| B | `PYTHONPATH=packages/gove-zone/src python examples/semantica_evidence_export/demo.py` | exit 0, one JSON line, `status: "pass"`, < 30 s, Semantica absent |
| B | `uv run python -m pytest tests/docs --import-mode=importlib -q` | green with the new example registered |
| B | `make lint-docs` | green |
| C | `uv run python -m pytest tests/docs --import-mode=importlib -q` | green (link resolution) |
| D | `uv run python -m pytest tests/docs --import-mode=importlib -q` + `make lint-docs` | green; invariant string intact in every required doc |

No `make verify` — this is a single-package + docs change, not multi-package validation. No
gove-zone runtime suite is required unless a phase unexpectedly touches
`packages/gove-zone/src/gove_zone/**`, which it must not; if that ever happens, the change is out
of scope and the gate becomes
`uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q`
plus a security review lane.

Paste literal command output next to any pass/fail claim. A passing unit test does not prove
wiring — the example must be reached through the registered gate list, not by calling the mapping
function directly.

---

## Sources

- `packages/gove-zone/src/gove_zone/receipt.py` — `DecisionReceipt`, `to_dict` (`:161`),
  `compute_hash` (`:253`), `from_record` (`:268`), `verify` (`:361`), self-validation
  (`:302-307`, `:481-506`), DENY/ESCALATE rejection (`:554-557`).
- `packages/gove-zone/src/gove_zone/decision.py` — `Decision` (`:21-27`), `RecordKind` (`:30`),
  `ActionTier` (`:44`), `DecisionRecord` (`:98`), `sha256_json` (`:89`).
- `packages/gove-zone/src/gove_zone/executor.py` — `execute_with_receipt` (`:346`), reason codes
  (`:49-64`), required actor (`:471-483`), missing-receipt refusal (`:508-520`),
  `GovernedExecutor` (`:802`).
- `docs/CLAIMS.md` — rows 7–24 (implemented/tested claims), row 18 (replay limits), `:39` (gate
  position), `:44-51` (explicit non-claims), `:53-55` (public wording rule).
- `docs/DECISION_RECEIPT_SPEC.md` — public schema table (`:19-49`), three-schemas warning
  (`:51-61`).
- `AGENTS.md:9-11` — core invariant and the membrane boundary.
- `examples/python_tool_gate/demo.py:74-139`, `examples/mcp_tool_gate/README.md`,
  `examples/copilotkit_governed/README.md` — the example shape this plan copies (temp dir, strict
  fixture, single-line JSON, explicit limitations section).
- `tests/docs/test_docs_and_examples.py:12-49`, `:56-101`, `:134-172` — the gate constraints that
  became the acceptance criteria.
- `packages/gove-zone/pyproject.toml:21`, `:33-59` — runtime deps and extras.
- `acgi-ai/src/routes/console/AuditProof.tsx:23` — the existing per-receipt console surface.
- `docs/plans/2026-06-13-001-feat-tamper-evident-consumption-ledger-plan.md` — format reference.
- Semantica investigation, 2026-08-17: `semantica-agi/semantica` `main`, v0.6.5 (external; not
  re-verified in this planning run).

---

## Execution refinements (2026-08-17)

Applied during the first implementation pass. These supersede the original sequencing where they
conflict:

1. **Track A is optional for landing B/C.** The example is designed to pass with Semantica
   absent (B1). A live `pip install semantica==0.6.5` is still attempted in a throwaway
   **Python 3.12** venv. The first attempt on the host default (3.14) failed compiling
   `gensim` (`Python.h` missing). That is itself a product-boundary signal: do not put this
   stack in the kernel or the `dev` extra.
2. **Track D surface reduced.** Landed: `docs/CLAIMS.md` row first, example README compose
   note, and an "Adjacent observation layers" section in `docs/INTEGRATION_MATRIX.md`.
   Deferred: `docs/COMPARISON.md` and `docs/POSITIONING.md` (still claim-bearing; no need
   this pass).
3. **No fabricated ACGS fields.** Mapping omits `confidence` and `reasoning`. The lazy emit
   path may pass `ACGS_NO_REASONING_FIELD` / `0.0` as Semantica-required protocol padding
   only, labelled as such.
4. **Field mapping (from `DecisionReceipt.to_dict()`).**

| Receipt key | Classification | Semantica destination |
|---|---|---|
| `receipt_id` | mapped | `decision_id` + `metadata.receipt_id` |
| `proposed_action` | mapped | `category` |
| `declared_goal` (else `proposed_action`) | mapped | `scenario` |
| `decision` | mapped | `outcome` (`allow`/`deny`/`transform`/`escalate`) |
| `actor` | mapped | `decision_maker` (proposer, never validator) |
| `expires_at` | mapped | `valid_until` when non-empty |
| `request_id`, `tenant_id`, `subject`, `execution_boundary`, `policy_*`, `matched_rules`, `constraints`, `transformations`, `approval_chain_summary`, `timestamp`, `authority`, `validator_id`, `validator_role`, `argument_hash`, `action_tier`, `previous_audit_hash`, `audit_event_hash`, `signature_*`, `receipt_hash`, `signature` | metadata-only | `metadata.<key>` (opaque) |
| `reasoning`, `confidence` | not in ACGS | omitted from payload; emit-path placeholders only |

5. **Kernel still untouched.** No file under `packages/gove-zone/src/gove_zone/**` changed.
6. **Track A spike results (Python 3.12 throwaway venv, `semantica==0.6.5`).** Host default 3.14 failed (`gensim` needs `Python.h`). On 3.12:
   - Ungated `record_decision` **accepted** with no receipt (A4).
   - `add_causal_relationship` on a missing node **no-ops**; a real pair of decision nodes **does** add `CAUSED` (A5). First probe misfired by counting `belongs_to`/`made_by` edges from `record_decision` itself.
   - `record_decision` **mints a UUID**; ACGS `receipt_id` is preserved only via `id_map` in `emit_to_semantica`.
   - Live emit from the adapter succeeded (`used_reasoning_placeholder` / `used_confidence_placeholder` true).

## Do not implement until human approval

Original authoring-run gate. Owner approved refine-and-execute on 2026-08-17. Tracks B, C, and
the reduced Track D landed in the same change. Track A live Semantica I/O remains best-effort
in `.tmp/semantica-spike/` and is not a merge blocker.
