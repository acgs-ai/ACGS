# Decision Receipt Spec as a Standards Candidate — Publication Plan

> Plan for opening the Decision Receipt format as a vendor-neutral standards candidate:
> a versioned, standalone spec repo plus a public auditor/vendor comment process.
> Context on what remains externally unvalidated: [`../research/limitations.md`](../research/limitations.md).
>
> Status of the underlying artifact: **alpha** (`0.1.0a1`). Nothing in this plan is a
> compliance certification, production-readiness claim, or endorsement by any standards body.
> Claim-safe discipline per `docs/CLAIMS.md` applies to every external publication step.
> Date: 2026-07-03.

## 1. What is being standardized

The **Decision Receipt** format: a single vendor-neutral record binding actor, action,
arguments, policy, authority, and audit anchor for one pre-execution authorization decision,
plus its canonical-hash and validation semantics. Source of truth today:

- Spec: `docs/DECISION_RECEIPT_SPEC.md` (29-field schema, binding rules, 20-step validation
  algorithm, invalid-receipt cases).
- Reference implementation: `packages/gove-zone/src/gove_zone/receipt.py`
  (`DecisionReceipt`, `Validator`, `from_record`, `verify`).

The standard candidate is the *format and validation semantics*, not the gove-zone kernel.
The kernel becomes "a reference implementation of the spec," which is exactly the
vendor-neutral position this project claims, and the defense against a rival format: a
copied spec with our adoption is a win; a copied idea with a rival spec is the loss this
plan pre-empts.

## 2. Spec-vs-implementation conformance statement

Conformance review performed 2026-07-03 by reading `docs/DECISION_RECEIPT_SPEC.md` in full
against `packages/gove-zone/src/gove_zone/receipt.py` in full (read-only; no tests were
executed for this review — test-file evidence cited below is as referenced by the spec, not
re-run here).

**Confirmed matches:**

- **Field inventory:** all 29 schema-table fields exist on `DecisionReceipt` and are
  serialized by `to_dict()` with the exact spec names; no extra or missing serialized fields.
- **Hash rule:** `compute_hash()` is SHA-256 over canonical JSON with exactly `receipt_hash`
  and `signature` popped — matches the spec's hash-behavior section verbatim.
- **Signature semantics:** unsigned default (`signature_algorithm="none"`,
  `signature="unsigned_local"`); a receipt that *claims* a signature is rejected without a
  configured verifier regardless of `require_signature`; algorithm and key id are bound into
  `receipt_hash` (anti-downgrade). All as specified.
- **Self-validation:** `from_record` refuses validator == proposer at mint; `verify()`
  enforces the caller-anchored check when `expected_actor` is supplied plus a residual
  `validator_id == actor` fallback. Matches the spec's actor-binding and validator sections.
- **Decision gating:** `deny`/`escalate` receipts are non-executable; `transform` requires
  exact-match of executed args to approved transformations; `allow` re-hashes expected args
  against `argument_hash`. Matches.
- **Expiry:** optional, bound into hash, timezone-aware comparison, unparseable timestamps
  fail closed. Matches.
- **Validation coverage:** all 20 spec-listed rejection conditions have a corresponding check
  in `verify()` (checks 1, 2, 2a–2d, 3–13 in code).

**Drift found (honest list — to be fixed in-spec before any external publication):**

1. **`declared_goal` required-ness.** The spec schema table marks `declared_goal` required
   ("yes"), but `verify()`'s required-field list omits it: a receipt with an empty
   `declared_goal` passes verification, and `from_record` itself mints `record.goal or ""`.
   Either the spec table should mark it optional-but-always-present, or `verify()` should
   enforce it. Currently the implementation is more permissive than the spec.
2. **"Required" semantics are inconsistent in the spec table.** `signing_key_id`,
   `matched_rules`, `constraints`, `transformations`, and `approval_chain_summary` are marked
   required yet are legitimately empty (`""`, `[]`, `{}`) in the spec's own minimal example
   and in unsigned receipts. The spec conflates "must be present in serialization" with
   "must be non-empty"; the standalone spec must define both properties per field
   (presence vs. non-emptiness) explicitly.
3. **Rejection-order nuance.** The spec's validation algorithm lists "signed receipt without
   a configured verifier" (step 3) before "unsigned receipt when signature is required"
   (step 5); the implementation checks the unsigned-when-required case first. Outcomes are
   identical for every input; only the first-error message differs on doubly-invalid
   receipts. The standalone spec should state that rejection *set* is normative and rejection
   *order* is not (or fix the order).
4. **Two receipt types share the module.** `receipt.py` also defines a kernel-internal
   `Receipt` (dispatch proof: `DecisionRecord` + audit hash + result hash). The spec covers
   only `DecisionReceipt`. Not a conformance bug, but the standalone spec must state that
   the kernel `Receipt` is out of scope, to prevent external implementers conflating them.

Net assessment: implementation and spec agree on every security-relevant binding and
fail-closed behavior inspected; the drift is documentation-precision drift (items 1–2), a
non-normative ordering nuance (3), and a scoping clarification (4). No case was found where
the implementation accepts what the spec forbids on a security property, with the single
exception of empty `declared_goal` (item 1), which is descriptive metadata, not a binding
field — it is nonetheless bound into `receipt_hash` like every serialized field.

## 3. Versioning scheme (proposal)

- **Spec versions are decoupled from gove-zone package versions.** The spec starts at
  **`draft-01`** (explicitly a draft series: `draft-01`, `draft-02`, …) and graduates to
  **`v1.0.0`** semver only after the public-comment window closes and at least one external
  implementation passes the conformance fixtures. Alpha software status stays visible: the
  draft label *is* the honesty mechanism.
- **Semver semantics after 1.0:**
  - **major** — any change to canonical hashing, the field set bound into `receipt_hash`,
    or the normative rejection set (breaks verification interop);
  - **minor** — new optional fields (must be excluded from the hash of receipts minted under
    older minors, or introduced via a `spec_version` field — see next point), new optional
    verifier checks;
  - **patch** — editorial, examples, clarified prose with no behavioral change.
- **Add a `spec_version` field in `draft-01`.** The current wire format has no
  self-identification; an external verifier cannot know which rule set applies. This is the
  one deliberate format addition proposed as part of standardization (a major-class change,
  cheapest now, before any external implementation exists).
- **Signature-algorithm registry:** the spec defines `none` and `ed25519` and a registration
  rule for future algorithms (minor version + explicit anti-downgrade statement), rather than
  an open-ended string.
- Each spec release ships as a **tagged GitHub release** with: the spec text, a JSON Schema,
  the conformance fixture corpus, and a changelog entry classifying every change
  major/minor/patch.

## 4. Repo split: standalone spec repo vs. this monorepo

**Moves to the standalone spec repo (proposed name: `decision-receipt-spec`):**

- The normative spec text (derived from `docs/DECISION_RECEIPT_SPEC.md`, with the §2 drift
  items fixed and implementation-specific prose removed — no `receipt.py` line references,
  no gove-zone API names in normative sections).
- A machine-readable **JSON Schema** for the receipt format.
- A **conformance fixture corpus**: valid and invalid receipt JSON files with expected
  verdicts (the existing internal verifier fixture corpus is the natural seed — it exists on
  a local branch per project memory and would need human review before externalization).
- A minimal **language-neutral conformance harness description** ("your verifier must reject
  every fixture in `invalid/` and accept every fixture in `valid/`").
- Governance files: LICENSE (spec text under a liberal license, e.g. CC-BY-4.0 for prose +
  Apache-2.0 for schema/fixtures), CONTRIBUTING with the comment process (§5), a
  CHANGELOG, and a clear STATUS banner: *draft, alpha-derived, not a certification*.

**Stays in this monorepo:**

- The reference implementation (`packages/gove-zone/.../receipt.py`, `signing.py`,
  `executor.py`, `contracts.py`) and all its tests.
- Integration/adapter documentation (MCP gateway, hooks, executors) — implementation
  concerns, not format concerns.
- `docs/DECISION_RECEIPT_SPEC.md` becomes a thin pointer: "the normative spec lives at
  <spec repo>; gove-zone tracks spec version X and its conformance status is reported by the
  fixture suite," plus anything gove-zone-specific (gate API usage, `expected_*` parameter
  guidance).
- The offline proof-pack verifier stays here as product, but a stripped-down
  **receipt-only reference verifier** (single file, stdlib-only — consistent with the
  zero-runtime-deps posture) is a strong candidate to *copy* into the spec repo as the
  executable definition of the validation algorithm.

Rule of thumb: **the spec repo owns "what a valid receipt is"; the monorepo owns "how
gove-zone mints, gates, and stores them."**

## 5. Public-comment process

- **Where:** GitHub Issues + Discussions on the spec repo, with an issue template per
  comment class. All comments public by default; a contact address for parties who cannot
  comment publicly (auditors often can't), with their feedback summarized into public issues
  with permission.
- **Comment classes solicited (the issue templates):**
  1. *Evidence sufficiency* (auditors/GRC): would this receipt format, with its hash chain
     and offline verification, satisfy your evidence standards for "this action was
     authorized before execution"? What is missing?
  2. *Format review* (implementers/vendors): field semantics, canonicalization ambiguities,
     JSON Schema correctness, anything blocking a non-Python implementation.
  3. *Security review*: binding gaps, downgrade paths, replay concerns beyond the documented
     residuals (key custody, distribution, revocation — already stated as open in the spec).
  4. *Interop reports*: "we implemented a verifier/minter in X; here is our fixture pass
     rate" — the highest-value comment class.
- **Cadence:** a defined comment window per draft (e.g., 60 days for `draft-01`), a written
  disposition-of-comments document for every window (every comment gets a recorded
  accept/reject/defer with rationale — this is the practice that makes the effort credible
  to standards-track people later), then `draft-02` or graduation.
- **Announcement surfaces** (each requires a human decision to publish): the gove-zone
  README/docs, the security-community channels already used for the VulnClaw/OSINT wedge
  content, direct outreach to the auditor(s) engaged in the auditor-validation track, and direct
  invitations to potential implementers (MCP gateway authors, agent-framework maintainers).

## 6. Success metrics

Target: **≥2 external implementations or formal comments.** Operationalized:

1. **External implementations (target ≥2):** an implementation counts only if it is (a)
   written by people outside this project, (b) mints *or* verifies Decision Receipts against
   the published JSON Schema, and (c) passes the public conformance fixtures, with the run
   reproducible by us. Tracked in a public `IMPLEMENTATIONS.md` in the spec repo.
2. **Formal comments (count toward the same ≥2 bar):** a comment counts as *formal* only if
   it is written, attributable (named person/org, or anonymized-with-permission for
   auditors), addresses a normative section, and receives a recorded disposition. Drive-by
   reactions, stars, and unattributed feedback do not count.

Secondary indicators (not success claims): fixture-suite downloads/CI usage by third
parties, and citations of the spec in third-party governance documentation.

## 7. Standards venue comparison

| Venue | What it looks like | Pros | Cons |
|---|---|---|---|
| **Standalone GitHub spec repo with versioned releases** | Public repo, draft series, JSON Schema + fixtures, disposition-of-comments docs | Ships in days, not quarters; full control of cadence; PLG-compatible (implementers arrive via GitHub anyway); conformance fixtures are first-class; zero membership cost; honest about alpha status | No institutional imprimatur; "standard" is reputational only; discoverability depends on our own distribution reach |
| **IETF Internet-Draft** | Individual I-D submission (no WG required to start); possible BoF → WG if interest materializes | Real institutional weight; I-Ds are free and individual-submittable; IETF security review culture is exactly the scrutiny this format needs; a datatracker document is citable by regulators | Slow (WG adoption typically 1–2+ years); an expired I-D with no WG signals *less* credibility than a maintained repo; IETF fit is imperfect — this is an evidence/artifact format, not a wire protocol; heavy process cost against a single-maintainer team |
| **OASIS** | Form or join a Technical Committee; committee-specification track | Natural home for XML/JSON evidence and security vocabularies (SAML, ODRL heritage); auditor/GRC audiences recognize OASIS; TC process yields formal statements of use | Membership fees + minimum-participant requirements a single-maintainer project cannot credibly sustain; committee formation before external adoption exists inverts the correct order; risk of the spec being reshaped by whoever shows up to the TC — the rival-format risk realized *inside* the venue |

**Recommendation: standalone GitHub spec repo now, deliberately structured as an
IETF-ready draft series later.**

Rationale:

- The project is **validation-starved**: the binding constraint is external evidence (see
  [`../research/limitations.md`](../research/limitations.md) §2), and the two existential
  threats — platform vendors bundling governance, and a rival format — are *time-bound*. A GitHub spec repo is the only venue that can exist within weeks and start
  accumulating the actual metric (implementations + formal comments). Both formal venues
  measure success in years and consume exactly the single-maintainer capacity this project
  must protect.
- Standards bodies reward *incoming adoption*, not incoming proposals. Two external
  implementations plus a disposition-of-comments track record is the strongest possible
  opening position for a later IETF individual draft (the natural second step — free,
  individual-submittable, and the security-review culture fits) — or for OASIS if the
  auditor/GRC pull turns out to be the dominant audience.
- To keep the upgrade path cheap: write the spec repo's normative text in RFC-2119/8174
  keyword style (MUST/SHOULD/MAY) from `draft-01`, keep normative format text separate from
  implementation guidance, and maintain the fixture corpus as the interop test — these are
  the pieces an I-D conversion reuses directly.
- Decision trigger for escalating venue: **after** the ≥2 external implementations/formal
  comments metric is met, or if a credible competing format appears in a formal venue
  (rival-format defense), whichever comes first.

## 8. Execution order (agent-executable vs. human-gated)

Agent-executable next (in this repo, as normal PR work):

1. Fix drift items §2.1–§2.4 in `docs/DECISION_RECEIPT_SPEC.md` (spec-side wording fixes;
   decide `declared_goal` required-ness with a matching `verify()` change + test if
   "required" is chosen).
2. Draft the standalone spec text (RFC-keyword style), JSON Schema, and a receipt-only
   stdlib reference verifier as *candidate content* staged under `docs/` for human review.
3. Prepare the conformance fixture corpus for externalization (seeded from the existing
   internal verifier fixtures; requires human review of every fixture before publishing).

Human-gated (see humanActionsRequired):

- Creating and publishing the external `decision-receipt-spec` repository, choosing licenses,
  and tagging `draft-01`.
- All outreach: auditors, potential implementers, security-community announcements.
- Any later IETF I-D submission or OASIS engagement.
- Any public statement about the spec's status — must remain within `docs/CLAIMS.md`
  boundaries (alpha, no certification, no regulator acceptance implied).
