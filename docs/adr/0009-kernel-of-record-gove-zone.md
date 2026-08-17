# ADR-0009: gove-zone as kernel of record for the ACGS governance family

## Status

Proposed (human ratification required before Phase 3 of the kernel
unification program; Phase 1 is additive/experimental and may proceed in
parallel as draft-ADR per the program plan)

## Date

2026-07-10

## Relates to

- `docs/internal/superpowers/plans/2026-07-10-kernel-unification-program.md` — the
  kernel unification program this ADR is Task 0 of; later phases (1–5) cite
  this decision and are scoped as separate plans.
- ADR-0003 (monorepo topology and submodules) — governs how
  `packages/acgs-lite` is committed and pointer-bumped as a nested repo;
  unaffected by this decision.
- ADR-0007 (AUTHZ trace cryptographic core) — a different codebase
  (`acgs_governance_eval_mvp/governance/crypto/`), not in scope here.

## Context

The monorepo carries two independently evolved governance-kernel
implementations under one brand:

- **acgs-lite** (`legitimacy/`, `audit.py`) — published on PyPI at v2.x,
  `requires-python = ">=3.10"`, with a constitution engine, ~20 framework
  adapters, and a lifecycle server. This is the only one of the two with
  external distribution and downstream consumers (Acgs-Swarm, clinicalguard).
- **gove-zone** — in-tree at 1.0.0rc1, zero runtime dependencies, stdlib
  kernel with an optional `cryptography` extra for Ed25519 signing.

The two share zero code. They also do not share a receipt format, and the
formats are not interoperable: canonicalization differs (acgs-lite's
`ensure_ascii=True` default vs. gove-zone's `ensure_ascii=False` — any
non-ASCII payload hashes differently), and signature preimages differ
(acgs-lite signs `b"acgs-receipt-v1\x00" + hash`, gove-zone signs bare hash
bytes). Audit chains share nothing between the two. A translation layer
between the two receipt formats would therefore be lossy and cryptographically
meaningless, not a lightweight adapter.

### Evidence: gove-zone vs. acgs-lite kernel properties (2026-07-10 extraction)

| Property | acgs-lite (`legitimacy/`, `audit.py`) | gove-zone |
|---|---|---|
| Receipt hash coverage | all fields except hash | all fields except hash+sig, **`signature_algorithm`+`signing_key_id` inside the hash (anti-downgrade)** |
| Audit anchoring | receipt ↔ audit chain unlinked | `previous_audit_hash`/`audit_event_hash` hash-bound into receipt |
| Validator separation | roles in separate `maci.py`, not receipt-bound | `validator_id` ≠ `actor` enforced at mint, in-hash |
| Chain hash | `sha256(...)[:16]` **truncated**, genesis `"genesis"`, **trims at 10k entries and re-roots chain** (`audit.py:375-379`) | full 64-hex `sha256_json`, genesis `"0"*64`, append-only |
| Argument binding | none on receipt | `argument_hash` + executor `expected_args` check |
| Single-use | `ExecutionBoundary.single_use` flag (advisory) | `ReceiptConsumptionLedger` burn-before-execute |

On every row where the two diverge, gove-zone's design is the stronger
security posture: full (not truncated) chain hashes with an append-only chain
(no re-rooting at a size threshold), hash-bound audit anchoring instead of an
unlinked receipt/audit pair, in-hash validator/actor separation instead of a
separate advisory module, argument binding on the receipt itself, and
enforced (not advisory) single-use consumption.

This ADR records a decision about future direction. It does not claim gove-zone
or acgs-lite are already unified, migrated, or in production, and it makes no
runtime claims — no entry is added to `docs/CLAIMS.md`-adjacent
claim-tracking docs as a result of this document.

## Decision

### D1 — gove-zone is the kernel of record

gove-zone becomes the kernel of record for the ACGS governance family:
receipts, signing, the audit chain, and the executor gate all live there
going forward. acgs-lite becomes a distribution layer *above* the kernel —
its constitution engine, framework adapters, and lifecycle server — rather
than a second, competing kernel implementation. The unification seam is a
`Policy` adapter (acgs-lite's `GovernanceEngine` wrapped as a
`gove_zone.policy.Policy`), not receipt-format translation.

### D2 — dependency edge: acgs-lite → gove-zone, one way only

`gove-zone` keeps `dependencies = []` forever. The dependency edge points
acgs-lite → gove-zone, never the reverse, and never circular — no
`acgs-lite` extra is added inside gove-zone. acgs-lite's published floor
(`requires-python = ">=3.10"` for the 2.x line) is preserved; the new
gove-zone bridge is carried as an optional extra marked
`python_version >= '3.11'` (gove-zone uses `StrEnum`, which needs 3.11), so
existing 2.x installs on 3.10 are unaffected.

### D3 — 4-verdict kernel taxonomy with 8-state surface mapping

Kernel-level verdicts are gove-zone's four (`Decision.ALLOW`, `DENY`,
`TRANSFORM`, `ESCALATE`). acgs-lite's 8-state `DecisionState` surface maps
onto them losslessly — the original state is preserved by carrying it in
`DecisionRecord.reason` (`acgs-lite:<STATE>:` prefix) and by carrying rule
ids in `matched_rules`, so no acgs-lite-specific information is discarded at
the kernel boundary:

| acgs-lite `DecisionState` | gove-zone `Decision` |
|---|---|
| `ALLOW` | `ALLOW` |
| `ALLOW_WITH_CONTROLS` | `ALLOW` |
| `TRANSFORM_REQUIRED` | `TRANSFORM` |
| `STRUCTURED_REVIEW_REQUIRED` | `ESCALATE` |
| `REPLAN_REQUIRED` | `DENY` |
| `DENY_OPERATION_WITH_ALTERNATIVE` | `DENY` |
| `DENY_GOAL` | `DENY` |
| `HARD_DENY` | `DENY` |

An unknown/unmapped state must raise rather than silently default to a
verdict — callers fail closed on new or unrecognized acgs-lite states.

### D4 — gove-zone `canonical_json` is the sole canonical form for new evidence

`gove_zone`'s canonicalization (`sort_keys=True, ensure_ascii=False,
separators=(",", ":")`) is the one true canonical form for all *new* evidence
minted after this decision — receipts, decisions, audit entries. An
acgs-lite legacy hash must never be treated as, compared against, or
re-derived as a gove-zone hash; the two canonicalizations are incompatible by
construction (see Context).

## Consequences

- **acgs-lite 3.0 is a major version.** Because the kernel of record moves
  underneath acgs-lite's public surface, a future acgs-lite 3.0 line
  deprecates `legitimacy/` in favor of re-export shims over
  `gove_zone.receipt`/`gove_zone.signing`, with new evidence minted as
  gove-zone `DecisionReceipt`s. This is a separate, later phase (Phase 3 of
  the program plan) and is not delivered by this ADR.
- **The legacy verifier is retained forever.** Existing acgs-lite evidence
  (receipts, audit chains) already minted under the old canonicalization
  stays verifiable with the legacy acgs-lite verifier indefinitely; there is
  no retro-migration of historical evidence to gove-zone's format.
- **Release ordering is constrained.** No acgs-lite release to PyPI may ship
  the `gove` extra until gove-zone itself is published on PyPI (this is
  FINAL-GOAL G1.1, a separate human-gated milestone). In-workspace
  development uses `[tool.uv.sources]` in the interim.
- **Nested-repo discipline is unchanged.** `packages/acgs-lite` remains an
  independent git repo (ADR-0003); all Phase 1+ commits implementing this
  decision happen inside that nested repo, with parent-pointer bumps as a
  separate, later step.
- **Downstream consumers are not migrated by this ADR.** Acgs-Swarm and
  clinicalguard both currently depend on acgs-lite's 2.x API; their move to
  an acgs-lite 3.x floor is Phase 4 of the program plan, blocked on Phase 3.

## Alternatives rejected

### Receipt-format translation between acgs-lite and gove-zone

Rejected. As established in Context, the two canonicalizations
(`ensure_ascii=True` vs. `False`) and signature preimages
(`b"acgs-receipt-v1\x00" + hash` vs. bare hash bytes) are incompatible by
construction. A translation layer would either have to re-sign under a
different preimage (breaking the original signature's meaning) or fabricate
a gove-zone-shaped hash that was never actually computed by gove-zone's
canonicalization — in both cases the resulting artifact is cryptographically
meaningless, not a faithful representation of the original evidence.

### Freeze acgs-lite, standardize on gove-zone alone

Rejected. acgs-lite is the only one of the two kernels with an external
PyPI release and real downstream consumers (Acgs-Swarm, clinicalguard).
Freezing it abandons the only currently-published product in the family and
forces every downstream consumer into an uncoordinated, unplanned migration
with no adapter seam. The chosen approach (D1) keeps acgs-lite's published
surface alive as a distribution layer while consolidating the kernel
underneath it.

### Maintain both kernels in parallel indefinitely

Rejected. Running two competing, non-interoperable governance-kernel
implementations under one brand indefinitely means every claim about
"ACGS governance guarantees" has to be qualified by which kernel produced
the evidence, doubles the security-review surface for receipts/signing/audit
code (per the program plan's dangerous-edit-zone constraint), and leaves
reviewers and integrators unable to point at one canonical audit chain.
Consolidating on a single kernel of record removes this permanent ambiguity.

## References

- `docs/internal/superpowers/plans/2026-07-10-kernel-unification-program.md` — full
  program plan, Global Constraints section, and Task 0–5 breakdown.
- ADR-0003 — monorepo topology and submodule strategy (governs
  `packages/acgs-lite` commit discipline, unaffected by this decision).
- `packages/acgs-lite/pyproject.toml` — sealed constitutional-hash header
  (line 1); untouched by this ADR.
