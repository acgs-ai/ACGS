# Platform Reconstruction — §7 Decision Record

> Platform-reconstruction program, document 6 of 6. Resolves the five open
> decisions in `00-EXECUTIVE-SUMMARY.md` §7. Decisions were prepared by the
> maintainer's agent under an explicit "do it for me" delegation (2026-07-06)
> and are **reversible until the PRs they unblock merge** — rejecting this PR
> rejects the calls. Each call follows the direction already settled in
> `04-platform-blueprint.md` §2 where one exists.

## D1 — L0 receipt-schema ownership (§7:1)

**Call: the gove-zone lineage owns the L0 receipt schema.** The extracted
`acgs-evidence` L0 library derives its schema from the gove-zone kernel's
receipt format; `acgs-lite` remains the published SDK bound by a
receipt-format contract (blueprint §2 — no repo merge), enforced by the
cross-lineage contract test (roadmap item `cross-lineage-contract-test`).

*Why:* blueprint §2 already designates gove-zone as kernel of record; the
kernel format is the one with 634+ tests, replay, signing, and single-use
enforcement behind it. *Residual:* §7:1 notes an acgs-lite source checkout is
needed to confirm every acgs-lite receipt field is representable — the
contract test is the enforcement point; if a field cannot be represented,
that surfaces there, not silently.

## D2 — Standards timing (§7:2)

**Call: align at L0 design time, now.** The `acgs-evidence` schema carries the
Agent Receipts attachment points (Ed25519 signatures, W3C-VC envelope
compatibility) from its first version, with the internal format explicitly
versioned so alignment work stays additive. IETF AER / SCITT are tracked as
targets, not blockers.

*Why:* doc-00 §1/§3 — the 12–18-month window rewards the standard-aligned,
offline-verifiable receipt as *the* differentiator; retrofitting standards
onto a stabilized internal format is strictly more work than versioning from
day one.

## D3 — Defaults-flip rollout (§7:3)

**Call: direct flip with an explicit dev-mode escape, in the next release.**
Signing + single-use receipts become default-ON; unsigned/dev operation
requires an explicit, loudly-named opt-out (never a production claim). No
one-cycle deprecation profile.

*Why:* gove-zone is `0.1.0a1` — a pre-1.0 alpha with minimal external
surface. A deprecation cycle protects almost nobody while prolonging a
known-weak default (doc-00 §2 lists opt-in integrity as a top defect). The
flip lands as a clearly-labeled breaking change in release notes.

## D4 — L2 control plane shape (§7:4)

**Call: embedded library first; deployed service deferred.** The
receipt-verification / control-plane capability ships as an importable
library surface; standing up a deployed service waits until staging exists
and the runner SPOF is mitigated.

*Why:* doc-00 §1 — the production gap is operational, not architectural.
Adding a deployed surface before a staging environment exists inverts the
risk order. doc-05 scope shrinks accordingly; the roadmap item
`receipt-verification-control-plane-api` is re-scoped to the library shape.

## D5 — Constitutional-hash gate (§7:5)

**Call: populate (activate).** Inventory the genuinely sealed files (the hash
lock and offline verifier already exist) so the parent gate checks a real
inventory. Descope only if population proves the inventory is empty by
nature — in which case remove the gate rather than leave a no-op that reads
as a control.

*Why:* §7:5's own framing — "a no-op that reads as a control is the worst
option." Populating is the honest activation; the roadmap item
`populate-or-descope-constitutional-hash-gate` implements it with populate
as the primary path.

## Unblocked by this record

| Item | Phase | Decision |
|---|---|---|
| `defaults-flip-signing-single-use` | B | D3 |
| `populate-or-descope-constitutional-hash-gate` | B | D5 |
| `extract-acgs-evidence-l0` | B | D1 + D2 |
| `align-l0-to-agent-receipts-standards` | C | D2 (after extract-l0 merges) |
| `cross-lineage-contract-test` | C | D1 (after extract-l0 merges) |
| `receipt-verification-control-plane-api` | C | D4 — re-scoped to embedded library |
