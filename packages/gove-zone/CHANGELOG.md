# Changelog

All notable changes to gove-zone are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/) over the surface defined in
`docs/API_STABILITY.md`.

## [Unreleased]

### Changed

- Aligned the root and package READMEs with the canonical
  `1.0.0rc1` / Beta source metadata, while separating source version from
  verified PyPI publication and production-readiness claims.
- Reworked the release runbook and PyPI-readiness checklist to make external
  approval, private-repository constraints, exact-SHA verification,
  post-publish acceptance, and yank/fix-forward handling explicit.

### Release-process note

The source tree currently reports `1.0.0rc1`, but package and public-surface
changes landed after the original release-candidate preparation. Reconcile all
such changes, the public API fixture, the stability contract, and this
changelog before creating a release tag.

## `1.0.0rc1` candidate preparation - 2026-07-11

This records the source state prepared for an intended first release
candidate. It does not assert that an immutable tag or PyPI release was
created. Later public-surface changes mean this is not a complete inventory of
the current source; rebuild the candidate entry before release.

### Added

- Fail-closed governed execution: `execute_with_receipt`, `GovernedExecutor`,
  `Kernel` — no valid Decision Receipt, no side effect.
- Policy layer: `Policy` ABC, `RuleSetPolicy`, `CompositePolicy`,
  `BoundaryPolicy`/`PathBoundaryPolicy`, `YAMLPolicy`, tenant policy store.
- Receipts + audit: `DecisionReceipt`, `ReceiptVerifier`, append-oriented
  `ChainHashAuditStore`, replay verification.
- Signing: `Ed25519Signer` (via `crypto` extra), `NullSigner` (dev only),
  signature-required executor gates.
- Adapters and tooling: hook receipt emission, workflow DAG receipts,
  sandbox providers, the `gove_zone` and `mcp_gateway` wheel packages, and the
  `gove-zone`, `gove-zone-api`, and `acgs` console scripts.

### Notes

- Candidate preparation only: the proposed API snapshot is not frozen until
  release reconciliation completes and an immutable candidate is cut. No
  production-readiness or compliance-certification claim is made.
