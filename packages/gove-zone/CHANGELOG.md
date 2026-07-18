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

## [1.0.0rc1] - 2026-07-11

First release candidate. Freezes the public API surface
(`tests/fixtures/public_api.txt`).

### Added

- Fail-closed governed execution: `execute_with_receipt`, `GovernedExecutor`,
  `Kernel` — no valid Decision Receipt, no side effect.
- Policy layer: `Policy` ABC, `RuleSetPolicy`, `CompositePolicy`,
  `BoundaryPolicy`/`PathBoundaryPolicy`, `YAMLPolicy`, tenant policy store.
- Receipts + audit: `DecisionReceipt`, `ReceiptVerifier`, append-only
  `ChainHashAuditStore`, replay verification.
- Signing: `Ed25519Signer` (via `crypto` extra), `NullSigner` (dev only),
  signature-required executor gates.
- Adapters and tooling: hook receipt emission, workflow DAG receipts,
  sandbox providers, `gove-zone` / `gove-zone-api` CLIs.

### Notes

- Release candidate: API frozen, pending final-1.0.0 sign-off. Not claimed
  production-ready or compliance-certified.
