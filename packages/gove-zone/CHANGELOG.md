# Changelog

All notable changes to gove-zone are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/) over the surface defined in
`docs/API_STABILITY.md`.

## [Unreleased]

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
