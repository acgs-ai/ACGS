# API Stability (semver contract)

Effective from stable `v1.0.0`. The `1.0.0rc1` source metadata is a proposed
candidate contract, not evidence that the candidate was tagged or published.

## Covered surface

The public Python API is exactly the names exported by top-level `gove_zone`
(`gove_zone.__all__`), pinned by `tests/fixtures/public_api.txt` and enforced
by `tests/test_public_api.py`. The three shipped console-script names
(`gove-zone`, `gove-zone-api`, and `acgs`) and their documented behavior and
exit codes are also covered.

The wheel also ships the `mcp_gateway` import package, but its public import
surface is not represented in the current fixture. Before stable `v1.0.0`,
either define and test that package's SemVer contract or explicitly classify
it as internal. This is a release blocker, not an implied stability promise.

## Not covered

- Submodule paths (`gove_zone.receipt` internals etc.) — import from the
  top level.
- Anything prefixed with `_`.
- `mcp_gateway` internals until the stable-release classification above is
  resolved.
- The textual content of reasons/messages (only their documented structure).

## Rules

- MAJOR: remove/rename a covered name, change a covered signature
  incompatibly, weaken a fail-closed default.
- MINOR: add names, add keyword-only parameters with defaults.
- PATCH: behavior-preserving fixes.

Deprecations ship at least one MINOR release before removal and raise
`DeprecationWarning`.
