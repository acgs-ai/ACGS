# API Stability (semver contract)

Effective from v1.0.0.

## Covered surface

The public API is exactly the names exported by top-level ``gove_zone``
(``gove_zone.__all__``), pinned by ``tests/fixtures/public_api.txt`` and
enforced by ``tests/test_public_api.py``. The two console scripts
(``gove-zone``, ``gove-zone-api``) and their documented exit codes are also
covered.

## Not covered

- Submodule paths (``gove_zone.receipt`` internals etc.) — import from the
  top level.
- Anything prefixed with ``_``.
- The textual content of reasons/messages (only their documented structure).

## Rules

- MAJOR: remove/rename a covered name, change a covered signature
  incompatibly, weaken a fail-closed default.
- MINOR: add names, add keyword-only parameters with defaults.
- PATCH: behavior-preserving fixes.

Deprecations ship at least one MINOR release before removal and raise
``DeprecationWarning``.
