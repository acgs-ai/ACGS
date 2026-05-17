# AGENTS.md — automation/tests

## Purpose

Pytest suite that exercises the automation lifecycle as a whole: proposal
generation, registry / policy / proposal validation, danger-pattern detection,
and audit-log emission. The tests treat `automation/scripts/` as a black box
where possible — they invoke the public functions (`validate_registry`,
`validate_policy`, `validate_proposal`, `detect_dangerous_commands`,
`append_event`) and assert on the resulting JSONL, registry shape, and exit
codes rather than on internal helpers.

## Key Files

- `test_automation_system.py` — Single end-to-end suite covering:
  - Registry schema validation against `REGISTRY_REQUIRED_FIELDS`
  - Policy YAML loading and validation
  - Proposal validation (happy path + missing-field / dangerous-command paths)
  - `detect_dangerous_commands` regex coverage (rm -rf, curl|sh, sudo, ...)
  - `append_event` writing well-formed JSONL with required keys

## Workflow / Commands

```bash
# Run just this suite
pytest automation/tests -q

# Single test with full output
pytest automation/tests/test_automation_system.py::test_reviewed_proposal_validates -s -vv

# Run with coverage scoped to the automation scripts
pytest automation/tests \
  --cov=automation/scripts \
  --cov-report=term-missing
```

## Gotchas / Conventions

- The test file uses the same `sys.path` bootstrap pattern as the scripts
  themselves (`SCRIPTS = ROOT / "scripts"; sys.path.insert(0, str(SCRIPTS))`).
  Keep the `# noqa: E402` comments — they document the required import order.
- Tests construct their own fixture dicts via the `reviewed_proposal()` helper
  rather than reading from `automation/proposals/` to stay hermetic. When you
  change the proposal schema, update both the helper here and the live
  proposals in lockstep.
- `append_event` writes to a real file under `automation/logs/` if you pass it
  the default path. In tests, always pass `log_path=tmp_path / "audit.jsonl"`
  (or similar) so the run does not pollute the repo's audit chain.
- `detect_dangerous_commands` is a string-pattern check, not a parser. Adding
  a new safe primitive that happens to contain a dangerous substring requires
  refining the regex; do not work around it by mutating test fixtures.
- The suite is the gate before any change to `automation/scripts/` lands —
  run it locally before pushing, not just in CI.
