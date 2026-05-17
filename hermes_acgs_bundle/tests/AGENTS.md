# AGENTS.md — hermes_acgs_bundle/tests

## Purpose

Pytest suite for the Hermes ACGS middleware bundle. The tests instantiate a
real `HermesACGSMiddleware` against the bundle's own
`constitution.min.yaml` and a per-test evidence path, then assert on the
denial/redaction/human-approval/soft-block decision modes plus the
chain-hashed evidence rows the middleware appends. This is the regression net
for any change to `hermes_acgs_middleware.py`, `evidence_writer.py`, or the
shipped constitution.

## Key Files

- `test_hermes_acgs_middleware.py` — Verifies the four decision modes
  (`DENY`, `REDACT`, `REQUIRE_HUMAN`, `SOFT_BLOCK_WITH_EXPLANATION`),
  non-allowlisted-tool denial with audit emission, evidence JSONL shape, and
  `DEFAULT_CONSTITUTION` resolution. Uses `tmp_path` for evidence so runs are
  hermetic.

## Workflow / Commands

```bash
# Run the bundle's tests in isolation
pytest hermes_acgs_bundle/tests -q

# Single-test debugging with stdout
pytest hermes_acgs_bundle/tests/test_hermes_acgs_middleware.py::test_non_allowlisted_tool_is_denied_and_audited -s -vv

# Coverage of the middleware
pytest hermes_acgs_bundle/tests \
  --cov=hermes_acgs_bundle.hermes_acgs_middleware \
  --cov-report=term-missing
```

## Gotchas / Conventions

- The test module performs a `sys.path` bootstrap (`ROOT = parents[1]`,
  `sys.path.insert(0, str(ROOT))`) so it can import `hermes_acgs_middleware`
  and `evidence_writer` as top-level modules. The `# noqa: E402` comments are
  required — do not let isort reorder them.
- `build_middleware(tmp_path)` is the canonical factory. New tests should
  call it (and not hand-construct `HermesACGSMiddleware`) so future
  constructor changes only need a one-line fix.
- Evidence assertions read from `tmp_path / "session.jsonl"` — never from a
  fixed path in the repo. A test that writes to `hermes_acgs_bundle/evidence/`
  is broken and will pollute the audit chain.
- `session_id="pytest-session"` and `agent_id="hermes-test-agent"` are the
  canonical identifiers; downstream evidence-chain tests pin these values.
- When extending the constitution, update both `constitution.min.yaml` and
  these tests together; the suite is intentionally fixture-light so any
  drift in allowed tools or decision modes is caught immediately.
