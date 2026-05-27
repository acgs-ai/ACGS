# AGENTS.md — acgs-cft-governance-pack/tests

## Purpose

Pytest suite for the `acgs_cft_governance_pack` policy engine. The tests load
real Terraform plan JSON fixtures from `acgs-cft-governance-pack/examples/`
and real YAML policies from `acgs-cft-governance-pack/policies/`, then assert
that the resulting evidence records carry the expected decision, plan hash,
and control attribution. This is the canonical regression net for any change
to `evaluator.py`, `controls.py`, `evidence.py`, `hashing.py`, `policy_io.py`,
`terraform_plan.py`, the CLI, or the policy schema.

## Key Files

- `test_evaluator.py` — End-to-end checks: allowed plan -> `allow` decision +
  `sha256:` plan hash; denied plan -> `deny` decision with matching rule IDs;
  evidence JSONL round-trip; actor/tenant attribution propagation.
- `test_controls.py` — Focused checks for rule dispatch, violation shape, and
  unknown rule-kind hard failures.
- `test_evidence.py` — Evidence envelope construction, decision/reason text,
  deterministic timestamping, and Merkle-root shape.
- `test_hashing.py` — Canonical JSON hashing and Merkle-root invariants.
- `test_policy_io.py` — YAML policy loading and JSONL writer behavior.
- `test_cli.py` — CLI exit-code and evidence-writing smoke tests.
- `test_terraform_plan.py` — Terraform plan shape helpers for active changes,
  `after` payloads, firewall ports, and violation records.

## Workflow / Commands

```bash
# Run only this package's tests
pytest acgs-cft-governance-pack/tests -q

# Single test with verbose output and stdout capture disabled
pytest acgs-cft-governance-pack/tests/test_evaluator.py::test_project_factory_allowed_plan_emits_allow_decision -s -vv

# Generate coverage for the evaluator
pytest acgs-cft-governance-pack/tests \
  --cov=acgs_cft_governance_pack \
  --cov-report=term-missing
```

## Gotchas / Conventions

- Fixtures resolve paths relative to the package root via
  `Path(__file__).resolve().parents[1]`. If you move tests up or down a level,
  update `parents[N]` or the example/policy paths will resolve to the wrong
  directory and fixtures will silently 404.
- Plan hashes are stable: the suite asserts `plan_hash.startswith("sha256:")`
  rather than pinning the full digest so adding metadata fields to plans
  doesn't break tests, but the canonicalisation rules in `hashing.py` still
  matter — any change there will shift digests for downstream chain stores.
- `actor_id`, `actor_role`, and `tenant` are required positional kwargs to
  `evaluate_plan()`; tests use `platform-ci` / `validator` / `cft` as the
  default identity. Use the same triple when adding new tests to keep
  evidence-store diff noise low.
- Do not write evidence to the real repo paths during tests — use
  `tmp_path` (pytest) when exercising `write_evidence_jsonl`.
