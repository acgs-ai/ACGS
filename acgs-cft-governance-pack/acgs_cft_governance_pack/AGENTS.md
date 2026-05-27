# AGENTS.md — acgs-cft-governance-pack/acgs_cft_governance_pack

## Purpose

Python package that evaluates Google Cloud Foundation Toolkit (CFT) Terraform
plans against the ACGS governance controls and emits hash-chained evidence
JSONL. This is the importable / CLI surface — the parent repo's `policies/`
directory carries the YAML rule bundles consumed at runtime, and
`acgs-cft-governance-pack/tests/` exercises the public API.

## Key Files

- `__init__.py` — Public re-exports: `evaluate_plan`, `load_policies`,
  `write_evidence_jsonl`
- `__main__.py` — Enables `python -m acgs_cft_governance_pack` invocation
- `cli.py` — `acgs-cft-govern` console script; subcommands `evaluate`, plus arg
  parsing for `--plan`, `--policy-dir`, `--policy`, evidence output paths
- `evaluator.py` — Public orchestration facade: plan hashing, policy iteration,
  control evaluation, and evidence builder delegation.
- `controls.py` — Terraform plan walker, rule-kind dispatch, and violation
  construction for every bundled governance control.
- `evidence.py` — Evidence envelope construction, decision/reason text,
  timestamping, and Merkle-root assignment.
- `hashing.py` — Canonical JSON SHA-256 hashing and Merkle-root construction.
- `policy_io.py` — YAML policy loading and evidence JSONL writing.
- `terraform_plan.py` — Terraform plan shape helpers for active changes,
  `after` payloads, firewall ports, and violation records.

## Workflow / Commands

```bash
# Evaluate a captured plan against the default policy directory
python -m acgs_cft_governance_pack evaluate \
  --plan terraform-plan.json \
  --policy-dir ../policies

# Run the package's tests from the repo root
pytest acgs-cft-governance-pack/tests -q

# Install in editable mode while iterating
pip install -e ./acgs-cft-governance-pack
```

## Gotchas / Conventions

- Evidence is the contract: every evaluation produces a JSONL record whose
  `plan_hash` field starts with `sha256:` and whose `decision` is one of
  `allow`/`deny`/`warn`. Tests in `tests/test_evaluator.py` pin these shapes —
  do not rename keys without updating the consumers (governance audit chain).
- `load_policies()` accepts both a directory of YAML files and explicit
  `--policy` paths; the CLI flattens both into a single list before
  `evaluate_plan()` runs, so policy precedence follows insertion order.
- `evaluator.py` intentionally re-exports `load_policies()` and
  `write_evidence_jsonl()` from `policy_io.py` for backward-compatible imports.
- Keep `evaluator.py` import-light at module top. YAML/JSON file work belongs
  in `policy_io.py`; deterministic hashing belongs in `hashing.py`; evidence
  envelope assembly belongs in `evidence.py`; plan-rule logic belongs in
  `controls.py`; Terraform plan shape parsing belongs in `terraform_plan.py`.
