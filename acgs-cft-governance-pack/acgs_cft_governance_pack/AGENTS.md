# AGENTS.md — acgs-cft-governance-pack/acgs_cft_governance_pack

## Purpose

Python package that evaluates Google Cloud Foundation Toolkit (CFT) Terraform
plans against the ACGS governance controls and emits hash-chained evidence
JSONL. This is the importable / CLI surface — the parent repo's `policies/`
directory carries the YAML rule bundles consumed at runtime, and
`acgs-cft-governance-pack/tests/` exercises the public API.

## Key Files

- `__init__.py` — Public re-exports: `evaluate_plan`, `load_policies`
- `__main__.py` — Enables `python -m acgs_cft_governance_pack` invocation
- `cli.py` — `acgs-cft-govern` console script; subcommands `evaluate`, plus arg
  parsing for `--plan`, `--policy-dir`, `--policy`, evidence output paths
- `evaluator.py` — Core engine: policy loader, plan walker, decision builder
  (`allow` / `deny` / `warn`), evidence record assembly with `plan_hash` SHA-256

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
- The package depends on `governance.models.sha256_json` from
  `acgs_governance_eval_mvp` only for evidence canonicalisation in some
  pipelines; the local evaluator implements its own hashing for the
  Terraform-plan path to stay drop-in installable.
- Keep `evaluator.py` import-light at module top — heavy YAML/JSON work belongs
  inside `load_policies()` and `evaluate_plan()` so `python -m` startup stays
  under ~300 ms.
