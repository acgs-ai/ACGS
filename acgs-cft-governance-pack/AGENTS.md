# AGENTS.md — acgs-cft-governance-pack

## Purpose

This is a companion policy and evidence pack for Google Cloud's Cloud Foundation Toolkit (CFT) Terraform modules. It demonstrates a narrow, reviewable governance gate that sits between `terraform plan` and `terraform apply` — converting a plan JSON through `gcloud terraform vet` / OPA / ACGS controls into an append-only evidence bundle that downstream CI can require before allowing apply. The pack is intentionally external to `terraform-google-modules` so enterprises can adopt it without forking upstream.

## Key Files / Subdirs

- `acgs_cft_governance_pack/evaluator.py` — Public orchestration facade: hashes the plan, iterates policies, calls the control evaluator, and delegates evidence event assembly.
- `acgs_cft_governance_pack/controls.py` — Terraform plan resource selection, rule dispatch, and rule implementations (`forbidden_apis`, `require_project_labels`, `deny_iam_roles`, `require_gke_private_nodes`, etc.).
- `acgs_cft_governance_pack/evidence.py` — Evidence envelope construction: `allow` / `deny` decision text, timestamping, and Merkle-root assignment.
- `acgs_cft_governance_pack/hashing.py` — Canonical JSON SHA-256 hashing and Merkle-root construction for evidence records.
- `acgs_cft_governance_pack/policy_io.py` — YAML policy loading and evidence JSONL writing.
- `acgs_cft_governance_pack/terraform_plan.py` — Terraform plan shape helpers for active changes, `after` payloads, firewall ports, and violation records.
- `acgs_cft_governance_pack/cli.py` + `__main__.py` — `python -m acgs_cft_governance_pack evaluate ...` entrypoint.
- `policies/*.yaml` — Bundled control sets for Project Factory, network exposure, GKE secure baseline, SA-key posture, and GitHub Actions runner gate.
- `examples/` — Allowed / denied Terraform plan fixtures used by tests and the README walkthrough.
- `ci/github-actions-acgs-gate.yaml` — Reference GitHub Actions workflow that runs `terraform show -json`, calls this evaluator, and uploads the evidence bundle.
- `evidence/sample-governed-terraform-plan.jsonl` — Reference output for verifier development.
- `tests/` — Pytest suite covering rule behavior, evidence hashing, policy IO, and CLI smoke contracts.

## Workflow / Commands

```bash
# Install with test extras
python -m pip install -e ".[test]"

# Evaluate an allowed Project Factory plan -> evidence JSONL
python -m acgs_cft_governance_pack evaluate \
  --plan examples/project-factory/terraform-plan.allowed.json \
  --policy-dir policies \
  --actor platform-ci --role validator \
  --out evidence/local-project-factory.jsonl

# Run the test suite
python -m pytest acgs-cft-governance-pack/tests -q
```

## Conventions

- Each evaluation emits exactly one JSONL event with schema `acgs.cft.evidence.v1`, including `plan_hash`, `actor`, `decision`, control `reasons`, and a Merkle root over the per-control receipts.
- Denied plans exit with code `2` so CI can hard-fail without parsing JSON; allowed plans exit `0`.
- This pack complements (does not replace) `gcloud beta terraform vet` and Google Cloud policy validation — run both in the same job for defense in depth.

## Gotchas

- Policy YAML schemas are strict: an unknown `rule.kind` is a hard error, not a warning. When adding a new control kind, register it in `controls.py` and document it in the README rule-kinds table in the same change.
- The evidence JSONL is append-only and Merkle-rooted per evaluation. Never edit emitted events by hand — regenerate from the original plan instead.
