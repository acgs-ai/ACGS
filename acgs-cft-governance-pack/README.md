# ACGS CFT Governance Pack

Companion policy and evidence pack for Google Cloud's Cloud Foundation Toolkit (CFT) Terraform modules.

This project is intentionally external to `terraform-google-modules`. It demonstrates a narrow, reviewable governance gate that enterprises can place around CFT plans without changing upstream modules:

```text
terraform plan JSON -> gcloud terraform vet / OPA / ACGS checks -> evidence bundle -> apply gate
```

## What it proves

- **Project Factory governance**: validate project labels, folders, billing accounts, IAM roles, APIs, and service account key posture before apply.
- **Network governance**: deny broad SSH/RDP exposure and require firewall/subnet logging evidence.
- **GKE governance profile**: encode secure-baseline expectations such as private nodes, Workload Identity, Shielded Nodes, and release channels.
- **CI/CD attachment point**: show how a GitHub Actions runner workflow can publish an evidence bundle before Terraform apply.
- **Audit evidence**: emit JSONL containing plan hash, actor role, policy decision, control reasons, timestamp, and a Merkle root.

## Quickstart

```bash
python -m pip install -e ".[test]"

python -m acgs_cft_governance_pack evaluate \
  --plan examples/project-factory/terraform-plan.allowed.json \
  --policy-dir policies \
  --actor platform-ci \
  --role validator \
  --out evidence/local-project-factory.jsonl
```

Denied plans exit with code `2`:

```bash
python -m acgs_cft_governance_pack evaluate \
  --plan examples/network-firewall-policy/terraform-plan.denied.json \
  --policy-dir policies \
  --actor platform-ci \
  --role validator \
  --out evidence/local-network-denied.jsonl
```

## Evidence format

Each evaluation writes one JSONL event:

```json
{
  "schema": "acgs.cft.evidence.v1",
  "event_type": "terraform_plan_evaluation",
  "decision": "deny",
  "plan_hash": "sha256:...",
  "actor": {"id": "platform-ci", "role": "validator"},
  "reason": "Denied by 3 governance controls",
  "merkle_root": "sha256:..."
}
```

The sample bundle in `evidence/sample-governed-terraform-plan.jsonl` is generated from the allowed Project Factory fixture.

## Policy schema

Policies are YAML files with one or more controls:

```yaml
id: cft-project-creation
description: Baseline controls for CFT Project Factory plans.
controls:
  - id: cft-project-required-labels
    severity: high
    resource_types:
      - google_project
    rule:
      kind: require_project_labels
      labels:
        - environment
        - owner
        - data_classification
```

Implemented rule kinds:

| Kind | Purpose |
| --- | --- |
| `forbidden_apis` | Deny project services that should not be enabled. |
| `require_project_labels` | Require labels on `google_project`. |
| `restrict_project_folder` | Restrict project placement to approved folders. |
| `restrict_billing_account` | Restrict billing accounts. |
| `deny_service_account_keys` | Deny creating long-lived service account keys. |
| `deny_iam_roles` | Deny broad IAM roles such as `roles/editor`. |
| `deny_public_ingress` | Deny public ingress on sensitive ports. |
| `require_firewall_log_config` | Require firewall logging metadata. |
| `require_subnet_flow_logs` | Require VPC subnet flow logs. |
| `require_gke_private_nodes` | Require private GKE nodes. |
| `require_gke_workload_identity` | Require GKE Workload Identity. |
| `require_gke_shielded_nodes` | Require Shielded Nodes. |
| `require_gke_release_channel` | Require an approved GKE release channel. |
| `require_github_oidc_provider` | Require GitHub OIDC provider hardening. |

## CI pattern

`ci/github-actions-acgs-gate.yaml` shows the intended use:

1. Generate `tfplan.binary`.
2. Convert it with `terraform show -json`.
3. Run existing Terraform-native policy checks such as `gcloud beta terraform vet`.
4. Run this ACGS evidence gate.
5. Upload the JSONL evidence bundle as a CI artifact.

This complements CFT and Google Cloud policy validation; it does not replace them.
